"""Healthcheck engine (issue #6): probes defined in a mounted healthchecks.yaml.

The Celery beat task ``server_monitor.tasks.run_healthchecks`` (every 30
min) loads the yaml config (path from the ``HEALTHCHECKS_CONFIG`` env var,
default ``./healthchecks.yaml``; in production the file is mounted at
``/config/healthchecks.yaml`` — compose wiring is issue #9's scope) and
runs each probe, writing one Redis snapshot per check name so
``server_monitor_check_up{check}`` / ``server_monitor_check_last_run_seconds{check}`` work
through the #3 metrics shell.

Five probe types (all thresholds configurable in the yaml):

- ``http``:      GET ``url``, ok when the status equals ``expected_status``.
- ``container``: Docker container state/health via the read-only docker
  socket (same ``UnixSocketDockerClient`` httpx-over-uds pattern as the
  #5 image digest check).
- ``disk``:      ``statvfs`` on ``path``; ``warn`` above ``warn_percent``
  used, ``fail`` above ``fail_percent``.
- ``internet``:  HTTP probe to a stable endpoint; fails only after 2
  consecutive failures (counter in Redis, key ``server_monitor:consec-fail:<name>``).
- ``fail2ban``:  recent bans across all jails via the read-only fail2ban
  unix socket; fails when the total exceeds ``max_recent_bans``.

Every external interaction goes through an injectable seam so tests never
touch the network, the docker socket, the filesystem or the fail2ban
socket:

- ``HttpFetcher``: ``(url, timeout_s) -> status code`` (default httpx).
- ``ContainerInspector``: ``inspect_container(name) -> dict`` (default
  Engine API over the unix socket).
- ``StatvfsProbe``: ``(path) -> os.statvfs_result`` (default ``os.statvfs``).
- ``Fail2banClient``: ``jails()`` + ``currently_banned(jail)`` (default
  minimal JSON-ish client on the fail2ban unix socket).
- The Redis client (for the internet consecutive-failure counter) is the
  store's injected client.
"""

import json
import os
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import yaml

from server_monitor.checks.docker_images import UnixSocketDockerClient

#: Env var holding the healthchecks yaml path; default is the repo-root file.
CONFIG_ENV = "HEALTHCHECKS_CONFIG"
DEFAULT_CONFIG_PATH = "./healthchecks.yaml"

#: Stable default internet probe endpoint (answers 200 with plain text).
DEFAULT_INTERNET_URL = "https://cloudflare.com/cdn-cgi/trace"

#: The internet check fails only after this many consecutive probe failures.
INTERNET_FAIL_THRESHOLD = 2

#: Redis key prefix for the internet check's consecutive-failure counter.
CONSEC_FAIL_PREFIX = "server_monitor:consec-fail:"

DEFAULT_FAIL2BAN_SOCK = "/var/run/fail2ban/fail2ban.sock"

VALID_TYPES = ("http", "container", "disk", "internet", "fail2ban")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthcheckConfig:
    """One probe definition from healthchecks.yaml, defaults applied."""

    name: str
    type: str
    url: str = ""  # http / internet
    expected_status: int = 200  # http
    timeout_s: float = 5.0  # http / internet
    container_name: str = ""  # container
    path: str = "/"  # disk
    warn_percent: float = 80.0  # disk
    fail_percent: float = 90.0  # disk
    socket: str = DEFAULT_FAIL2BAN_SOCK  # fail2ban
    max_recent_bans: int = 10  # fail2ban


def _config_from_entry(entry: Any, index: int) -> HealthcheckConfig:
    if not isinstance(entry, dict):
        raise ValueError(f"checks[{index}] must be a mapping, got {type(entry).__name__}")
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"checks[{index}]: 'name' is required and must be a non-empty string")
    ctype = entry.get("type")
    if ctype not in VALID_TYPES:
        raise ValueError(
            f"check {name!r}: unknown type {ctype!r} (valid types: {', '.join(VALID_TYPES)})"
        )
    config = HealthcheckConfig(
        name=name,
        type=ctype,
        url=str(entry.get("url") or (DEFAULT_INTERNET_URL if ctype == "internet" else "")),
        expected_status=int(entry.get("expected_status", 200)),
        timeout_s=float(entry.get("timeout_s", 5.0)),
        container_name=str(entry.get("container_name", "")),
        path=str(entry.get("path", "/")),
        warn_percent=float(entry.get("warn_percent", 80.0)),
        fail_percent=float(entry.get("fail_percent", 90.0)),
        socket=str(entry.get("socket", DEFAULT_FAIL2BAN_SOCK)),
        max_recent_bans=int(entry.get("max_recent_bans", 10)),
    )
    if ctype == "http" and not config.url:
        raise ValueError(f"check {name!r} (http): 'url' is required")
    if ctype == "container" and not config.container_name:
        raise ValueError(f"check {name!r} (container): 'container_name' is required")
    return config


def load_healthchecks(path: str | os.PathLike[str] | None = None) -> list[HealthcheckConfig]:
    """Load and validate the healthchecks yaml; env var ``HEALTHCHECKS_CONFIG``
    (default ``./healthchecks.yaml``) supplies the path when ``path`` is None."""
    resolved = os.fspath(path) if path is not None else os.environ.get(
        CONFIG_ENV, DEFAULT_CONFIG_PATH
    )
    with open(resolved, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("checks"), list):
        raise ValueError(
            f"{resolved}: expected a top-level 'checks' list, got: {data!r}"
        )
    configs = [_config_from_entry(entry, i) for i, entry in enumerate(data["checks"])]
    seen: set[str] = set()
    for config in configs:
        if config.name in seen:
            raise ValueError(f"{resolved}: duplicate check name {config.name!r}")
        seen.add(config.name)
    return configs


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthcheckResult:
    """One probe outcome; ``status`` is "ok" | "warn" | "fail"."""

    name: str
    type: str
    status: str
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _result(
    config: HealthcheckConfig, status: str, detail: str, **extra: Any
) -> HealthcheckResult:
    return HealthcheckResult(
        name=config.name, type=config.type, status=status, detail=detail, extra=extra
    )


# ---------------------------------------------------------------------------
# Seams
# ---------------------------------------------------------------------------

#: HTTP seam: (url, timeout_s) -> HTTP status code; raises on failure.
HttpFetcher = Callable[[str, float], int]


def fetch_status(url: str, timeout_s: float) -> int:
    """Default ``HttpFetcher``: one GET with httpx, returning the status code."""
    with httpx.Client(timeout=timeout_s, follow_redirects=True) as client:
        return client.get(url).status_code


class ContainerNotFound(RuntimeError):
    """The docker daemon has no container with that name (API 404)."""


class ContainerInspector(Protocol):
    """The slice of the Docker Engine API the container check relies on."""

    def inspect_container(self, name: str) -> dict[str, Any]:
        """``GET /containers/<name>/json``: State.Status, State.Health, ..."""
        ...


class UnixSocketContainerClient(UnixSocketDockerClient):
    """Default ``ContainerInspector``: same read-only unix-socket httpx
    client as the #5 image digest check, plus the container inspect call."""

    def inspect_container(self, name: str) -> dict[str, Any]:
        response = self._client.get(f"/containers/{name}/json")
        if response.status_code == 404:
            raise ContainerNotFound(f"no such container: {name}")
        response.raise_for_status()
        return response.json()


def default_container_client(sock_path: str | None = None) -> ContainerInspector:
    """Production seam default: Engine API on DOCKER_SOCK."""
    return UnixSocketContainerClient(sock_path)


#: Filesystem seam: (path) -> os.statvfs_result for that path.
StatvfsProbe = Callable[[str], os.statvfs_result]


class Fail2banClient(Protocol):
    """The slice of the fail2ban server API the check relies on."""

    def jails(self) -> list[str]:
        """Names of all active jails (``status``)."""
        ...

    def currently_banned(self, jail: str) -> int:
        """Currently banned count for one jail (``status <jail>``)."""
        ...


class Fail2banSocketClient:
    """Default ``Fail2banClient``: minimal calls over the fail2ban unix socket.

    The fail2ban server socket speaks a simple JSON-ish protocol: the client
    sends one JSON-encoded command list (e.g. ``["status", "sshd"]``) as a
    single line, half-closes the connection, and reads the response until
    EOF. Only the two calls the check needs are implemented: ``status``
    (jail list) and ``status <jail>`` (per-jail ban counts). Responses may
    be JSON or the classic pretty-printed text; both are parsed.
    """

    def __init__(self, sock_path: str | None = None, timeout: float = 5.0) -> None:
        self._sock_path = sock_path or os.environ.get(
            "FAIL2BAN_SOCK", DEFAULT_FAIL2BAN_SOCK
        )
        self._timeout = timeout

    def _call(self, *command: str) -> str:
        payload = json.dumps(list(command)).encode("utf-8") + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect(self._sock_path)
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # server may already have closed its side
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")

    def jails(self) -> list[str]:
        return parse_jail_list(self._call("status"))

    def currently_banned(self, jail: str) -> int:
        return parse_currently_banned(self._call("status", jail))


def _response_text(raw: str) -> str:
    """Normalize a socket response: unwrap JSON containers to their text."""
    text = raw.strip()
    if text.startswith(("[", "{")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return raw
        if isinstance(data, list):
            return "\n".join(str(item) for item in data if isinstance(item, str))
        if isinstance(data, dict):
            return "\n".join(str(value) for value in data.values())
    return raw


def parse_jail_list(raw: str) -> list[str]:
    """Parse jail names out of a ``status`` response (``Jail list: a, b``)."""
    text = _response_text(raw)
    match = re.search(r"Jail list:\s*(.+)", text)
    if not match:
        return []
    return [jail.strip() for jail in match.group(1).split(",") if jail.strip()]


def parse_currently_banned(raw: str) -> int:
    """Parse ``Currently banned: N`` out of a ``status <jail>`` response."""
    text = _response_text(raw)
    match = re.search(r"Currently banned:\s*(\d+)", text)
    return int(match.group(1)) if match else 0


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


def probe_http(config: HealthcheckConfig, fetch: HttpFetcher) -> HealthcheckResult:
    """GET ``url``; ok when the response status equals ``expected_status``."""
    try:
        status_code = fetch(config.url, config.timeout_s)
    except Exception as exc:
        return _result(config, "fail", f"GET {config.url} failed: {exc}")
    if status_code == config.expected_status:
        return _result(
            config, "ok", f"GET {config.url} -> {status_code}", status_code=status_code
        )
    return _result(
        config,
        "fail",
        f"GET {config.url} -> {status_code}, expected {config.expected_status}",
        status_code=status_code,
    )


def probe_container(
    config: HealthcheckConfig, docker: ContainerInspector
) -> HealthcheckResult:
    """Ok when the container is running and (if it defines a HEALTHCHECK)
    healthy; any other state/health is a failure."""
    try:
        info = docker.inspect_container(config.container_name)
    except ContainerNotFound:
        return _result(
            config, "fail", f"container {config.container_name!r} not found"
        )
    except Exception as exc:
        return _result(
            config,
            "fail",
            f"docker inspect of {config.container_name!r} failed: {exc}",
        )
    state = info.get("State") or {}
    container_state = state.get("Status", "unknown")
    health = (state.get("Health") or {}).get("Status")
    extra = {"container_state": container_state, "health": health}
    if container_state != "running":
        return _result(
            config,
            "fail",
            f"container {config.container_name!r} state: {container_state}",
            **extra,
        )
    if health is not None and health != "healthy":
        return _result(
            config,
            "fail",
            f"container {config.container_name!r} health: {health}",
            **extra,
        )
    detail = f"container {config.container_name!r} running"
    if health:
        detail += f", health: {health}"
    return _result(config, "ok", detail, **extra)


def probe_disk(
    config: HealthcheckConfig, statvfs: StatvfsProbe = os.statvfs
) -> HealthcheckResult:
    """Disk usage of ``path`` via statvfs: ``warn`` above ``warn_percent``
    used, ``fail`` above ``fail_percent`` (strictly greater, per the design
    decision "warn >80%, fail >90%")."""
    try:
        stats = statvfs(config.path)
    except OSError as exc:
        return _result(config, "fail", f"statvfs {config.path} failed: {exc}")
    if stats.f_blocks <= 0:
        return _result(config, "fail", f"{config.path}: filesystem reports 0 blocks")
    used_percent = (stats.f_blocks - stats.f_bfree) * 100.0 / stats.f_blocks
    thresholds = (
        f"warn >{config.warn_percent:g}%, fail >{config.fail_percent:g}%"
    )
    detail = f"{used_percent:.1f}% used on {config.path} ({thresholds})"
    extra = {"used_percent": round(used_percent, 1), "path": config.path}
    if used_percent > config.fail_percent:
        return _result(config, "fail", detail, **extra)
    if used_percent > config.warn_percent:
        return _result(config, "warn", detail, **extra)
    return _result(config, "ok", detail, **extra)


def probe_internet(
    config: HealthcheckConfig,
    fetch: HttpFetcher,
    redis: Any,
) -> HealthcheckResult:
    """Probe a stable endpoint; any HTTP response means the internet is
    reachable. Fails only after ``INTERNET_FAIL_THRESHOLD`` consecutive
    failures — the counter lives in Redis under
    ``server_monitor:consec-fail:<name>`` and resets on success."""
    key = f"{CONSEC_FAIL_PREFIX}{config.name}"
    try:
        fetch(config.url, config.timeout_s)
    except Exception as exc:
        raw = redis.get(key)
        try:
            failures = (int(raw) + 1) if raw is not None else 1
        except (TypeError, ValueError):
            failures = 1
        redis.set(key, str(failures))
        if failures >= INTERNET_FAIL_THRESHOLD:
            return _result(
                config,
                "fail",
                f"{config.url} unreachable ({failures} consecutive failures: {exc})",
                consecutive_failures=failures,
            )
        return _result(
            config,
            "ok",
            f"{config.url} unreachable once "
            f"({failures}/{INTERNET_FAIL_THRESHOLD} consecutive failures: {exc})",
            consecutive_failures=failures,
        )
    redis.delete(key)  # success: reset the consecutive-failure counter
    return _result(config, "ok", f"{config.url} reachable")


def probe_fail2ban(
    config: HealthcheckConfig, client: Fail2banClient
) -> HealthcheckResult:
    """Ok while the total currently-banned count across all jails is
    <= ``max_recent_bans``; above that the check fails (suspicious login
    activity)."""
    try:
        jails = client.jails()
        per_jail = {jail: client.currently_banned(jail) for jail in jails}
    except Exception as exc:
        return _result(
            config, "fail", f"fail2ban query via {config.socket} failed: {exc}"
        )
    total = sum(per_jail.values())
    breakdown = ", ".join(f"{jail}={count}" for jail, count in sorted(per_jail.items()))
    detail = (
        f"{total} recent bans across {len(jails)} jails "
        f"(max {config.max_recent_bans})"
        + (f": {breakdown}" if breakdown else "")
    )
    extra = {
        "total_bans": total,
        "jails": len(jails),
        "bans_per_jail": per_jail,
        "max_recent_bans": config.max_recent_bans,
    }
    if total > config.max_recent_bans:
        return _result(config, "fail", detail, **extra)
    return _result(config, "ok", detail, **extra)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_healthchecks(
    configs: list[HealthcheckConfig],
    *,
    redis: Any,
    fetch: HttpFetcher = fetch_status,
    docker: ContainerInspector | None = None,
    statvfs: StatvfsProbe = os.statvfs,
    fail2ban_client: Fail2banClient | None = None,
) -> list[HealthcheckResult]:
    """Run every configured probe and return one result per check.

    Seams default to the production clients but are always injectable;
    ``redis`` is the store's client (used by the internet check's
    consecutive-failure counter). A probe that raises internally is
    converted to a failed result by the probe itself, so one broken probe
    never aborts the run.
    """
    results: list[HealthcheckResult] = []
    for config in configs:
        if config.type == "http":
            results.append(probe_http(config, fetch))
        elif config.type == "container":
            results.append(
                probe_container(
                    config, docker if docker is not None else default_container_client()
                )
            )
        elif config.type == "disk":
            results.append(probe_disk(config, statvfs))
        elif config.type == "internet":
            results.append(probe_internet(config, fetch, redis))
        elif config.type == "fail2ban":
            results.append(
                probe_fail2ban(
                    config,
                    fail2ban_client
                    if fail2ban_client is not None
                    else Fail2banSocketClient(config.socket),
                )
            )
        else:  # pragma: no cover - load_healthchecks rejects unknown types
            raise ValueError(f"unknown check type: {config.type!r}")
    return results
