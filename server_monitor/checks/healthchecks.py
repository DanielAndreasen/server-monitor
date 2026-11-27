"""Healthcheck engine (issue #6): probes defined in a mounted healthchecks.yaml.

The Celery beat task ``server_monitor.tasks.run_healthchecks`` (every 30
min) loads the yaml config (path from the ``HEALTHCHECKS_CONFIG`` env var,
default ``./healthchecks.yaml``; in production the file is mounted at
``/config/healthchecks.yaml`` — compose wiring is issue #9's scope) and
runs each probe, writing one Redis snapshot per check name so
``server_monitor_check_up{check}`` / ``server_monitor_check_last_run_seconds{check}`` work
through the #3 metrics shell.

Twelve probe types (all thresholds configurable in the yaml):

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
- ``cert-expiry`` (issue #20): TLS handshake to ``host:port``, read the peer
  certificate's ``notAfter``; ``warn``/``fail`` by remaining days
  (``warn_days``/``fail_days``).
- ``load`` (#20): 1-min loadavg from ``loadavg_path`` (/proc/loadavg) plus
  used memory % from ``meminfo_path`` (/proc/meminfo); the probe reports
  the worse of the load and memory statuses.
- ``temperature`` (#20): millidegrees from ``sensor`` (a /sys thermal zone
  file); ``warn``/``fail`` above ``warn_c``/``fail_c``.
- ``reboot-required`` (#20): ``warn`` when the marker file ``path``
  (default /var/run/reboot-required) exists on the host.
- ``backup-freshness`` (#20): newest file mtime in ``dir``; ``fail`` when
  older than ``max_age_hours``.
- ``tcp-port`` (#20): bare TCP connect to ``host:port``; ``fail`` on
  refusal/timeout.
- ``error-scan`` (#20): count ERROR/CRITICAL lines in the last
  ``since_minutes`` of ``log`` (or of ``journalctl --since`` output when
  ``journal: true``); ``fail`` above ``max_errors``.

Every external interaction goes through an injectable seam so tests never
touch the network, the docker socket, the filesystem or the fail2ban
socket:

- ``HttpFetcher``: ``(url, timeout_s) -> status code`` (default httpx).
- ``ContainerInspector``: ``inspect_container(name) -> dict`` (default
  Engine API over the unix socket).
- ``StatvfsProbe``: ``(path) -> os.statvfs_result`` (default ``os.statvfs``).
- ``Fail2banClient``: ``jails()`` + ``currently_banned(jail)`` (default
  minimal JSON-ish client on the fail2ban unix socket).
- ``HostFilesystem``: ``read_text`` / ``exists`` / ``dir_mtimes`` (default
  ``LocalHostFilesystem``; in production the host's /proc, /sys, /var/run
  and backup dir are bind-mounted read-only into the worker).
- ``CertFetcher``: ``(host, port, timeout_s) -> notAfter datetime``
  (default TLS handshake via ``ssl``).
- ``TcpConnector``: ``(host, port, timeout_s) -> None``, raising on
  refusal/timeout (default ``socket.create_connection``).
- ``LogRunner``: ``(journalctl args) -> stdout`` (default subprocess).
- The Redis client (for the internet consecutive-failure counter) is the
  store's injected client.
"""

import calendar
import json
import os
import re
import socket
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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

# --- issue #20 probe defaults ---------------------------------------------
DEFAULT_CERT_PORT = 443
DEFAULT_CERT_WARN_DAYS = 14.0
DEFAULT_CERT_FAIL_DAYS = 7.0
DEFAULT_REBOOT_REQUIRED_PATH = "/var/run/reboot-required"
DEFAULT_LOADAVG_PATH = "/proc/loadavg"
DEFAULT_MEMINFO_PATH = "/proc/meminfo"
DEFAULT_WARN_LOAD = 4.0
DEFAULT_FAIL_LOAD = 8.0
DEFAULT_MEM_WARN_PERCENT = 80.0
DEFAULT_MEM_FAIL_PERCENT = 90.0
DEFAULT_SENSOR_PATH = "/sys/class/thermal/thermal_zone0/temp"
DEFAULT_WARN_C = 70.0
DEFAULT_FAIL_C = 85.0
DEFAULT_BACKUP_DIR = "/mnt/backups"
DEFAULT_MAX_AGE_HOURS = 26.0
DEFAULT_LOG_PATH = "/var/log/syslog"
DEFAULT_SINCE_MINUTES = 60.0
DEFAULT_MAX_ERRORS = 20

VALID_TYPES = (
    "http",
    "container",
    "disk",
    "internet",
    "fail2ban",
    "cert-expiry",
    "load",
    "temperature",
    "reboot-required",
    "backup-freshness",
    "tcp-port",
    "error-scan",
)

#: Option keys allowed per check type in healthchecks.yaml (besides the
#: mandatory ``name``/``type``); any other key is rejected at load time.
TYPE_KEYS: dict[str, frozenset[str]] = {
    "http": frozenset({"url", "expected_status", "timeout_s"}),
    "container": frozenset({"container_name"}),
    "disk": frozenset({"path", "warn_percent", "fail_percent"}),
    "internet": frozenset({"url", "timeout_s"}),
    "fail2ban": frozenset({"socket", "max_recent_bans"}),
    "cert-expiry": frozenset({"host", "port", "timeout_s", "warn_days", "fail_days"}),
    "load": frozenset(
        {
            "loadavg_path",
            "meminfo_path",
            "warn_load",
            "fail_load",
            "mem_warn_percent",
            "mem_fail_percent",
        }
    ),
    "temperature": frozenset({"sensor", "warn_c", "fail_c"}),
    "reboot-required": frozenset({"path"}),
    "backup-freshness": frozenset({"dir", "max_age_hours"}),
    "tcp-port": frozenset({"host", "port", "timeout_s"}),
    "error-scan": frozenset({"log", "since_minutes", "max_errors", "journal"}),
}


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
    timeout_s: float = 5.0  # http / internet / cert-expiry / tcp-port
    container_name: str = ""  # container
    path: str = "/"  # disk / reboot-required (default depends on type)
    warn_percent: float = 80.0  # disk
    fail_percent: float = 90.0  # disk
    socket: str = DEFAULT_FAIL2BAN_SOCK  # fail2ban
    max_recent_bans: int = 10  # fail2ban
    host: str = ""  # cert-expiry / tcp-port
    port: int = DEFAULT_CERT_PORT  # cert-expiry (default 443) / tcp-port
    warn_days: float = DEFAULT_CERT_WARN_DAYS  # cert-expiry
    fail_days: float = DEFAULT_CERT_FAIL_DAYS  # cert-expiry
    loadavg_path: str = DEFAULT_LOADAVG_PATH  # load
    meminfo_path: str = DEFAULT_MEMINFO_PATH  # load
    warn_load: float = DEFAULT_WARN_LOAD  # load
    fail_load: float = DEFAULT_FAIL_LOAD  # load
    mem_warn_percent: float = DEFAULT_MEM_WARN_PERCENT  # load
    mem_fail_percent: float = DEFAULT_MEM_FAIL_PERCENT  # load
    sensor: str = DEFAULT_SENSOR_PATH  # temperature
    warn_c: float = DEFAULT_WARN_C  # temperature
    fail_c: float = DEFAULT_FAIL_C  # temperature
    dir: str = DEFAULT_BACKUP_DIR  # backup-freshness
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS  # backup-freshness
    log: str = DEFAULT_LOG_PATH  # error-scan
    since_minutes: float = DEFAULT_SINCE_MINUTES  # error-scan
    max_errors: int = DEFAULT_MAX_ERRORS  # error-scan
    journal: bool = False  # error-scan


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
    allowed = TYPE_KEYS[ctype] | {"name", "type"}
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise ValueError(
            f"check {name!r} ({ctype}): unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )
    default_path = DEFAULT_REBOOT_REQUIRED_PATH if ctype == "reboot-required" else "/"
    config = HealthcheckConfig(
        name=name,
        type=ctype,
        url=str(entry.get("url") or (DEFAULT_INTERNET_URL if ctype == "internet" else "")),
        expected_status=int(entry.get("expected_status", 200)),
        timeout_s=float(entry.get("timeout_s", 5.0)),
        container_name=str(entry.get("container_name", "")),
        path=str(entry.get("path", default_path)),
        warn_percent=float(entry.get("warn_percent", 80.0)),
        fail_percent=float(entry.get("fail_percent", 90.0)),
        socket=str(entry.get("socket", DEFAULT_FAIL2BAN_SOCK)),
        max_recent_bans=int(entry.get("max_recent_bans", 10)),
        host=str(entry.get("host", "")),
        port=int(entry.get("port", DEFAULT_CERT_PORT)),
        warn_days=float(entry.get("warn_days", DEFAULT_CERT_WARN_DAYS)),
        fail_days=float(entry.get("fail_days", DEFAULT_CERT_FAIL_DAYS)),
        loadavg_path=str(entry.get("loadavg_path", DEFAULT_LOADAVG_PATH)),
        meminfo_path=str(entry.get("meminfo_path", DEFAULT_MEMINFO_PATH)),
        warn_load=float(entry.get("warn_load", DEFAULT_WARN_LOAD)),
        fail_load=float(entry.get("fail_load", DEFAULT_FAIL_LOAD)),
        mem_warn_percent=float(entry.get("mem_warn_percent", DEFAULT_MEM_WARN_PERCENT)),
        mem_fail_percent=float(entry.get("mem_fail_percent", DEFAULT_MEM_FAIL_PERCENT)),
        sensor=str(entry.get("sensor", DEFAULT_SENSOR_PATH)),
        warn_c=float(entry.get("warn_c", DEFAULT_WARN_C)),
        fail_c=float(entry.get("fail_c", DEFAULT_FAIL_C)),
        dir=str(entry.get("dir", DEFAULT_BACKUP_DIR)),
        max_age_hours=float(entry.get("max_age_hours", DEFAULT_MAX_AGE_HOURS)),
        log=str(entry.get("log", DEFAULT_LOG_PATH)),
        since_minutes=float(entry.get("since_minutes", DEFAULT_SINCE_MINUTES)),
        max_errors=int(entry.get("max_errors", DEFAULT_MAX_ERRORS)),
        journal=bool(entry.get("journal", False)),
    )
    if ctype == "http" and not config.url:
        raise ValueError(f"check {name!r} (http): 'url' is required")
    if ctype == "container" and not config.container_name:
        raise ValueError(f"check {name!r} (container): 'container_name' is required")
    if ctype in ("cert-expiry", "tcp-port") and not config.host:
        raise ValueError(f"check {name!r} ({ctype}): 'host' is required")
    if ctype == "tcp-port" and "port" not in entry:
        raise ValueError(f"check {name!r} (tcp-port): 'port' is required")
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


# ---------------------------------------------------------------------------
# Issue #20 seams: host filesystem, TLS cert, bare TCP, journalctl
# ---------------------------------------------------------------------------


class HostFilesystem(Protocol):
    """The slice of the host filesystem the #20 probes rely on. In
    production the host's /proc, /sys, /var/run and backup dir are
    bind-mounted read-only into the worker, so these are plain local
    reads at the mounted paths."""

    def read_text(self, path: str) -> str:
        """Whole contents of a (small) text file; raises OSError if missing."""
        ...

    def exists(self, path: str) -> bool:
        """Whether a file exists."""
        ...

    def dir_mtimes(self, path: str) -> list[tuple[str, float]]:
        """``(name, mtime)`` for every entry of a directory; raises OSError."""
        ...


class LocalHostFilesystem:
    """Default ``HostFilesystem``: plain ``os`` calls on the mounted paths."""

    def read_text(self, path: str) -> str:
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def dir_mtimes(self, path: str) -> list[tuple[str, float]]:
        with os.scandir(path) as entries:
            return [(entry.name, entry.stat().st_mtime) for entry in entries]


def default_hostfs() -> HostFilesystem:
    """Production seam default: the local (read-only mounted) filesystem."""
    return LocalHostFilesystem()


#: TLS certificate seam: (host, port, timeout_s) -> cert notAfter (aware UTC).
CertFetcher = Callable[[str, int, float], datetime]


def parse_cert_time(text: str) -> datetime:
    """Parse an X.509 ASN.1 time string (``notAfter``, e.g.
    ``'Jun  1 12:00:00 2027 GMT'``) into an aware UTC datetime."""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(text), tz=timezone.utc)


def fetch_cert_not_after(host: str, port: int, timeout_s: float = 5.0) -> datetime:
    """Default ``CertFetcher``: TLS handshake to host:port, read the peer
    certificate's ``notAfter``."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout_s) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = (cert or {}).get("notAfter")
    if not not_after:
        raise ValueError(f"peer certificate for {host}:{port} has no notAfter")
    return parse_cert_time(not_after)


#: Bare-TCP seam: (host, port, timeout_s) -> None; raises on refusal/timeout.
TcpConnector = Callable[[str, int, float], None]


def tcp_connect(host: str, port: int, timeout_s: float) -> None:
    """Default ``TcpConnector``: one blocking connect, then close."""
    with socket.create_connection((host, port), timeout=timeout_s):
        pass


#: journalctl seam for the error-scan probe's ``journal: true`` mode:
#: (args after ``journalctl``) -> stdout; raises on failure.
LogRunner = Callable[[list[str]], str]


def run_journalctl(args: list[str]) -> str:
    """Default ``LogRunner``: run ``journalctl <args>``, return stdout."""
    proc = subprocess.run(
        ["journalctl", *args], capture_output=True, text=True, check=True
    )
    return proc.stdout


# ---------------------------------------------------------------------------
# Pure parsers for the #20 probes (unit-tested directly, no I/O)
# ---------------------------------------------------------------------------

_STATUS_RANK = {"ok": 0, "warn": 1, "fail": 2}


def _worst(*statuses: str) -> str:
    """The most severe of the given statuses ("ok" < "warn" < "fail")."""
    return max(statuses, key=lambda status: _STATUS_RANK[status])


def parse_loadavg(text: str) -> tuple[float, float, float]:
    """Parse ``/proc/loadavg`` (``'0.52 1.10 1.99 2/345 12345'``) into
    ``(1min, 5min, 15min)`` load averages."""
    fields = text.split()
    if len(fields) < 3:
        raise ValueError(f"malformed loadavg line: {text!r}")
    return float(fields[0]), float(fields[1]), float(fields[2])


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse ``/proc/meminfo`` into a ``{key: kB}`` mapping."""
    info: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            info[key.strip()] = int(parts[0])
        except ValueError:
            continue  # e.g. the "VmallocChunk: 0 kB" style is fine; skip junk
    return info


def mem_used_percent(info: dict[str, int]) -> float:
    """Used memory percentage from a parsed meminfo mapping
    (``MemAvailable`` preferred, ``MemFree`` as fallback)."""
    total = info.get("MemTotal")
    if not total:
        raise ValueError("meminfo has no MemTotal entry")
    available = info.get("MemAvailable", info.get("MemFree", 0))
    return (total - available) * 100.0 / total


def parse_millidegrees(text: str) -> float:
    """Thermal sensor files report millidegrees Celsius: ``'42000'`` -> 42.0."""
    return int(text.strip()) / 1000.0


#: Lines matching this are counted by the error-scan probe.
ERROR_LINE_RE = re.compile(r"\b(?:ERROR|CRITICAL)\b")

_ISO_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_SYSLOG_PREFIX_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
_MONTHS = {name: number for number, name in enumerate(calendar.month_abbr) if name}


def parse_line_timestamp(line: str, now: datetime) -> datetime | None:
    """Parse a leading log-line timestamp into an aware UTC datetime.

    Supports ISO-8601 prefixes (``2026-11-27T14:23:01`` / ``2026-11-27 14:23:01``,
    as emitted by ``journalctl --output=short-iso``) and classic syslog
    prefixes (``Nov 27 14:23:01``). Syslog timestamps carry no year: the
    current year is assumed, rolled back one year when that would land in
    the future. Returns None when the line has no parseable timestamp.
    """
    iso = _ISO_PREFIX_RE.match(line)
    if iso:
        try:
            parsed = datetime.fromisoformat(f"{iso.group(1)}T{iso.group(2)}")
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc)
    syslog = _SYSLOG_PREFIX_RE.match(line)
    if syslog:
        month = _MONTHS.get(syslog.group(1))
        if month is None:
            return None
        try:
            hour, minute, second = (int(part) for part in syslog.group(3).split(":"))
            parsed = datetime(
                now.year, month, int(syslog.group(2)), hour, minute, second,
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
        if parsed > now + timedelta(days=1):
            parsed = parsed.replace(year=now.year - 1)  # e.g. Dec line seen in Jan
        return parsed
    return None


def count_recent_errors(text: str, since_minutes: float, now: datetime) -> int:
    """Count ERROR/CRITICAL lines within the last ``since_minutes`` of ``now``.

    Lines with a parseable timestamp older than the cutoff are skipped;
    error lines *without* a parseable timestamp are counted (conservative:
    when we cannot prove a line is old, it counts).
    """
    cutoff = now - timedelta(minutes=since_minutes)
    count = 0
    for line in text.splitlines():
        if not ERROR_LINE_RE.search(line):
            continue
        timestamp = parse_line_timestamp(line, now)
        if timestamp is not None and timestamp < cutoff:
            continue
        count += 1
    return count



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
# Issue #20 probes
# ---------------------------------------------------------------------------


def probe_cert_expiry(
    config: HealthcheckConfig,
    fetch_cert: CertFetcher,
    now: datetime | None = None,
) -> HealthcheckResult:
    """TLS handshake to ``host:port``; status by days until the peer cert's
    ``notAfter``: ``fail`` below ``fail_days``, ``warn`` below ``warn_days``,
    else ``ok`` (a cert with exactly ``fail_days`` left is still ``warn``)."""
    now = now or datetime.now(timezone.utc)
    try:
        not_after = fetch_cert(config.host, config.port, config.timeout_s)
    except Exception as exc:
        return _result(
            config,
            "fail",
            f"TLS handshake with {config.host}:{config.port} failed: {exc}",
            host=config.host,
            port=config.port,
        )
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    remaining_days = (not_after - now).total_seconds() / 86400.0
    thresholds = f"warn <{config.warn_days:g}d, fail <{config.fail_days:g}d"
    detail = (
        f"{config.host}:{config.port} cert expires {not_after:%Y-%m-%d %H:%M} UTC "
        f"({remaining_days:.1f} days left; {thresholds})"
    )
    extra = {
        "not_after": not_after.isoformat(),
        "remaining_days": round(remaining_days, 2),
        "warn_days": config.warn_days,
        "fail_days": config.fail_days,
        "host": config.host,
        "port": config.port,
    }
    if remaining_days < config.fail_days:
        return _result(config, "fail", detail, **extra)
    if remaining_days < config.warn_days:
        return _result(config, "warn", detail, **extra)
    return _result(config, "ok", detail, **extra)


def probe_load(config: HealthcheckConfig, hostfs: HostFilesystem) -> HealthcheckResult:
    """1-min loadavg from ``loadavg_path`` plus used memory % from
    ``meminfo_path``; the probe reports the worse of the load status
    (``warn``/``fail`` above ``warn_load``/``fail_load``) and the memory
    status (above ``mem_warn_percent``/``mem_fail_percent`` used)."""
    try:
        load1, load5, load15 = parse_loadavg(hostfs.read_text(config.loadavg_path))
        info = parse_meminfo(hostfs.read_text(config.meminfo_path))
        mem_pct = mem_used_percent(info)
    except Exception as exc:
        return _result(config, "fail", f"load/mem probe failed: {exc}")
    load_status = "ok"
    if load1 > config.fail_load:
        load_status = "fail"
    elif load1 > config.warn_load:
        load_status = "warn"
    mem_status = "ok"
    if mem_pct > config.mem_fail_percent:
        mem_status = "fail"
    elif mem_pct > config.mem_warn_percent:
        mem_status = "warn"
    status = _worst(load_status, mem_status)
    detail = (
        f"load {load1:.2f}/{load5:.2f}/{load15:.2f} "
        f"(warn >{config.warn_load:g}, fail >{config.fail_load:g}), "
        f"mem {mem_pct:.1f}% used "
        f"(warn >{config.mem_warn_percent:g}%, fail >{config.mem_fail_percent:g}%)"
    )
    extra = {
        "load_1min": load1,
        "load_5min": load5,
        "load_15min": load15,
        "mem_used_percent": round(mem_pct, 1),
        "mem_total_kb": info.get("MemTotal", 0),
        "mem_available_kb": info.get("MemAvailable", info.get("MemFree", 0)),
    }
    return _result(config, status, detail, **extra)


def probe_temperature(
    config: HealthcheckConfig, hostfs: HostFilesystem
) -> HealthcheckResult:
    """Read millidegrees Celsius from ``sensor``; ``warn``/``fail`` when the
    temperature is strictly above ``warn_c``/``fail_c``."""
    try:
        temp_c = parse_millidegrees(hostfs.read_text(config.sensor))
    except Exception as exc:
        return _result(
            config, "fail", f"temperature read from {config.sensor} failed: {exc}"
        )
    thresholds = f"warn >{config.warn_c:g}C, fail >{config.fail_c:g}C"
    detail = f"{temp_c:.1f}C from {config.sensor} ({thresholds})"
    extra = {
        "temp_c": round(temp_c, 2),
        "millidegrees": int(round(temp_c * 1000)),
        "sensor": config.sensor,
    }
    if temp_c > config.fail_c:
        return _result(config, "fail", detail, **extra)
    if temp_c > config.warn_c:
        return _result(config, "warn", detail, **extra)
    return _result(config, "ok", detail, **extra)


def probe_reboot_required(
    config: HealthcheckConfig, hostfs: HostFilesystem
) -> HealthcheckResult:
    """``warn`` when the host's reboot-required marker file (``path``)
    exists; ``ok`` when absent."""
    try:
        required = hostfs.exists(config.path)
    except Exception as exc:
        return _result(config, "fail", f"stat of {config.path} failed: {exc}")
    if required:
        return _result(
            config,
            "warn",
            f"reboot required ({config.path} exists)",
            reboot_required=True,
            path=config.path,
        )
    return _result(
        config,
        "ok",
        f"no reboot required ({config.path} absent)",
        reboot_required=False,
        path=config.path,
    )


def probe_backup_freshness(
    config: HealthcheckConfig,
    hostfs: HostFilesystem,
    now: datetime | None = None,
) -> HealthcheckResult:
    """Newest file mtime in ``dir``; ``fail`` when it is older than
    ``max_age_hours`` (exactly ``max_age_hours`` old is still ``ok``).
    An empty/unreadable backup dir fails the check."""
    now = now or datetime.now(timezone.utc)
    try:
        entries = hostfs.dir_mtimes(config.dir)
    except OSError as exc:
        return _result(
            config, "fail", f"cannot list backup dir {config.dir}: {exc}"
        )
    if not entries:
        return _result(
            config,
            "fail",
            f"no files found in backup dir {config.dir}",
            dir=config.dir,
            max_age_hours=config.max_age_hours,
        )
    newest_name, newest_mtime = max(entries, key=lambda item: item[1])
    age_hours = (now.timestamp() - newest_mtime) / 3600.0
    detail = (
        f"newest backup {newest_name!r} in {config.dir} is {age_hours:.1f}h old "
        f"(max {config.max_age_hours:g}h)"
    )
    extra = {
        "newest_file": newest_name,
        "newest_mtime": newest_mtime,
        "age_hours": round(age_hours, 2),
        "max_age_hours": config.max_age_hours,
        "dir": config.dir,
    }
    if age_hours > config.max_age_hours:
        return _result(config, "fail", detail, **extra)
    return _result(config, "ok", detail, **extra)


def probe_tcp_port(config: HealthcheckConfig, connect: TcpConnector) -> HealthcheckResult:
    """Bare TCP connect to ``host:port``; ``fail`` on refusal/timeout."""
    try:
        connect(config.host, config.port, config.timeout_s)
    except Exception as exc:
        return _result(
            config,
            "fail",
            f"TCP connect to {config.host}:{config.port} failed: {exc}",
            host=config.host,
            port=config.port,
        )
    return _result(
        config,
        "ok",
        f"{config.host}:{config.port} accepting TCP connections",
        host=config.host,
        port=config.port,
    )


def probe_error_scan(
    config: HealthcheckConfig,
    hostfs: HostFilesystem,
    runner: LogRunner,
    now: datetime | None = None,
) -> HealthcheckResult:
    """Count ERROR/CRITICAL lines in the last ``since_minutes`` of ``log``
    (or of ``journalctl --since`` output when ``journal: true``); ``fail``
    when the count exceeds ``max_errors`` (exactly ``max_errors`` is ok)."""
    now = now or datetime.now(timezone.utc)
    if config.journal:
        since = (now - timedelta(minutes=config.since_minutes)).isoformat()
        try:
            text = runner(["--no-pager", "--output=short-iso", "--since", since])
        except Exception as exc:
            return _result(
                config, "fail", f"journalctl --since {since} failed: {exc}"
            )
        source = "journalctl"
    else:
        try:
            text = hostfs.read_text(config.log)
        except Exception as exc:
            return _result(config, "fail", f"cannot read log {config.log}: {exc}")
        source = config.log
    count = count_recent_errors(text, config.since_minutes, now)
    detail = (
        f"{count} ERROR/CRITICAL lines in last {config.since_minutes:g} min "
        f"of {source} (max {config.max_errors})"
    )
    extra = {
        "error_count": count,
        "max_errors": config.max_errors,
        "since_minutes": config.since_minutes,
        "source": source,
    }
    if count > config.max_errors:
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
    hostfs: HostFilesystem | None = None,
    cert_fetch: CertFetcher | None = None,
    tcp_connector: TcpConnector | None = None,
    log_runner: LogRunner | None = None,
    now: datetime | None = None,
) -> list[HealthcheckResult]:
    """Run every configured probe and return one result per check.

    Seams default to the production clients but are always injectable;
    ``redis`` is the store's client (used by the internet check's
    consecutive-failure counter). ``now`` pins "now" for the time-based
    probes (cert-expiry, backup-freshness, error-scan) so tests are
    deterministic. A probe that raises internally is converted to a
    failed result by the probe itself, so one broken probe never aborts
    the run.
    """
    fs = hostfs if hostfs is not None else default_hostfs()
    fetch_cert = cert_fetch if cert_fetch is not None else fetch_cert_not_after
    connect = tcp_connector if tcp_connector is not None else tcp_connect
    runner = log_runner if log_runner is not None else run_journalctl
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
        elif config.type == "cert-expiry":
            results.append(probe_cert_expiry(config, fetch_cert, now))
        elif config.type == "load":
            results.append(probe_load(config, fs))
        elif config.type == "temperature":
            results.append(probe_temperature(config, fs))
        elif config.type == "reboot-required":
            results.append(probe_reboot_required(config, fs))
        elif config.type == "backup-freshness":
            results.append(probe_backup_freshness(config, fs, now))
        elif config.type == "tcp-port":
            results.append(probe_tcp_port(config, connect))
        elif config.type == "error-scan":
            results.append(probe_error_scan(config, fs, runner, now))
        else:  # pragma: no cover - load_healthchecks rejects unknown types
            raise ValueError(f"unknown check type: {config.type!r}")
    return results
