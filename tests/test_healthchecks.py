"""Tests for the healthcheck engine (issue #6): yaml loading, each probe
type over injected fake seams (http fetcher, docker client, statvfs,
fail2ban socket client), disk warn/fail boundaries, internet
consecutive-failure logic via FakeRedis, per-check snapshots, metrics
reflection, and the */30 beat schedule entry."""

import json
import os
from pathlib import Path

import pytest
import yaml

from server_monitor.celery_app import app as celery_app
from server_monitor.checks.healthchecks import (
    CONFIG_ENV,
    CONSEC_FAIL_PREFIX,
    DEFAULT_CONFIG_PATH,
    DEFAULT_FAIL2BAN_SOCK,
    DEFAULT_INTERNET_URL,
    INTERNET_FAIL_THRESHOLD,
    ContainerNotFound,
    HealthcheckConfig,
    load_healthchecks,
    parse_currently_banned,
    parse_jail_list,
    probe_container,
    probe_disk,
    probe_fail2ban,
    probe_http,
    probe_internet,
)
from server_monitor.checks.healthchecks import (
    run_healthchecks as run_all_probes,
)
from server_monitor.store import read_snapshot, snapshot_key
from server_monitor.tasks import (
    HEALTHCHECKS_CONFIG_CHECK,
    run_healthchecks,
    run_healthchecks_snapshot,
)
from tests.conftest import FakeRedis

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_YAML = REPO_ROOT / "healthchecks.yaml"


# ---------------------------------------------------------------------------
# Fakes (seams)
# ---------------------------------------------------------------------------


class FakeFetch:
    """Fake HttpFetcher: (url, timeout_s) -> status code, recording calls."""

    def __init__(self, responses: dict[str, int | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, float]] = []

    def __call__(self, url: str, timeout_s: float) -> int:
        self.calls.append((url, timeout_s))
        outcome = self.responses[url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeContainerDocker:
    """Fake ContainerInspector: inspect_container(name) -> State dict."""

    def __init__(self, containers: dict[str, dict]) -> None:
        self.containers = containers
        self.inspected: list[str] = []

    def inspect_container(self, name: str) -> dict:
        self.inspected.append(name)
        if name not in self.containers:
            raise ContainerNotFound(f"no such container: {name}")
        return self.containers[name]


def statvfs_with_usage(used_percent: float) -> os.statvfs_result:
    """A statvfs_result for a filesystem with ``used_percent`` used blocks."""
    blocks = 1000
    bfree = round(blocks * (100 - used_percent) / 100)
    return os.statvfs_result((4096, 4096, blocks, bfree, bfree, 0, 0, 0, 0, 255))


class FakeFail2ban:
    """Fake Fail2banClient: jails() + currently_banned(jail)."""

    def __init__(self, bans: dict[str, int]) -> None:
        self.bans = bans
        self.jail_calls: list[str] = []

    def jails(self) -> list[str]:
        return list(self.bans)

    def currently_banned(self, jail: str) -> int:
        self.jail_calls.append(jail)
        return self.bans[jail]


def make_config(**overrides) -> HealthcheckConfig:
    base = {
        "name": "test-check",
        "type": "http",
        "url": "http://service.example/health",
    }
    base.update(overrides)
    return HealthcheckConfig(**base)


# ---------------------------------------------------------------------------
# yaml loading
# ---------------------------------------------------------------------------


def test_repo_healthchecks_yaml_loads_with_all_five_types_and_defaults() -> None:
    configs = load_healthchecks(REPO_YAML)
    assert [c.type for c in configs] == [
        "http",
        "container",
        "disk",
        "internet",
        "fail2ban",
    ]
    by_name = {c.name: c for c in configs}
    http = by_name["web-self"]
    assert http.url == "http://localhost:8000/health"
    assert http.expected_status == 200  # default
    assert http.timeout_s == 5.0  # default
    assert by_name["redis-container"].container_name == "redis"
    disk = by_name["root-disk"]
    assert disk.path == "/"  # default
    assert disk.warn_percent == 80.0  # default
    assert disk.fail_percent == 90.0  # default
    internet = by_name["internet"]
    assert internet.url == DEFAULT_INTERNET_URL
    fail2ban = by_name["fail2ban"]
    assert fail2ban.socket == DEFAULT_FAIL2BAN_SOCK
    assert fail2ban.max_recent_bans == 10  # default
    # names are unique (they key the snapshots)
    assert len({c.name for c in configs}) == 5


def test_load_healthchecks_applies_overrides_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "checks": [
                    {
                        "name": "api",
                        "type": "http",
                        "url": "http://api.example/",
                        "expected_status": 204,
                        "timeout_s": 2.5,
                    },
                    {
                        "name": "data-disk",
                        "type": "disk",
                        "path": "/data",
                        "warn_percent": 70,
                        "fail_percent": 85,
                    },
                    {
                        "name": "net",
                        "type": "internet",
                        "url": "http://probe.example/204",
                        "timeout_s": 3,
                    },
                    {
                        "name": "f2b",
                        "type": "fail2ban",
                        "socket": "/run/fail2ban/custom.sock",
                        "max_recent_bans": 3,
                    },
                ]
            }
        )
    )
    configs = load_healthchecks(path)
    by_name = {c.name: c for c in configs}
    assert by_name["api"].expected_status == 204
    assert by_name["api"].timeout_s == 2.5
    assert by_name["data-disk"].path == "/data"
    assert by_name["data-disk"].warn_percent == 70.0
    assert by_name["data-disk"].fail_percent == 85.0
    assert by_name["net"].url == "http://probe.example/204"
    assert by_name["f2b"].socket == "/run/fail2ban/custom.sock"
    assert by_name["f2b"].max_recent_bans == 3


def test_load_healthchecks_uses_healthchecks_config_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "env.yaml"
    path.write_text(yaml.safe_dump({"checks": [{"name": "x", "type": "disk"}]}))
    monkeypatch.setenv(CONFIG_ENV, str(path))
    configs = load_healthchecks(None)  # path from the env var
    assert [c.name for c in configs] == ["x"]
    assert configs[0].type == "disk"
    assert configs[0].path == "/"  # default applied


def test_load_healthchecks_default_path_is_repo_root_yaml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(CONFIG_ENV, raising=False)
    monkeypatch.chdir(REPO_ROOT)
    assert DEFAULT_CONFIG_PATH == "./healthchecks.yaml"
    configs = load_healthchecks(None)
    assert len(configs) == 5  # the committed example file


@pytest.mark.parametrize(
    "payload",
    [
        {"checks": [{"name": "x", "type": "carrier-pigeon"}]},  # unknown type
        {"checks": [{"type": "http", "url": "http://x.example"}]},  # no name
        {"checks": [{"name": "x", "type": "http"}]},  # http without url
        {"checks": [{"name": "x", "type": "container"}]},  # container without name
        {"checks": [{"name": "x", "type": "disk"}, {"name": "x", "type": "disk"}]},  # dup
        {"nope": []},  # missing top-level checks list
        {"checks": "not-a-list"},
    ],
)
def test_load_healthchecks_rejects_invalid_configs(
    tmp_path: Path, payload: dict
) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(payload))
    with pytest.raises(ValueError):
        load_healthchecks(path)


# ---------------------------------------------------------------------------
# http probe
# ---------------------------------------------------------------------------


def test_http_probe_ok_on_expected_status() -> None:
    fetch = FakeFetch({"http://service.example/health": 200})
    result = probe_http(make_config(), fetch)
    assert result.ok is True
    assert result.status == "ok"
    assert result.name == "test-check"
    assert "200" in result.detail
    assert result.extra["status_code"] == 200
    # the timeout from the config is passed through to the fetcher
    assert fetch.calls == [("http://service.example/health", 5.0)]


def test_http_probe_custom_expected_status_and_timeout() -> None:
    fetch = FakeFetch({"http://api.example/": 204})
    result = probe_http(
        make_config(url="http://api.example/", expected_status=204, timeout_s=2.5), fetch
    )
    assert result.ok is True
    assert fetch.calls == [("http://api.example/", 2.5)]


def test_http_probe_fails_on_unexpected_status() -> None:
    fetch = FakeFetch({"http://service.example/health": 503})
    result = probe_http(make_config(expected_status=200), fetch)
    assert result.ok is False
    assert result.status == "fail"
    assert "503" in result.detail and "expected 200" in result.detail


def test_http_probe_fails_on_connection_error() -> None:
    fetch = FakeFetch({"http://service.example/health": OSError("connection refused")})
    result = probe_http(make_config(), fetch)
    assert result.status == "fail"
    assert "connection refused" in result.detail


# ---------------------------------------------------------------------------
# container probe
# ---------------------------------------------------------------------------


def _container(state: str, health: str | None = None) -> dict:
    entry = {"State": {"Status": state}}
    if health is not None:
        entry["State"]["Health"] = {"Status": health}
    return entry


def test_container_probe_ok_when_running_without_healthcheck() -> None:
    docker = FakeContainerDocker({"redis": _container("running")})
    result = probe_container(make_config(type="container", container_name="redis"), docker)
    assert result.ok is True
    assert "running" in result.detail
    assert result.extra["container_state"] == "running"
    assert docker.inspected == ["redis"]


def test_container_probe_ok_when_running_and_healthy() -> None:
    docker = FakeContainerDocker({"app": _container("running", "healthy")})
    result = probe_container(make_config(type="container", container_name="app"), docker)
    assert result.ok is True
    assert "healthy" in result.detail


def test_container_probe_fails_when_unhealthy_or_starting() -> None:
    for health in ("unhealthy", "starting"):
        docker = FakeContainerDocker({"app": _container("running", health)})
        result = probe_container(
            make_config(type="container", container_name="app"), docker
        )
        assert result.status == "fail"
        assert health in result.detail


def test_container_probe_fails_when_not_running() -> None:
    for state in ("exited", "created", "restarting", "dead"):
        docker = FakeContainerDocker({"app": _container(state)})
        result = probe_container(
            make_config(type="container", container_name="app"), docker
        )
        assert result.status == "fail"
        assert state in result.detail


def test_container_probe_fails_when_container_missing_or_socket_broken() -> None:
    docker = FakeContainerDocker({})
    result = probe_container(make_config(type="container", container_name="ghost"), docker)
    assert result.status == "fail"
    assert "not found" in result.detail

    class BrokenDocker:
        def inspect_container(self, name: str) -> dict:
            raise OSError("cannot connect to /var/run/docker.sock")

    result = probe_container(
        make_config(type="container", container_name="app"), BrokenDocker()
    )
    assert result.status == "fail"
    assert "docker.sock" in result.detail


# ---------------------------------------------------------------------------
# disk probe (warn/fail boundaries)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "used_percent,expected_status",
    [
        (50.0, "ok"),
        (79.9, "ok"),
        (80.0, "ok"),  # warn is strictly above warn_percent (design: warn >80%)
        (80.5, "warn"),
        (89.9, "warn"),
        (90.0, "warn"),  # fail is strictly above fail_percent (fail >90%)
        (90.5, "fail"),
        (100.0, "fail"),
    ],
)
def test_disk_probe_warn_fail_boundaries(used_percent: float, expected_status: str) -> None:
    config = make_config(type="disk", path="/data")
    result = probe_disk(config, lambda path: statvfs_with_usage(used_percent))
    assert result.status == expected_status
    assert result.name == "test-check"
    assert result.extra["used_percent"] == pytest.approx(used_percent, abs=0.05)
    assert "/data" in result.detail
    assert result.ok is (expected_status == "ok")


def test_disk_probe_custom_thresholds() -> None:
    config = make_config(type="disk", path="/", warn_percent=70, fail_percent=85)
    assert probe_disk(config, lambda p: statvfs_with_usage(75)).status == "warn"
    assert probe_disk(config, lambda p: statvfs_with_usage(86)).status == "fail"
    assert probe_disk(config, lambda p: statvfs_with_usage(60)).status == "ok"


def test_disk_probe_fails_on_statvfs_error() -> None:
    def boom(path: str) -> os.statvfs_result:
        raise OSError("No such file or directory")

    result = probe_disk(make_config(type="disk", path="/gone"), boom)
    assert result.status == "fail"
    assert "No such file or directory" in result.detail


# ---------------------------------------------------------------------------
# internet probe (consecutive-failure logic)
# ---------------------------------------------------------------------------


def _internet_config() -> HealthcheckConfig:
    return make_config(type="internet", url=DEFAULT_INTERNET_URL, timeout_s=3.0)


def test_internet_probe_ok_when_reachable_and_resets_counter(fake_redis: FakeRedis) -> None:
    config = _internet_config()
    key = f"{CONSEC_FAIL_PREFIX}{config.name}"
    fetch = FakeFetch({DEFAULT_INTERNET_URL: 200})
    fake_redis.set(key, "1")  # stale counter from before
    result = probe_internet(config, fetch, fake_redis)
    assert result.ok is True
    assert "reachable" in result.detail
    assert fake_redis.get(key) is None  # reset on success
    assert fetch.calls == [(DEFAULT_INTERNET_URL, 3.0)]


def test_internet_probe_first_failure_still_ok_second_consecutive_fails(
    fake_redis: FakeRedis,
) -> None:
    url = DEFAULT_INTERNET_URL
    failing = FakeFetch({url: TimeoutError("timed out")})
    config = _internet_config()
    key = f"{CONSEC_FAIL_PREFIX}{config.name}"

    first = probe_internet(config, failing, fake_redis)
    assert first.status == "ok"  # fails only after 2 consecutive failures
    assert first.extra["consecutive_failures"] == 1
    assert fake_redis.get(key) == "1"

    second = probe_internet(config, failing, fake_redis)
    assert second.status == "fail"
    assert second.extra["consecutive_failures"] == INTERNET_FAIL_THRESHOLD == 2
    assert "2 consecutive failures" in second.detail
    assert fake_redis.get(key) == "2"

    third = probe_internet(config, failing, fake_redis)
    assert third.status == "fail"
    assert third.extra["consecutive_failures"] == 3
    assert fake_redis.get(key) == "3"


def test_internet_probe_success_after_failures_resets_counter(fake_redis: FakeRedis) -> None:
    url = DEFAULT_INTERNET_URL
    config = _internet_config()
    key = f"{CONSEC_FAIL_PREFIX}{config.name}"
    failing = FakeFetch({url: OSError("no route to host")})
    ok_fetch = FakeFetch({url: 200})

    probe_internet(config, failing, fake_redis)
    probe_internet(config, failing, fake_redis)
    assert probe_internet(config, failing, fake_redis).status == "fail"
    assert fake_redis.get(key) == "3"

    # one success resets the counter...
    assert probe_internet(config, ok_fetch, fake_redis).status == "ok"
    assert fake_redis.get(key) is None
    # ...so the next single failure is ok again, not an instant fail
    assert probe_internet(config, failing, fake_redis).status == "ok"
    assert fake_redis.get(key) == "1"


def test_internet_probe_counts_any_http_response_as_reachable(
    fake_redis: FakeRedis,
) -> None:
    # even a 500 from the probe endpoint proves connectivity
    fetch = FakeFetch({DEFAULT_INTERNET_URL: 500})
    assert probe_internet(_internet_config(), fetch, fake_redis).status == "ok"


# ---------------------------------------------------------------------------
# fail2ban probe
# ---------------------------------------------------------------------------


def test_fail2ban_probe_ok_under_threshold() -> None:
    client = FakeFail2ban({"sshd": 3, "dovecot": 4})  # 7 <= 10
    result = probe_fail2ban(make_config(type="fail2ban", max_recent_bans=10), client)
    assert result.ok is True
    assert result.extra["total_bans"] == 7
    assert result.extra["bans_per_jail"] == {"sshd": 3, "dovecot": 4}
    assert result.extra["jails"] == 2
    assert "7 recent bans" in result.detail
    assert sorted(client.jail_calls) == ["dovecot", "sshd"]


def test_fail2ban_probe_fails_above_threshold_and_boundary_is_ok() -> None:
    at_limit = FakeFail2ban({"sshd": 10})  # == max_recent_bans -> still ok
    result = probe_fail2ban(make_config(type="fail2ban", max_recent_bans=10), at_limit)
    assert result.status == "ok"

    over = FakeFail2ban({"sshd": 8, "dovecot": 4})  # 12 > 10 -> fail
    result = probe_fail2ban(make_config(type="fail2ban", max_recent_bans=10), over)
    assert result.status == "fail"
    assert "12 recent bans" in result.detail
    assert result.extra["total_bans"] == 12

    custom = probe_fail2ban(
        make_config(type="fail2ban", max_recent_bans=3), FakeFail2ban({"sshd": 4})
    )
    assert custom.status == "fail"


def test_fail2ban_probe_fails_when_socket_query_fails() -> None:
    class BrokenFail2ban:
        def jails(self) -> list[str]:
            raise OSError("cannot connect to /var/run/fail2ban/fail2ban.sock")

        def currently_banned(self, jail: str) -> int:
            raise OSError("unreachable")

    result = probe_fail2ban(make_config(type="fail2ban"), BrokenFail2ban())
    assert result.status == "fail"
    assert "fail2ban.sock" in result.detail


def test_fail2ban_response_parsers_handle_text_and_jsonish() -> None:
    text_status = (
        "Status\n|- Number of jail:\t2\n|- Jail list:\tsshd, dovecot\n"
    )
    assert parse_jail_list(text_status) == ["sshd", "dovecot"]
    text_jail = (
        "Status for the jail: sshd\n|- Status\n"
        "|  |- Currently banned:\t3\n"
        "|  |- Total banned:\t42\n"
        "|- Banned IP list:\t192.0.2.1\n"
    )
    assert parse_currently_banned(text_jail) == 3
    # JSON-ish responses (list/dict) are unwrapped to their text
    assert parse_jail_list(json.dumps(["ok", "Jail list:\tsshd"])) == ["sshd"]
    assert parse_currently_banned(json.dumps(["ok", "Currently banned:\t7"])) == 7
    assert parse_currently_banned(json.dumps({"status": "Currently banned: 2"})) == 2
    # nothing recognizable -> empty / zero, never an exception
    assert parse_jail_list("garbage") == []
    assert parse_currently_banned("garbage") == 0


# ---------------------------------------------------------------------------
# runner + snapshots
# ---------------------------------------------------------------------------

ALL_CHECKS_YAML = {
    "checks": [
        {"name": "web", "type": "http", "url": "http://web.example/health"},
        {"name": "redis-c", "type": "container", "container_name": "redis"},
        {"name": "disk", "type": "disk", "path": "/"},
        {"name": "net", "type": "internet"},
        {"name": "f2b", "type": "fail2ban"},
    ]
}


def _write_config(tmp_path: Path, payload: dict = ALL_CHECKS_YAML) -> Path:
    path = tmp_path / "healthchecks.yaml"
    path.write_text(yaml.safe_dump(payload))
    return path


def _fake_seams():
    fetch = FakeFetch(
        {
            "http://web.example/health": 200,
            DEFAULT_INTERNET_URL: 200,
        }
    )
    docker = FakeContainerDocker({"redis": _container("running", "healthy")})
    statvfs = lambda path: statvfs_with_usage(55.0)
    fail2ban = FakeFail2ban({"sshd": 2})
    return fetch, docker, statvfs, fail2ban


def test_run_healthchecks_returns_one_result_per_check() -> None:
    configs = [
        HealthcheckConfig(name="a", type="http", url="http://a.example/"),
        HealthcheckConfig(name="b", type="disk"),
    ]
    fetch = FakeFetch({"http://a.example/": 200})
    results = run_all_probes(
        configs,
        redis=FakeRedis(),
        fetch=fetch,
        statvfs=lambda path: statvfs_with_usage(10.0),
    )
    assert [r.name for r in results] == ["a", "b"]
    assert all(r.status == "ok" for r in results)
    assert all(r.ok for r in results)


def test_run_healthchecks_snapshot_writes_one_snapshot_per_check_name(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    path = _write_config(tmp_path)
    fetch, docker, statvfs, fail2ban = _fake_seams()
    snapshots = run_healthchecks_snapshot(
        fake_redis,
        str(path),
        fetch=fetch,
        docker=docker,
        statvfs=statvfs,
        fail2ban_client=fail2ban,
    )
    assert [s["check"] for s in snapshots] == ["web", "redis-c", "disk", "net", "f2b"]
    by_name = {s["check"]: s for s in snapshots}
    assert all(s["status"] == "ok" for s in snapshots)
    assert by_name["web"]["check_type"] == "http"
    assert by_name["web"]["status_code"] == 200
    assert by_name["redis-c"]["check_type"] == "container"
    assert by_name["redis-c"]["container_state"] == "running"
    assert by_name["disk"]["used_percent"] == pytest.approx(55.0)
    assert by_name["f2b"]["total_bans"] == 2
    # each snapshot persisted under the store's key scheme and readable back
    for name, snapshot in by_name.items():
        assert fake_redis.get(snapshot_key(name)) is not None
        assert read_snapshot(fake_redis, name) == snapshot
        assert isinstance(snapshot["last_run"], float)


def test_run_healthchecks_snapshot_records_failures_per_check(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    path = _write_config(tmp_path)
    fetch = FakeFetch(
        {
            "http://web.example/health": 500,  # http fails
            DEFAULT_INTERNET_URL: OSError("down"),  # internet: 1st failure -> ok
        }
    )
    docker = FakeContainerDocker({"redis": _container("exited")})
    snapshots = run_healthchecks_snapshot(
        fake_redis,
        str(path),
        fetch=fetch,
        docker=docker,
        statvfs=lambda p: statvfs_with_usage(95.0),  # disk: fail
        fail2ban_client=FakeFail2ban({"sshd": 50}),  # fail2ban: fail
    )
    by_name = {s["check"]: s for s in snapshots}
    assert by_name["web"]["status"] == "fail"
    assert by_name["redis-c"]["status"] == "fail"
    assert by_name["disk"]["status"] == "fail"
    assert by_name["f2b"]["status"] == "fail"
    assert by_name["net"]["status"] == "ok"  # only 1 consecutive failure so far
    assert by_name["net"]["consecutive_failures"] == 1
    # second run: the internet check now fails (2 consecutive failures)
    snapshots2 = run_healthchecks_snapshot(
        fake_redis,
        str(path),
        fetch=fetch,
        docker=docker,
        statvfs=lambda p: statvfs_with_usage(95.0),
        fail2ban_client=FakeFail2ban({"sshd": 50}),
    )
    by_name2 = {s["check"]: s for s in snapshots2}
    assert by_name2["net"]["status"] == "fail"
    assert by_name2["net"]["consecutive_failures"] == 2
    assert fake_redis.get(f"{CONSEC_FAIL_PREFIX}net") == "2"


def test_run_healthchecks_snapshot_bad_config_writes_fail_snapshot(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("checks:\n  - {name: x, type: nope}\n")
    snapshots = run_healthchecks_snapshot(fake_redis, str(path))
    assert len(snapshots) == 1
    assert snapshots[0]["check"] == HEALTHCHECKS_CONFIG_CHECK
    assert snapshots[0]["status"] == "fail"
    assert "unknown type" in snapshots[0]["detail"]
    assert read_snapshot(fake_redis, HEALTHCHECKS_CONFIG_CHECK) == snapshots[0]


def test_run_healthchecks_snapshot_missing_config_file_writes_fail_snapshot(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    snapshots = run_healthchecks_snapshot(fake_redis, str(tmp_path / "missing.yaml"))
    assert snapshots[0]["check"] == HEALTHCHECKS_CONFIG_CHECK
    assert snapshots[0]["status"] == "fail"


def test_run_healthchecks_snapshot_uses_env_var_for_config_path(
    tmp_path: Path, fake_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(
        tmp_path,
        {"checks": [{"name": "only-disk", "type": "disk", "warn_percent": 50}]},
    )
    monkeypatch.setenv(CONFIG_ENV, str(path))
    snapshots = run_healthchecks_snapshot(
        fake_redis, None, statvfs=lambda p: statvfs_with_usage(60.0)
    )
    assert [s["check"] for s in snapshots] == ["only-disk"]
    assert snapshots[0]["status"] == "warn"  # 60% > custom warn 50%
    assert snapshots[0]["detail"].startswith("60.0% used")


def test_celery_task_registered_on_app() -> None:
    assert "server_monitor.tasks.run_healthchecks" in celery_app.tasks


def test_celery_task_runs_with_injected_seams(
    tmp_path: Path, fake_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path)
    monkeypatch.setenv(CONFIG_ENV, str(path))
    monkeypatch.setattr("server_monitor.tasks.get_redis", lambda: fake_redis)
    fetch, docker, statvfs, fail2ban = _fake_seams()
    monkeypatch.setattr("server_monitor.tasks.fetch_status", fetch)
    monkeypatch.setattr(
        "server_monitor.checks.healthchecks.default_container_client",
        lambda sock_path=None: docker,
    )
    monkeypatch.setattr(
        "server_monitor.checks.healthchecks.Fail2banSocketClient",
        lambda sock_path=None, timeout=5.0: fail2ban,
    )
    monkeypatch.setattr(os, "statvfs", statvfs)
    snapshots = run_healthchecks()  # task body runs synchronously when called
    assert [s["check"] for s in snapshots] == ["web", "redis-c", "disk", "net", "f2b"]
    assert all(s["status"] == "ok" for s in snapshots)
    assert read_snapshot(fake_redis, "web")["status"] == "ok"


# ---------------------------------------------------------------------------
# beat schedule + web/metrics reflection
# ---------------------------------------------------------------------------


def test_beat_schedule_has_healthchecks_every_30min() -> None:
    entries = [
        entry
        for entry in celery_app.conf.beat_schedule.values()
        if entry["task"] == "server_monitor.tasks.run_healthchecks"
    ]
    assert len(entries) == 1
    cron = entries[0]["schedule"]
    assert cron.minute == {0, 30}  # crontab(minute="*/30")
    assert cron.hour == set(range(24))  # every hour
    assert cron.day_of_week == set(range(7))  # every day


def test_metrics_and_status_page_reflect_healthcheck_snapshots(
    tmp_path: Path, client, fake_redis: FakeRedis
) -> None:
    path = _write_config(
        tmp_path,
        {
            "checks": [
                {"name": "web", "type": "http", "url": "http://web.example/health"},
                {"name": "disk", "type": "disk", "warn_percent": 50},
            ]
        },
    )
    run_healthchecks_snapshot(
        fake_redis,
        str(path),
        fetch=FakeFetch({"http://web.example/health": 200}),
        statvfs=lambda p: statvfs_with_usage(75.0),  # 75% > warn 50 -> warn
    )
    body = client.get("/metrics").text
    assert 'server_monitor_check_up{check="web"} 1.0' in body
    assert 'server_monitor_check_up{check="disk"} 0.0' in body  # warn is not up
    assert 'server_monitor_check_last_run_seconds{check="web"}' in body
    page = client.get("/").text
    assert "web" in page and "disk" in page
    assert "warn" in page
    assert "75.0% used" in page
