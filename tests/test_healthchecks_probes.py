"""Tests for the seven issue #20 probe types (cert-expiry, load, temperature,
reboot-required, backup-freshness, tcp-port, error-scan): yaml validation,
each probe over injected fake seams (host filesystem, TLS cert fetcher, TCP
connector, journalctl runner), threshold boundaries, and per-check snapshot
writing through the runner. No real network, sockets, /proc or /sys are
touched — every seam is faked.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from server_monitor.checks.healthchecks import (
    VALID_TYPES,
    HealthcheckConfig,
    count_recent_errors,
    load_healthchecks,
    mem_used_percent,
    parse_cert_time,
    parse_line_timestamp,
    parse_loadavg,
    parse_meminfo,
    parse_millidegrees,
    probe_backup_freshness,
    probe_cert_expiry,
    probe_error_scan,
    probe_load,
    probe_reboot_required,
    probe_tcp_port,
    probe_temperature,
)
from server_monitor.checks.healthchecks import (
    run_healthchecks as run_all_probes,
)
from server_monitor.store import read_snapshot, snapshot_key
from server_monitor.tasks import HEALTHCHECKS_CONFIG_CHECK, run_healthchecks_snapshot
from tests.conftest import FakeRedis
from tests.test_healthchecks import (
    FakeContainerDocker,
    FakeFail2ban,
    FakeFetch,
    _container,
    statvfs_with_usage,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_YAML = REPO_ROOT / "healthchecks.yaml"

#: Fixed "now" for all time-based probes (2026-11-27 12:00:00 UTC).
NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fakes (seams)
# ---------------------------------------------------------------------------


class FakeHostFs:
    """Fake HostFilesystem: canned file contents, existence and dir listings."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        existing: set[str] | None = None,
        dir_entries: dict[str, list[tuple[str, float]]] | None = None,
        errors: dict[str, OSError] | None = None,
    ) -> None:
        self.files = files or {}
        self.existing = existing or set()
        self.dir_entries = dir_entries or {}
        self.errors = errors or {}
        self.reads: list[str] = []

    def read_text(self, path: str) -> str:
        self.reads.append(path)
        if path in self.errors:
            raise self.errors[path]
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def exists(self, path: str) -> bool:
        return path in self.existing

    def dir_mtimes(self, path: str) -> list[tuple[str, float]]:
        if path in self.errors:
            raise self.errors[path]
        if path not in self.dir_entries:
            raise FileNotFoundError(path)
        return self.dir_entries[path]


class FakeCertFetch:
    """Fake CertFetcher: (host, port, timeout_s) -> notAfter datetime."""

    def __init__(self, not_after: datetime | Exception) -> None:
        self.not_after = not_after
        self.calls: list[tuple[str, int, float]] = []

    def __call__(self, host: str, port: int, timeout_s: float) -> datetime:
        self.calls.append((host, port, timeout_s))
        if isinstance(self.not_after, Exception):
            raise self.not_after
        return self.not_after


class FakeTcpConnect:
    """Fake TcpConnector: records calls, optionally raises."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, int, float]] = []

    def __call__(self, host: str, port: int, timeout_s: float) -> None:
        self.calls.append((host, port, timeout_s))
        if self.error is not None:
            raise self.error


class FakeLogRunner:
    """Fake LogRunner: records journalctl args, returns canned stdout."""

    def __init__(self, output: str = "", error: Exception | None = None) -> None:
        self.output = output
        self.error = error
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(list(args))
        if self.error is not None:
            raise self.error
        return self.output


def make_config(**overrides) -> HealthcheckConfig:
    base = {"name": "probe", "type": "http", "url": "http://service.example/"}
    base.update(overrides)
    return HealthcheckConfig(**base)


def _write_yaml(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "healthchecks.yaml"
    path.write_text(yaml.safe_dump(payload))
    return path


# ---------------------------------------------------------------------------
# yaml loading: all 12 types, defaults, unknown keys/fields rejected
# ---------------------------------------------------------------------------


def test_all_twelve_types_are_valid(tmp_path: Path) -> None:
    assert len(VALID_TYPES) == 12
    entries: list[dict] = []
    for ctype in VALID_TYPES:
        entry: dict = {"name": f"c-{ctype}", "type": ctype}
        if ctype == "http":
            entry["url"] = "http://x.example/"
        if ctype == "container":
            entry["container_name"] = "redis"
        if ctype in ("cert-expiry", "tcp-port"):
            entry["host"] = "svc.example.com"
        if ctype == "tcp-port":
            entry["port"] = 5432
        entries.append(entry)
    configs = load_healthchecks(_write_yaml(tmp_path, {"checks": entries}))
    assert sorted(c.type for c in configs) == sorted(VALID_TYPES)


def test_new_probe_defaults_applied(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        {
            "checks": [
                {"name": "cert", "type": "cert-expiry", "host": "svc.example.com"},
                {"name": "load", "type": "load"},
                {"name": "temp", "type": "temperature"},
                {"name": "reboot", "type": "reboot-required"},
                {"name": "backups", "type": "backup-freshness"},
                {"name": "db", "type": "tcp-port", "host": "db.example", "port": 5432},
                {"name": "errs", "type": "error-scan"},
            ]
        },
    )
    by_name = {c.name: c for c in load_healthchecks(path)}
    cert = by_name["cert"]
    assert cert.port == 443 and cert.warn_days == 14.0 and cert.fail_days == 7.0
    assert cert.timeout_s == 5.0
    load = by_name["load"]
    assert load.loadavg_path == "/proc/loadavg"
    assert load.meminfo_path == "/proc/meminfo"
    assert (load.warn_load, load.fail_load) == (4.0, 8.0)
    assert (load.mem_warn_percent, load.mem_fail_percent) == (80.0, 90.0)
    temp = by_name["temp"]
    assert temp.sensor == "/sys/class/thermal/thermal_zone0/temp"
    assert (temp.warn_c, temp.fail_c) == (70.0, 85.0)
    assert by_name["reboot"].path == "/var/run/reboot-required"
    backups = by_name["backups"]
    assert backups.dir == "/mnt/backups" and backups.max_age_hours == 26.0
    db = by_name["db"]
    assert db.host == "db.example" and db.port == 5432
    errs = by_name["errs"]
    assert errs.log == "/var/log/syslog"
    assert errs.since_minutes == 60.0 and errs.max_errors == 20
    assert errs.journal is False


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "x", "type": "cert-expiry"},  # no host
        {"name": "x", "type": "tcp-port", "host": "db.example"},  # no port
        {"name": "x", "type": "tcp-port", "port": 5432},  # no host
        {"name": "x", "type": "disk", "path": "/", "bogus_key": 1},  # unknown key
        {"name": "x", "type": "load", "url": "http://x.example/"},  # url not valid for load
        {"name": "x", "type": "temperature", "host": "h.example"},  # host not valid here
        {"name": "x", "type": "error-scan", "port": 22},  # port not valid here
        {"name": "x", "type": "backup-freshness", "sensor": "/sys/x"},  # sensor invalid
    ],
)
def test_load_healthchecks_rejects_bad_new_type_entries(
    tmp_path: Path, entry: dict
) -> None:
    path = _write_yaml(tmp_path, {"checks": [entry]})
    with pytest.raises(ValueError):
        load_healthchecks(path)


def test_repo_yaml_header_documents_all_twelve_types_and_examples_are_placeholders() -> None:
    text = REPO_YAML.read_text(encoding="utf-8")
    for ctype in VALID_TYPES:
        assert ctype in text, f"healthchecks.yaml header must document type {ctype!r}"
    # the #20 example entries are commented-out placeholders (public-repo
    # rule): the active check list is still the original six
    configs = load_healthchecks(REPO_YAML)
    assert len(configs) == 6
    assert {c.type for c in configs} <= {
        "http",
        "container",
        "disk",
        "internet",
        "fail2ban",
    }
    assert "#  - name: web-cert" in text  # commented placeholder example
    assert "example.com" in text  # placeholder hosts only


# ---------------------------------------------------------------------------
# cert-expiry probe
# ---------------------------------------------------------------------------


def test_parse_cert_time_parses_notafter_format() -> None:
    parsed = parse_cert_time("Jun  1 12:00:00 2027 GMT")
    assert parsed == datetime(2027, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert parse_cert_time("Dec 31 23:59:59 2026 GMT").year == 2026


@pytest.mark.parametrize(
    "days_left,expected_status",
    [
        (30.0, "ok"),
        (14.0, "ok"),  # warn only below warn_days (strictly)
        (13.9, "warn"),
        (7.0, "warn"),  # fail only below fail_days (strictly)
        (6.9, "fail"),
        (0.5, "fail"),
        (-1.0, "fail"),  # already expired
    ],
)
def test_cert_expiry_probe_day_boundaries(days_left: float, expected_status: str) -> None:
    config = make_config(type="cert-expiry", host="svc.example.com", port=443)
    fetch = FakeCertFetch(NOW + timedelta(days=days_left))
    result = probe_cert_expiry(config, fetch, now=NOW)
    assert result.status == expected_status
    assert result.ok is (expected_status == "ok")
    assert result.extra["remaining_days"] == pytest.approx(days_left, abs=0.01)
    assert result.extra["warn_days"] == 14.0 and result.extra["fail_days"] == 7.0
    assert "svc.example.com:443" in result.detail
    # host/port/timeout from the config are passed to the seam
    assert fetch.calls == [("svc.example.com", 443, 5.0)]


def test_cert_expiry_custom_thresholds_and_port_timeout() -> None:
    config = make_config(
        type="cert-expiry", host="svc.example.com", port=8443,
        timeout_s=2.5, warn_days=30, fail_days=10,
    )
    fetch = FakeCertFetch(NOW + timedelta(days=20))
    result = probe_cert_expiry(config, fetch, now=NOW)
    assert result.status == "warn"  # 20 < warn 30, but >= fail threshold 10
    # host/port/timeout from the config are passed through to the seam
    assert fetch.calls == [("svc.example.com", 8443, 2.5)]


def test_cert_expiry_probe_fails_on_handshake_error() -> None:
    config = make_config(type="cert-expiry", host="down.example.com")
    result = probe_cert_expiry(
        config, FakeCertFetch(OSError("connection refused")), now=NOW
    )
    assert result.status == "fail"
    assert "connection refused" in result.detail
    assert "down.example.com" in result.detail


# ---------------------------------------------------------------------------
# load probe (loadavg + meminfo parsing, boundaries)
# ---------------------------------------------------------------------------

LOADAVG_TEXT = "0.52 1.10 1.99 2/345 12345\n"
MEMINFO_TEXT = (
    "MemTotal:       16000000 kB\n"
    "MemFree:         1000000 kB\n"
    "MemAvailable:    8000000 kB\n"
    "Buffers:          500000 kB\n"
    "Cached:          6500000 kB\n"
)


def test_parse_loadavg_and_meminfo() -> None:
    assert parse_loadavg(LOADAVG_TEXT) == (0.52, 1.10, 1.99)
    with pytest.raises(ValueError):
        parse_loadavg("garbage")
    info = parse_meminfo(MEMINFO_TEXT)
    assert info["MemTotal"] == 16000000
    assert info["MemAvailable"] == 8000000
    assert mem_used_percent(info) == pytest.approx(50.0)
    # MemFree fallback when MemAvailable is absent
    assert mem_used_percent({"MemTotal": 1000, "MemFree": 250}) == pytest.approx(75.0)
    with pytest.raises(ValueError):
        mem_used_percent({"MemFree": 1})


def test_parse_millidegrees() -> None:
    assert parse_millidegrees("42000\n") == 42.0
    assert parse_millidegrees("85001") == 85.001
    assert parse_millidegrees("-5000") == -5.0


def _load_fs(load1: str, meminfo: str = MEMINFO_TEXT) -> FakeHostFs:
    return FakeHostFs(
        files={"/proc/loadavg": f"{load1} 1.10 1.99 2/345 12345\n", "/proc/meminfo": meminfo}
    )


@pytest.mark.parametrize(
    "load1,mem_used,expected_status",
    [
        ("3.9", 79.9, "ok"),
        ("4.0", 80.0, "ok"),  # warn is strictly above the thresholds
        ("4.1", 80.0, "warn"),
        ("8.0", 80.0, "warn"),  # fail only strictly above fail_load
        ("8.1", 80.0, "fail"),
        ("1.0", 90.1, "fail"),  # memory over mem_fail_percent -> fail
        ("1.0", 85.0, "warn"),  # memory over mem_warn_percent -> warn
        ("9.0", 95.0, "fail"),  # worst of both wins
    ],
)
def test_load_probe_boundaries(load1: str, mem_used: float, expected_status: str) -> None:
    available = round(1000 * (100 - mem_used) / 100)  # meminfo values are integer kB
    meminfo = f"MemTotal: 1000 kB\nMemAvailable: {available} kB\n"
    config = make_config(type="load")
    result = probe_load(config, _load_fs(load1, meminfo))
    assert result.status == expected_status
    assert result.extra["load_1min"] == pytest.approx(float(load1))
    assert result.extra["mem_used_percent"] == pytest.approx(mem_used, abs=0.05)
    assert "load" in result.detail and "mem" in result.detail


def test_load_probe_custom_thresholds_and_missing_files() -> None:
    config = make_config(type="load", warn_load=2.0, fail_load=4.0, mem_fail_percent=60)
    assert probe_load(config, _load_fs("2.5")).status == "warn"
    assert probe_load(config, _load_fs("4.5")).status == "fail"
    # unreadable /proc -> fail, never an exception
    result = probe_load(config, FakeHostFs(files={}))
    assert result.status == "fail"
    assert "load/mem probe failed" in result.detail


# ---------------------------------------------------------------------------
# temperature probe (millidegrees, boundaries)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_millidegrees,expected_status",
    [
        ("45000", "ok"),
        ("70000", "ok"),  # warn is strictly above warn_c
        ("70001", "warn"),
        ("85000", "warn"),  # fail is strictly above fail_c
        ("85001", "fail"),
        ("95000", "fail"),
    ],
)
def test_temperature_probe_boundaries(raw_millidegrees: str, expected_status: str) -> None:
    config = make_config(type="temperature")
    fs = FakeHostFs(files={config.sensor: raw_millidegrees + "\n"})
    result = probe_temperature(config, fs)
    assert result.status == expected_status
    assert result.extra["temp_c"] == pytest.approx(int(raw_millidegrees) / 1000.0, abs=0.01)
    assert result.extra["millidegrees"] == int(raw_millidegrees)
    assert config.sensor in result.detail
    assert fs.reads == [config.sensor]


def test_temperature_probe_custom_sensor_and_read_error() -> None:
    config = make_config(
        type="temperature", sensor="/sys/class/thermal/thermal_zone1/temp",
        warn_c=50, fail_c=60,
    )
    fs = FakeHostFs(files={config.sensor: "55000"})
    assert probe_temperature(config, fs).status == "warn"
    assert probe_temperature(config, FakeHostFs(files={})).status == "fail"
    assert probe_temperature(
        config, FakeHostFs(files={config.sensor: "not-a-number"})
    ).status == "fail"


# ---------------------------------------------------------------------------
# reboot-required probe
# ---------------------------------------------------------------------------


def test_reboot_required_probe_warns_when_marker_exists() -> None:
    # the type-specific default path comes from yaml loading (see
    # test_new_probe_defaults_applied); here the path is set explicitly
    config = make_config(type="reboot-required", path="/var/run/reboot-required")
    fs = FakeHostFs(existing={config.path})
    result = probe_reboot_required(config, fs)
    assert result.status == "warn"
    assert result.ok is False
    assert result.extra["reboot_required"] is True
    assert "reboot required" in result.detail


def test_reboot_required_probe_ok_when_marker_absent() -> None:
    config = make_config(type="reboot-required", path="/var/run/reboot-required")
    result = probe_reboot_required(config, FakeHostFs(existing=set()))
    assert result.status == "ok"
    assert result.ok is True
    assert result.extra["reboot_required"] is False
    assert "absent" in result.detail


# ---------------------------------------------------------------------------
# backup-freshness probe (age boundaries)
# ---------------------------------------------------------------------------


def _backup_fs(age_hours: float, extra_old: bool = False) -> FakeHostFs:
    newest = NOW.timestamp() - age_hours * 3600.0
    entries = [("backup-newest.tar", newest)]
    if extra_old:
        entries.append(("backup-old.tar", newest - 100 * 3600.0))
    return FakeHostFs(dir_entries={"/mnt/backups": entries})


@pytest.mark.parametrize(
    "age_hours,expected_status",
    [
        (1.0, "ok"),
        (26.0, "ok"),  # exactly max_age_hours is still ok (fail is strictly older)
        (26.1, "fail"),
        (72.0, "fail"),
    ],
)
def test_backup_freshness_probe_age_boundaries(age_hours: float, expected_status: str) -> None:
    config = make_config(type="backup-freshness", dir="/mnt/backups", max_age_hours=26)
    result = probe_backup_freshness(config, _backup_fs(age_hours, extra_old=True), now=NOW)
    assert result.status == expected_status
    assert result.extra["age_hours"] == pytest.approx(age_hours, abs=0.01)
    assert result.extra["newest_file"] == "backup-newest.tar"
    assert result.extra["max_age_hours"] == 26.0
    assert "/mnt/backups" in result.detail


def test_backup_freshness_probe_empty_dir_and_missing_dir_fail() -> None:
    config = make_config(type="backup-freshness")
    empty = probe_backup_freshness(
        config, FakeHostFs(dir_entries={"/mnt/backups": []}), now=NOW
    )
    assert empty.status == "fail"
    assert "no files" in empty.detail
    missing = probe_backup_freshness(config, FakeHostFs(files={}), now=NOW)
    assert missing.status == "fail"
    assert "cannot list" in missing.detail
    unreadable = probe_backup_freshness(
        config,
        FakeHostFs(errors={"/mnt/backups": OSError("permission denied")}),
        now=NOW,
    )
    assert unreadable.status == "fail"
    assert "permission denied" in unreadable.detail


# ---------------------------------------------------------------------------
# tcp-port probe (ok / refused / timeout)
# ---------------------------------------------------------------------------


def test_tcp_port_probe_ok_when_connect_succeeds() -> None:
    config = make_config(type="tcp-port", host="db.example.internal", port=5432, timeout_s=3.0)
    connect = FakeTcpConnect()
    result = probe_tcp_port(config, connect)
    assert result.status == "ok"
    assert result.ok is True
    assert "db.example.internal:5432" in result.detail
    assert result.extra["port"] == 5432
    assert connect.calls == [("db.example.internal", 5432, 3.0)]


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("Connection refused"),
        TimeoutError("timed out"),
        OSError("network unreachable"),
    ],
)
def test_tcp_port_probe_fails_on_refusal_or_timeout(error: Exception) -> None:
    config = make_config(type="tcp-port", host="db.example.internal", port=5432)
    result = probe_tcp_port(config, FakeTcpConnect(error))
    assert result.status == "fail"
    assert not result.ok
    assert "failed" in result.detail
    assert str(error) in result.detail


# ---------------------------------------------------------------------------
# error-scan probe (timestamp parsing, window, counts, journal mode)
# ---------------------------------------------------------------------------


def test_parse_line_timestamp_iso_and_syslog() -> None:
    iso = parse_line_timestamp("2026-11-27T11:30:00Z host app[1]: ERROR x", NOW)
    assert iso == datetime(2026, 11, 27, 11, 30, 0, tzinfo=timezone.utc)
    iso_space = parse_line_timestamp("2026-11-27 11:30:00 host app: ERROR x", NOW)
    assert iso_space == datetime(2026, 11, 27, 11, 30, 0, tzinfo=timezone.utc)
    syslog = parse_line_timestamp("Nov 27 11:45:00 host app[1]: ERROR x", NOW)
    assert syslog == datetime(2026, 11, 27, 11, 45, 0, tzinfo=timezone.utc)
    # syslog year rollover: a December line seen in January is last year's
    jan = datetime(2026, 1, 5, 12, 0, 0, tzinfo=timezone.utc)
    dec = parse_line_timestamp("Dec 31 23:59:59 host app: ERROR x", jan)
    assert dec == datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    # no parseable timestamp -> None
    assert parse_line_timestamp("continuation line of a traceback", NOW) is None
    assert parse_line_timestamp("garbage", NOW) is None


def test_count_recent_errors_window_and_patterns() -> None:
    log = "\n".join(
        [
            "Nov 27 11:30:00 host app[1]: ERROR disk failure",  # in window -> count
            "Nov 27 11:00:00 host app[2]: CRITICAL raid degraded",  # in window -> count
            "Nov 27 10:00:00 host app[1]: ERROR too old",  # outside 60 min -> skip
            "2026-11-27T11:10:00Z host app[3]: ERROR iso line",  # in window -> count
            "Nov 27 11:20:00 host app[1]: INFO all good",  # not an error line
            "a traceback continuation with ERROR but no timestamp",  # counted (conservative)
        ]
    )
    assert count_recent_errors(log, 60, NOW) == 4
    # a wider window picks up the old line too
    assert count_recent_errors(log, 180, NOW) == 5
    assert count_recent_errors("", 60, NOW) == 0


def test_error_scan_probe_boundaries_on_counts() -> None:
    config = make_config(type="error-scan", log="/var/log/syslog", since_minutes=60, max_errors=2)
    log = "\n".join(
        f"Nov 27 11:{minute:02d}:00 host app[1]: ERROR number {minute}" for minute in (10, 20, 30)
    )
    fs = FakeHostFs(files={"/var/log/syslog": log})
    runner = FakeLogRunner()
    at_limit = probe_error_scan(
        make_config(type="error-scan", max_errors=3), fs, runner, now=NOW
    )
    assert at_limit.status == "ok"  # 3 == max_errors is ok
    assert at_limit.extra["error_count"] == 3
    over = probe_error_scan(config, fs, runner, now=NOW)
    assert over.status == "fail"  # 3 > max_errors 2
    assert over.extra["error_count"] == 3
    assert over.extra["max_errors"] == 2
    assert over.extra["source"] == "/var/log/syslog"
    assert "3 ERROR/CRITICAL lines" in over.detail
    assert runner.calls == []  # file mode never calls journalctl


def test_error_scan_probe_missing_log_fails() -> None:
    config = make_config(type="error-scan")
    result = probe_error_scan(config, FakeHostFs(files={}), FakeLogRunner(), now=NOW)
    assert result.status == "fail"
    assert "cannot read log" in result.detail


def test_error_scan_probe_journal_mode_uses_runner_with_since() -> None:
    config = make_config(
        type="error-scan", journal=True, since_minutes=30, max_errors=1
    )
    output = "\n".join(
        [
            "2026-11-27T11:50:00+00:00 host app[1]: ERROR one",
            "2026-11-27T11:55:00+00:00 host app[1]: CRITICAL two",
        ]
    )
    runner = FakeLogRunner(output=output)
    fs = FakeHostFs(files={})
    result = probe_error_scan(config, fs, runner, now=NOW)
    assert result.status == "fail"  # 2 > max_errors 1
    assert result.extra["source"] == "journalctl"
    assert len(runner.calls) == 1
    args = runner.calls[0]
    assert "--since" in args
    since = args[args.index("--since") + 1]
    assert since == (NOW - timedelta(minutes=30)).isoformat()
    assert fs.reads == []  # journal mode does not read the log file


def test_error_scan_probe_journal_runner_failure_fails() -> None:
    config = make_config(type="error-scan", journal=True)
    result = probe_error_scan(
        config,
        FakeHostFs(files={}),
        FakeLogRunner(error=OSError("journalctl missing")),
        now=NOW,
    )
    assert result.status == "fail"
    assert "journalctl" in result.detail


# ---------------------------------------------------------------------------
# runner + snapshots for the new probe types
# ---------------------------------------------------------------------------

NEW_PROBES_YAML = {
    "checks": [
        {"name": "cert", "type": "cert-expiry", "host": "svc.example.com"},
        {"name": "load", "type": "load"},
        {"name": "temp", "type": "temperature"},
        {"name": "reboot", "type": "reboot-required"},
        {"name": "backups", "type": "backup-freshness", "dir": "/mnt/backups"},
        {"name": "db-port", "type": "tcp-port", "host": "db.example.internal", "port": 5432},
        {"name": "errors", "type": "error-scan"},
    ]
}


def _new_probe_seams() -> tuple[FakeHostFs, FakeCertFetch, FakeTcpConnect, FakeLogRunner]:
    fs = FakeHostFs(
        files={
            "/proc/loadavg": "1.20 1.50 1.80 1/100 999\n",
            "/proc/meminfo": MEMINFO_TEXT,
            "/sys/class/thermal/thermal_zone0/temp": "45000\n",
            "/var/log/syslog": "Nov 27 11:30:00 host app[1]: ERROR one\n",
        },
        existing=set(),  # no reboot-required marker
        dir_entries={"/mnt/backups": [("backup.tar", NOW.timestamp() - 3600.0)]},
    )
    cert = FakeCertFetch(NOW + timedelta(days=30))
    tcp = FakeTcpConnect()
    runner = FakeLogRunner(output="")
    return fs, cert, tcp, runner


def test_runner_writes_one_snapshot_per_new_probe(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    path = _write_yaml(tmp_path, NEW_PROBES_YAML)
    fs, cert, tcp, runner = _new_probe_seams()
    snapshots = run_healthchecks_snapshot(
        fake_redis,
        str(path),
        hostfs=fs,
        cert_fetch=cert,
        tcp_connector=tcp,
        log_runner=runner,
        now=NOW,
    )
    assert [s["check"] for s in snapshots] == [
        HEALTHCHECKS_CONFIG_CHECK, "cert", "load", "temp", "reboot", "backups",
        "db-port", "errors",
    ]
    by_name = {s["check"]: s for s in snapshots}
    assert all(s["status"] == "ok" for s in snapshots)
    assert by_name["cert"]["check_type"] == "cert-expiry"
    assert by_name["cert"]["remaining_days"] == pytest.approx(30.0, abs=0.01)
    assert by_name["load"]["load_1min"] == pytest.approx(1.20)
    assert by_name["load"]["mem_used_percent"] == pytest.approx(50.0)
    assert by_name["temp"]["temp_c"] == 45.0
    assert by_name["reboot"]["reboot_required"] is False
    assert by_name["backups"]["age_hours"] == pytest.approx(1.0, abs=0.01)
    assert by_name["db-port"]["port"] == 5432
    assert by_name["errors"]["error_count"] == 1
    assert tcp.calls == [("db.example.internal", 5432, 5.0)]
    assert cert.calls == [("svc.example.com", 443, 5.0)]
    # every snapshot persisted under the store's key scheme and readable back
    for name, snapshot in by_name.items():
        assert fake_redis.get(snapshot_key(name)) is not None
        assert read_snapshot(fake_redis, name) == snapshot


def test_runner_records_failures_and_warns_per_new_probe(
    tmp_path: Path, fake_redis: FakeRedis
) -> None:
    path = _write_yaml(tmp_path, NEW_PROBES_YAML)
    fs = FakeHostFs(
        files={
            "/proc/loadavg": "9.50 8.00 7.00 5/100 999\n",  # load fail
            "/proc/meminfo": MEMINFO_TEXT,
            "/sys/class/thermal/thermal_zone0/temp": "80000\n",  # 80C -> warn
            "/var/log/syslog": "\n".join(
                f"Nov 27 11:{m:02d}:00 host app[1]: ERROR e{m}" for m in range(25)
            ),  # 25 errors > default max 20 -> fail
        },
        existing={"/var/run/reboot-required"},  # -> warn
        dir_entries={"/mnt/backups": [("old.tar", NOW.timestamp() - 100 * 3600.0)]},
    )
    cert = FakeCertFetch(NOW + timedelta(days=3))  # < fail_days 7 -> fail
    tcp = FakeTcpConnect(error=ConnectionRefusedError("refused"))
    snapshots = run_healthchecks_snapshot(
        fake_redis,
        str(path),
        hostfs=fs,
        cert_fetch=cert,
        tcp_connector=tcp,
        log_runner=FakeLogRunner(),
        now=NOW,
    )
    by_name = {s["check"]: s for s in snapshots}
    assert by_name["cert"]["status"] == "fail"
    assert by_name["load"]["status"] == "fail"
    assert by_name["temp"]["status"] == "warn"
    assert by_name["reboot"]["status"] == "warn"
    assert by_name["backups"]["status"] == "fail"
    assert by_name["db-port"]["status"] == "fail"
    assert by_name["errors"]["status"] == "fail"
    assert read_snapshot(fake_redis, "temp")["status"] == "warn"


def test_run_all_probes_dispatches_all_twelve_types(tmp_path: Path) -> None:
    payload = {
        "checks": [
            {"name": "web", "type": "http", "url": "http://web.example/health"},
            {"name": "redis-c", "type": "container", "container_name": "redis"},
            {"name": "disk", "type": "disk", "path": "/"},
            {"name": "net", "type": "internet"},
            {"name": "f2b", "type": "fail2ban"},
            {"name": "cert", "type": "cert-expiry", "host": "svc.example.com"},
            {"name": "load", "type": "load"},
            {"name": "temp", "type": "temperature"},
            {"name": "reboot", "type": "reboot-required"},
            {"name": "backups", "type": "backup-freshness"},
            {"name": "db", "type": "tcp-port", "host": "db.example", "port": 5432},
            {"name": "errors", "type": "error-scan"},
        ]
    }
    configs = load_healthchecks(_write_yaml(tmp_path, payload))
    fs, cert, tcp, runner = _new_probe_seams()
    fetch = FakeFetch(
        {"http://web.example/health": 200, "https://cloudflare.com/cdn-cgi/trace": 200}
    )
    results = run_all_probes(
        configs,
        redis=FakeRedis(),
        fetch=fetch,
        docker=FakeContainerDocker({"redis": _container("running", "healthy")}),
        statvfs=lambda path: statvfs_with_usage(50.0),
        fail2ban_client=FakeFail2ban({"sshd": 1}),
        hostfs=fs,
        cert_fetch=cert,
        tcp_connector=tcp,
        log_runner=runner,
        now=NOW,
    )
    assert [r.type for r in results] == [
        "http", "container", "disk", "internet", "fail2ban",
        "cert-expiry", "load", "temperature",
        "reboot-required", "backup-freshness", "tcp-port", "error-scan",
    ]
    assert all(r.status == "ok" for r in results)


def test_metrics_and_status_page_reflect_new_probe_snapshots(
    tmp_path: Path, client, fake_redis: FakeRedis
) -> None:
    path = _write_yaml(tmp_path, {"checks": [{"name": "temp", "type": "temperature"}]})
    fs = FakeHostFs(files={"/sys/class/thermal/thermal_zone0/temp": "80000\n"})  # warn
    run_healthchecks_snapshot(fake_redis, str(path), hostfs=fs, now=NOW)
    body = client.get("/metrics").text
    assert 'server_monitor_check_up{check="temp"} 0.0' in body  # warn is not up
    assert 'server_monitor_check_last_run_seconds{check="temp"}' in body
    page = client.get("/").text
    assert "temp" in page and "warn" in page and "80.0C" in page
