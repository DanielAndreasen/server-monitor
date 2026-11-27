"""Tests for the apt update check (issue #4): parsing of fake
``apt list --upgradable`` output, security-pocket classification, counts,
the snapshot written to FakeRedis, and the Beat schedule entry."""

import subprocess

from server_monitor.celery_app import app as celery_app
from server_monitor.checks.apt import (
    APT_LIST_COMMAND,
    check_apt,
    parse_upgradable,
    run_apt_list,
)
from server_monitor.store import read_snapshot
from server_monitor.tasks import run_apt_check, run_apt_snapshot
from tests.conftest import FakeRedis

FAKE_UPGRADABLE = """\
Listing... Done
base-files/jammy-updates,now 12.4ubuntu4.6 amd64 [upgradable from: 12.4ubuntu4.5]
openssl/jammy-security 3.0.2-0ubuntu1.10 amd64 [upgradable from: 3.0.2-0ubuntu1.9]
libssl3/jammy-security,now 3.0.2-0ubuntu1.10 amd64 [upgradable from: 3.0.2-0ubuntu1.9]
containerd.io/Debian:12/bookworm 1.7.18-1 amd64 [upgradable from: 1.7.16-1]
libfake-security/jammy-updates 2.0 amd64 [upgradable from: 1.9]
local-pkg/now 5.0 all [upgradable from: 4.0]
"""


def test_parse_skips_listing_header_and_blank_lines() -> None:
    updates = parse_upgradable("Listing... Done\n\n" + FAKE_UPGRADABLE)
    assert len(updates) == 6
    assert all(not u.package.startswith("Listing") for u in updates)


def test_parse_entry_fields() -> None:
    (update,) = parse_upgradable(
        "base-files/jammy-updates,now 12.4ubuntu4.6 amd64 [upgradable from: 12.4ubuntu4.5]\n"
    )
    assert update.package == "base-files"
    assert update.archive == "jammy-updates"  # ",now" suffix stripped
    assert update.candidate == "12.4ubuntu4.6"
    assert update.installed == "12.4ubuntu4.5"
    assert update.architecture == "amd64"
    assert update.security is False


def test_security_pocket_classified_as_security() -> None:
    updates = parse_upgradable(FAKE_UPGRADABLE)
    security = {u.package for u in updates if u.security}
    assert security == {"openssl", "libssl3"}


def test_origin_labelled_security_archive_classified() -> None:
    # e.g. "Ubuntu:22.04/jammy-security" as the origin/archive field
    (update,) = parse_upgradable(
        "openssl/Ubuntu:22.04/jammy-security 3.0.2-0ubuntu1.10 amd64 [upgradable from: 3.0.2-0ubuntu1.9]\n"
    )
    assert update.archive == "jammy-security"
    assert update.security is True


def test_package_name_ending_in_security_is_not_security() -> None:
    (update,) = parse_upgradable(
        "libfake-security/jammy-updates 2.0 amd64 [upgradable from: 1.9]\n"
    )
    assert update.security is False


def test_now_archive_and_plain_archive_are_not_security() -> None:
    updates = parse_upgradable(FAKE_UPGRADABLE)
    by_name = {u.package: u for u in updates}
    assert by_name["local-pkg"].archive == "now"
    assert by_name["local-pkg"].security is False
    assert by_name["containerd.io"].archive == "bookworm"
    assert by_name["containerd.io"].security is False


def test_empty_output_yields_zero_updates() -> None:
    assert parse_upgradable("Listing... Done\n") == []
    result = check_apt(runner=lambda: "Listing... Done\n")
    assert result.updates_pending == 0
    assert result.security_updates == 0


def test_check_apt_counts_pending_and_security() -> None:
    result = check_apt(runner=lambda: FAKE_UPGRADABLE)
    assert result.updates_pending == 6
    assert result.security_updates == 2


def test_run_apt_list_goes_through_subprocess(monkeypatch) -> None:
    calls = {}

    class Proc:
        stdout = "Listing... Done\n"

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_apt_list() == "Listing... Done\n"
    assert calls["cmd"] == APT_LIST_COMMAND == ["apt", "list", "--upgradable"]
    assert calls["kwargs"]["check"] is True
    assert calls["kwargs"]["capture_output"] is True


def test_run_apt_snapshot_writes_snapshot_to_fake_redis(fake_redis: FakeRedis) -> None:
    snapshot = run_apt_snapshot(fake_redis, runner=lambda: FAKE_UPGRADABLE)
    assert snapshot["check"] == "apt"
    assert snapshot["status"] == "ok"
    assert snapshot["detail"] == "6 updates pending (2 security)"
    assert snapshot["updates_pending"] == 6
    assert snapshot["security_updates"] == 2
    assert isinstance(snapshot["last_run"], float)
    packages = snapshot["packages"]
    assert {p["package"] for p in packages} == {
        "base-files",
        "openssl",
        "libssl3",
        "containerd.io",
        "libfake-security",
        "local-pkg",
    }
    assert {p["package"] for p in packages if p["security"]} == {"openssl", "libssl3"}
    # persisted under the store's key scheme and readable back
    assert read_snapshot(fake_redis, "apt") == snapshot
    assert fake_redis.get("server_monitor:snapshot:apt") is not None


def test_run_apt_snapshot_runner_failure_writes_fail_snapshot(
    fake_redis: FakeRedis,
) -> None:
    def boom() -> str:
        raise subprocess.CalledProcessError(100, APT_LIST_COMMAND, stderr="boom")

    snapshot = run_apt_snapshot(fake_redis, runner=boom)
    assert snapshot["check"] == "apt"
    assert snapshot["status"] == "fail"
    assert "apt check failed" in snapshot["detail"]
    assert read_snapshot(fake_redis, "apt") == snapshot


def test_celery_task_registered_on_app() -> None:
    assert "server_monitor.tasks.run_apt_check" in celery_app.tasks


def test_celery_task_writes_snapshot_via_injected_seams(
    monkeypatch, fake_redis: FakeRedis
) -> None:
    class Proc:
        stdout = FAKE_UPGRADABLE

    monkeypatch.setattr(subprocess, "run", lambda cmd, **kwargs: Proc())
    monkeypatch.setattr("server_monitor.tasks.get_redis", lambda: fake_redis)
    snapshot = run_apt_check()  # task body runs synchronously when called
    assert snapshot["check"] == "apt"
    assert snapshot["status"] == "ok"
    assert snapshot["updates_pending"] == 6
    assert snapshot["security_updates"] == 2
    assert read_snapshot(fake_redis, "apt") == snapshot


def test_beat_schedule_has_apt_check_daily_at_0600() -> None:
    entries = [
        entry
        for entry in celery_app.conf.beat_schedule.values()
        if entry["task"] == "server_monitor.tasks.run_apt_check"
    ]
    assert len(entries) == 1
    cron = entries[0]["schedule"]
    assert cron.hour == {6}
    assert cron.minute == {0}
    assert cron.day_of_week == set(range(7))  # every day
