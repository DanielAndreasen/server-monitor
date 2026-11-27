"""Snapshot store tests against the fake in-memory Redis."""

from server_monitor.store import (
    SNAPSHOT_PREFIX,
    list_snapshots,
    read_snapshot,
    snapshot_key,
    write_snapshot,
)
from tests.conftest import FakeRedis


def test_write_read_roundtrip(fake_redis: FakeRedis) -> None:
    written = write_snapshot(
        fake_redis,
        "apt",
        "fail",
        detail="3 updates pending (1 security)",
        last_run=1764259200.0,
        updates_pending=3,
        security_updates=1,
    )
    assert read_snapshot(fake_redis, "apt") == written
    assert written["check"] == "apt"
    assert written["status"] == "fail"
    assert written["last_run"] == 1764259200.0


def test_write_defaults_last_run_to_now(fake_redis: FakeRedis) -> None:
    snapshot = write_snapshot(fake_redis, "internet", "ok")
    assert isinstance(snapshot["last_run"], float)
    assert snapshot["last_run"] > 0


def test_read_missing_returns_none(fake_redis: FakeRedis) -> None:
    assert read_snapshot(fake_redis, "nope") is None


def test_write_overwrites_previous_snapshot(fake_redis: FakeRedis) -> None:
    write_snapshot(fake_redis, "disk", "ok", detail="fine", last_run=1.0)
    write_snapshot(fake_redis, "disk", "fail", detail="90% full", last_run=2.0)
    snapshot = read_snapshot(fake_redis, "disk")
    assert snapshot is not None
    assert snapshot["status"] == "fail"
    assert snapshot["detail"] == "90% full"


def test_list_snapshots_returns_all_keyed_by_check(fake_redis: FakeRedis) -> None:
    write_snapshot(fake_redis, "docker", "ok", outdated_images=2, last_run=3.0)
    write_snapshot(fake_redis, "apt", "ok", updates_pending=5, last_run=4.0)
    snapshots = list_snapshots(fake_redis)
    assert set(snapshots) == {"apt", "docker"}
    assert snapshots["docker"]["outdated_images"] == 2
    assert snapshots["apt"]["updates_pending"] == 5


def test_list_snapshots_empty(fake_redis: FakeRedis) -> None:
    assert list_snapshots(fake_redis) == {}


def test_snapshot_key_scheme(fake_redis: FakeRedis) -> None:
    write_snapshot(fake_redis, "apt", "ok")
    assert snapshot_key("apt") == f"{SNAPSHOT_PREFIX}apt"
    assert fake_redis.get("server_monitor:snapshot:apt") is not None
