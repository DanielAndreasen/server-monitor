"""Redis-backed snapshot store: latest result per check.

Key scheme: ``server_monitor:snapshot:<check name>`` holding a JSON document, e.g.::

    {
      "check": "apt",
      "status": "ok",            # "ok" | "fail" (checks may add "warn")
      "last_run": 1764259200.0,  # unix timestamp, seconds
      "detail": "12 updates pending (3 security)",
      "updates_pending": 12,     # optional extras consumed by /metrics and /
      "security_updates": 3,
      "outdated_images": 0
    }

All helpers take the Redis client as their first argument so tests can
inject a fake in-memory client instead of a real Redis.
"""

import json
import os
import time
from typing import Any, Iterable, Protocol

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

SNAPSHOT_PREFIX = "server_monitor:snapshot:"


class Snapshot(dict[str, Any]):
    """One check's latest result. Plain dict; see module docstring for keys."""


class RedisLike(Protocol):
    """The slice of the redis client API the store relies on."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> bool: ...

    def scan_iter(self, match: str = "*") -> Iterable[str]: ...

    def ping(self) -> bool: ...


def get_redis() -> RedisLike:
    """FastAPI dependency: a real Redis client from REDIS_URL.

    ``decode_responses=True`` so ``get`` returns ``str``. Creating the
    client does not connect; commands raise ``redis.RedisError`` when
    Redis is unreachable, which the web layer treats as "no snapshots".
    """
    import redis

    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def snapshot_key(check: str) -> str:
    return f"{SNAPSHOT_PREFIX}{check}"


def write_snapshot(
    client: RedisLike,
    check: str,
    status: str,
    *,
    detail: str = "",
    last_run: float | None = None,
    **extra: Any,
) -> Snapshot:
    """Store the latest snapshot for ``check`` and return it."""
    snapshot = Snapshot(
        check=check,
        status=status,
        last_run=time.time() if last_run is None else float(last_run),
        detail=detail,
        **extra,
    )
    client.set(snapshot_key(check), json.dumps(snapshot))
    return snapshot


def read_snapshot(client: RedisLike, check: str) -> Snapshot | None:
    """Return the latest snapshot for ``check``, or None if none stored."""
    raw = client.get(snapshot_key(check))
    if raw is None:
        return None
    return Snapshot(json.loads(raw))


def list_snapshots(client: RedisLike) -> dict[str, Snapshot]:
    """Return all stored snapshots keyed by check name, sorted by name."""
    snapshots: dict[str, Snapshot] = {}
    for key in client.scan_iter(match=f"{SNAPSHOT_PREFIX}*"):
        raw = client.get(key)
        if raw is None:
            continue
        try:
            snapshot = Snapshot(json.loads(raw))
        except json.JSONDecodeError:
            continue  # corrupt entry: skip rather than break the page
        snapshots[snapshot.get("check", key.removeprefix(SNAPSHOT_PREFIX))] = snapshot
    return dict(sorted(snapshots.items()))
