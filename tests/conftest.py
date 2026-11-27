"""Shared fixtures: a fake in-memory Redis injected into the app."""

from collections.abc import Iterator
from fnmatch import fnmatch

import pytest
from fastapi.testclient import TestClient

from hermod_monitor.main import app
from hermod_monitor.store import get_redis


class FakeRedis:
    """Minimal in-memory stand-in for the redis client (str values)."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def ping(self) -> bool:
        return True

    def set(self, key: str, value: str) -> bool:
        self._data[key] = value
        return True

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def scan_iter(self, match: str = "*") -> Iterator[str]:
        for key in sorted(self._data):
            if fnmatch(key, match):
                yield key

    def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            removed += self._data.pop(key, None) is not None
        return removed


@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture
def client(fake_redis: FakeRedis) -> Iterator[TestClient]:
    """TestClient with the store's Redis dependency overridden by FakeRedis."""
    app.dependency_overrides[get_redis] = lambda: fake_redis
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
