"""Smoke tests for the placeholder endpoints."""

from fastapi.testclient import TestClient

from server_monitor.main import app

client = TestClient(app)


def test_root_returns_200() -> None:
    response = client.get("/")
    assert response.status_code == 200


def test_health_returns_200() -> None:
    response = client.get("/health")
    assert response.status_code == 200
