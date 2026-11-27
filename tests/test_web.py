"""Route tests: /health, /metrics and the status page over a fake Redis."""

from fastapi.testclient import TestClient

from server_monitor.store import write_snapshot
from tests.conftest import FakeRedis


def test_health_returns_200_and_redis_up(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "redis": "up"}


def test_metrics_empty_store_reports_zero_counts(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "server_monitor_apt_updates_pending 0.0" in body
    assert "server_monitor_apt_security_updates_pending 0.0" in body
    assert "server_monitor_docker_images_outdated 0.0" in body


def test_metrics_reflect_fake_snapshots(
    client: TestClient, fake_redis: FakeRedis
) -> None:
    write_snapshot(
        fake_redis,
        "apt",
        "ok",
        detail="5 updates pending (2 security)",
        last_run=1000.0,
        updates_pending=5,
        security_updates=2,
    )
    write_snapshot(fake_redis, "docker", "fail", outdated_images=3, last_run=2000.0)
    write_snapshot(fake_redis, "http-gotify", "fail", detail="HTTP 503", last_run=3000.0)

    body = client.get("/metrics").text
    assert 'server_monitor_check_up{check="apt"} 1.0' in body
    assert 'server_monitor_check_up{check="docker"} 0.0' in body
    assert 'server_monitor_check_up{check="http-gotify"} 0.0' in body
    assert 'server_monitor_check_last_run_seconds{check="apt"} 1000.0' in body
    assert "server_monitor_apt_updates_pending 5.0" in body
    assert "server_monitor_apt_security_updates_pending 2.0" in body
    assert "server_monitor_docker_images_outdated 3.0" in body


def test_status_page_empty_store(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "No check snapshots yet." in response.text


def test_status_page_renders_snapshots(
    client: TestClient, fake_redis: FakeRedis
) -> None:
    write_snapshot(
        fake_redis,
        "apt",
        "fail",
        detail="7 updates pending (2 security)",
        last_run=1764259200.0,
        updates_pending=7,
        security_updates=2,
    )
    write_snapshot(
        fake_redis, "docker", "ok", detail="3 images outdated", outdated_images=3, last_run=1764259300.0
    )

    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "apt" in body
    assert "docker" in body
    assert "fail" in body
    assert "7 updates pending (2 security)" in body
    assert "3 images outdated" in body
    assert "2025-11-27 16:00:00 UTC" in body  # 1764259200 formatted UTC
    # summary line carries the pending counts and outdated images
    assert "<strong>7</strong>" in body
    assert "<strong>2</strong>" in body
    assert "<strong>3</strong>" in body


def test_status_page_escapes_html(client: TestClient, fake_redis: FakeRedis) -> None:
    write_snapshot(fake_redis, "weird", "fail", detail="<script>alert(1)</script>")
    body = client.get("/").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
