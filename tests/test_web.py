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


# --- issue #18: dark-theme dashboard ---------------------------------------


def test_status_page_has_dark_theme_and_responsive_markers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    # dark theme by default: dark background + dark color-scheme in inline CSS
    assert "#0d1117" in body
    assert "color-scheme: dark" in body
    # status colors green/amber/red defined for the badges
    assert "--ok: #3fb950" in body
    assert "--warn: #d29922" in body
    assert "--fail: #f85149" in body
    # responsive: mobile media query present
    assert "@media (max-width: 640px)" in body
    assert 'name="viewport"' in body
    # no external assets: styles are inline, auto-refresh via meta tag
    assert "<style>" in body
    assert "http://" not in body
    assert "https://" not in body
    assert 'http-equiv="refresh"' in body


def test_status_page_empty_state_is_styled(client: TestClient) -> None:
    body = client.get("/").text
    assert "No check snapshots yet." in body
    assert 'class="empty"' in body


def test_status_page_renders_outdated_images_table(
    client: TestClient, fake_redis: FakeRedis
) -> None:
    write_snapshot(
        fake_redis,
        "docker",
        "fail",
        detail="1 image outdated",
        last_run=1764259300.0,
        outdated_images=[
            {
                "image": "myapp/web:latest",
                "local_digest": "sha256:" + "a" * 64,
                "remote_digest": "sha256:" + "b" * 64,
            }
        ],
    )
    body = client.get("/").text
    assert "Outdated Docker images" in body
    assert "myapp/web:latest" in body
    assert "sha256:aaaaaaaaaaaa" in body  # local digest, shortened to 12 hex chars
    assert "sha256:bbbbbbbbbbbb" in body  # registry digest, shortened
    assert "<strong>1</strong>" in body  # summary card counts the detailed list


def test_status_page_escapes_outdated_image_values(
    client: TestClient, fake_redis: FakeRedis
) -> None:
    write_snapshot(
        fake_redis,
        "docker",
        "fail",
        outdated_images=[
            {
                "image": "<script>alert(2)</script>",
                "local_digest": "",
                "remote_digest": "sha256:" + "c" * 64,
            }
        ],
    )
    body = client.get("/").text
    assert "<script>alert(2)</script>" not in body
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in body
    assert ">none<" in body  # empty local digest renders as "none"
