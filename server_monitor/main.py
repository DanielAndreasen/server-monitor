"""FastAPI application: status page, /health and Prometheus /metrics.

State + web shell (issue #3): all endpoints read the check snapshots
from the Redis snapshot store. No auth in v1; LAN-only bind is a deploy
concern (compose/reverse proxy), not code.
"""

import html
from datetime import datetime, timezone

import redis
from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse, Response
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

from server_monitor.metrics import SnapshotMetricsCollector
from server_monitor.store import RedisLike, Snapshot, get_redis, list_snapshots

app = FastAPI(title="server-monitor")


def _snapshots_or_empty(client: RedisLike) -> dict[str, Snapshot]:
    """All snapshots; empty when Redis is unreachable (shell stays up)."""
    try:
        return list_snapshots(client)
    except redis.RedisError:
        return {}


@app.get("/", response_class=HTMLResponse)
def status_page(client: RedisLike = Depends(get_redis)) -> HTMLResponse:
    return HTMLResponse(render_status_page(_snapshots_or_empty(client)))


@app.get("/health")
def health(client: RedisLike = Depends(get_redis)) -> dict[str, str]:
    """200 when the app is up; reports the Redis ping alongside."""
    try:
        client.ping()
        redis_status = "up"
    except redis.RedisError:
        redis_status = "down"
    return {"status": "ok", "redis": redis_status}


@app.get("/metrics")
def metrics(client: RedisLike = Depends(get_redis)) -> Response:
    registry = CollectorRegistry()
    registry.register(SnapshotMetricsCollector(_snapshots_or_empty(client)))
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


def _short_digest(digest: str) -> str:
    """Shorten ``sha256:<hex>`` for display; empty digest -> ``none``."""
    if not digest:
        return "none"
    if ":" in digest:
        algo, hexdigest = digest.split(":", 1)
        return f"{algo}:{hexdigest[:12]}"
    return digest[:19]


def render_outdated_images(snapshot: Snapshot) -> str:
    """Table of outdated images (local vs registry digest) for the page.

    Only the #5 docker check stores ``outdated_images`` as a list of
    ``{image, local_digest, remote_digest}``; anything else renders nothing.
    """
    outdated = snapshot.get("outdated_images")
    if not isinstance(outdated, list) or not outdated:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(entry.get('image', '')))}</td>"
        f"<td>{html.escape(_short_digest(str(entry.get('local_digest', ''))))}</td>"
        f"<td>{html.escape(_short_digest(str(entry.get('remote_digest', ''))))}</td>"
        "</tr>"
        for entry in outdated
    )
    return (
        "<h2>Outdated Docker images</h2>"
        "<table><thead><tr><th>Image</th><th>Local digest</th>"
        f"<th>Registry digest</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def render_status_page(snapshots: dict[str, Snapshot]) -> str:
    """Minimal human-readable status page over the stored snapshots."""
    apt = snapshots.get("apt", {})
    docker = snapshots.get("docker", {})

    def count(snapshot: Snapshot, key: str) -> str:
        if key not in snapshot:
            return "n/a"
        value = snapshot[key]
        # outdated_images may be the detailed list; the summary shows its length
        return str(len(value)) if isinstance(value, list) else str(value)

    rows = []
    for name, snapshot in snapshots.items():
        status = html.escape(str(snapshot.get("status", "unknown")))
        last_run = snapshot.get("last_run")
        if last_run is not None:
            stamp = datetime.fromtimestamp(float(last_run), tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        else:
            stamp = "n/a"
        rows.append(
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            f'<td class="{status}">{status}</td>'
            f"<td>{html.escape(stamp)}</td>"
            f"<td>{html.escape(str(snapshot.get('detail', '')))}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Check</th><th>Status</th>"
        "<th>Last run</th><th>Detail</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else "<p>No check snapshots yet.</p>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>server-monitor status</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
table {{ border-collapse: collapse; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.3rem 0.7rem; text-align: left; }}
td.ok {{ color: #137333; font-weight: 600; }}
td.fail {{ color: #c5221f; font-weight: 600; }}
td.warn {{ color: #b06000; font-weight: 600; }}
</style>
</head>
<body>
<h1>server-monitor status</h1>
<p>Pending apt updates: <strong>{html.escape(count(apt, 'updates_pending'))}</strong>
(<strong>{html.escape(count(apt, 'security_updates'))}</strong> security) &middot;
outdated Docker images: <strong>{html.escape(count(docker, 'outdated_images'))}</strong></p>
{render_outdated_images(docker)}
{table}
</body>
</html>"""
