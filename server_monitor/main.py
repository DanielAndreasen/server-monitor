"""FastAPI application: status page, /health and Prometheus /metrics.

State + web shell (issue #3): all endpoints read the check snapshots
from the Redis snapshot store. No auth in v1; LAN-only bind is a deploy
concern (compose/reverse proxy), not code.

Status page (issue #18): sleek dark-theme dashboard, fully self-hosted —
inline CSS only, no external CDN/fonts. Auto-refreshes via meta refresh.
All dynamic values are HTML-escaped before interpolation.
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


_STATUS_CLASSES = ("ok", "warn", "fail")


def _status_badge(status: str) -> str:
    """Color-coded pill for a check status (green/amber/red, unknown -> red)."""
    cls = status if status in _STATUS_CLASSES else "unknown"
    return f'<span class="badge {cls}">{html.escape(status)}</span>'


# Inline stylesheet for the status page: dark theme, no external assets.
# Kept as a plain (non-f-string) constant so CSS braces need no escaping.
_PAGE_CSS = """
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --panel: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --ok: #3fb950;
  --warn: #d29922;
  --fail: #f85149;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: #0d1117;
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  padding: 2rem 1rem;
}
.container { max-width: 960px; margin: 0 auto; }
header h1 { margin: 0; font-size: 1.6rem; letter-spacing: -0.01em; }
.subtitle { color: var(--muted); margin: 0.25rem 0 0; font-size: 0.9rem; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-top: 1.5rem;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1rem 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.card .label {
  color: var(--muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.card .value { font-size: 1.75rem; font-weight: 700; }
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.25rem;
  margin-top: 1.5rem;
}
.panel h2 { margin: 0 0 0.75rem; font-size: 1rem; font-weight: 600; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th {
  text-align: left;
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
td {
  padding: 0.55rem 0.75rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tbody tr:last-child td { border-bottom: none; }
.badge {
  display: inline-block;
  padding: 0.15rem 0.65rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 600;
  white-space: nowrap;
}
.badge.ok { color: var(--ok); background: rgba(63, 185, 80, 0.15); }
.badge.warn { color: var(--warn); background: rgba(210, 153, 34, 0.15); }
.badge.fail, .badge.unknown { color: var(--fail); background: rgba(248, 81, 73, 0.15); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; }
.empty {
  color: var(--muted);
  text-align: center;
  padding: 2rem 1rem;
  border: 1px dashed var(--border);
  border-radius: 12px;
  margin: 0;
}
footer { color: var(--muted); font-size: 0.75rem; text-align: center; margin-top: 2rem; }
@media (max-width: 640px) {
  body { padding: 1rem 0.75rem; }
  header h1 { font-size: 1.3rem; }
  .card { padding: 0.75rem 1rem; }
  .card .value { font-size: 1.4rem; }
  .panel { padding: 1rem; }
  th, td { padding: 0.45rem 0.5rem; }
}
"""


def render_outdated_images(snapshot: Snapshot) -> str:
    """Panel with a table of outdated images (local vs registry digest).

    Only the #5 docker check stores ``outdated_images`` as a list of
    ``{image, local_digest, remote_digest}``; anything else renders nothing.
    """
    outdated = snapshot.get("outdated_images")
    if not isinstance(outdated, list) or not outdated:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(entry.get('image', '')) if isinstance(entry, dict) else '')}</td>"
        f'<td class="mono">{html.escape(_short_digest(str(entry.get('local_digest', '')) if isinstance(entry, dict) else ''))}</td>'
        f'<td class="mono">{html.escape(_short_digest(str(entry.get('remote_digest', '')) if isinstance(entry, dict) else ''))}</td>'
        "</tr>"
        for entry in outdated
    )
    return (
        '<section class="panel"><h2>Outdated Docker images</h2>'
        '<div class="table-wrap"><table><thead><tr><th>Image</th>'
        "<th>Local digest</th><th>Registry digest</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div></section>"
    )


def render_healthcheck_table(snapshots: dict[str, Snapshot]) -> str:
    """Panel with one row per check: name, status badge, last run, detail."""
    rows = []
    for name, snapshot in snapshots.items():
        status = str(snapshot.get("status", "unknown"))
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
            f"<td>{_status_badge(status)}</td>"
            f'<td class="mono">{html.escape(stamp)}</td>'
            f"<td>{html.escape(str(snapshot.get('detail', '')))}</td>"
            "</tr>"
        )
    if not rows:
        body = '<p class="empty">No check snapshots yet.</p>'
    else:
        body = (
            '<div class="table-wrap"><table><thead><tr><th>Check</th>'
            "<th>Status</th><th>Last run</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
    return f'<section class="panel"><h2>Healthchecks</h2>{body}</section>'


def render_status_page(snapshots: dict[str, Snapshot]) -> str:
    """Dark-theme dashboard over the stored snapshots (all values escaped)."""
    apt = snapshots.get("apt", {})
    docker = snapshots.get("docker", {})

    def count(snapshot: Snapshot, key: str) -> str:
        if key not in snapshot:
            return "n/a"
        value = snapshot[key]
        # outdated_images may be the detailed list; the summary shows its length
        return str(len(value)) if isinstance(value, list) else str(value)

    def card(label: str, value: str) -> str:
        return (
            f'<div class="card"><span class="label">{label}</span>'
            f'<span class="value"><strong>{html.escape(value)}</strong></span></div>'
        )

    cards = (
        card("Pending apt updates", count(apt, "updates_pending"))
        + card("Security updates", count(apt, "security_updates"))
        + card("Outdated Docker images", count(docker, "outdated_images"))
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>server-monitor status</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
<div class="container">
<header>
<h1>server-monitor</h1>
<p class="subtitle">Status overview &middot; auto-refreshes every 60&thinsp;s</p>
</header>
<main>
<section class="cards" aria-label="Summary">
{cards}
</section>
{render_outdated_images(docker)}
{render_healthcheck_table(snapshots)}
</main>
<footer>server-monitor &middot; latest snapshots from Redis</footer>
</div>
</body>
</html>"""
