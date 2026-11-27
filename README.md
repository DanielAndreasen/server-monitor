# hermod-monitor

Self-hosted service on the `hermod` home server that shows pending updates
(system packages + Docker images) and runs general healthchecks, with push
notifications when something needs attention.

Status: **idea outline only** — no implementation yet.

## General idea

A small always-on service that answers two questions at a glance: "what needs
updating?" and "is everything healthy?" Checks run on a schedule in the
background; results show on a tiny status page and in Prometheus metrics;
push notifications go out when updates are pending or a healthcheck fails.

## Goal

- **Update tracking**: list pending `apt` upgrades (via `apt list
  --upgradable` / unattended-upgrades dry-run) and outdated Docker images by
  comparing local image digests against the registry manifest (Docker Registry
  HTTP API v2 — no extra tooling needed).
- **Healthchecks**: probe the server's own services (HTTP endpoints, Docker
  container states) on a schedule.
- **Visibility**: `/health` endpoint, Prometheus `/metrics`, and a minimal
  web status page.
- **Notifications**: ntfy.sh topic or Gotify when updates are pending or a
  check fails.

Scheduling and notification dispatch run as **Celery Beat** periodic tasks
with **Celery workers**, **Redis** as broker — not ad-hoc cron inside one
container.

## Technologies

- Python 3.14, managed with `uv`
- FastAPI for the status page + `/health` + `/metrics`
- Celery + Celery Beat + Redis (scheduled checks, async dispatch)
- prometheus-client for metrics
- Docker + Docker Compose (compose stack: redis, worker, beat, web)
- apt / unattended-upgrades for system update detection
- Docker Registry HTTP API v2 for image digest comparison
- ntfy.sh or Gotify for push notifications
- pytest

## Open questions

- Read-only access to the Docker socket vs. a small privileged helper for
  image inspection.
- Notification channel: ntfy.sh (simplest) vs. self-hosted Gotify.
- Whether healthchecks live in this service or a separate probe.
