# hermod-monitor

[![CI](https://github.com/DanielAndreasen/server-monitor/actions/workflows/ci.yaml/badge.svg)](https://github.com/DanielAndreasen/server-monitor/actions/workflows/ci.yaml)

Self-hosted service on the `hermod` home server that shows pending updates
(system packages + Docker images) and runs general healthchecks, with push
notifications when something needs attention.

Status: **implementation started** — scaffold + CI are on `master` (issues #2, #8); the remaining tickets are tracked as sub-issues of #1. Design decisions live in `docs/wiki/design-decisions.md`.

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

## Resolved questions (2026-11-27, see docs/wiki/design-decisions.md)

- Docker access: read-only `/var/run/docker.sock` mount — inspection only, no privileged helper.
- Notifications: self-hosted **Gotify** on hermod. Healthcheck failures alert immediately; pending updates go in one daily digest at 09:00.
- Healthchecks live in this service, defined in a mounted `healthchecks.yaml`.

## Development

- `uv sync && uv run pytest` — local dev/test (Python 3.14 via uv)
- CI: `.github/workflows/ci.yaml` runs uv + pytest on push/PR to `master`
- Run the stack: `docker compose up -d` (services: redis, worker, beat, web); secrets in `.env` (see `.env.example`)
