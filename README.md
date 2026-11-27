# server-monitor

[![CI](https://github.com/DanielAndreasen/server-monitor/actions/workflows/ci.yaml/badge.svg)](https://github.com/DanielAndreasen/server-monitor/actions/workflows/ci.yaml)

Self-hosted service on the home server that shows pending updates
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
- Notifications: self-hosted **Gotify** on the home server. Healthcheck failures alert immediately; pending updates go in one daily digest at 09:00.
- Healthchecks live in this service, defined in a mounted `healthchecks.yaml`.

## Development

- `uv sync && uv run pytest` — local dev/test (Python 3.14 via uv)
- CI: `.github/workflows/ci.yaml` runs uv + pytest on push/PR to `master`
- Run the stack locally: `docker compose up -d` (services: redis, worker, beat, web); secrets in `.env` (see `.env.example`)

## Deploy on the home server

Production runs from a git clone on the home server itself, using the base compose
file plus the production override `docker-compose.prod.yml` (which keeps all
base services and adds the worker's read-only host mounts: docker.sock,
host apt dirs, host docker config, fail2ban socket, and `healthchecks.yaml`).

1. **Clone and configure** (on the home server):
   ```sh
   git clone <repo-url> server-monitor && cd server-monitor
   cp .env.example .env
   ```
   Edit `.env` (never committed — it is gitignored) and fill in:
   - `GOTIFY_URL` / `GOTIFY_TOKEN` — your Gotify instance and an app token
     (create the app in Gotify first).
   - `REDIS_URL` — leave as `redis://redis:6379/0`; inside the compose
     network the `redis` service is reachable under that name.
   - `TZ` — set your local timezone (e.g. `TZ=Europe/Copenhagen`) so the
     06:00 apt check and 09:00 digest run at local time; compose falls back
     to `UTC`.
   - `HOST_DOCKER_CONFIG` — only if your docker config is not at
     `~/.docker` on the host (that is the default).
   - `DOCKER_SOCK` / `HEALTHCHECKS_CONFIG` — already match the prod mounts
     (`/var/run/docker.sock`, `/config/healthchecks.yaml`); change only if
     you change the mounts.
   Edit `healthchecks.yaml` in the clone to point at your real services
   (it is mounted read-only into the worker).

2. **Start the stack**:
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

3. **Verify** (see the checklist below):
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
   curl -fsS http://localhost:8000/health
   ```
   The status page is then reachable on the LAN at `http://<server>:8000`
   (no auth in v1 — LAN only).

4. **View logs**:
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f            # everything
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f worker     # check runs
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f beat       # schedule firing
   ```

### Live-verification checklist (run on the home server; docker is unavailable in CI/dev sandboxes)

- [ ] `docker compose -f docker-compose.yml -f docker-compose.prod.yml ps` shows
      all four services (`redis`, `worker`, `beat`, `web`) as `Up`.
- [ ] `curl -fsS http://localhost:8000/health` returns the health payload.
- [ ] `docker compose ... exec worker sh -c 'test -S /var/run/docker.sock && ls /etc/apt /var/lib/dpkg /config/healthchecks.yaml'`
      — the read-only host mounts are visible inside the worker.
- [ ] `docker compose ... logs worker` shows healthcheck probes running
      (every 30 min), the apt check at 06:00 local time, and the Docker image
      digest check every 6 h — no mount/socket errors.
- [ ] A Gotify push arrives on the owner's phone: immediately when a
      healthcheck flips ok→fail, and the daily digest at 09:00 local when
      updates are pending or checks are failing.
- [ ] The status page `http://<server>:8000` shows pending apt updates
      (security flagged), outdated Docker images, and the healthcheck table.

### Secret handling

- Real secrets (`GOTIFY_TOKEN`, etc.) live **only** in the uncommitted,
  gitignored `.env` on the home server. `.env.example` carries placeholders only
  (public-repo rule, see `docs/wiki/public-repo-rule.md`).
- The host mounts are all **read-only** (`:ro`), including the Docker and
  fail2ban sockets — the worker inspects the host but cannot modify it.

