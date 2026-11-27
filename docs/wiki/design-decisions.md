# Design decisions

Agreed with the owner on 2026-11-27 during a grilling session; source of truth is GitHub issue #1 (spec) and its sub-issues #2–#9. This page records the decisions, not the code.

- State: Redis holds latest snapshot per check + Celery results; web/metrics/notifier all read from it. No separate DB.
- Notifications: existing self-hosted Gotify on home-server. Healthcheck ok→fail alerts immediately; everything else goes in one daily digest at 09:00, sent only if something needs attention. Transition markers in Redis prevent repeat alerts.
- apt check: daily 06:00 via `apt list --upgradable` on the *host's* apt state (read-only mounts of /etc/apt, /var/lib/apt/lists, /var/lib/dpkg into the worker), with a separate security-pocket count.
- Docker check: every 6 h, only images referenced by containers (not unused images/compose files); read-only docker.sock; digest vs Docker Registry HTTP API v2 (manifest-list aware); host ~/.docker/config.json mounted read-only for registry auth.
- Healthchecks: every 30 min from a mounted healthchecks.yaml; types http, container, disk (warn >80%, fail >90%), internet (fail after 2 consecutive probe failures), fail2ban (malicious access via read-only fail2ban socket). Server is not beefy — probes stay lightweight.
- Web: no auth in v1, LAN-only; /health unauthenticated. Status page shows pending apt updates, outdated images, healthcheck table.
- Metrics: server_monitor_check_up{check}, server_monitor_apt_updates_pending, server_monitor_apt_security_updates_pending, server_monitor_docker_images_outdated, server_monitor_check_last_run_seconds{check}.
- Deploy: `docker compose up -d` from a git clone on home-server; services redis/worker/beat/web, restart: unless-stopped; secrets in uncommitted .env.
- Stack: Python 3.14 + uv, FastAPI, Celery/Beat/Redis, prometheus-client, pytest.
- Tests: mock at the check-runner boundary (injected clients) and FastAPI routes with fake Redis; Beat scheduling and Gotify dispatch are untested glue.
- CI: GitHub Actions (uv + pytest on push/PR to master) — issue #8. CD to server_monitor: planned follow-up after deploy (issue #9).
