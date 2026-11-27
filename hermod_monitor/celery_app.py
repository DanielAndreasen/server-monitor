"""Celery application used by the worker and beat compose services.

Tasks live in ``hermod_monitor.tasks``, wired in via ``include`` so both
worker and beat import them. The Beat schedule below runs the apt update
check daily at 06:00, the docker image digest check every 6 hours, the
healthchecks.yaml probes every 30 minutes, the ok->fail transition alerts
every 30 minutes right after the healthchecks (issue #7), and the single
Gotify daily digest at 09:00 (issue #7). Beat's default timezone is UTC;
a container TZ via compose is issue #9's scope).
"""

import os

from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "hermod_monitor",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["hermod_monitor.tasks"],
)

app.conf.beat_schedule = {
    "apt-check-daily": {
        "task": "hermod_monitor.tasks.run_apt_check",
        "schedule": crontab(hour=6, minute=0),  # daily at 06:00
    },
    "docker-images-check": {
        "task": "hermod_monitor.tasks.run_docker_images_check",
        "schedule": crontab(minute=0, hour="*/6"),  # every 6 h at minute 0
    },
    "healthchecks-every-30min": {
        "task": "hermod_monitor.tasks.run_healthchecks",
        "schedule": crontab(minute="*/30"),  # every 30 minutes
    },
    "healthcheck-transitions-every-30min": {
        "task": "hermod_monitor.tasks.check_healthcheck_transitions",
        # one minute after each healthchecks run, so snapshots are fresh
        "schedule": crontab(minute="1,31"),
    },
    "daily-digest-0900": {
        "task": "hermod_monitor.tasks.send_daily_digest",
        "schedule": crontab(hour=9, minute=0),  # daily at 09:00
    },
}
