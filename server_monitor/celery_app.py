"""Celery application used by the worker and beat compose services.

Tasks live in ``server_monitor.tasks``, wired in via ``include`` so both
worker and beat import them. The Beat schedule below runs the apt update
check daily at 06:00 and the docker image digest check every 6 hours
(beat's default timezone is UTC; a container TZ via compose is issue #9's
scope).
"""

import os

from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "server_monitor",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["server_monitor.tasks"],
)

app.conf.beat_schedule = {
    "apt-check-daily": {
        "task": "server_monitor.tasks.run_apt_check",
        "schedule": crontab(hour=6, minute=0),  # daily at 06:00
    },
    "docker-images-check": {
        "task": "server_monitor.tasks.run_docker_images_check",
        "schedule": crontab(minute=0, hour="*/6"),  # every 6 h at minute 0
    },
}
