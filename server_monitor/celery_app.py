"""Celery application used by the worker and beat compose services."""

import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery("server_monitor", broker=REDIS_URL, backend=REDIS_URL)
