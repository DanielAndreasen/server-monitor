"""Check runners: one module per check, subprocess/clients injectable.

Each check is a plain function taking an injected runner/client and
returning a result; the Celery tasks in ``server_monitor.tasks`` turn the
result into a Redis snapshot. Tests fake only the runner seam, never the
real subprocess, network or socket.
"""
