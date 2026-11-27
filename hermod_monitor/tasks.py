"""Celery tasks: scheduled checks that write snapshots to the Redis store.

Worker and beat pick these up via ``include=["hermod_monitor.tasks"]`` in
``celery_app.py``, where the Beat schedule lives as well. The Redis client
and the check-runner seam are injected into the plain ``*_snapshot``
functions so tests can fake both (FakeRedis + canned apt output).
"""

from hermod_monitor.celery_app import app
from hermod_monitor.checks.apt import CommandRunner, check_apt, run_apt_list
from hermod_monitor.store import RedisLike, Snapshot, get_redis, write_snapshot

APT_CHECK = "apt"


def run_apt_snapshot(
    client: RedisLike,
    runner: CommandRunner = run_apt_list,
) -> Snapshot:
    """Run the apt check, store its snapshot under check name ``apt``, return it.

    Extras stored alongside status/detail: ``updates_pending``,
    ``security_updates`` and the pending ``packages`` list (consumed by
    /metrics, the status page and the daily digest).
    """
    try:
        result = check_apt(runner=runner)
    except Exception as exc:
        # Runner failure (apt missing, nonzero exit): record a failed check
        # instead of letting the beat entry die.
        return write_snapshot(
            client, APT_CHECK, "fail", detail=f"apt check failed: {exc}"
        )
    pending = result.updates_pending
    security = result.security_updates
    return write_snapshot(
        client,
        APT_CHECK,
        "ok",
        detail=f"{pending} updates pending ({security} security)",
        updates_pending=pending,
        security_updates=security,
        packages=[
            {
                "package": update.package,
                "archive": update.archive,
                "candidate": update.candidate,
                "security": update.security,
            }
            for update in result.updates
        ],
    )


@app.task
def run_apt_check() -> Snapshot:
    """Beat task (daily 06:00): apt update check -> Redis snapshot."""
    return run_apt_snapshot(get_redis())
