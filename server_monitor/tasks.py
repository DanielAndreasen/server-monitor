"""Celery tasks: scheduled checks that write snapshots to the Redis store,
plus the issue #7 notification tasks (ok->fail transition alerts and the
daily 09:00 digest) that read those snapshots and dispatch via the
``server_monitor.notify`` seam.

Worker and beat pick these up via ``include=["server_monitor.tasks"]`` in
``celery_app.py``, where the Beat schedule lives as well. The Redis client
and the check-runner seams are injected into the plain ``*_snapshot``
functions so tests can fake both (FakeRedis + fake http/docker/statvfs/
fail2ban clients).
"""

import os

from server_monitor import notify
from server_monitor.celery_app import app
from server_monitor.checks.apt import CommandRunner, check_apt, run_apt_list
from server_monitor.checks.docker_images import (
    DockerAPI,
    RegistryFetcher,
    check_docker_images,
    default_docker_client,
    fetch_manifest_digest,
)
from server_monitor.checks.healthchecks import (
    CONFIG_ENV,
    DEFAULT_CONFIG_PATH,
    ContainerInspector,
    Fail2banClient,
    HttpFetcher,
    StatvfsProbe,
    fetch_status,
    load_healthchecks,
)
from server_monitor.checks.healthchecks import (
    run_healthchecks as run_all_probes,
)
from server_monitor.store import RedisLike, Snapshot, get_redis, write_snapshot

APT_CHECK = "apt"
DOCKER_IMAGES_CHECK = "docker"  # matches metrics.DOCKER_CHECK / the #3 web shell
#: Snapshot check name used when the healthchecks.yaml itself cannot be loaded.
HEALTHCHECKS_CONFIG_CHECK = "healthchecks-config"


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


def run_docker_images_snapshot(
    client: RedisLike,
    docker: DockerAPI | None = None,
    fetch: RegistryFetcher | None = None,
) -> Snapshot:
    """Run the docker image digest check, store it under check name ``docker``.

    Extras stored alongside status/detail: ``outdated_images`` (the list of
    ``{image, local_digest, remote_digest}`` entries), ``outdated_images_count``
    (consumed by /metrics and the status page), ``images_checked`` and
    per-image registry lookup ``errors``. A failure of the check itself
    (docker socket unreachable, ...) records a failed snapshot.
    """
    try:
        result = check_docker_images(
            docker if docker is not None else default_docker_client(),
            fetch if fetch is not None else fetch_manifest_digest,
        )
    except Exception as exc:
        # Docker API failure: record a failed check instead of letting the
        # beat entry die.
        return write_snapshot(
            client, DOCKER_IMAGES_CHECK, "fail", detail=f"docker images check failed: {exc}"
        )
    outdated_images = [
        {
            "image": status.image,
            "local_digest": status.local_digest,
            "remote_digest": status.remote_digest,
        }
        for status in result.outdated
    ]
    detail = f"{result.outdated_count} images outdated"
    if result.errors:
        detail += f" ({len(result.errors)} registry lookup errors)"
    return write_snapshot(
        client,
        DOCKER_IMAGES_CHECK,
        "ok",
        detail=detail,
        outdated_images=outdated_images,
        outdated_images_count=result.outdated_count,
        images_checked=len(result.checked),
        errors=result.errors,
    )


@app.task
def run_docker_images_check() -> Snapshot:
    """Beat task (every 6 h): docker image digest check -> Redis snapshot."""
    return run_docker_images_snapshot(get_redis())


def run_healthchecks_snapshot(
    client: RedisLike,
    config_path: str | None = None,
    *,
    fetch: HttpFetcher | None = None,
    docker: ContainerInspector | None = None,
    statvfs: StatvfsProbe | None = None,
    fail2ban_client: Fail2banClient | None = None,
) -> list[Snapshot]:
    """Run every probe in healthchecks.yaml and store one snapshot per check
    name (``server_monitor:snapshot:<name>``), so ``server_monitor_check_up{check}`` and
    ``server_monitor_check_last_run_seconds{check}`` work via the #3 metrics shell.

    The config path comes from ``config_path``, else the
    ``HEALTHCHECKS_CONFIG`` env var, else ``./healthchecks.yaml`` (in
    production the file is mounted at ``/config/healthchecks.yaml``). All
    probe seams (http fetcher, docker client, statvfs, fail2ban client) are
    injectable; ``client`` doubles as the internet check's Redis counter
    store. A config that cannot be loaded records a single failed snapshot
    under ``healthchecks-config`` instead of killing the beat entry.
    """
    path = config_path or os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH)
    try:
        configs = load_healthchecks(path)
    except Exception as exc:
        return [
            write_snapshot(
                client,
                HEALTHCHECKS_CONFIG_CHECK,
                "fail",
                detail=f"healthchecks config failed to load ({path}): {exc}",
            )
        ]
    results = run_all_probes(
        configs,
        redis=client,
        fetch=fetch if fetch is not None else fetch_status,
        docker=docker,
        statvfs=statvfs if statvfs is not None else os.statvfs,
        fail2ban_client=fail2ban_client,
    )
    snapshots: list[Snapshot] = []
    for result in results:
        snapshots.append(
            write_snapshot(
                client,
                result.name,
                result.status,  # "ok" | "warn" | "fail"
                detail=result.detail,
                check_type=result.type,
                **result.extra,
            )
        )
    return snapshots


@app.task
def run_healthchecks() -> list[Snapshot]:
    """Beat task (every 30 min): healthchecks.yaml probes -> per-check snapshots."""
    return run_healthchecks_snapshot(get_redis())


@app.task
def check_healthcheck_transitions() -> list[notify.Transition]:
    """Beat task (every 30 min, one minute after the healthchecks run).

    Compares every stored snapshot with its last-seen status in Redis
    (``server_monitor:notified:<check>``) and sends one immediate Gotify alert per
    ok->fail transition — no repeats while the check keeps failing; a
    low-priority recovery notice on fail->ok clears the marker. See
    ``server_monitor.notify.check_transitions``.
    """
    return notify.check_transitions(get_redis(), notify.get_notifier())


@app.task
def send_daily_digest() -> notify.Digest | None:
    """Beat task (daily 09:00): one Gotify digest of pending apt updates,
    outdated docker images and not-ok checks — sent only when something
    needs attention. See ``server_monitor.notify.send_digest``."""
    return notify.send_digest(get_redis(), notify.get_notifier())
