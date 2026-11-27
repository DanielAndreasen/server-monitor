"""Prometheus collector that derives metrics from stored check snapshots.

Exposes (per design-decisions.md):

- ``hermod_check_up{check}``                 1 if the check's last run was ok
- ``hermod_check_last_run_seconds{check}``   unix timestamp of the last run
- ``hermod_apt_updates_pending``             pending apt updates (0 if no apt snapshot)
- ``hermod_apt_security_updates_pending``    pending apt security updates
- ``hermod_docker_images_outdated``          outdated images used by containers

Labeled metrics are absent until a snapshot for that check exists; the
unlabeled gauges report 0 when no apt/docker snapshot exists yet.
"""

from collections.abc import Iterator

from prometheus_client.metrics_core import GaugeMetricFamily

from hermod_monitor.store import Snapshot

APT_CHECK = "apt"
DOCKER_CHECK = "docker"


class SnapshotMetricsCollector:
    """prometheus_client collector reading from already-loaded snapshots."""

    def __init__(self, snapshots: dict[str, Snapshot]) -> None:
        self._snapshots = snapshots

    def collect(self) -> Iterator[GaugeMetricFamily]:
        up = GaugeMetricFamily(
            "hermod_check_up",
            "1 if the check's last run was ok, 0 otherwise",
            labels=["check"],
        )
        last_run = GaugeMetricFamily(
            "hermod_check_last_run_seconds",
            "Unix timestamp (seconds) of the check's last run",
            labels=["check"],
        )
        for name, snapshot in self._snapshots.items():
            up.add_metric([name], 1 if snapshot.get("status") == "ok" else 0)
            if "last_run" in snapshot:
                last_run.add_metric([name], float(snapshot["last_run"]))
        yield up
        yield last_run

        apt = self._snapshots.get(APT_CHECK, {})
        yield GaugeMetricFamily(
            "hermod_apt_updates_pending",
            "Pending apt updates on the host",
            value=int(apt.get("updates_pending", 0)),
        )
        yield GaugeMetricFamily(
            "hermod_apt_security_updates_pending",
            "Pending apt security-pocket updates on the host",
            value=int(apt.get("security_updates", 0)),
        )
        docker = self._snapshots.get(DOCKER_CHECK, {})
        outdated = docker.get("outdated_images", 0)
        # The #5 check stores the detailed list; older/int snapshots store
        # the bare count — the gauge reports the number either way.
        outdated_count = len(outdated) if isinstance(outdated, list) else int(outdated)
        yield GaugeMetricFamily(
            "hermod_docker_images_outdated",
            "Docker images used by containers whose registry digest is newer",
            value=outdated_count,
        )
