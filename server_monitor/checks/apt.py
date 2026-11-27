"""apt update check runner (issue #4).

Runs ``apt list --upgradable`` against the *host's* apt state. In
production the worker container gets read-only bind mounts of the host's
apt directories, so the container's own apt reads the host's package
database and lists (the compose mounts themselves are issue #9's scope;
the paths are noted here so the wiring is discoverable):

    host /etc/apt            -> /etc/apt:ro
    host /var/lib/apt/lists  -> /var/lib/apt/lists:ro
    host /var/lib/dpkg       -> /var/lib/dpkg:ro

The subprocess call goes through the injectable ``runner`` seam: tests
pass a fake returning canned ``apt list --upgradable`` output and never
touch a real subprocess.
"""

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

APT_LIST_COMMAND = ["apt", "list", "--upgradable"]

#: A runner executes the apt command and returns its stdout (raises on failure).
CommandRunner = Callable[[], str]

_UPGRADABLE_FROM = re.compile(r"\[upgradable from:\s*([^\]]+)\]")


def run_apt_list() -> str:
    """Default runner: execute ``apt list --upgradable`` and return stdout."""
    proc = subprocess.run(
        APT_LIST_COMMAND,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


@dataclass(frozen=True)
class AptUpdate:
    """One pending package upgrade parsed from ``apt list --upgradable``."""

    package: str
    archive: str  # origin/archive pocket, e.g. "jammy-security" ("now" if local)
    candidate: str  # version apt would upgrade to
    installed: str  # currently installed version ("upgradable from")
    architecture: str
    security: bool  # True when the pocket is a *-security pocket


@dataclass(frozen=True)
class AptCheckResult:
    """Result of one apt check run."""

    updates: list[AptUpdate] = field(default_factory=list)

    @property
    def updates_pending(self) -> int:
        return len(self.updates)

    @property
    def security_updates(self) -> int:
        return sum(1 for update in self.updates if update.security)


def _is_security_archive(archive: str) -> bool:
    """A pocket like ``jammy-security`` (or ``.../jammy-security``) is a
    security pocket. Matching only the archive segment avoids flagging
    packages whose *name* merely ends in ``-security``."""
    return "-security" in archive


def parse_upgradable(output: str) -> list[AptUpdate]:
    """Parse ``apt list --upgradable`` stdout into pending package entries.

    Line format (apt >= 2.x; the archive may carry a ``,now`` suffix and an
    origin label, e.g. ``containerd.io/Debian:12/bookworm`` or
    ``Ubuntu:22.04/jammy-security``)::

        Listing... Done
        base-files/jammy-updates,now 12.4ubuntu4.6 amd64 [upgradable from: 12.4ubuntu4.5]
        openssl/jammy-security 3.0.2-0ubuntu1.10 amd64 [upgradable from: 3.0.2-0ubuntu1.9]
        local-pkg/now 5.0 all [upgradable from: 4.0]

    The first token is ``name/archive``; the *last* ``/`` segment of that
    token is the pocket, and a ``-security`` pocket marks a security update.
    """
    updates: list[AptUpdate] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue  # "Listing... Done" header / blank lines
        tokens = line.split()
        head = tokens[0]
        # "name/archive" where the archive may be origin-labelled with extra
        # "/" segments, e.g. "containerd.io/Debian:12/bookworm" or
        # "openssl/Ubuntu:22.04/jammy-security": package is the first segment,
        # the pocket is the last one.
        segments = head.split("/")
        package = segments[0]
        archive = segments[-1].split(",")[0] if len(segments) > 1 else ""  # drop ",now"
        candidate = tokens[1] if len(tokens) > 1 else ""
        architecture = tokens[2] if len(tokens) > 2 else ""
        match = _UPGRADABLE_FROM.search(line)
        installed = match.group(1) if match else ""
        updates.append(
            AptUpdate(
                package=package,
                archive=archive,
                candidate=candidate,
                installed=installed,
                architecture=architecture,
                security=_is_security_archive(archive),
            )
        )
    return updates


def check_apt(runner: CommandRunner = run_apt_list) -> AptCheckResult:
    """Run the apt upgradable check via ``runner`` and return the result."""
    return AptCheckResult(updates=parse_upgradable(runner()))
