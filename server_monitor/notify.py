"""Gotify notifications (issue #7): immediate ok->fail alerts + one 09:00 digest.

Two notification flows, both behind the small ``Notifier`` interface (the
default implementation is Gotify; the spec keeps the seam so the channel
can change later):

- **Immediate alerts**: the Celery task
  ``server_monitor.tasks.check_healthcheck_transitions`` (beat every 30 min,
  one minute after the healthchecks run) calls :func:`check_transitions`,
  which compares every stored snapshot's status with the last-seen status
  kept in Redis under ``server_monitor:notified:<check>``. A check that transitions
  into ``fail`` (from ``ok``, ``warn``, or first sight) gets exactly one
  high-priority Gotify message; while it keeps failing the marker suppresses
  repeats. A ``fail -> ok`` recovery clears the marker and sends a clearly
  low-priority recovery notice.
- **Daily digest**: the Celery task ``server_monitor.tasks.send_daily_digest``
  (beat daily at 09:00) calls :func:`send_digest`, which builds one message
  from the snapshots (pending apt updates + security count, outdated docker
  images, every check not ``ok``) and sends it **only when something needs
  attention** — silence means all good.

Security (public-repo rule): the Gotify app token travels only in the query
string of the request URL. It is never logged, and :func:`redact` strips it
from any error message (httpx errors embed the request URL) before the error
is re-raised as :class:`GotifyError`.

All functions take the Redis client and the notifier as arguments so tests
inject FakeRedis + a fake http/notifier seam; no test touches the network.
"""

import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from server_monitor.store import RedisLike, Snapshot, list_snapshots

#: Env vars holding the Gotify server URL and app token (see .env.example).
GOTIFY_URL_ENV = "GOTIFY_URL"
GOTIFY_TOKEN_ENV = "GOTIFY_TOKEN"

#: Gotify message priorities (0-10; higher = more urgent).
PRIORITY_FAILURE = 8  # immediate ok->fail alert
PRIORITY_DIGEST = 3  # the single daily 09:00 digest
PRIORITY_RECOVERY = 1  # fail->ok recovery notice (clearly low priority)

#: Redis key prefix for the last-seen status per check: ``server_monitor:notified:<check>``.
NOTIFIED_PREFIX = "server_monitor:notified:"

#: Replacement text for redacted secrets.
REDACTED = "<redacted>"

#: Snapshot check names written by the apt / docker tasks (see tasks.py).
APT_CHECK = "apt"
DOCKER_CHECK = "docker"


def notified_key(check: str) -> str:
    """Redis key holding the last-seen status of ``check``."""
    return f"{NOTIFIED_PREFIX}{check}"


def redact(text: str, token: str) -> str:
    """Replace every occurrence of ``token`` in ``text`` with REDACTED.

    Tokens must never appear in logs or error messages, and httpx error
    messages embed the request URL (which carries the token in the query
    string), so every error path runs through here.
    """
    if not token:
        return text
    return text.replace(token, REDACTED)


# ---------------------------------------------------------------------------
# Notifier interface + Gotify implementation
# ---------------------------------------------------------------------------


class Notifier(Protocol):
    """The small notification interface: send one push message."""

    def send(self, title: str, message: str, priority: int) -> None: ...


class GotifyError(RuntimeError):
    """Sending a Gotify message failed; the message never contains the token."""


class ResponseLike(Protocol):
    """The slice of httpx.Response the notifier relies on."""

    def raise_for_status(self) -> None: ...


class HttpPoster(Protocol):
    """The slice of httpx.Client the notifier relies on (the injectable seam).

    Tests pass a fake recording ``post`` calls; production uses a real
    ``httpx.Client``. No test ever touches the network.
    """

    def post(
        self, url: str, *, json: dict[str, Any], headers: dict[str, str]
    ) -> ResponseLike: ...


class GotifyNotifier:
    """Default ``Notifier``: POSTs to ``GOTIFY_URL/message?token=GOTIFY_TOKEN``.

    ``url``/``token`` default to the ``GOTIFY_URL``/``GOTIFY_TOKEN`` env
    vars; ``http`` is the injectable httpx-like seam. The token is used
    only in the request URL's query string, is never logged, and is
    redacted from any raised error.
    """

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        *,
        http: HttpPoster | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = (
            url if url is not None else os.environ.get(GOTIFY_URL_ENV, "")
        ).rstrip("/")
        self._token = token if token is not None else os.environ.get(GOTIFY_TOKEN_ENV, "")
        self._http = http
        self._timeout = timeout

    @classmethod
    def from_env(cls, http: HttpPoster | None = None) -> "GotifyNotifier":
        """Build a notifier from the GOTIFY_URL/GOTIFY_TOKEN env vars."""
        return cls(http=http)

    def _client(self) -> HttpPoster:
        if self._http is None:
            self._http = httpx.Client(timeout=self._timeout)
        return self._http

    def send(self, title: str, message: str, priority: int = PRIORITY_DIGEST) -> None:
        """POST one message to the Gotify ``/message`` endpoint.

        Raises :class:`GotifyError` (token-redacted) when Gotify is not
        configured or the POST fails.
        """
        if not self._url or not self._token:
            raise GotifyError(
                "Gotify is not configured: set GOTIFY_URL and GOTIFY_TOKEN"
            )
        url = f"{self._url}/message?token={self._token}"
        payload = {"title": title, "message": message, "priority": int(priority)}
        try:
            response = self._client().post(
                url, json=payload, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
        except GotifyError:
            raise
        except Exception as exc:
            # httpx errors embed the request URL (token included): redact
            # before the error escapes, so the token never lands in logs.
            raise GotifyError(redact(f"Gotify POST failed: {exc}", self._token)) from exc


def get_notifier() -> Notifier:
    """Production notifier built from the environment (GOTIFY_URL/GOTIFY_TOKEN)."""
    return GotifyNotifier.from_env()


# ---------------------------------------------------------------------------
# Immediate ok->fail transition alerts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Transition:
    """One notification produced by :func:`check_transitions`."""

    check: str
    kind: str  # "failure" | "recovery"
    title: str
    message: str
    priority: int


def check_transitions(
    client: RedisLike,
    notifier: Notifier,
    snapshots: dict[str, Snapshot] | None = None,
) -> list[Transition]:
    """Compare each stored snapshot with its last-seen status in Redis and
    send one Gotify message per transition.

    - status ``fail`` while the last-seen status (``server_monitor:notified:<check>``)
      was anything else — ``ok``, ``warn``, or no marker yet: one immediate
      alert at ``PRIORITY_FAILURE``; the marker is set to ``fail`` so a
      still-failing check never re-alerts.
    - status ``ok`` while the last-seen status was ``fail``: clear the marker
      and send a low-priority recovery notice (``PRIORITY_RECOVERY``).
    - anything else (``warn``, unchanged statuses): no alert; the marker is
      updated to the current status so a later ``warn -> fail`` still alerts.

    Returns the transitions sent (handy for tests and logging).
    """
    if snapshots is None:
        snapshots = list_snapshots(client)
    sent: list[Transition] = []
    for name in sorted(snapshots):
        status = str(snapshots[name].get("status", ""))
        if not status:
            continue
        key = notified_key(name)
        last = client.get(key)
        detail = str(snapshots[name].get("detail", "")).strip()
        if status == "fail" and last != "fail":
            transition = Transition(
                check=name,
                kind="failure",
                title=f"server-monitor: {name} is failing",
                message=detail or "status: fail",
                priority=PRIORITY_FAILURE,
            )
            notifier.send(transition.title, transition.message, transition.priority)
            client.set(key, "fail")
            sent.append(transition)
        elif status == "ok" and last == "fail":
            transition = Transition(
                check=name,
                kind="recovery",
                title=f"server-monitor: {name} recovered",
                message=detail or "status: ok",
                priority=PRIORITY_RECOVERY,
            )
            notifier.send(transition.title, transition.message, transition.priority)
            client.delete(key)  # recovered: clear the marker
            sent.append(transition)
        elif last != status:
            client.set(key, status)
    return sent


# ---------------------------------------------------------------------------
# Daily 09:00 digest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Digest:
    """One daily digest message; sent only when something needs attention."""

    title: str
    message: str
    priority: int


def build_digest(snapshots: dict[str, Snapshot]) -> Digest | None:
    """Build the daily digest from the snapshots, or None when all is well.

    The digest needs attention when pending apt updates > 0, outdated
    docker images > 0, or any stored check is not ``ok`` (``fail`` or
    ``warn``). The message carries the pending/security counts, the
    outdated image names, and one line per not-ok check.
    """
    lines: list[str] = []

    apt = snapshots.get(APT_CHECK) or {}
    pending = int(apt.get("updates_pending") or 0)
    security = int(apt.get("security_updates") or 0)
    if pending:
        lines.append(f"{pending} apt updates pending ({security} security)")

    docker = snapshots.get(DOCKER_CHECK) or {}
    outdated = docker.get("outdated_images") or []
    if isinstance(outdated, list):
        outdated_count = len(outdated)
        names = [
            str(entry.get("image", "?"))
            for entry in outdated
            if isinstance(entry, dict)
        ]
    else:  # older/int snapshots store the bare count
        outdated_count = int(outdated or 0)
        names = []
    if outdated_count:
        line = f"{outdated_count} outdated docker images"
        if names:
            line += ": " + ", ".join(names)
        lines.append(line)

    for name, snapshot in sorted(snapshots.items()):
        status = snapshot.get("status")
        if status == "ok" or status is None:
            continue
        detail = str(snapshot.get("detail", "")).strip()
        lines.append(f"check {name}: {status}" + (f" - {detail}" if detail else ""))

    if not lines:
        return None  # nothing needs attention: send nothing
    return Digest(
        title="server-monitor daily digest",
        message="\n".join(lines),
        priority=PRIORITY_DIGEST,
    )


def send_digest(
    client: RedisLike,
    notifier: Notifier,
    snapshots: dict[str, Snapshot] | None = None,
) -> Digest | None:
    """Send the single daily digest via ``notifier``, only when needed.

    Reads the snapshots from Redis unless ``snapshots`` is given. Returns
    the sent :class:`Digest`, or None when nothing needs attention (no
    message is sent — silence means all good).
    """
    if snapshots is None:
        snapshots = list_snapshots(client)
    digest = build_digest(snapshots)
    if digest is None:
        return None
    notifier.send(digest.title, digest.message, digest.priority)
    return digest
