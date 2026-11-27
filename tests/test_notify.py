"""Tests for Gotify notifications (issue #7): the notifier seam (URL, body,
headers, priorities, token redaction in errors), ok->fail transition alerts
(one immediate message, no repeats while failing, recovery clears the
marker, warn handling), the daily digest (sent only when something needs
attention, content includes counts), the Celery task wiring, and the beat
schedule entries. No test touches the network: the http seam is faked."""

import httpx
import pytest

from server_monitor import notify, tasks
from server_monitor.celery_app import app as celery_app
from server_monitor.notify import (
    GOTIFY_TOKEN_ENV,
    GOTIFY_URL_ENV,
    NOTIFIED_PREFIX,
    PRIORITY_DIGEST,
    PRIORITY_FAILURE,
    PRIORITY_RECOVERY,
    GotifyError,
    GotifyNotifier,
    build_digest,
    check_transitions,
    notified_key,
    redact,
    send_digest,
)
from server_monitor.store import write_snapshot
from tests.conftest import FakeRedis

GOTIFY_URL = "https://gotify.example.com"
TOKEN = "fake-token-for-unit-tests"


# ---------------------------------------------------------------------------
# Fakes (seams)
# ---------------------------------------------------------------------------


class FakeResponse:
    """Fake httpx response: raise_for_status raises like httpx would."""

    def __init__(self, status_code: int = 200, url: str = "") -> None:
        self.status_code = status_code
        self._url = url

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            # httpx error messages embed the request URL (token included).
            raise httpx.HTTPStatusError(
                f"Server error '{self.status_code} Internal Server Error' "
                f"for url '{self._url}'",
                request=httpx.Request("POST", self._url),
                response=httpx.Response(self.status_code),
            )


class FakeGotifyHttp:
    """Fake HttpPoster seam: records every post; can be told to fail."""

    def __init__(self, fail_with: Exception | None = None, status_code: int = 200) -> None:
        self.posts: list[dict] = []
        self.fail_with = fail_with
        self.status_code = status_code

    def post(self, url: str, *, json: dict, headers: dict) -> FakeResponse:
        self.posts.append({"url": url, "json": json, "headers": headers})
        if self.fail_with is not None:
            raise self.fail_with
        return FakeResponse(self.status_code, url)


class FakeNotifier:
    """Fake Notifier: records (title, message, priority) of every send."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, int]] = []

    def send(self, title: str, message: str, priority: int) -> None:
        self.sent.append((title, message, priority))


# ---------------------------------------------------------------------------
# GotifyNotifier: request shape + token handling
# ---------------------------------------------------------------------------


def test_gotify_send_posts_to_message_endpoint_with_token_in_url() -> None:
    http = FakeGotifyHttp()
    notifier = GotifyNotifier(GOTIFY_URL, TOKEN, http=http)
    notifier.send("title here", "message body", PRIORITY_FAILURE)
    assert len(http.posts) == 1
    post = http.posts[0]
    assert post["url"] == f"{GOTIFY_URL}/message?token={TOKEN}"
    assert post["json"] == {
        "title": "title here",
        "message": "message body",
        "priority": PRIORITY_FAILURE,
    }
    assert post["headers"]["Content-Type"] == "application/json"


def test_gotify_send_uses_priority_argument_verbatim() -> None:
    http = FakeGotifyHttp()
    notifier = GotifyNotifier(GOTIFY_URL, TOKEN, http=http)
    notifier.send("t", "m", 8)
    notifier.send("t", "m", 3)
    notifier.send("t", "m", 1)
    assert [p["json"]["priority"] for p in http.posts] == [8, 3, 1]


def test_gotify_defaults_come_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GOTIFY_URL_ENV, "https://env-gotify.example.com/")
    monkeypatch.setenv(GOTIFY_TOKEN_ENV, "fake-env-token-for-unit-tests")
    http = FakeGotifyHttp()
    notifier = GotifyNotifier(http=http)  # url/token from env
    notifier.send("t", "m", PRIORITY_DIGEST)
    assert http.posts[0]["url"] == "https://env-gotify.example.com/message?token=fake-env-token-for-unit-tests"
    env_notifier = GotifyNotifier.from_env(http=http)
    env_notifier.send("t", "m", PRIORITY_DIGEST)
    assert http.posts[1]["url"] == "https://env-gotify.example.com/message?token=fake-env-token-for-unit-tests"


def test_gotify_missing_config_raises_without_leaking_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(GOTIFY_URL_ENV, raising=False)
    monkeypatch.delenv(GOTIFY_TOKEN_ENV, raising=False)
    http = FakeGotifyHttp()
    notifier = GotifyNotifier(http=http)
    with pytest.raises(GotifyError) as excinfo:
        notifier.send("t", "m", 8)
    assert "GOTIFY_URL" in str(excinfo.value) and "GOTIFY_TOKEN" in str(excinfo.value)
    assert http.posts == []  # nothing was sent


def test_redact_replaces_every_token_occurrence() -> None:
    text = f"url https://x/message?token={TOKEN}&other={TOKEN} end"
    assert redact(text, TOKEN) == f"url https://x/message?token=<redacted>&other=<redacted> end"
    assert redact("no token here", TOKEN) == "no token here"
    assert redact("empty token", "") == "empty token"


def test_gotify_transport_error_is_redacted_and_never_contains_token() -> None:
    url_with_token = f"{GOTIFY_URL}/message?token={TOKEN}"
    http = FakeGotifyHttp(
        fail_with=httpx.ConnectError(f"connection failed for url '{url_with_token}'")
    )
    notifier = GotifyNotifier(GOTIFY_URL, TOKEN, http=http)
    with pytest.raises(GotifyError) as excinfo:
        notifier.send("t", "m", 8)
    message = str(excinfo.value)
    assert TOKEN not in message  # never in errors/logs
    assert "<redacted>" in message
    assert "Gotify POST failed" in message


def test_gotify_http_error_status_is_redacted_and_never_contains_token() -> None:
    http = FakeGotifyHttp(status_code=500)  # raise_for_status raises with the URL
    notifier = GotifyNotifier(GOTIFY_URL, TOKEN, http=http)
    with pytest.raises(GotifyError) as excinfo:
        notifier.send("t", "m", 8)
    message = str(excinfo.value)
    assert TOKEN not in message
    assert f"{GOTIFY_URL}/message?token=<redacted>" in message


# ---------------------------------------------------------------------------
# Transition detection (ok->fail alerts, marker in Redis)
# ---------------------------------------------------------------------------


def test_ok_to_fail_sends_one_immediate_alert_and_no_repeat_while_failing() -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    assert check_transitions(redis, notifier) == []
    assert notifier.sent == []
    assert redis.get(notified_key("web-self")) == "ok"

    write_snapshot(redis, "web-self", "fail", detail="connection refused")
    sent = check_transitions(redis, notifier)
    assert len(sent) == 1
    assert sent[0].kind == "failure"
    assert sent[0].check == "web-self"
    assert len(notifier.sent) == 1
    title, message, priority = notifier.sent[0]
    assert "web-self" in title and "fail" in title.lower()
    assert "connection refused" in message
    assert priority == PRIORITY_FAILURE
    assert redis.get(notified_key("web-self")) == "fail"  # marker set

    # still failing on the next run: no repeat alert
    write_snapshot(redis, "web-self", "fail", detail="still down")
    assert check_transitions(redis, notifier) == []
    assert len(notifier.sent) == 1
    assert redis.get(notified_key("web-self")) == "fail"


def test_first_seen_failing_check_alerts_once() -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    write_snapshot(redis, "internet", "fail", detail="probe unreachable")
    sent = check_transitions(redis, notifier)
    assert len(sent) == 1 and sent[0].kind == "failure"
    write_snapshot(redis, "internet", "fail", detail="still unreachable")
    assert check_transitions(redis, notifier) == []
    assert len(notifier.sent) == 1


def test_fail_to_ok_clears_marker_and_sends_low_priority_recovery() -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    write_snapshot(redis, "web-self", "fail", detail="connection refused")
    check_transitions(redis, notifier)
    assert redis.get(notified_key("web-self")) == "fail"
    assert len(notifier.sent) == 1

    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    sent = check_transitions(redis, notifier)
    assert len(sent) == 1 and sent[0].kind == "recovery"
    title, message, priority = notifier.sent[1]
    assert "web-self" in title and "recover" in title.lower()
    assert "200 OK" in message
    assert priority == PRIORITY_RECOVERY
    assert priority < PRIORITY_DIGEST < PRIORITY_FAILURE  # clearly low priority
    assert redis.get(notified_key("web-self")) is None  # marker cleared

    # steady ok afterwards: nothing more
    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    assert check_transitions(redis, notifier) == []
    assert len(notifier.sent) == 2


def test_warn_does_not_alert_but_warn_to_fail_does() -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    write_snapshot(redis, "root-disk", "ok", detail="42% used")
    check_transitions(redis, notifier)

    # ok -> warn: no alert, marker tracks warn
    write_snapshot(redis, "root-disk", "warn", detail="85% used")
    assert check_transitions(redis, notifier) == []
    assert notifier.sent == []
    assert redis.get(notified_key("root-disk")) == "warn"

    # warn -> fail: alert (transition into fail from a non-fail state)
    write_snapshot(redis, "root-disk", "fail", detail="95% used")
    sent = check_transitions(redis, notifier)
    assert len(sent) == 1 and sent[0].kind == "failure"
    assert notifier.sent[0][2] == PRIORITY_FAILURE

    # fail -> warn: no recovery (only fail->ok recovers), no alert
    write_snapshot(redis, "root-disk", "warn", detail="85% used")
    assert check_transitions(redis, notifier) == []
    assert len(notifier.sent) == 1

    # warn -> ok: no recovery message either
    write_snapshot(redis, "root-disk", "ok", detail="42% used")
    assert check_transitions(redis, notifier) == []
    assert len(notifier.sent) == 1


def test_only_transitioning_checks_alert() -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    write_snapshot(redis, "root-disk", "ok", detail="42% used")
    check_transitions(redis, notifier)
    assert notifier.sent == []

    write_snapshot(redis, "web-self", "fail", detail="500 Internal Server Error")
    write_snapshot(redis, "root-disk", "ok", detail="43% used")
    sent = check_transitions(redis, notifier)
    assert [t.check for t in sent] == ["web-self"]
    assert len(notifier.sent) == 1
    assert "web-self" in notifier.sent[0][0]
    assert "root-disk" not in notifier.sent[0][0]


def test_notified_marker_key_scheme() -> None:
    assert notified_key("web-self") == f"{NOTIFIED_PREFIX}web-self"
    assert notified_key("web-self").startswith("server_monitor:notified:")


# ---------------------------------------------------------------------------
# Daily digest
# ---------------------------------------------------------------------------


def _quiet_snapshots() -> FakeRedis:
    redis = FakeRedis()
    write_snapshot(redis, "apt", "ok", detail="0 updates pending (0 security)",
                   updates_pending=0, security_updates=0, packages=[])
    write_snapshot(redis, "docker", "ok", detail="0 images outdated",
                   outdated_images=[], outdated_images_count=0, images_checked=5)
    write_snapshot(redis, "web-self", "ok", detail="200 OK", check_type="http")
    return redis


def test_digest_not_sent_when_nothing_needs_attention() -> None:
    redis = _quiet_snapshots()
    notifier = FakeNotifier()
    assert send_digest(redis, notifier) is None
    assert notifier.sent == []
    assert build_digest({}) is None


def test_digest_sent_once_with_counts_when_updates_pending() -> None:
    redis = FakeRedis()
    write_snapshot(redis, "apt", "ok", detail="5 updates pending (2 security)",
                   updates_pending=5, security_updates=2, packages=[])
    write_snapshot(redis, "docker", "ok", detail="0 images outdated",
                   outdated_images=[], outdated_images_count=0)
    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    notifier = FakeNotifier()
    digest = send_digest(redis, notifier)
    assert digest is not None
    assert len(notifier.sent) == 1  # exactly one message
    title, message, priority = notifier.sent[0]
    assert priority == PRIORITY_DIGEST
    assert "digest" in title.lower()
    assert "5 apt updates pending (2 security)" in message


def test_digest_lists_outdated_docker_images() -> None:
    redis = FakeRedis()
    write_snapshot(redis, "docker", "ok", detail="2 images outdated",
                   outdated_images=[
                       {"image": "ghcr.io/a/b:1", "local_digest": "sha256:aaa",
                        "remote_digest": "sha256:bbb"},
                       {"image": "redis:7", "local_digest": "sha256:ccc",
                        "remote_digest": "sha256:ddd"},
                   ],
                   outdated_images_count=2)
    notifier = FakeNotifier()
    digest = send_digest(redis, notifier)
    assert digest is not None
    assert len(notifier.sent) == 1
    _, message, priority = notifier.sent[0]
    assert priority == PRIORITY_DIGEST
    assert "2 outdated docker images" in message
    assert "ghcr.io/a/b:1" in message and "redis:7" in message


def test_digest_includes_failing_and_warn_checks() -> None:
    redis = FakeRedis()
    write_snapshot(redis, "web-self", "fail", detail="connection refused",
                   check_type="http")
    write_snapshot(redis, "root-disk", "warn", detail="85% used", check_type="disk")
    notifier = FakeNotifier()
    digest = send_digest(redis, notifier)
    assert digest is not None
    _, message, _ = notifier.sent[0]
    assert "check web-self: fail" in message
    assert "connection refused" in message
    assert "check root-disk: warn" in message
    assert "85% used" in message


def test_digest_is_one_message_when_several_things_need_attention() -> None:
    redis = FakeRedis()
    write_snapshot(redis, "apt", "ok", detail="3 updates pending (1 security)",
                   updates_pending=3, security_updates=1, packages=[])
    write_snapshot(redis, "docker", "ok", detail="1 images outdated",
                   outdated_images=[{"image": "redis:7"}], outdated_images_count=1)
    write_snapshot(redis, "web-self", "fail", detail="500", check_type="http")
    notifier = FakeNotifier()
    digest = send_digest(redis, notifier)
    assert digest is not None
    assert len(notifier.sent) == 1  # still exactly one message
    _, message, priority = notifier.sent[0]
    assert priority == PRIORITY_DIGEST
    assert "3 apt updates pending (1 security)" in message
    assert "1 outdated docker images: redis:7" in message
    assert "check web-self: fail" in message


def test_digest_handles_docker_count_int_snapshot() -> None:
    redis = FakeRedis()
    write_snapshot(redis, "docker", "ok", detail="2 images outdated",
                   outdated_images=2)  # older/int snapshot shape
    notifier = FakeNotifier()
    assert send_digest(redis, notifier) is not None
    assert "2 outdated docker images" in notifier.sent[0][1]


# ---------------------------------------------------------------------------
# Celery task wiring + beat schedule
# ---------------------------------------------------------------------------


def test_tasks_are_registered_with_celery() -> None:
    assert "server_monitor.tasks.check_healthcheck_transitions" in celery_app.tasks
    assert "server_monitor.tasks.send_daily_digest" in celery_app.tasks


def test_transition_task_reads_redis_and_sends_via_notifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis = FakeRedis()
    notifier = FakeNotifier()
    monkeypatch.setattr(tasks, "get_redis", lambda: redis)
    monkeypatch.setattr(notify, "get_notifier", lambda: notifier)
    write_snapshot(redis, "web-self", "ok", detail="200 OK")
    assert tasks.check_healthcheck_transitions() == []
    write_snapshot(redis, "web-self", "fail", detail="connection refused")
    sent = tasks.check_healthcheck_transitions()
    assert len(sent) == 1 and sent[0].kind == "failure"
    assert notifier.sent[0][2] == PRIORITY_FAILURE


def test_digest_task_sends_only_when_something_needs_attention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis = _quiet_snapshots()
    notifier = FakeNotifier()
    monkeypatch.setattr(tasks, "get_redis", lambda: redis)
    monkeypatch.setattr(notify, "get_notifier", lambda: notifier)
    assert tasks.send_daily_digest() is None
    assert notifier.sent == []
    write_snapshot(redis, "apt", "ok", detail="2 updates pending (0 security)",
                   updates_pending=2, security_updates=0, packages=[])
    digest = tasks.send_daily_digest()
    assert digest is not None
    assert len(notifier.sent) == 1
    assert notifier.sent[0][2] == PRIORITY_DIGEST


def test_beat_schedule_has_transition_check_every_30min_right_after_healthchecks() -> None:
    entries = [
        entry
        for entry in celery_app.conf.beat_schedule.values()
        if entry["task"] == "server_monitor.tasks.check_healthcheck_transitions"
    ]
    assert len(entries) == 1
    cron = entries[0]["schedule"]
    assert cron.minute == {1, 31}  # 1 min after the */30 healthchecks run
    assert cron.hour == set(range(24))  # every hour
    assert cron.day_of_week == set(range(7))  # every day


def test_beat_schedule_has_daily_digest_at_0900() -> None:
    entries = [
        entry
        for entry in celery_app.conf.beat_schedule.values()
        if entry["task"] == "server_monitor.tasks.send_daily_digest"
    ]
    assert len(entries) == 1
    cron = entries[0]["schedule"]
    assert cron.hour == {9}
    assert cron.minute == {0}
    assert cron.day_of_week == set(range(7))  # every day
