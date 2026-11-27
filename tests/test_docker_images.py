"""Tests for the docker image digest check (issue #5): the check runner
over fake Docker API / registry seams, the default Registry API v2 client
(fake HTTP: token flow, private-registry auth, redaction), the snapshot
written to FakeRedis, web/metrics rendering, and the Beat schedule entry."""

import base64
import hashlib
import json

import pytest

from server_monitor.celery_app import app as celery_app
from server_monitor.checks.docker_images import (
    DOCKER_HUB_API,
    MANIFEST_ACCEPT,
    RegistryError,
    RegistryV2Client,
    check_docker_images,
    load_docker_auth,
    parse_www_authenticate,
    redact_headers,
    split_repository,
    split_tag,
)
from server_monitor.store import read_snapshot, write_snapshot
from server_monitor.tasks import run_docker_images_check, run_docker_images_snapshot
from tests.conftest import FakeRedis

LOCAL_NGINX = "sha256:" + "a" * 64
REMOTE_NGINX = "sha256:" + "b" * 64
LOCAL_APP = "sha256:" + "c" * 64
REMOTE_REDIS = "sha256:" + "d" * 64


class FakeDocker:
    """Fake Docker API seam: containers(all=True) + inspect_image(id)."""

    def __init__(
        self,
        containers: list[dict],
        images: dict[str, dict],
    ) -> None:
        self._containers = containers
        self._images = images
        self.containers_calls: list[bool] = []
        self.inspected: list[str] = []

    def containers(self, all: bool = True) -> list[dict]:
        self.containers_calls.append(all)
        return self._containers

    def inspect_image(self, image_id: str) -> dict:
        self.inspected.append(image_id)
        return self._images[image_id]


class FakeRegistry:
    """Fake registry seam: (repo, tag, headers) -> digest, recording calls."""

    def __init__(self, digests: dict[tuple[str, str], str]) -> None:
        self.digests = digests
        self.calls: list[tuple[str, str, dict]] = []

    def __call__(self, repo: str, tag: str, headers) -> str:
        self.calls.append((repo, tag, dict(headers)))
        return self.digests[(repo, tag)]


def make_docker() -> FakeDocker:
    return FakeDocker(
        containers=[
            {"Id": "c1", "Image": "sha256:aaa", "State": "running"},
            {"Id": "c2", "Image": "sha256:bbb", "State": "exited"},  # stopped
            {"Id": "c3", "Image": "sha256:ddd", "State": "running"},  # dangling
            {"Id": "c4", "Image": "sha256:eee", "State": "running"},  # <none>
            {"Id": "c5", "Image": "sha256:fff", "State": "running"},  # no digest
        ],
        images={
            "sha256:aaa": {
                "RepoTags": ["nginx:1.27"],
                "RepoDigests": [f"nginx@{LOCAL_NGINX}"],
            },
            "sha256:bbb": {
                "RepoTags": ["ghcr.io/foo/bar:v2"],
                "RepoDigests": [f"ghcr.io/foo/bar@{LOCAL_APP}"],
            },
            "sha256:ddd": {"RepoTags": [], "RepoDigests": []},  # dangling
            "sha256:eee": {"RepoTags": ["<none>:<none>"], "RepoDigests": []},
            "sha256:fff": {"RepoTags": ["redis:7"], "RepoDigests": []},
            # unused image, referenced by no container: must never be inspected
            "sha256:ccc": {
                "RepoTags": ["unused:latest"],
                "RepoDigests": [f"unused@{LOCAL_NGINX}"],
            },
        },
    )


def make_registry() -> FakeRegistry:
    return FakeRegistry(
        {
            ("nginx", "1.27"): REMOTE_NGINX,  # differs from local -> outdated
            ("ghcr.io/foo/bar", "v2"): LOCAL_APP,  # equal -> up to date
            ("redis", "7"): REMOTE_REDIS,  # local digest missing -> outdated
        }
    )


def test_split_repository() -> None:
    assert split_repository("nginx") == (DOCKER_HUB_API, "library/nginx")
    assert split_repository("user/repo") == (DOCKER_HUB_API, "user/repo")
    assert split_repository("ghcr.io/a/b") == ("ghcr.io", "a/b")
    assert split_repository("localhost:5000/x") == ("localhost:5000", "x")
    assert split_repository("registry.example.com:443/t/app") == (
        "registry.example.com:443",
        "t/app",
    )


def test_split_tag() -> None:
    assert split_tag("nginx:1.27") == ("nginx", "1.27")
    assert split_tag("nginx") == ("nginx", "latest")
    assert split_tag("localhost:5000/repo") == ("localhost:5000/repo", "latest")
    assert split_tag("localhost:5000/repo:v1") == ("localhost:5000/repo", "v1")


def test_parse_www_authenticate() -> None:
    params = parse_www_authenticate(
        'Bearer realm="https://auth.docker.io/token",'
        'service="registry.docker.io",scope="repository:library/nginx:pull"'
    )
    assert params == {
        "realm": "https://auth.docker.io/token",
        "service": "registry.docker.io",
        "scope": "repository:library/nginx:pull",
    }


def test_redact_headers_hides_authorization() -> None:
    headers = {"Accept": "x", "Authorization": "Bearer sekrit-token"}
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "<redacted>"
    assert "sekrit-token" not in str(redacted)
    assert redacted["Accept"] == "x"


def test_check_compares_digests_and_flags_outdated_missing_and_equal() -> None:
    result = check_docker_images(make_docker(), make_registry())
    by_image = {status.image: status for status in result.checked}
    assert set(by_image) == {"nginx:1.27", "ghcr.io/foo/bar:v2", "redis:7"}
    assert by_image["nginx:1.27"].outdated is True  # local != remote
    assert by_image["nginx:1.27"].local_digest == LOCAL_NGINX
    assert by_image["nginx:1.27"].remote_digest == REMOTE_NGINX
    assert by_image["ghcr.io/foo/bar:v2"].outdated is False  # digests equal
    assert by_image["redis:7"].outdated is True  # local digest missing
    assert by_image["redis:7"].local_digest == ""
    assert result.outdated_count == 2
    assert {s.image for s in result.outdated} == {"nginx:1.27", "redis:7"}
    assert result.errors == []


def test_check_uses_all_containers_and_skips_dangling_and_none() -> None:
    docker = make_docker()
    result = check_docker_images(docker, make_registry())
    assert docker.containers_calls == [True]  # running + stopped containers
    # every container-referenced image inspected, the unused one never
    assert sorted(docker.inspected) == [
        "sha256:aaa",
        "sha256:bbb",
        "sha256:ddd",
        "sha256:eee",
        "sha256:fff",
    ]
    assert "sha256:ccc" not in docker.inspected
    # dangling (no RepoTags) and <none> skipped: not in checked
    assert all(not s.image.startswith("<none>") for s in result.checked)
    assert len(result.checked) == 3


def test_check_requests_manifest_list_aware_accept_header() -> None:
    registry = make_registry()
    check_docker_images(make_docker(), registry)
    assert registry.calls, "registry seam must be called per image"
    for repo, tag, headers in registry.calls:
        accept = headers["Accept"]
        assert "application/vnd.docker.distribution.manifest.list.v2+json" in accept
        assert "application/vnd.oci.image.index.v1+json" in accept
        assert "application/vnd.docker.distribution.manifest.v2+json" in accept
        assert "application/vnd.oci.image.manifest.v1+json" in accept
    assert ("nginx", "1.27") in [(r, t) for r, t, _ in registry.calls]


def test_check_collects_per_image_registry_errors_without_failing() -> None:
    def fetch(repo: str, tag: str, headers) -> str:
        if repo == "redis":
            raise RegistryError("registry returned HTTP 500")
        return {("nginx", "1.27"): REMOTE_NGINX, ("ghcr.io/foo/bar", "v2"): LOCAL_APP}[
            (repo, tag)
        ]

    result = check_docker_images(make_docker(), fetch)
    assert result.outdated_count == 1  # only nginx
    assert len(result.errors) == 1
    assert "redis:7" in result.errors[0]
    assert "HTTP 500" in result.errors[0]


def test_run_docker_images_snapshot_writes_snapshot_to_fake_redis(
    fake_redis: FakeRedis,
) -> None:
    snapshot = run_docker_images_snapshot(fake_redis, make_docker(), make_registry())
    assert snapshot["check"] == "docker"
    assert snapshot["status"] == "ok"
    assert snapshot["detail"] == "2 images outdated"
    assert snapshot["outdated_images"] == [
        {
            "image": "nginx:1.27",
            "local_digest": LOCAL_NGINX,
            "remote_digest": REMOTE_NGINX,
        },
        {
            "image": "redis:7",
            "local_digest": "",
            "remote_digest": REMOTE_REDIS,
        },
    ]
    assert snapshot["outdated_images_count"] == 2
    assert snapshot["images_checked"] == 3
    assert snapshot["errors"] == []
    assert isinstance(snapshot["last_run"], float)
    # persisted under the store's key scheme and readable back
    assert read_snapshot(fake_redis, "docker") == snapshot
    assert fake_redis.get("server_monitor:snapshot:docker") is not None


def test_run_docker_images_snapshot_docker_failure_writes_fail_snapshot(
    fake_redis: FakeRedis,
) -> None:
    class BrokenDocker:
        def containers(self, all: bool = True) -> list[dict]:
            raise OSError("cannot connect to /var/run/docker.sock")

        def inspect_image(self, image_id: str) -> dict:
            raise OSError("unreachable")

    snapshot = run_docker_images_snapshot(fake_redis, BrokenDocker(), make_registry())
    assert snapshot["check"] == "docker"
    assert snapshot["status"] == "fail"
    assert "docker images check failed" in snapshot["detail"]
    assert "docker.sock" in snapshot["detail"]
    assert read_snapshot(fake_redis, "docker") == snapshot


def test_celery_task_registered_on_app() -> None:
    assert "server_monitor.tasks.run_docker_images_check" in celery_app.tasks


def test_celery_task_writes_snapshot_via_injected_seams(
    monkeypatch, fake_redis: FakeRedis
) -> None:
    monkeypatch.setattr("server_monitor.tasks.get_redis", lambda: fake_redis)
    monkeypatch.setattr(
        "server_monitor.tasks.default_docker_client", make_docker
    )
    monkeypatch.setattr(
        "server_monitor.tasks.fetch_manifest_digest", make_registry()
    )
    snapshot = run_docker_images_check()  # task body runs synchronously when called
    assert snapshot["check"] == "docker"
    assert snapshot["status"] == "ok"
    assert snapshot["outdated_images_count"] == 2
    assert read_snapshot(fake_redis, "docker") == snapshot


def test_beat_schedule_has_docker_images_check_every_6h() -> None:
    entries = [
        entry
        for entry in celery_app.conf.beat_schedule.values()
        if entry["task"] == "server_monitor.tasks.run_docker_images_check"
    ]
    assert len(entries) == 1
    cron = entries[0]["schedule"]
    assert cron.minute == {0}
    assert cron.hour == {0, 6, 12, 18}
    assert cron.day_of_week == set(range(7))  # every day


def test_metrics_and_status_page_reflect_outdated_images_list(
    client, fake_redis: FakeRedis
) -> None:
    write_snapshot(
        fake_redis,
        "docker",
        "ok",
        detail="1 images outdated",
        last_run=1000.0,
        outdated_images=[
            {
                "image": "nginx:1.27",
                "local_digest": LOCAL_NGINX,
                "remote_digest": REMOTE_NGINX,
            }
        ],
        outdated_images_count=1,
    )
    body = client.get("/metrics").text
    assert "server_monitor_docker_images_outdated 1.0" in body
    assert 'server_monitor_check_up{check="docker"} 1.0' in body
    page = client.get("/").text
    assert "<strong>1</strong>" in page  # summary count from the list length
    assert "Outdated Docker images" in page
    assert "nginx:1.27" in page
    assert "sha256:aaaaaaaaaaaa" in page  # shortened local digest
    assert "sha256:bbbbbbbbbbbb" in page  # shortened registry digest


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        headers: dict | None = None,
        json_data=None,
        content: bytes = b"",
    ) -> None:
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._json_data = json_data
        self.content = content

    def json(self):
        return self._json_data


class FakeHttp:
    """Fake GET-only HTTP client returning queued responses, recording requests."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    def get(self, url: str, headers=None, params=None) -> FakeResponse:
        self.requests.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected request: {url}")
        return self.responses.pop(0)


HUB_CHALLENGE = (
    'Bearer realm="https://auth.docker.io/token",'
    'service="registry.docker.io",scope="repository:library/nginx:pull"'
)


def test_registry_client_docker_hub_token_flow_401_realm_retry() -> None:
    http = FakeHttp(
        FakeResponse(401, headers={"WWW-Authenticate": HUB_CHALLENGE}),
        FakeResponse(200, json_data={"token": "hub-token-123"}),
        FakeResponse(
            200, headers={"Docker-Content-Digest": REMOTE_NGINX}, content=b"manifest"
        ),
    )
    registry = RegistryV2Client(http=http, docker_config_dir="/nonexistent")
    digest = registry.manifest_digest("nginx", "latest", MANIFEST_ACCEPT)
    assert digest == REMOTE_NGINX
    # first request: Docker Hub API, library/ path, manifest-list Accept, no auth
    first = http.requests[0]
    assert first["url"] == (
        f"https://{DOCKER_HUB_API}/v2/library/nginx/manifests/latest"
    )
    assert "Authorization" not in first["headers"]
    accept = first["headers"]["Accept"]
    assert "manifest.list.v2+json" in accept and "oci.image.index.v1+json" in accept
    # token request: realm URL with service + scope query params
    token_request = http.requests[1]
    assert token_request["url"] == "https://auth.docker.io/token"
    assert token_request["params"] == {
        "service": "registry.docker.io",
        "scope": "repository:library/nginx:pull",
    }
    # retry: same manifest URL with the bearer token
    retry = http.requests[2]
    assert retry["url"] == first["url"]
    assert retry["headers"]["Authorization"] == "Bearer hub-token-123"


def test_registry_client_uses_docker_content_digest_and_hashes_fallback() -> None:
    http = FakeHttp(
        FakeResponse(200, headers={"Docker-Content-Digest": "sha256:aaa"}, content=b"x")
    )
    registry = RegistryV2Client(http=http, docker_config_dir="/nonexistent")
    assert registry.manifest_digest("ghcr.io/a/b", "v1", MANIFEST_ACCEPT) == "sha256:aaa"
    assert http.requests[0]["url"] == "https://ghcr.io/v2/a/b/manifests/v1"

    body = b"single-manifest-body"
    http2 = FakeHttp(FakeResponse(200, content=body))
    registry2 = RegistryV2Client(http=http2, docker_config_dir="/nonexistent")
    assert registry2.manifest_digest("ghcr.io/a/b", "v1", MANIFEST_ACCEPT) == (
        "sha256:" + hashlib.sha256(body).hexdigest()
    )


def test_registry_client_private_registry_basic_auth_from_config(tmp_path) -> None:
    token = base64.b64encode(b"user:pass").decode()
    (tmp_path / "config.json").write_text(
        json.dumps({"auths": {"registry.example.com": {"auth": token}}})
    )
    http = FakeHttp(
        FakeResponse(200, headers={"Docker-Content-Digest": "sha256:priv"})
    )
    registry = RegistryV2Client(http=http, docker_config_dir=str(tmp_path))
    digest = registry.manifest_digest(
        "registry.example.com/team/app", "v1", MANIFEST_ACCEPT
    )
    assert digest == "sha256:priv"
    request = http.requests[0]
    assert request["url"] == "https://registry.example.com/v2/team/app/manifests/v1"
    assert request["headers"]["Authorization"] == f"Basic {token}"


def test_registry_client_docker_hub_config_key_normalized(tmp_path) -> None:
    token = base64.b64encode(b"hub:cred").decode()
    (tmp_path / "config.json").write_text(
        json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": token}}})
    )
    http = FakeHttp(
        FakeResponse(200, headers={"Docker-Content-Digest": "sha256:hub"})
    )
    registry = RegistryV2Client(http=http, docker_config_dir=str(tmp_path))
    registry.manifest_digest("nginx", "latest", MANIFEST_ACCEPT)
    assert http.requests[0]["headers"]["Authorization"] == f"Basic {token}"


def test_load_docker_auth_missing_or_broken_config_yields_nothing(tmp_path) -> None:
    assert load_docker_auth(str(tmp_path)) == {}
    (tmp_path / "config.json").write_text("{not json")
    assert load_docker_auth(str(tmp_path)) == {}
    (tmp_path / "config.json").write_text(json.dumps({"auths": {}}))
    assert load_docker_auth(str(tmp_path)) == {}


def test_registry_error_never_leaks_credentials(tmp_path) -> None:
    token = base64.b64encode(b"user:pass").decode()
    (tmp_path / "config.json").write_text(
        json.dumps({"auths": {"registry.example.com": {"auth": token}}})
    )
    # 403 with Basic auth configured: error must redact the Authorization header
    http = FakeHttp(FakeResponse(403))
    registry = RegistryV2Client(http=http, docker_config_dir=str(tmp_path))
    with pytest.raises(RegistryError) as excinfo:
        registry.manifest_digest("registry.example.com/a/b", "v1", MANIFEST_ACCEPT)
    message = str(excinfo.value)
    assert token not in message
    assert "<redacted>" in message

    # bearer token from a 401 flow must not leak into error messages either
    http2 = FakeHttp(
        FakeResponse(401, headers={"WWW-Authenticate": HUB_CHALLENGE}),
        FakeResponse(200, json_data={"token": "sekrit-token"}),
        FakeResponse(401, headers={"WWW-Authenticate": HUB_CHALLENGE}),
    )
    registry2 = RegistryV2Client(http=http2, docker_config_dir="/nonexistent")
    with pytest.raises(RegistryError) as excinfo2:
        registry2.manifest_digest("nginx", "latest", MANIFEST_ACCEPT)
    message2 = str(excinfo2.value)
    assert "sekrit-token" not in message2
    assert "<redacted>" in message2
