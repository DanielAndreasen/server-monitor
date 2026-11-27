"""Docker image digest check runner (issue #5).

Lists the images referenced by containers (running *or* stopped) through
the Docker Engine API on the read-only docker socket, and compares each
image's local ``RepoDigests`` against the registry's manifest digest for
its tag (Docker Registry HTTP API v2, manifest-list aware). An image is
outdated when the digests differ or the local digest is missing.

Production wiring (the compose mounts themselves are issue #9's scope; the
paths are noted here so the wiring is discoverable):

    host /var/run/docker.sock  -> /var/run/docker.sock:ro
    host ~/.docker             -> /root/.docker:ro   (registry auth only)

The socket path is configurable via ``DOCKER_SOCK`` (default
``/var/run/docker.sock``); the docker config dir via ``DOCKER_CONFIG``
(default ``~/.docker``).

Two seams are injectable so tests never touch the socket or the network:

- ``DockerAPI``: ``containers(all=True)`` + ``inspect_image(image_id)``.
  The default implementation talks plain HTTP over the unix socket with
  httpx (``httpx.HTTPTransport(uds=...)``), avoiding a docker SDK
  dependency.
- ``RegistryFetcher``: ``(repo, tag, headers) -> manifest digest``. The
  default implementation speaks Registry HTTP API v2 over HTTPS: it
  requests the manifest with an ``Accept`` covering manifest lists /
  OCI indexes *and* single manifests, follows the ``WWW-Authenticate``
  bearer flow on 401 (Docker Hub: ``registry-1.docker.io`` with service
  ``registry.docker.io`` and scope ``repository:<repo>:pull``), and adds
  ``Basic`` auth from the host's ``config.json`` for private registries.

Secrets hygiene (public-repo rule): tokens and Authorization headers are
never logged; error messages carry ``redact_headers`` output only.
"""

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_DOCKER_SOCK = "/var/run/docker.sock"

#: Docker Hub's registry API host and the index name used in config.json.
DOCKER_HUB_API = "registry-1.docker.io"
DOCKER_HUB_ALIASES = {"index.docker.io", "docker.io", "registry-1.docker.io"}

#: Accept header covering manifest lists / OCI indexes and single
#: manifests: registries answer with the list/index digest (what
#: RepoDigests reference) when a list type is acceptable.
MANIFEST_ACCEPT_TYPES = (
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
)
MANIFEST_ACCEPT: dict[str, str] = {"Accept": ", ".join(MANIFEST_ACCEPT_TYPES)}

REDACTED = "<redacted>"


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy of ``headers`` with Authorization values replaced — never log tokens."""
    return {
        key: REDACTED if key.lower() == "authorization" else value
        for key, value in headers.items()
    }


class RegistryError(RuntimeError):
    """Registry lookup failed; the message never contains credentials."""


class DockerAPI(Protocol):
    """The slice of the Docker Engine API the check relies on."""

    def containers(self, all: bool = True) -> list[dict[str, Any]]:
        """Container summaries; ``all=True`` includes stopped containers."""
        ...

    def inspect_image(self, image_id: str) -> dict[str, Any]:
        """``GET /images/<id>/json``: RepoTags, RepoDigests, ..."""
        ...


class UnixSocketDockerClient:
    """Default ``DockerAPI``: Engine API over the unix socket via httpx."""

    def __init__(self, sock_path: str | None = None, timeout: float = 10.0) -> None:
        sock = sock_path or os.environ.get("DOCKER_SOCK", DEFAULT_DOCKER_SOCK)
        transport = httpx.HTTPTransport(uds=sock)
        self._client = httpx.Client(
            transport=transport, timeout=timeout, base_url="http://docker"
        )

    def containers(self, all: bool = True) -> list[dict[str, Any]]:
        response = self._client.get("/containers/json", params={"all": 1 if all else 0})
        response.raise_for_status()
        return response.json()

    def inspect_image(self, image_id: str) -> dict[str, Any]:
        response = self._client.get(f"/images/{image_id}/json")
        response.raise_for_status()
        return response.json()


def default_docker_client() -> DockerAPI:
    """Production seam default: the Engine API on DOCKER_SOCK."""
    return UnixSocketDockerClient()


class HttpResponseLike(Protocol):
    status_code: int
    headers: Mapping[str, str]
    content: bytes

    def json(self) -> Any: ...


class HttpClientLike(Protocol):
    """Minimal GET-only HTTP client (httpx.Client satisfies this)."""

    def get(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponseLike: ...


#: Registry seam: (repository, tag, request headers) -> manifest digest
#: ("sha256:...") for that tag, manifest-list aware.
RegistryFetcher = Callable[[str, str, Mapping[str, str]], str]


def split_repository(image: str) -> tuple[str, str]:
    """Split an image reference into (registry host, repository path).

    ``nginx`` -> (Docker Hub API, ``library/nginx``); ``user/repo`` ->
    (Docker Hub API, ``user/repo``); ``ghcr.io/a/b`` -> (``ghcr.io``,
    ``a/b``); ``localhost:5000/x`` -> (``localhost:5000``, ``x``).
    A first segment containing ``.`` or ``:`` (or ``localhost``) is a
    registry host.
    """
    parts = image.split("/")
    first = parts[0]
    if len(parts) == 1 or (
        "." not in first and ":" not in first and first != "localhost"
    ):
        repository = f"library/{image}" if len(parts) == 1 else image
        return DOCKER_HUB_API, repository
    return first, "/".join(parts[1:])


def split_tag(reference: str) -> tuple[str, str]:
    """Split ``repo:tag``; tag defaults to ``latest``.

    Only a ``:`` after the last ``/`` counts, so registry ports
    (``localhost:5000/repo``) don't confuse the split.
    """
    if ":" in reference.rsplit("/", 1)[-1]:
        repo, tag = reference.rsplit(":", 1)
        return repo, tag
    return reference, "latest"


def parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse ``Bearer realm="...",service="...",scope="..."`` into params."""
    return {
        match.group(1): match.group(2)
        for match in re.finditer(r'(\w+)="([^"]*)"', header)
    }


def load_docker_auth(docker_config_dir: str) -> dict[str, str]:
    """Map normalized registry host -> ``Basic <auth>`` from config.json.

    Reads ``<docker_config_dir>/config.json`` ``auths`` entries. Missing or
    unreadable config yields no auth (public registries need none).
    """
    path = os.path.join(docker_config_dir, "config.json")
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    auths: dict[str, str] = {}
    for registry, entry in (config.get("auths") or {}).items():
        if not isinstance(entry, dict):
            continue
        token = entry.get("auth")
        if not token:
            continue  # credsStore/credHelpers are out of scope
        host = registry.split("://")[-1].rstrip("/").removesuffix("/v1")
        auths[host] = f"Basic {token}"
    return auths


class RegistryV2Client:
    """Default registry seam: Docker Registry HTTP API v2 over HTTPS.

    ``manifest_digest`` requests the manifest for ``repo:tag`` with the
    caller's headers (the check passes the manifest-list-aware ``Accept``),
    adds registry auth from the docker config when present, follows the
    bearer-token flow on 401, and returns the ``Docker-Content-Digest``
    (falling back to hashing the body, which matches for single manifests).
    """

    def __init__(
        self,
        http: HttpClientLike | None = None,
        docker_config_dir: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._http = http if http is not None else httpx.Client(timeout=timeout)
        self._config_dir = docker_config_dir or os.environ.get(
            "DOCKER_CONFIG", os.path.expanduser("~/.docker")
        )

    def manifest_digest(
        self, repo: str, tag: str, headers: Mapping[str, str]
    ) -> str:
        registry, repository = split_repository(repo)
        url = f"https://{registry}/v2/{repository}/manifests/{tag}"
        request_headers = {**headers, **self._auth_headers(registry)}
        response = self._http.get(url, headers=request_headers)
        if response.status_code == 401:
            token = self._bearer_token(response.headers, repository)
            if token:
                request_headers = {
                    **request_headers,
                    "Authorization": f"Bearer {token}",
                }
                response = self._http.get(url, headers=request_headers)
        if response.status_code != 200:
            raise RegistryError(
                f"registry {registry} returned HTTP {response.status_code} for "
                f"{repo}:{tag}; request headers: {redact_headers(request_headers)}"
            )
        digest = response.headers.get("docker-content-digest")
        if digest:
            return digest
        return "sha256:" + hashlib.sha256(response.content).hexdigest()

    def _auth_headers(self, registry: str) -> dict[str, str]:
        """Basic auth for ``registry`` from the docker config, if configured."""
        for host, value in load_docker_auth(self._config_dir).items():
            if registry == host or (
                registry == DOCKER_HUB_API and host in DOCKER_HUB_ALIASES
            ):
                return {"Authorization": value}
        return {}

    def _bearer_token(
        self, headers: Mapping[str, str], repository: str
    ) -> str | None:
        """Fetch a bearer token from the 401's WWW-Authenticate realm."""
        challenge = headers.get("www-authenticate", "")
        params = parse_www_authenticate(challenge)
        realm = params.get("realm")
        if not realm:
            return None
        query = {"scope": params.get("scope") or f"repository:{repository}:pull"}
        if params.get("service"):
            query["service"] = params["service"]
        response = self._http.get(realm, params=query)
        if response.status_code != 200:
            raise RegistryError(
                f"token realm {realm} returned HTTP {response.status_code} for "
                f"scope {query['scope']}"
            )
        data = response.json()
        return data.get("token") or data.get("access_token")


def fetch_manifest_digest(
    repo: str, tag: str, headers: Mapping[str, str]
) -> str:
    """Default ``RegistryFetcher``: one-off Registry API v2 client."""
    return RegistryV2Client().manifest_digest(repo, tag, headers)


@dataclass(frozen=True)
class ImageDigestStatus:
    """One checked image reference and its local vs registry digest."""

    image: str  # repo:tag as tagged locally
    local_digest: str  # RepoDigests entry ("" when missing)
    remote_digest: str  # registry manifest digest for the tag
    outdated: bool  # True when local != remote (including missing local)


@dataclass(frozen=True)
class DockerImagesResult:
    """Result of one docker image digest check run."""

    checked: list[ImageDigestStatus] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # per-image lookup errors

    @property
    def outdated(self) -> list[ImageDigestStatus]:
        return [status for status in self.checked if status.outdated]

    @property
    def outdated_count(self) -> int:
        return len(self.outdated)


def _digest_by_repo(repo_digests: list[str]) -> dict[str, str]:
    """Map ``repo`` -> ``sha256:...`` from RepoDigests entries (``repo@digest``)."""
    digests: dict[str, str] = {}
    for entry in repo_digests:
        if "@" in entry:
            repo, digest = entry.split("@", 1)
            digests.setdefault(repo, digest)
    return digests


def check_docker_images(
    docker: DockerAPI,
    fetch: RegistryFetcher = fetch_manifest_digest,
) -> DockerImagesResult:
    """Check every container-referenced image against its registry digest.

    Only images referenced by containers (running or stopped, via
    ``containers(all=True)``) are inspected — unused local images are
    ignored. Images with no RepoTags (dangling) and ``<none>`` tags are
    skipped. An image is outdated when its local RepoDigest differs from
    the registry's manifest digest for its tag, or is missing entirely.
    Per-image registry lookup failures are collected in ``errors`` and do
    not fail the whole check.
    """
    containers = docker.containers(all=True)
    image_ids = sorted({c["Image"] for c in containers if c.get("Image")})
    checked: list[ImageDigestStatus] = []
    errors: list[str] = []
    seen: set[str] = set()
    for image_id in image_ids:
        info = docker.inspect_image(image_id)
        digests = _digest_by_repo(info.get("RepoDigests") or [])
        for reference in info.get("RepoTags") or []:
            if not reference or reference.startswith("<none>"):
                continue  # dangling image or untagged <none>:<none>
            if reference in seen:
                continue
            seen.add(reference)
            repo, tag = split_tag(reference)
            local_digest = digests.get(repo, "")
            try:
                remote_digest = fetch(repo, tag, MANIFEST_ACCEPT)
            except Exception as exc:
                errors.append(f"{reference}: {exc}")
                continue
            checked.append(
                ImageDigestStatus(
                    image=reference,
                    local_digest=local_digest,
                    remote_digest=remote_digest,
                    outdated=local_digest != remote_digest,
                )
            )
    return DockerImagesResult(checked=checked, errors=errors)
