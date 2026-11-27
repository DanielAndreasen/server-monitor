"""Tests for the production compose override (issue #9).

The dev/CI sandbox has no docker, so these tests validate
``docker-compose.prod.yml`` statically with PyYAML: it must keep every base
service from ``docker-compose.yml`` and add the read-only host mounts and
env vars the worker needs to run checks against the real host on home-server.

Usage on home-server (documented in the README):

    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_COMPOSE = REPO_ROOT / "docker-compose.yml"
PROD_COMPOSE = REPO_ROOT / "docker-compose.prod.yml"

BASE_SERVICES = ("redis", "worker", "beat", "web")

#: Read-only host mounts the worker must get in production (host:container:ro).
REQUIRED_WORKER_MOUNTS = (
    "/var/run/docker.sock:/var/run/docker.sock:ro",
    "/etc/apt:/etc/apt:ro",
    "/var/lib/apt/lists:/var/lib/apt/lists:ro",
    "/var/lib/dpkg:/var/lib/dpkg:ro",
    "/var/run/fail2ban/fail2ban.sock:/var/run/fail2ban/fail2ban.sock:ro",
    "./healthchecks.yaml:/config/healthchecks.yaml:ro",
)

#: Host docker config dir mount: source is parameterized via HOST_DOCKER_CONFIG
#: (defaulting to the host's ~/.docker), target is /root/.docker:ro.
HOST_DOCKER_CONFIG_MOUNT_TARGET = ":/root/.docker:ro"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    assert isinstance(loaded, dict), f"{path.name} must be a compose mapping"
    return loaded


def _env_as_dict(service: dict) -> dict[str, str]:
    """Normalize a compose ``environment`` block (list or mapping) to a dict."""
    env = service.get("environment", {})
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    result: dict[str, str] = {}
    for entry in env or []:
        key, sep, value = str(entry).partition("=")
        result[key] = value if sep else ""
    return result


def test_base_compose_defines_all_services() -> None:
    base = _load(BASE_COMPOSE)
    for service in BASE_SERVICES:
        assert service in base["services"], f"base compose lost service {service!r}"


def test_prod_override_only_customizes_existing_base_services() -> None:
    base = _load(BASE_COMPOSE)
    prod = _load(PROD_COMPOSE)
    # merge semantics: the override may only touch services the base defines
    assert set(prod["services"]) <= set(base["services"])
    assert "worker" in prod["services"]


def test_worker_has_all_required_read_only_host_mounts() -> None:
    prod = _load(PROD_COMPOSE)
    volumes = prod["services"]["worker"].get("volumes", [])
    for mount in REQUIRED_WORKER_MOUNTS:
        assert mount in volumes, f"worker missing mount {mount!r}"
    # every mount must be read-only
    assert volumes, "worker must declare volumes"
    for mount in volumes:
        assert str(mount).endswith(":ro"), f"mount not read-only: {mount!r}"


def test_worker_mounts_host_docker_config_read_only() -> None:
    prod = _load(PROD_COMPOSE)
    volumes = [str(v) for v in prod["services"]["worker"].get("volumes", [])]
    docker_config_mounts = [
        v for v in volumes if v.endswith(HOST_DOCKER_CONFIG_MOUNT_TARGET)
    ]
    assert len(docker_config_mounts) == 1, (
        f"expected exactly one host docker-config mount ending in "
        f"{HOST_DOCKER_CONFIG_MOUNT_TARGET!r}, got {docker_config_mounts!r}"
    )
    source = docker_config_mounts[0][: -len(HOST_DOCKER_CONFIG_MOUNT_TARGET)]
    # parameterized via HOST_DOCKER_CONFIG, defaulting to the host's ~/.docker
    assert source.startswith("${HOST_DOCKER_CONFIG")
    assert "$HOME/.docker" in source or "~/.docker" in source


def test_worker_environment_points_at_the_mounts() -> None:
    prod = _load(PROD_COMPOSE)
    env = _env_as_dict(prod["services"]["worker"])
    assert env["DOCKER_SOCK"] == "/var/run/docker.sock"
    assert env["HEALTHCHECKS_CONFIG"] == "/config/healthchecks.yaml"
    assert "TZ" in env, "worker needs TZ so beat schedules are local"


def test_worker_and_beat_set_tz_with_utc_default() -> None:
    prod = _load(PROD_COMPOSE)
    for service in ("worker", "beat"):
        env = _env_as_dict(prod["services"][service])
        assert env.get("TZ") == "${TZ:-UTC}", (
            f"{service} must set TZ with a UTC fallback, got {env.get('TZ')!r}"
        )


def test_prod_override_does_not_change_base_service_images_or_commands() -> None:
    """The override is mount/env-only; images/commands stay in the base file."""
    base = _load(BASE_COMPOSE)
    prod = _load(PROD_COMPOSE)
    for service, spec in prod["services"].items():
        for key in ("image", "build", "command", "ports", "depends_on"):
            assert key not in spec, (
                f"prod override should not redefine {key!r} of {service!r}"
            )
        assert service in base["services"]
