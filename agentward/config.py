import json
import os
from pathlib import Path
from typing import Any


# ADOP directory configuration.
# Defaults to an ADOP directory located alongside AgentWard.
ADOP_ROOT = Path(
    os.environ.get(
        "ADOP_ROOT",
        str(Path(__file__).resolve().parents[2] / "adop-cyse"),
    )
).resolve()

REPO_ROOT = ADOP_ROOT / "testbed-repo"


# Policy configuration.
POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "policies"
    / "healthcare_policies.json"
)


def _load_policy_config() -> dict[str, Any]:
    # Load and validate the policy configuration.
    with POLICY_PATH.open("r", encoding="utf-8") as file:
        config = json.load(file)

    if not isinstance(config, dict):
        raise ValueError("Policy configuration must be a JSON object.")

    for field in (
        "approved_external_sources",
        "approved_memory_namespaces",
        "restricted_source_directories",
    ):
        values = config.get(field)

        if not isinstance(values, list) or not all(
            isinstance(value, str) and bool(value.strip())
            for value in values
        ):
            raise ValueError(
                f"Invalid or missing policy configuration: {field}"
            )

    dependencies = config.get("approved_dependencies")
    if not isinstance(dependencies, dict) or not all(
        isinstance(name, str)
        and name.strip()
        and isinstance(version, str)
        and version.strip()
        for name, version in dependencies.items()
    ):
        raise ValueError("Invalid approved dependency configuration.")

    thresholds = config.get("tool_usage_thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("Missing tool usage thresholds.")
    for prefix in ("task_calls", "repeated_calls", "failed_retries"):
        medium = thresholds.get(prefix + "_medium")
        high = thresholds.get(prefix + "_high")
        if (
            type(medium) is not int
            or type(high) is not int
            or not 1 <= medium < high
        ):
            raise ValueError(f"Invalid tool usage thresholds: {prefix}")

    return config


POLICY_CONFIG = _load_policy_config()

APPROVED_EXTERNAL_SOURCES = set(
    POLICY_CONFIG["approved_external_sources"]
)

APPROVED_MEMORY_NAMESPACES = set(
    POLICY_CONFIG["approved_memory_namespaces"]
)


def _load_resource_tags() -> dict[Path, dict[str, Any]]:
    # Load the declared resource classifications from ADOP.
    with (REPO_ROOT / "resource-tags.json").open("r", encoding="utf-8") as file:
        config = json.load(file)

    if (
        not isinstance(config, dict)
        or not isinstance(config.get("resources"), list)
    ):
        raise ValueError("Invalid ADOP resource tag map.")

    resources = {}
    for resource in config["resources"]:
        if not isinstance(resource, dict):
            raise ValueError("Invalid resource classification.")

        path = resource.get("path")
        tags = resource.get("tags")
        approval = resource.get("requires_prior_approval")
        actors = resource.get("approved_actors")

        if (
            not isinstance(path, str) or not path.strip()
            or not isinstance(tags, list) or not tags
            or not all(isinstance(tag, str) and tag.strip() for tag in tags)
            or not isinstance(approval, bool)
            or not isinstance(actors, list)
            or not all(isinstance(actor, str) and actor.strip() for actor in actors)
        ):
            raise ValueError("Invalid resource classification fields.")

        resolved = (REPO_ROOT / path).resolve()
        if (
            Path(path).is_absolute()
            or not resolved.is_relative_to(REPO_ROOT.resolve())
        ):
            raise ValueError("Resource tag path must be repository-relative.")
        if resolved in resources:
            raise ValueError("Duplicate resource classification.")
        resources[resolved] = resource

    return resources


RESOURCE_TAGS = _load_resource_tags()


# Restricted source directories are defined by AgentWard policy.
RESTRICTED_SOURCE_DIRECTORIES = []
for directory in POLICY_CONFIG["restricted_source_directories"]:
    resolved = (REPO_ROOT / directory).resolve()
    if (
        Path(directory).is_absolute()
        or not resolved.is_relative_to(REPO_ROOT.resolve())
        or resolved == REPO_ROOT.resolve()
    ):
        raise ValueError("Restricted source directory must be inside the repository.")
    RESTRICTED_SOURCE_DIRECTORIES.append(resolved)
