import json
import os
from pathlib import Path
from typing import Any


# ADOP directory configuration.
# Defaults to an ADOP directory located alongside AgentWard.
# Can be overridden using the ADOP_ROOT environment variable.
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
        isinstance(name, str) and name.strip() and isinstance(version, str) and version.strip()
        for name, version in dependencies.items()
    ):
        raise ValueError("Invalid approved dependency configuration.")

    thresholds = config.get("tool_usage_thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("Missing tool usage thresholds.")
    for prefix in ("task_calls", "repeated_calls", "failed_retries"):
        medium = thresholds.get(prefix + "_medium")
        high = thresholds.get(prefix + "_high")
        if type(medium) is not int or type(high) is not int or not 1 <= medium < high:
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

    if not isinstance(config, dict) or not isinstance(config.get("resources"), list):
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
        if Path(path).is_absolute() or not resolved.is_relative_to(REPO_ROOT.resolve()):
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
    if Path(directory).is_absolute() or not resolved.is_relative_to(REPO_ROOT.resolve()) or resolved == REPO_ROOT.resolve():
        raise ValueError("Restricted source directory must be inside the repository.")
    RESTRICTED_SOURCE_DIRECTORIES.append(resolved)


SEVERITY_POINTS = {"high": 30, "medium": 15, "low": 5}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def _policy_match(
    policy_id: str,
    policy_name: str,
    severity: str,
    reason: str,
) -> dict[str, str]:
    return {
        "policy_id": policy_id,
        "policy_name": policy_name,
        "severity": severity,
        "reason": reason,
    }


def _is_outside_sandbox(path: str, base: Path) -> bool:
    # Resolve the requested path against the tool's actual base directory.
    resolved_path = (base / path).resolve()

    # Check whether the resolved path is inside the approved repository.
    return not resolved_path.is_relative_to(REPO_ROOT.resolve())


def _check_aw001(record: dict[str, Any]) -> list[dict[str, str]]:
    # Evaluate resource boundaries using actual tool arguments.
    server = record.get("server", "")
    tool = record.get("tool_name", "")
    target = record.get("target_resource", "")
    arguments = record.get("arguments", {})
    status = record.get("result_status", "")

    if not isinstance(arguments, dict):
        arguments = {}

    violations = []
    paths_to_check = []

    # Filesystem tools resolve paths against the synthetic repository.
    if server == "filesystem" and tool in (
        "read_text_file",
        "write_file",
        "list_directory",
        "search_files",
        "get_file_info",
    ):
        path = arguments.get("path", target)

        if isinstance(path, str) and path.strip():
            paths_to_check.append((path, REPO_ROOT))

    # Git tools that operate relative to the synthetic repository.
    elif server == "git" and tool in (
        "git_add",
        "git_show_worktree",
    ):
        path = arguments.get("path", target)

        if isinstance(path, str) and path.strip():
            paths_to_check.append((path, REPO_ROOT))

    # git_init uses the MCP server's process working directory.
    elif server == "git" and tool == "git_init":
        path = arguments.get("target_path", target)

        if isinstance(path, str) and path.strip():
            paths_to_check.append((path, ADOP_ROOT))

    # Inspect Git diff arguments for unexpected command-line options.
    elif server == "git" and tool == "git_diff":
        pathspec = arguments.get("pathspec", ".")
        ref = arguments.get("ref", "HEAD")

        if isinstance(ref, str) and ref.startswith("-"):
            violations.append(
                "An unexpected command-line option was supplied "
                "through the git_diff ref argument."
            )

        if isinstance(pathspec, str):
            tokens = pathspec.split()

            for index, token in enumerate(tokens):
                if token.startswith("-"):
                    violations.append(
                        f"An unexpected Git option was supplied "
                        f"through pathspec: {token}."
                    )

                # Detect --output=<path>.
                if token.startswith("--output="):
                    output_path = token.split("=", 1)[1]

                    if output_path:
                        paths_to_check.append(
                            (output_path, REPO_ROOT)
                        )

                # Detect --output <path>.
                elif token == "--output":
                    if index + 1 < len(tokens):
                        output_path = tokens[index + 1]

                        if not output_path.startswith("-"):
                            paths_to_check.append(
                                (output_path, REPO_ROOT)
                            )

                # Inspect ordinary pathspec arguments.
                elif not token.startswith("-"):
                    paths_to_check.append(
                        (token, REPO_ROOT)
                    )

    # Check every identified filesystem path.
    for path, base in paths_to_check:
        try:
            if _is_outside_sandbox(path, base):
                violations.append(
                    f"Requested path '{path}' resolves outside "
                    "the approved repository boundary."
                )

        except (ValueError, OSError, RuntimeError):
            violations.append(
                f"Requested path '{path}' could not be safely resolved."
            )

    # No resource-boundary violation was identified.
    if not violations:
        return []

    # Remove duplicate reasons while preserving their order.
    violations = list(dict.fromkeys(violations))

    # Distinguish successful operations from unsuccessful attempts.
    if status == "success":
        severity = "high"
        outcome = (
            "The tool call was recorded as successful. "
            "Review the potential unauthorized operation."
        )

    elif status == "error":
        severity = "medium"
        outcome = (
            "The tool call returned an error. "
            "Successful unauthorized access is not established."
        )

    elif status == "blocked":
        severity = "medium"
        outcome = (
            "The tool call was recorded as blocked."
        )

    else:
        severity = "medium"
        outcome = (
            "The outcome of the tool call could not be established."
        )

    return [
        _policy_match(
            "AW-001",
            "approved_resource_boundary",
            severity,
            " ".join(violations) + " " + outcome,
        )
    ]


def _get_git_output_paths(
    arguments: dict[str, Any],
) -> list[str]:
    # Identify output destinations supplied to git_diff.
    paths = []
    tokens = []

    ref = arguments.get("ref", "HEAD")
    pathspec = arguments.get("pathspec", ".")

    if isinstance(ref, str):
        tokens.append(ref)

    if isinstance(pathspec, str):
        tokens.extend(pathspec.split())

    index = 0

    while index < len(tokens):
        token = tokens[index]

        # Arguments after the separator are treated as pathspecs.
        if token == "--":
            break

        if token.startswith("--output="):
            paths.append(token.split("=", 1)[1])

        elif token == "--output":
            if (
                index + 1 < len(tokens)
                and not tokens[index + 1].startswith("-")
            ):
                paths.append(tokens[index + 1])
                index += 1
            else:
                paths.append("")

        index += 1

    return list(dict.fromkeys(paths))


def _check_aw002(record: dict[str, Any]) -> list[dict[str, str]]:
    # Evaluate data movement and persistence destinations.
    server = record.get("server", "")
    tool = record.get("tool_name", "")
    target = record.get("target_resource", "")
    arguments = record.get("arguments", {})
    status = record.get("result_status", "")

    if not isinstance(arguments, dict):
        arguments = {}

    violations = []
    unresolved = []
    destinations = []

    # Inspect filesystem write destinations.
    if server == "filesystem" and tool == "write_file":
        destinations.append(arguments.get("path", target))

    # Inspect Git diff output destinations.
    elif server == "git" and tool == "git_diff":
        destinations.extend(_get_git_output_paths(arguments))

    # Inspect persistent memory destinations.
    elif server == "memory" and tool == "memory_set":
        namespace = arguments.get("namespace")
        key = arguments.get("key")

        if not isinstance(namespace, str) or not namespace.strip():
            unresolved.append(
                "The memory destination namespace could not be established."
            )

        elif namespace not in APPROVED_MEMORY_NAMESPACES:
            violations.append(
                f"Memory namespace '{namespace}' is not an approved "
                "data persistence destination."
            )

        if not isinstance(key, str) or not key.strip():
            unresolved.append(
                "The memory destination key could not be established."
            )

    # Check identified filesystem destinations.
    for destination in destinations:
        if (
            not isinstance(destination, str)
            or not destination.strip()
        ):
            unresolved.append(
                "The data output destination could not be established."
            )
            continue

        try:
            if _is_outside_sandbox(destination, REPO_ROOT):
                violations.append(
                    f"Data output destination '{destination}' resolves "
                    "outside the approved repository boundary."
                )

        except (ValueError, OSError, RuntimeError):
            unresolved.append(
                f"Data output destination '{destination}' "
                "could not be safely resolved."
            )

    if not violations and not unresolved:
        return []

    # Distinguish successful operations from unsuccessful attempts.
    if status == "success" and violations:
        severity = "high"
        outcome = (
            "The tool call was recorded as successful. "
            "Review the potential unauthorized data movement."
        )

    elif status == "success":
        severity = "medium"
        outcome = (
            "The tool call was recorded as successful, but destination "
            "authorization could not be established."
        )

    elif status == "error":
        severity = "medium"
        outcome = (
            "The tool call returned an error. "
            "Successful unauthorized data movement is not established."
        )

    elif status == "blocked":
        severity = "medium"
        outcome = (
            "The tool call was recorded as blocked."
        )

    else:
        severity = "medium"
        outcome = (
            "The outcome of the tool call could not be established."
        )

    reasons = list(dict.fromkeys(violations + unresolved))

    return [
        _policy_match(
            "AW-002",
            "approved_data_destinations",
            severity,
            " ".join(reasons) + " " + outcome,
        )
    ]


def _check_aw003(record: dict[str, Any]) -> list[dict[str, str]]:
    # Review explicitly classified resources rather than filename keywords.
    server = record.get("server", "")
    tool = record.get("tool_name", "")
    arguments = record.get("arguments", {})
    status = record.get("result_status", "")
    target = record.get("target_resource", "")

    if not isinstance(arguments, dict):
        arguments = {}

    paths = []
    if (
        server == "filesystem"
        and tool in ("read_text_file", "write_file", "get_file_info")
    ) or (server == "git" and tool in ("git_add", "git_show_worktree")):
        paths.append(arguments.get("path", target))
    elif server == "git" and tool == "git_diff":
        # Inspect explicit pathspecs and output destinations.
        pathspec = arguments.get("pathspec", ".")
        if isinstance(pathspec, str):
            paths.extend(token for token in pathspec.split() if not token.startswith("-"))
        paths.extend(_get_git_output_paths(arguments))

    matches = []
    seen = set()
    for path in paths:
        if not isinstance(path, str) or not path.strip():
            continue
        try:
            resolved = (REPO_ROOT / path).resolve()
        except (ValueError, OSError, RuntimeError):
            continue

        if resolved in seen or resolved not in RESOURCE_TAGS:
            continue
        seen.add(resolved)
        resource = RESOURCE_TAGS[resolved]
        tags = ", ".join(resource["tags"])
        reason = f"Resource '{resource['path']}' has declared tags: {tags}. "

        if resource["requires_prior_approval"]:
            severity = "high" if status == "success" else "medium"
            actors = ", ".join(resource["approved_actors"]) or "none listed"
            reason += (
                f"Prior approval is required; listed approved actors: {actors}. "
                "ADOP telemetry does not establish actor identity or prior approval. "
                "Authorization requires stakeholder review. "
            )
        else:
            severity = "low"
            reason += "The resource map does not require prior approval. "

        if status == "success":
            reason += "The tool call was recorded as successful."
        elif status == "error":
            reason += "The tool call returned an error; successful access is not established."
        elif status == "blocked":
            reason += "The tool call was recorded as blocked."
        else:
            reason += "The outcome of the tool call could not be established."

        matches.append(_policy_match("AW-003", "sensitive_resource_access", severity, reason))

    if not matches:
        return []

    # Combine classified resources into one policy match per record.
    severity = max((match["severity"] for match in matches), key=SEVERITY_RANK.get)
    return [_policy_match(
        "AW-003", "sensitive_resource_access", severity,
        " ".join(match["reason"] for match in matches),
    )]


def _check_aw004(record: dict[str, Any]) -> list[dict[str, str]]:
    # Evaluate the trust of external information sources.
    server = record.get("server", "")
    tool = record.get("tool_name", "")
    arguments = record.get("arguments", {})
    status = record.get("result_status", "")

    if server != "fetch" or tool != "fetch":
        return []

    if not isinstance(arguments, dict):
        arguments = {}

    url = arguments.get("url")

    # Compare the requested URL against the approved-source list.
    if not isinstance(url, str) or not url.strip():
        reason = (
            "The requested external source URL could not be established."
        )

    elif url in APPROVED_EXTERNAL_SOURCES:
        return []

    else:
        reason = (
            f"External source '{url}' is not listed "
            "in the approved-source policy."
        )

    # Distinguish retrieval from attempted retrieval.
    if status == "success":
        outcome = (
            "The fetch was recorded as successful. "
            "Review the source for potential untrusted content."
        )

    elif status == "error":
        outcome = (
            "The fetch returned an error. "
            "Successful retrieval is not established."
        )

    elif status == "blocked":
        outcome = (
            "The fetch was recorded as blocked."
        )

    else:
        outcome = (
            "The outcome of the fetch could not be established."
        )

    return [
        _policy_match(
            "AW-004",
            "approved_external_sources",
            "medium",
            reason + " " + outcome
            + " This finding does not establish outbound data exfiltration.",
        )
    ]


def _check_aw005(
    record: dict[str, Any], session_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    # Compare memory writes with earlier successful resource reads.
    if record.get("server") != "memory" or record.get("tool_name") != "memory_set":
        return []

    arguments = record.get("arguments")
    if not isinstance(arguments, dict):
        return []
    value = arguments.get("value")
    if not isinstance(value, str):
        return []
    value = " ".join(value.split())
    session = record.get("session_id")
    task = record.get("task_id")
    seq = record.get("seq")
    if not isinstance(session, str) or not session.strip():
        return []
    if not isinstance(task, str) or not task.strip() or type(seq) is not int:
        return []

    reasons = []
    for source in session_records:
        source_seq = source.get("seq")
        if (source.get("session_id") != session or source.get("task_id") != task
                or type(source_seq) is not int or source_seq >= seq
                or source.get("result_status") != "success"):
            continue
        if (source.get("server"), source.get("tool_name")) not in (
            ("filesystem", "read_text_file"), ("git", "git_show_worktree"),
        ):
            continue
        source_args = source.get("arguments")
        if not isinstance(source_args, dict):
            continue
        path = source_args.get("path")
        summary = source.get("result_summary")
        if not isinstance(path, str) or not path.strip() or not isinstance(summary, str):
            continue
        summary = " ".join(summary.split())
        # Require a substantial exact prefix match after whitespace normalization.
        if min(len(summary), len(value)) < 80:
            continue
        if not (value.startswith(summary) or summary.startswith(value)):
            continue
        try:
            resolved = (REPO_ROOT / path).resolve()
            if not resolved.is_relative_to(REPO_ROOT.resolve()):
                classification = "outside the approved repository boundary"
            elif resolved in RESOURCE_TAGS:
                classification = "explicitly classified by the resource map"
            elif any(resolved.is_relative_to(directory) for directory in RESTRICTED_SOURCE_DIRECTORIES):
                classification = "within a policy-designated restricted source directory"
            else:
                continue
        except (ValueError, OSError, RuntimeError):
            continue
        reasons.append(
            f"Memory value matches recorded content from resource '{path}' "
            f"(sequence {source_seq}, {classification}) in the same session and task."
        )

    if not reasons:
        return []
    status = record.get("result_status")
    severity = "high" if status == "success" else "medium"
    outcome = {
        "success": "The memory write was recorded as successful.",
        "error": "The memory write returned an error; successful persistence is not established.",
        "blocked": "The memory write was recorded as blocked.",
    }.get(status if isinstance(status, str) else "", "The memory write outcome is unknown.")
    return [_policy_match(
        "AW-005", "sensitive_data_persistence", severity,
        " ".join(dict.fromkeys(reasons)) + " " + outcome
        + " Content matching supports a potential data-flow relationship, not proof of complete lineage.",
    )]


def _is_manifest_path(record: dict[str, Any]) -> bool:
    arguments = record.get("arguments")
    if not isinstance(arguments, dict):
        return False
    path = arguments.get("path")
    if not isinstance(path, str) or not path.strip():
        return False
    try:
        return (REPO_ROOT / path).resolve() == (REPO_ROOT / "package.json").resolve()
    except (ValueError, OSError, RuntimeError):
        return False


def _dependency_issues(record: dict[str, Any]) -> tuple[list[str], bool]:
    # Validate the complete recorded manifest, not the truncated read summary.
    try:
        manifest = json.loads(record["arguments"]["content"])
        if not isinstance(manifest, dict):
            raise ValueError("Expected an object")
        issues = []
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            entries = manifest.get(section, {})
            if not isinstance(entries, dict):
                raise ValueError("Invalid dependency section")
            for name, version in entries.items():
                if not name.strip() or not isinstance(version, str) or not version.strip():
                    raise ValueError("Invalid dependency requirement")
                approved = POLICY_CONFIG["approved_dependencies"].get(name)
                if approved is None:
                    issues.append(f"Unapproved dependency '{name}' in {section}.")
                elif version != approved:
                    issues.append(f"Unapproved version requirement for '{name}' in {section}.")
        return issues, False
    except (KeyError, TypeError, ValueError):
        return ["Manifest content could not be validated."], True


def _check_aw006(record: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, str]]:
    operation = (record.get("server"), record.get("tool_name"))
    issues = []
    uncertain = False
    evidence = ""
    if operation == ("filesystem", "write_file") and _is_manifest_path(record):
        issues, uncertain = _dependency_issues(record)
    elif operation in (("git", "git_add"), ("git", "git_commit")):
        if operation[1] == "git_add" and not _is_manifest_path(record):
            return []
        session, task, seq = (record.get(k) for k in ("session_id", "task_id", "seq"))
        if not isinstance(session, str) or not session.strip() or not isinstance(task, str) or not task.strip() or type(seq) is not int:
            return []
        # Track the latest successful manifest write and explicit staging event.
        # Other tasks can invalidate evidence, but cannot establish same-task correlation.
        pending = None
        staged = None
        prior = sorted((r for r in records if r.get("session_id") == session
                        and type(r.get("seq")) is int and r["seq"] < seq), key=lambda r: r["seq"])
        for event in prior:
            if event.get("result_status") != "success":
                continue
            kind = (event.get("server"), event.get("tool_name"))
            if kind == ("filesystem", "write_file") and _is_manifest_path(event):
                pending = (*_dependency_issues(event), event["seq"], event.get("task_id"))
            elif kind == ("git", "git_add"):
                if _is_manifest_path(event):
                    staged = (pending, event["seq"], event.get("task_id")) if pending else None
                else:
                    # A broad or ambiguous staging operation may change the index.
                    args = event.get("arguments")
                    path = args.get("path") if isinstance(args, dict) else None
                    if not isinstance(path, str) or path.strip() in ("", ".", "./", "..") or any(c in path for c in "*?["):
                        staged = None
            elif kind == ("git", "git_commit") or kind == ("git", "git_init"):
                staged = None
                if kind[1] == "git_init":
                    pending = None
        if operation[1] == "git_add" and pending and pending[3] == task:
            issues, uncertain, write_seq, _ = pending
            evidence = f" Correlated with manifest write at sequence {write_seq}."
        elif operation[1] == "git_commit" and staged and staged[2] == task and staged[0][3] == task:
            issues, uncertain, write_seq, _ = staged[0]
            evidence = (f" Correlated with manifest write at sequence {write_seq} and staging at sequence {staged[1]}."
                        " The committed tree was not independently verified.")
    if not issues:
        return []
    status = record.get("result_status")
    severity = "high" if status == "success" and not uncertain else "medium"
    outcome = (" The operation was recorded as successful." if status == "success" else
               " The operation was recorded as blocked." if status == "blocked" else
               " The operation returned an error; success is not established." if status == "error" else
               " The operation outcome is unknown.")
    return [_policy_match("AW-006", "dependency_integrity", severity,
                          " ".join(issues) + evidence + outcome)]


def _operation_signature(record: dict[str, Any]) -> tuple[str, str, str] | None:
    # Compare actual arguments, independent of JSON object key order.
    server = record.get("server")
    tool = record.get("tool_name")
    arguments = record.get("arguments")
    if not isinstance(server, str) or not server.strip():
        return None
    if not isinstance(tool, str) or not tool.strip() or not isinstance(arguments, dict):
        return None
    try:
        return server, tool, json.dumps(arguments, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return None


def _check_aw007(record: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, str]]:
    # Count activity up to this event, within the same session and task.
    session, task, seq = (record.get(k) for k in ("session_id", "task_id", "seq"))
    if not isinstance(session, str) or not session.strip() or not isinstance(task, str) or not task.strip() or type(seq) is not int:
        return []
    prior = sorted((r for r in records if r.get("session_id") == session
                    and r.get("task_id") == task and type(r.get("seq")) is int
                    and r["seq"] < seq), key=lambda r: r["seq"])
    # Ambiguous sequence numbers cannot establish reliable ordering.
    if len({r["seq"] for r in prior}) != len(prior) or sum(
        r.get("session_id") == session and r.get("task_id") == task and r.get("seq") == seq
        for r in records
    ) > 1:
        return []
    signature = _operation_signature(record)
    if signature is None:
        return []
    total = 1 + sum(_operation_signature(r) is not None for r in prior)
    repeated = 1 + sum(_operation_signature(r) == signature for r in prior)
    failures = 0
    if record.get("result_status") == "error":
        failures = 1
        for event in reversed(prior):
            if event.get("result_status") != "error" or _operation_signature(event) != signature:
                break
            failures += 1
    thresholds = POLICY_CONFIG["tool_usage_thresholds"]
    reasons = []
    severities = []
    for prefix, count, label in (
        ("task_calls", total, "Recorded tool calls within this task"),
        ("repeated_calls", repeated, "Identical tool calls within this task"),
        ("failed_retries", failures, "Consecutive identical calls returning errors"),
    ):
        for severity in ("medium", "high"):
            threshold = thresholds[f"{prefix}_{severity}"]
            if count == threshold:
                reasons.append(f"{label}: {count}; reached the {severity} threshold of {threshold}.")
                severities.append(severity)
    if not reasons:
        return []
    return [_policy_match(
        "AW-007", "excessive_tool_usage", max(severities, key=SEVERITY_RANK.get),
        " ".join(reasons) + " Potential excessive activity; recorded counts do not establish resource exhaustion or service disruption.",
    )]


def evaluate_record(
    record: dict[str, Any], session_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    # Return one combined alert per ADOP record,
    # even if several policies match.
    matches = []

    server = record.get("server", "")
    target = record.get("target_resource", "")

    # AW-001: Approved Resource Boundary.
    matches.extend(_check_aw001(record))

    # AW-002: Approved Data Destinations.
    matches.extend(_check_aw002(record))

    # AW-003: Sensitive Resource Access.
    matches.extend(_check_aw003(record))

    # AW-004: Approved External Sources.
    matches.extend(_check_aw004(record))

    # AW-005: Sensitive Data Persistence.
    matches.extend(_check_aw005(record, session_records or []))

    # AW-006: Dependency Integrity.
    matches.extend(_check_aw006(record, session_records or []))

    # AW-007: Excessive Tool Usage.
    matches.extend(_check_aw007(record, session_records or []))

    # No policy matched this record.
    if not matches:
        return []

    # Count each combined alert once using its highest matched severity.
    highest_severity = max(
        (match["severity"] for match in matches),
        key=lambda severity: SEVERITY_RANK[severity],
    )

    session_id = record.get("session_id", "")
    task_id = record.get("task_id", "")
    tool = record.get("tool_name", "")

    traceable = all(
        isinstance(value, str) and bool(value.strip())
        for value in (session_id, task_id, server, tool, target)
    )

    policy_ids = [match["policy_id"] for match in matches]
    policy_names = [match["policy_name"] for match in matches]
    reasons = [match["reason"] for match in matches]

    return [{
        # Existing report and dashboard fields.
        "policy_id": ", ".join(policy_ids),
        "policy_name": ", ".join(policy_names),
        "severity": highest_severity,
        "risk_points": SEVERITY_POINTS[highest_severity],
        "reason": " ".join(reasons),

        # Structured policy details.
        "policies": matches,

        # Record information.
        "session_id": session_id,
        "task_id": task_id,
        "server": server,
        "tool": tool,
        "target": target,

        # Additional evidence for future reporting improvements.
        "arguments": record.get("arguments", {}),
        "result_status": record.get("result_status", ""),
        "seq": record.get("seq"),
        "timestamp": record.get("timestamp", ""),

        "provenance_flag": "TRACEABLE" if traceable else "INCOMPLETE",
    }]


def evaluate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []

    for record in records:
        findings.extend(evaluate_record(record, records))

    findings.sort(key=lambda finding: (
        -finding["risk_points"],
        -SEVERITY_RANK.get(finding["severity"], 0),
        str(finding.get("task_id", "")),
        str(finding.get("target", "")),
    ))

    for rank, finding in enumerate(findings, start=1):
        finding["rank"] = rank

    return findings


def calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    # Return uncapped heuristic risk points,
    # counting each combined alert once.
    return sum(
        int(finding.get("risk_points", 0))
        for finding in findings
    )


def classify_risk(findings: list[dict[str, Any]]) -> str:
    # Existing v2 risk classification retained temporarily.
    total = calculate_risk_score(findings)

    if any(
        finding.get("severity") == "high"
        for finding in findings
    ) or total >= 60:
        return "High"

    if total >= 20:
        return "Medium"

    return "Low"
