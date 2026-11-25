import json
from pathlib import Path
from typing import Any

from .config import (
    ADOP_ROOT,
    REPO_ROOT,
    POLICY_CONFIG,
    APPROVED_EXTERNAL_SOURCES,
    APPROVED_MEMORY_NAMESPACES,
    RESOURCE_TAGS,
    RESTRICTED_SOURCE_DIRECTORIES,
)
from .risk import SEVERITY_RANK


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


# AW-001: Approved resource boundary.
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


# AW-002: Approved data destinations.
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


# AW-003: Sensitive resource access.
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
        # Inspect paths and output destinations.
        pathspec = arguments.get("pathspec", ".")
        if isinstance(pathspec, str):
            paths.extend(token for token in pathspec.split() if not token.startswith("-"))
        paths.extend(_get_git_output_paths(arguments))

    matches = []
    seen_paths = set()
    for path in paths:
        if not isinstance(path, str) or not path.strip():
            continue
        try:
            resolved = (REPO_ROOT / path).resolve()
        except (ValueError, OSError, RuntimeError):
            continue

        if resolved in seen_paths or resolved not in RESOURCE_TAGS:
            continue
        seen_paths.add(resolved)
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
    return [
        _policy_match(
            "AW-003", "sensitive_resource_access", severity,
            " ".join(match["reason"] for match in matches),
        )
    ]


# AW-004: Approved external sources.
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


# AW-005: Sensitive data persistence.
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
    sequence = record.get("seq")
    if not isinstance(session, str) or not session.strip():
        return []
    if not isinstance(task, str) or not task.strip() or type(sequence) is not int:
        return []

    reasons = []
    for source in session_records:
        source_sequence = source.get("seq")
        if (source.get("session_id") != session or source.get("task_id") != task
                or type(source_sequence) is not int or source_sequence >= sequence
                or source.get("result_status") != "success"):
            continue
        if (source.get("server"), source.get("tool_name")) not in (
            ("filesystem", "read_text_file"), ("git", "git_show_worktree"),
        ):
            continue
        source_arguments = source.get("arguments")
        if not isinstance(source_arguments, dict):
            continue
        path = source_arguments.get("path")
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
            f"(sequence {source_sequence}, {classification}) in the same session and task."
        )

    if not reasons:
        return []
    status = record.get("result_status")
    severity = "high" if status == "success" else "medium"
    # Distinguish successful persistence from unsuccessful attempts.
    if isinstance(status, str) and status == "success":
        outcome = "The memory write was recorded as successful."
    elif isinstance(status, str) and status == "error":
        outcome = (
            "The memory write returned an error; "
            "successful persistence is not established."
        )
    elif isinstance(status, str) and status == "blocked":
        outcome = "The memory write was recorded as blocked."
    else:
        outcome = "The memory write outcome is unknown."
    return [
        _policy_match(
            "AW-005", "sensitive_data_persistence", severity,
            " ".join(dict.fromkeys(reasons)) + " " + outcome
            + " Content matching supports a potential data-flow relationship, not proof of complete lineage.",
        )
    ]


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
    # Validate the complete manifest instead of the truncated read summary.
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


# AW-006: Dependency integrity.
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
        session, task, sequence = (record.get(k) for k in ("session_id", "task_id", "seq"))
        if (
            not isinstance(session, str) or not session.strip()
            or not isinstance(task, str) or not task.strip()
            or type(sequence) is not int
        ):
            return []
        # Track the latest successful manifest write and explicit staging event.
        pending = None
        staged = None
        prior_events = sorted((event_record for event_record in records if event_record.get("session_id") == session
                        and type(event_record.get("seq")) is int and event_record["seq"] < sequence), key=lambda event_record: event_record["seq"])
        for event in prior_events:
            if event.get("result_status") != "success":
                continue
            event_operation = (event.get("server"), event.get("tool_name"))
            if event_operation == ("filesystem", "write_file") and _is_manifest_path(event):
                pending = (*_dependency_issues(event), event["seq"], event.get("task_id"))
            elif event_operation == ("git", "git_add"):
                if _is_manifest_path(event):
                    staged = (pending, event["seq"], event.get("task_id")) if pending else None
                else:

                    event_arguments = event.get("arguments")
                    path = event_arguments.get("path") if isinstance(event_arguments, dict) else None
                    if not isinstance(path, str) or path.strip() in ("", ".", "./", "..") or any(character in path for character in "*?["):
                        staged = None
            elif event_operation == ("git", "git_commit") or event_operation == ("git", "git_init"):
                staged = None
                if event_operation[1] == "git_init":
                    pending = None
        if operation[1] == "git_add" and pending and pending[3] == task:
            issues, uncertain, write_sequence, _ = pending
            evidence = f" Correlated with manifest write at sequence {write_sequence}."
        elif operation[1] == "git_commit" and staged and staged[2] == task and staged[0][3] == task:
            issues, uncertain, write_sequence, _ = staged[0]
            evidence = (f" Correlated with manifest write at sequence {write_sequence} and staging at sequence {staged[1]}."
                        " The committed tree was not independently verified.")
    if not issues:
        return []
    status = record.get("result_status")
    severity = "high" if status == "success" and not uncertain else "medium"
    # Distinguish successful operations from unsuccessful attempts.
    if status == "success":
        outcome = " The operation was recorded as successful."
    elif status == "blocked":
        outcome = " The operation was recorded as blocked."
    elif status == "error":
        outcome = " The operation returned an error; success is not established."
    else:
        outcome = " The operation outcome is unknown."
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


# AW-007: Excessive tool usage.
def _check_aw007(record: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, str]]:
    # Count activity up to this event, within the same session and task.
    session, task, sequence = (record.get(k) for k in ("session_id", "task_id", "seq"))
    if (
        not isinstance(session, str) or not session.strip()
        or not isinstance(task, str) or not task.strip()
        or type(sequence) is not int
    ):
        return []
    prior_events = sorted((event_record for event_record in records if event_record.get("session_id") == session
                    and event_record.get("task_id") == task and type(event_record.get("seq")) is int
                    and event_record["seq"] < sequence), key=lambda event_record: event_record["seq"])

    if len({event_record["seq"] for event_record in prior_events}) != len(prior_events) or sum(
        event_record.get("session_id") == session and event_record.get("task_id") == task and event_record.get("seq") == sequence
        for event_record in records
    ) > 1:
        return []
    signature = _operation_signature(record)
    if signature is None:
        return []
    total_calls = 1 + sum(_operation_signature(event_record) is not None for event_record in prior_events)
    repeated_calls = 1 + sum(_operation_signature(event_record) == signature for event_record in prior_events)
    failed_retries = 0
    if record.get("result_status") == "error":
        failed_retries = 1
        for event in reversed(prior_events):
            if event.get("result_status") != "error" or _operation_signature(event) != signature:
                break
            failed_retries += 1
    thresholds = POLICY_CONFIG["tool_usage_thresholds"]
    reasons = []
    severities = []
    for prefix, count, label in (
        ("task_calls", total_calls, "Recorded tool calls within this task"),
        ("repeated_calls", repeated_calls, "Identical tool calls within this task"),
        ("failed_retries", failed_retries, "Consecutive identical calls returning errors"),
    ):
        for severity in ("medium", "high"):
            threshold = thresholds[f"{prefix}_{severity}"]
            if count == threshold:
                reasons.append(f"{label}: {count}; reached the {severity} threshold of {threshold}.")
                severities.append(severity)
    if not reasons:
        return []
    return [
        _policy_match(
            "AW-007", "excessive_tool_usage", max(severities, key=SEVERITY_RANK.get),
            " ".join(reasons) + " Potential excessive activity; recorded counts do not establish resource exhaustion or service disruption.",
        )
    ]
