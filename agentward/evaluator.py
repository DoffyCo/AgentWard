from typing import Any

# Preserve existing evaluator imports for callers and tests.
from .config import (
    ADOP_ROOT,
    REPO_ROOT,
    POLICY_PATH,
    POLICY_CONFIG,
    APPROVED_EXTERNAL_SOURCES,
    APPROVED_MEMORY_NAMESPACES,
    RESOURCE_TAGS,
    RESTRICTED_SOURCE_DIRECTORIES,
    _load_policy_config,
    _load_resource_tags,
)
from .policy_checks import (
    _policy_match,
    _is_outside_sandbox,
    _get_git_output_paths,
    _check_aw001,
    _check_aw002,
    _check_aw003,
    _check_aw004,
    _check_aw005,
    _check_aw006,
    _check_aw007,
    _is_manifest_path,
    _dependency_issues,
    _operation_signature,
)
from .provenance import _find_prior_sources
from .risk import (
    SEVERITY_POINTS,
    SEVERITY_RANK,
    group_findings,
    calculate_risk_score,
    classify_risk,
)


def evaluate_record(
    record: dict[str, Any],
    session_records: list[dict[str, Any]] | None = None,
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

        # Recorded execution evidence.
        "arguments": record.get("arguments", {}),
        "result_status": record.get("result_status", ""),
        "seq": record.get("seq"),
        "timestamp": record.get("timestamp", ""),

        "provenance_flag": "TRACEABLE" if traceable else "INCOMPLETE",
        "prior_sources": _find_prior_sources(record, session_records or [], matches),
    }]


def evaluate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in records:
        findings.extend(evaluate_record(record, records))
    return group_findings(findings)
