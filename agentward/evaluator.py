from typing import Any

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


def evaluate_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    #Return one combined alert per ADOP record, even if several policies match.
    matches = []
    server = record.get("server", "")
    target = record.get("target_resource", "")

    if isinstance(target, str) and (
        target.startswith("../") or "/../" in target or target.startswith("..\\")
    ):
        matches.append(_policy_match(
            "AW-001",
            "approved_resource_boundary",
            "high",
            "The requested resource appears to be outside the agent's approved resource boundary.",
        ))

    if (
        server == "fetch"
        and isinstance(target, str)
        and target.startswith(("http://", "https://"))
    ):
        matches.append(_policy_match(
            "AW-002",
            "approved_data_destinations",
            "medium",
            "The agent accessed an external destination that requires destination-policy review.",
        ))

    if isinstance(target, str) and any(
        term in target.lower()
        for term in ("secret", "patient", "phi", "medical", "claims")
    ):
        matches.append(_policy_match(
            "AW-003",
            "sensitive_resource_access",
            "high",
            "The resource name suggests potentially sensitive information and requires authorization review.",
        ))

    # No policy matched this record.
    if not matches:
        return []

    # One ADOP record becomes one alert. Keep all matched policies, but count the record only once using its highest matched severity.
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
        # Retain these fields so the existing report can still display them.
        "policy_id": ", ".join(policy_ids),
        "policy_name": ", ".join(policy_names),
        "severity": highest_severity,
        "risk_points": SEVERITY_POINTS[highest_severity],
        "reason": " ".join(reasons),

        # Structured policy details for a more detailed report.
        "policies": matches,

        "session_id": session_id,
        "task_id": task_id,
        "server": server,
        "tool": tool,
        "target": target,
        "provenance_flag": "TRACEABLE" if traceable else "INCOMPLETE",
    }]


def evaluate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []

    for record in records:
        findings.extend(evaluate_record(record))

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
    #Return uncapped heuristic risk points, counting each combined alert once.
    return sum(int(finding.get("risk_points", 0)) for finding in findings)


def classify_risk(findings: list[dict[str, Any]]) -> str:
    #Assign a prototype risk band from alert severity and total points.
    total = calculate_risk_score(findings)

    if any(finding.get("severity") == "high" for finding in findings) or total >= 60:
        return "High"
    if total >= 20:
        return "Medium"
    return "Low"