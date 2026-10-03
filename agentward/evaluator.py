from typing import Any

# Evaluate one ADOP telemetry record against AgentWard v1 policies.
def evaluate_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []

    server = record.get("server", "")
    tool_name = record.get("tool_name", "")
    target = record.get("target_resource", "")
    task_id = record.get("task_id", "")

    # AW-001: Check for access outside the approved resource boundary.
    if isinstance(target, str) and (
        target.startswith("../")
        or "/../" in target
        or target.startswith("..\\")
    ):
        findings.append(
            {
                "policy_id": "AW-001",
                "policy_name": "approved_resource_boundary",
                "severity": "high",
                "task_id": task_id,
                "server": server,
                "tool": tool_name,
                "target": target,
                "reason": "The requested resource appears to be outside the agent's approved resource boundary.",
            }
        )

    # AW-002: Check external destinations.
    if server == "fetch" and isinstance(target, str):
        if target.startswith(("http://", "https://")):
            findings.append(
                {
                    "policy_id": "AW-002",
                    "policy_name": "approved_data_destinations",
                    "severity": "medium",
                    "task_id": task_id,
                    "server": server,
                    "tool": tool_name,
                    "target": target,
                    "reason": "The agent accessed an external destination that requires destination-policy review.",
                }
            )

    # AW-003: Check potentially sensitive resource access.
    if isinstance(target, str):
        sensitive_terms = [
            "secret",
            "patient",
            "phi",
            "medical",
            "claims",
        ]

        if any(term in target.lower() for term in sensitive_terms):
            findings.append(
                {
                    "policy_id": "AW-003",
                    "policy_name": "sensitive_resource_access",
                    "severity": "high",
                    "task_id": task_id,
                    "server": server,
                    "tool": tool_name,
                    "target": target,
                    "reason": "The resource name suggests potentially sensitive information and requires authorization review.",
                }
            )

    return findings

# Evaluate all ADOP records and return AgentWard findings.
def evaluate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []

    for record in records:
        findings.extend(evaluate_record(record))

    return findings