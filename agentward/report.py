from typing import Any

# Generate a human-readable AgentWard security assessment.
def generate_report(records: list[dict[str, Any]], findings: list[dict[str, Any]],) -> str:
    session_id = records[0].get("session_id", "unknown") if records else "unknown"
    scenario = records[0].get("scenario_tag", "unknown") if records else "unknown"

    lines = []

    lines.append("=" * 60)
    lines.append("AgentWard v1 Security Assessment")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"ADOP Session: {session_id}")
    lines.append(f"Scenario: {scenario}")
    lines.append(f"Records analyzed: {len(records)}")
    lines.append(f"Policy findings: {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No policy-relevant findings were detected.")
        return "\n".join(lines)

    # Group findings by severity.
    severity_order = ["high", "medium", "low"]

    for severity in severity_order:
        severity_findings = [
            finding
            for finding in findings
            if finding.get("severity", "").lower() == severity
        ]

        if not severity_findings:
            continue

        lines.append(severity.upper())
        lines.append("-" * 60)

        for finding in severity_findings:
            lines.append(
                f"{finding.get('policy_id', 'unknown')} | "
                f"{finding.get('policy_name', 'unknown')}"
            )
            lines.append(f"Task: {finding.get('task_id', 'unknown')}")
            lines.append(f"Server: {finding.get('server', 'unknown')}")
            lines.append(f"Tool: {finding.get('tool', 'unknown')}")
            lines.append(f"Target: {finding.get('target', 'unknown')}")
            lines.append(f"Reason: {finding.get('reason', 'No reason provided.')}")
            lines.append("")

    return "\n".join(lines)

# Save an AgentWard report to a text file.
def save_report(report: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)

# Save an AgentWard report to a text file.
def save_report(report: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)