from typing import Any
from agentward.evaluator import calculate_risk_score, classify_risk


def generate_report(records: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    session_id = records[0].get("session_id", "unknown") if records else "unknown"
    scenario = records[0].get("scenario_tag", "unknown") if records else "unknown"
    score = calculate_risk_score(findings)
    risk_band = classify_risk(findings)

    lines = [
        "=" * 60,
        "AgentWard v2 Decision-Support Assessment",
        "=" * 60,
        "",
        f"ADOP Session: {session_id}",
        f"Scenario: {scenario}",
        f"Records analyzed: {len(records)}",
        f"Policy findings: {len(findings)}",
        f"Heuristic risk points: {score}",
        f"Risk band: {risk_band}",
        "Score method: High=30, Medium=15, Low=5 per combined alert; uncapped sum.",
        "Risk bands: High if any high-severity alert or total >= 60; Medium if total >= 20; otherwise Low.",
        "Interpretation: triage aid only; not a probability, CVSS score, or proof of compromise.",
        "",
        "Ranked alerts",
        "-" * 60,
    ]

    if not findings:
        lines.append("No policy-relevant findings were detected.")
    else:
        for finding in findings:
            lines.extend([
                f"#{finding.get('rank')} | {finding.get('severity', 'unknown').upper()} | "
                f"{finding.get('policy_id', 'unknown')} | +{finding.get('risk_points', 0)} points",
                f"Provenance: {finding.get('provenance_flag', 'INCOMPLETE')} "
                "(TRACEABLE means linked to the listed ADOP event fields; it does not prove maliciousness.)",
                f"Session: {finding.get('session_id', 'unknown')} | Task: {finding.get('task_id', 'unknown')}",
                f"Server: {finding.get('server', 'unknown')} | Tool: {finding.get('tool', 'unknown')}",
                f"Target: {finding.get('target', 'unknown')}",
                f"Reason: {finding.get('reason', 'No reason provided.')}",
                "",
            ])

    lines.extend([
        "Limitations",
        "- Observe-only analysis of recorded ADOP telemetry; no live blocking or enforcement.",
        "- Risk points and bands are project-defined heuristics for triage, not calibrated risk measurements.",
        "- Each combined alert contributes once; separate ADOP records are counted separately.",
        "- Provenance flag checks event traceability, not data origin or whether PHI was disclosed.",
    ])
    return "\n".join(lines)


def save_report(report: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)