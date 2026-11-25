from typing import Any
from agentward.evaluator import calculate_risk_score, classify_risk


def generate_report(records: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    session_id = records[0].get("session_id", "unknown") if records else "unknown"

    # Identify the scenario from the ADOP records.
    scenarios = {
        record.get("scenario_tag")
        for record in records
        if record.get("scenario_tag") in ("clean", "poisoned")
    }

    if len(scenarios) == 1:
        scenario = next(iter(scenarios))
    elif len(scenarios) > 1:
        scenario = "mixed"
    else:
        scenario = "unknown"

    score = calculate_risk_score(findings)
    risk_band = classify_risk(findings)

    lines = [
        "=" * 60,
        "AgentWard v3 Decision-Support Assessment",
        "=" * 60,
        "",
        f"ADOP Session: {session_id}",
        f"Scenario: {scenario}",
        f"Records analyzed: {len(records)}",
        f"Grouped alerts: {len(findings)}",
        f"Flagged events: {sum(f.get('occurrence_count', 1) for f in findings)}",
        f"Heuristic risk score: {score} points",
        f"Risk band: {risk_band}",
        "Score method: High=30, Medium=15, Low=5 per grouped alert; uncapped cumulative total.",
        "Risk bands: Highest alert severity; Low if no findings.",
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
                f"Occurrences: {finding.get('occurrence_count', 1)}",
                "",
            ])

            for event in finding.get("events", [finding]):
                lines.extend([
                    f"  Sequence: {event.get('seq')} | Timestamp: {event.get('timestamp')}",
                    f"  Execution status: {event.get('result_status') or 'unknown'}",
                    f"  Severity: {event['severity']} | Policies: {event['policy_id']}",
                    f"  Reason: {event['reason']}",
                    "",
                ])

    lines.extend([
        "Limitations",
        "- Observe-only analysis of recorded ADOP telemetry; no live blocking or enforcement.",
        "- Risk points and bands are project-defined heuristics for triage, not calibrated risk measurements.",
        "- Each session/task/server/tool/recorded-target group contributes once at its highest severity. Incomplete identifiers remain separate.",
        "- Provenance flag checks event traceability, not data origin or whether PHI was disclosed.",
    ])
    return "\n".join(lines)


def save_report(report: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)
