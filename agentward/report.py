import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from agentward.evaluator import calculate_risk_score, classify_risk
from agentward.reader import identify_scenario


def format_timestamp(timestamp: Any) -> str:
    # Format recorded UTC timestamps for display without changing the original data.
    if not isinstance(timestamp, str) or not timestamp:
        return "unknown"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return timestamp

    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        return timestamp

    return parsed.strftime("%Y-%m-%d T %H:%M:%S")


def generate_report(records: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    session_id = records[0].get("session_id", "unknown") if records else "unknown"

    scenario = identify_scenario(records)

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
                f"Events with potential source relationships: {finding.get('correlated_event_count', 0)}",
                "",
            ])

            for event in finding.get("events", [finding]):
                lines.extend([
                    f"  Sequence: {event.get('seq')} | Timestamp: {format_timestamp(event.get('timestamp'))}",
                    f"  Execution status: {event.get('result_status') or 'unknown'}",
                    f"  Severity: {event['severity']} | Policies: {event['policy_id']}",
                    f"  Reason: {event['reason']}",
                ])
                # Show source relationships for each individual event.
                sources = event.get("prior_sources", [])
                if sources:
                    lines.append("  Potential source relationship (same session and task):")
                    for source in sources:
                        lines.append(
                            f"    Earlier successful fetch: sequence {source['seq']} | "
                            f"Timestamp: {format_timestamp(source['timestamp'])} | URL: {source['url']}"
                        )
                    lines.append("  Temporal ordering alone does not establish causation.")    
                else:
                    lines.append("  No qualifying prior source relationship identified.")
                lines.append("")

    lines.extend([
        "Limitations",
        "- Observe-only analysis of recorded ADOP telemetry; no live blocking or enforcement.",
        "- Risk points and bands are project-defined heuristics for triage, not calibrated risk measurements.",
        "- Each session/task/server/tool/recorded-target group contributes once at its highest severity. Incomplete identifiers remain separate.",
        "- Provenance flag checks event traceability, not data origin or whether PHI was disclosed.",
        "- Source correlation uses earlier successful unapproved fetches in the same session and task. It does not prove prompt injection or causation and does not change risk points.",
    ])
    return "\n".join(lines)


def save_report(report: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)


DISPOSITIONS = ("Needs review", "Escalate", "Dismiss")


def generate_audit_report(
    records: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    input_bytes: bytes,
    input_name: str,
    reviewer: str,
    decisions: dict[int, dict[str, str]],
) -> str:
    # Require a reviewer and a disposition for every grouped alert.
    if not reviewer.strip():
        raise ValueError("Enter a reviewer name or identifier.")
    if set(decisions) != {finding["rank"] for finding in findings}:
        raise ValueError("Decisions must match the ranked alerts.")

    lines = [
        generate_report(records, findings),
        "",
        "Stakeholder review",
        "-" * 60,
        f"Reviewer: {json.dumps(reviewer.strip(), ensure_ascii=False)}",
        f"Review timestamp (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d T %H:%M:%S')}",
        f"Input file: {json.dumps(input_name, ensure_ascii=False)}",
        f"Input SHA-256: {sha256(input_bytes).hexdigest()}",
        "Reviewer identity is self-reported, not authenticated.",
    ]
    for finding in findings:
        rank = finding["rank"]
        decision = decisions[rank]
        if decision["disposition"] not in DISPOSITIONS:
            raise ValueError("Invalid stakeholder disposition.")
        lines.extend([
            "",
            f"Alert #{rank}",
            f"Disposition: {decision['disposition']}",
            f"Rationale: {json.dumps(decision['rationale'], ensure_ascii=False)}",
        ])
    if not findings:
        lines.append("No alerts require disposition.")
    lines.append("Checksums help verify report integrity but do not provide authentication or prevent tampering.")
    return "\n".join(lines)


def save_audit_report(report: str, output_path: Path) -> tuple[bytes, bytes]:
    # Hash the exact UTF-8 bytes written to disk, including line endings.
    report_bytes = report.encode("utf-8")
    checksum_bytes = f"{sha256(report_bytes).hexdigest()}  {output_path.name}\n".encode("utf-8")
    checksum_path = output_path.with_suffix(output_path.suffix + ".sha256")
    with output_path.open("xb") as file:
        file.write(report_bytes)
    try:
        with checksum_path.open("xb") as file:
            file.write(checksum_bytes)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise
    return report_bytes, checksum_bytes
