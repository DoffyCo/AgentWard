import tempfile
from pathlib import Path
from datetime import datetime
from agentward.report import generate_report, save_report, format_timestamp
import streamlit as st

from agentward.reader import read_adop_records
from agentward.evaluator import (
    evaluate_records,
    calculate_risk_score,
    classify_risk,
)

st.set_page_config(page_title="AgentWard v3", layout="wide")
st.title("AgentWard v3")
st.caption("Decision-support dashboard · Observe-only analysis")

st.info(
    "AgentWard analyzes recorded ADOP telemetry. It does not block activity "
    "or enforce remediation. Risk points are project-defined triage heuristics."
)

uploaded_file = st.file_uploader("Upload an ADOP JSONL file", type=["jsonl", "txt"])

if uploaded_file is None:
    st.write("Upload a telemetry file to review its findings.")
    st.stop()

try:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as temp_file:
        temp_file.write(uploaded_file.getvalue())
        temp_path = Path(temp_file.name)

    records = read_adop_records(temp_path)
    findings = evaluate_records(records)
    score = calculate_risk_score(findings)
    risk_band = classify_risk(findings)

except Exception as exc:
    st.error(f"Could not analyze this file: {exc}")
    st.stop()

finally:
    if "temp_path" in locals():
        temp_path.unlink(missing_ok=True)

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

st.subheader("Assessment")
metric1, metric2, metric3, metric4 = st.columns(4)
metric1.metric("Risk band", risk_band)
metric2.metric("Heuristic risk score", f"{score} points")
metric3.metric("Grouped alerts", len(findings))
st.caption(f"Flagged events: {sum(f.get('occurrence_count', 1) for f in findings)}. Score is an uncapped cumulative total; risk band follows highest severity.")
metric4.metric("Records analyzed", len(records))

st.caption(f"ADOP session: {session_id} · Scenario: {scenario}")
st.subheader("Save assessment")

if st.button("Save report to the reports folder"):
    reports_dir = Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Include the scenario, date, and time in the report filename.
    timestamp = datetime.now().strftime("%m-%d-%Y_%H-%M-%S")
    input_name = Path(uploaded_file.name).stem
    base_name = f"{input_name}-{scenario}-assessment-{timestamp}"

    output_path = reports_dir / f"{base_name}.txt"
    counter = 1

    # Prevent existing reports from being overwritten.
    while output_path.exists():
        output_path = reports_dir / f"{base_name}-{counter}.txt"
        counter += 1

    report_text = generate_report(records, findings)
    save_report(report_text, str(output_path))

    st.success(f"Report saved to: {output_path}")
    st.download_button(
        "Download saved report",
        data=report_text,
        file_name=output_path.name,
        mime="text/plain",
    )

st.subheader("Ranked alerts")

if not findings:
    st.success("No policy-relevant findings were detected in this file.")
else:
    for finding in findings:
        title = (
            f"#{finding.get('rank', '?')} · "
            f"{finding.get('severity', 'unknown').upper()} · "
            f"{finding.get('policy_id', 'unknown')}"
        )

        with st.expander(title, expanded=(finding.get("rank") == 1)):
            left, right = st.columns([2, 1])

            with left:
                st.write(f"**Task:** {finding.get('task_id') or 'unknown'}")
                st.write(f"**Target:** {finding.get('target') or 'unknown'}")
                st.write(f"**Server / tool:** {finding.get('server') or 'unknown'} / "
                         f"{finding.get('tool') or 'unknown'}")
                st.text(f"Occurrences: {finding.get('occurrence_count', 1)}")
                for event in finding.get("events", [finding]):
                    st.text(f"Sequence: {event.get('seq')} | Timestamp: {format_timestamp(event.get('timestamp'))}")
                    st.text(f"Execution status: {event.get('result_status') or 'unknown'}")
                    st.text(f"Severity: {event['severity']} | Policies: {event['policy_id']}")
                    st.text(event["reason"])

                    # Display potential source relationships for this event.
                    sources = event.get("prior_sources", [])
                    if sources:
                        st.write("**Potential source relationship**")
                        for source in sources:
                            st.text(
                                f"Earlier successful fetch: sequence {source['seq']} | "
                                f"Timestamp: {format_timestamp(source['timestamp'])} | URL: {source['url']}"
                            )
                        st.caption("Same session and task; temporal ordering alone does not establish causation.")
                    else:
                        st.caption("No qualifying prior source relationship identified.")

            with right:
                provenance = finding.get("provenance_flag", "INCOMPLETE")
                st.write(f"**Provenance:** {provenance}")
                st.caption(
                    "TRACEABLE means the alert links to the listed ADOP event fields. "
                    "It does not prove maliciousness or confirm that PHI was disclosed."
                )
                st.text(f"Events with potential source relationships: {finding.get('correlated_event_count', 0)}")
                st.write(f"**Alert points:** +{finding.get('risk_points', 0)}")

            decision_key = f"decision_{finding.get('rank')}"
            rationale_key = f"rationale_{finding.get('rank')}"

            st.write("**Stakeholder decision**")
            st.selectbox(
                "Choose a disposition",
                ["Needs review", "Escalate", "Dismiss"],
                key=decision_key,
            )
            st.text_input(
                "Decision rationale (optional)",
                key=rationale_key,
                placeholder="Briefly explain the decision",
            )

st.divider()
st.caption(
    "Interpretation: triage aid only—not a probability, CVSS score, or proof of compromise. "
    "Source relationships are potential correlations, not proof of causation."
)