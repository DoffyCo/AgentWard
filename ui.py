import tempfile
from pathlib import Path
from datetime import datetime
from hashlib import sha256
from agentward.report import generate_audit_report, save_audit_report, format_timestamp, DISPOSITIONS
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
    st.session_state.pop("audit_input", None)
    st.session_state.pop("saved_audit", None)
    st.write("Upload a telemetry file to review its findings.")
    st.stop()

# Reset review state when the selected input changes.
input_bytes = uploaded_file.getvalue()
input_identity = (uploaded_file.name, sha256(input_bytes).hexdigest())
if st.session_state.get("audit_input") != input_identity:
    for key in list(st.session_state.keys()):
        if key.startswith(("decision_", "rationale_")) or key in ("reviewer", "saved_audit"):
            del st.session_state[key]
    st.session_state["audit_input"] = input_identity

try:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as temp_file:
        temp_file.write(input_bytes)
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
decisions = {}

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
            disposition = st.selectbox(
                "Choose a disposition",
                DISPOSITIONS,
                key=decision_key,
            )
            rationale = st.text_input(
                "Decision rationale (optional)",
                key=rationale_key,
                placeholder="Briefly explain the decision",
            )

            decisions[finding["rank"]] = {"disposition": disposition, "rationale": rationale}

st.subheader("Save assessment")
reviewer = st.text_input("Reviewer name or identifier", key="reviewer")
st.caption("Input SHA-256: " + input_identity[1])

if st.button("Save report to the reports folder"):
    try:
        report_text = generate_audit_report(records, findings, input_bytes, uploaded_file.name, reviewer, decisions)
        reports_dir = Path(__file__).resolve().parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%m-%d-%Y_%H-%M-%S")
        input_name = Path(uploaded_file.name).stem
        base_name = f"{input_name}-{scenario}-assessment-{timestamp}"
        output_path = reports_dir / f"{base_name}.txt"
        counter = 1
        # Avoid overwriting either an assessment or its checksum.
        while output_path.exists() or output_path.with_suffix(".txt.sha256").exists():
            output_path = reports_dir / f"{base_name}-{counter}.txt"
            counter += 1
        report_bytes, checksum_bytes = save_audit_report(report_text, output_path)
        st.session_state["saved_audit"] = (str(output_path), report_bytes, checksum_bytes)
    except (ValueError, OSError) as exc:
        st.error(str(exc))

# Keep the last saved snapshot available across dashboard reruns.
saved_audit = st.session_state.get("saved_audit")
if saved_audit:
    saved_path, report_bytes, checksum_bytes = saved_audit
    st.success(f"Last saved report: {saved_path}")
    st.caption("Downloads contain the last saved snapshot. Save again to include any changes.")
    st.download_button("Download saved report", data=report_bytes, file_name=Path(saved_path).name, mime="text/plain")
    st.download_button("Download report checksum", data=checksum_bytes, file_name=Path(saved_path).name + ".sha256", mime="text/plain")

st.divider()
st.caption(
    "Interpretation: triage aid only—not a probability, CVSS score, or proof of compromise. "
    "Source relationships are potential correlations, not proof of causation."
)