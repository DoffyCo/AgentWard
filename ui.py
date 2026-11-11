import tempfile
from pathlib import Path
from datetime import datetime
from agentward.report import generate_report, save_report
import streamlit as st

from agentward.reader import read_adop_records
from agentward.evaluator import (
    evaluate_records,
    calculate_risk_score,
    classify_risk,
)

st.set_page_config(page_title="AgentWard v2", layout="wide")
st.title("AgentWard v2")
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
scenario = records[0].get("scenario_tag", "unknown") if records else "unknown"

st.subheader("Assessment")
metric1, metric2, metric3, metric4 = st.columns(4)
metric1.metric("Risk band", risk_band)
metric2.metric("Heuristic risk points", score)
metric3.metric("Alerts", len(findings))
metric4.metric("Records analyzed", len(records))

st.caption(f"ADOP session: {session_id} · Scenario: {scenario}")
st.subheader("Save assessment")

if st.button("Save report to the reports folder"):
    reports_dir = Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%m-%d-%Y_%H-%M-%S")
    output_path = reports_dir / f"agentward-report-{timestamp}.txt"

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
                st.write(f"**Reason:** {finding.get('reason') or 'No reason provided.'}")

            with right:
                provenance = finding.get("provenance_flag", "INCOMPLETE")
                st.write(f"**Provenance:** {provenance}")
                st.caption(
                    "TRACEABLE means the alert links to the listed ADOP event fields. "
                    "It does not prove maliciousness or confirm that PHI was disclosed."
                )
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
    "Provenance indicates event traceability, not data origin."
)