import unittest
from agentward.evaluator import evaluate_records, calculate_risk_score
from agentward.report import generate_report


def fetch(seq=1, **changes):
    record = {
        "session_id": "session", "task_id": "task", "seq": seq,
        "server": "fetch", "tool_name": "fetch",
        "target_resource": "https://example.invalid/readme",
        "arguments": {"url": "https://example.invalid/readme"},
        "result_status": "success",
    }
    record.update(changes)
    return record


def access(seq=2, **changes):
    record = {
        "session_id": "session", "task_id": "task", "seq": seq,
        "server": "filesystem", "tool_name": "read_text_file",
        "target_resource": "../outside.txt",
        "arguments": {"path": "../outside.txt"}, "result_status": "success",
    }
    record.update(changes)
    return record


def boundary_alert(records):
    return next(alert for alert in evaluate_records(records) if "AW-001" in alert["policy_id"])


class TestCausalProvenance(unittest.TestCase):
    def test_prior_source(self):
        alert = boundary_alert([fetch(), access()])
        self.assertEqual(alert["events"][0]["prior_sources"][0]["seq"], 1)
        self.assertEqual(alert["correlated_event_count"], 1)

    def test_failed_fetch(self):
        self.assertEqual(boundary_alert([fetch(result_status="error"), access()])["correlated_event_count"], 0)

    def test_blocked_fetch(self):
        self.assertEqual(boundary_alert([fetch(result_status="blocked"), access()])["correlated_event_count"], 0)

    def test_approved_source(self):
        source = fetch(arguments={"url": "https://intranet.example/vendor-readme"})
        self.assertEqual(boundary_alert([source, access()])["correlated_event_count"], 0)

    def test_different_task(self):
        self.assertEqual(boundary_alert([fetch(task_id="other"), access()])["correlated_event_count"], 0)

    def test_different_session(self):
        self.assertEqual(boundary_alert([fetch(session_id="other"), access()])["correlated_event_count"], 0)

    def test_later_fetch(self):
        self.assertEqual(boundary_alert([fetch(3), access()])["correlated_event_count"], 0)

    def test_out_of_order(self):
        self.assertEqual(boundary_alert([access(), fetch()])["correlated_event_count"], 1)

    def test_duplicate_sequence(self):
        self.assertEqual(boundary_alert([fetch(2), access()])["correlated_event_count"], 0)

    def test_missing_sequence(self):
        self.assertEqual(boundary_alert([fetch(None), access()])["correlated_event_count"], 0)

    def test_missing_url(self):
        self.assertEqual(boundary_alert([fetch(arguments={}), access()])["correlated_event_count"], 0)

    def test_failed_access(self):
        alert = boundary_alert([fetch(), access(result_status="error")])
        self.assertEqual(alert["correlated_event_count"], 1)
        self.assertEqual(alert["severity"], "medium")

    def test_grouped_events(self):
        alert = boundary_alert([access(1), fetch(2), access(3)])
        self.assertEqual(alert["occurrence_count"], 2)
        self.assertEqual(alert["correlated_event_count"], 1)
        self.assertEqual(alert["events"][0]["prior_sources"], [])
        self.assertEqual(alert["events"][1]["prior_sources"][0]["seq"], 2)

    def test_multiple_sources(self):
        alert = boundary_alert([fetch(1), fetch(2), access(3)])
        self.assertEqual([source["seq"] for source in alert["events"][0]["prior_sources"]], [1, 2])

    def test_score_unchanged(self):
        self.assertEqual(calculate_risk_score(evaluate_records([fetch(), access()])), 45)

    def test_report_evidence(self):
        records = [fetch(), access()]
        report = generate_report(records, evaluate_records(records))
        self.assertIn("Earlier successful fetch: sequence 1", report)
        self.assertIn("Temporal ordering alone does not establish causation.", report)
