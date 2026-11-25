import unittest

from agentward.evaluator import evaluate_records, calculate_risk_score
from agentward.report import generate_report


def create_fetch(seq=1, **changes):
    record = {
        "session_id": "session", "task_id": "task", "seq": seq,
        "server": "fetch", "tool_name": "fetch",
        "target_resource": "https://example.invalid/readme",
        "arguments": {"url": "https://example.invalid/readme"},
        "result_status": "success",
    }
    record.update(changes)
    return record


def create_access(seq=2, **changes):
    record = {
        "session_id": "session", "task_id": "task", "seq": seq,
        "server": "filesystem", "tool_name": "read_text_file",
        "target_resource": "../outside.txt",
        "arguments": {"path": "../outside.txt"}, "result_status": "success",
    }
    record.update(changes)
    return record


def get_boundary_alert(records):
    return next(alert for alert in evaluate_records(records) if "AW-001" in alert["policy_id"])


class TestCausalProvenance(unittest.TestCase):

    def test_prior_source(self):
        alert = get_boundary_alert([create_fetch(), create_access()])
        self.assertEqual(alert["events"][0]["prior_sources"][0]["seq"], 1)
        self.assertEqual(alert["correlated_event_count"], 1)

    def test_failed_fetch(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(result_status="error"), create_access()])["correlated_event_count"],
            0,
        )

    def test_blocked_fetch(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(result_status="blocked"), create_access()])["correlated_event_count"],
            0,
        )

    def test_approved_source(self):
        source = create_fetch(arguments={"url": "https://intranet.example/vendor-readme"})
        self.assertEqual(
            get_boundary_alert([source, create_access()])["correlated_event_count"],
            0,
        )

    def test_different_task(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(task_id="other"), create_access()])["correlated_event_count"],
            0,
        )

    def test_different_session(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(session_id="other"), create_access()])["correlated_event_count"],
            0,
        )

    def test_later_fetch(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(3), create_access()])["correlated_event_count"],
            0,
        )

    def test_out_of_order(self):
        self.assertEqual(
            get_boundary_alert([create_access(), create_fetch()])["correlated_event_count"],
            1,
        )

    def test_duplicate_sequence(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(2), create_access()])["correlated_event_count"],
            0,
        )

    def test_missing_sequence(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(None), create_access()])["correlated_event_count"],
            0,
        )

    def test_missing_url(self):
        self.assertEqual(
            get_boundary_alert([create_fetch(arguments={}), create_access()])["correlated_event_count"],
            0,
        )

    def test_failed_access(self):
        alert = get_boundary_alert([create_fetch(), create_access(result_status="error")])
        self.assertEqual(alert["correlated_event_count"], 1)
        self.assertEqual(alert["severity"], "medium")

    def test_grouped_events(self):
        alert = get_boundary_alert([create_access(1), create_fetch(2), create_access(3)])
        self.assertEqual(alert["occurrence_count"], 2)
        self.assertEqual(alert["correlated_event_count"], 1)
        self.assertEqual(alert["events"][0]["prior_sources"], [])
        self.assertEqual(alert["events"][1]["prior_sources"][0]["seq"], 2)

    def test_multiple_sources(self):
        alert = get_boundary_alert([create_fetch(1), create_fetch(2), create_access(3)])
        self.assertEqual(
            [source["seq"] for source in alert["events"][0]["prior_sources"]],
            [1, 2],
        )

    def test_score_unchanged(self):
        self.assertEqual(
            calculate_risk_score(evaluate_records([create_fetch(), create_access()])),
            45,
        )

    def test_report_evidence(self):
        records = [create_fetch(), create_access()]
        report = generate_report(records, evaluate_records(records))
        self.assertIn("Earlier successful fetch: sequence 1", report)
        self.assertIn("Temporal ordering alone does not establish causation.", report)
