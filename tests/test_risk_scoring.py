import unittest

from agentward.evaluator import evaluate_record, group_findings, calculate_risk_score, classify_risk


def create_finding(seq=1, status="success", **changes):
    record = dict(session_id="session", task_id="task", server="filesystem",
                  tool_name="read_text_file", target_resource="../outside.txt",
                  arguments={"path": "../outside.txt"}, result_status=status, seq=seq)
    record.update(changes)
    return evaluate_record(record)[0]


class TestRiskScoring(unittest.TestCase):

    def test_duplicates(self):
        alerts = group_findings([create_finding(1), create_finding(2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["occurrence_count"], 2)
        self.assertEqual(calculate_risk_score(alerts), 30)

    def test_highest_severity(self):
        alerts = group_findings([create_finding(1, "error"), create_finding(2)])
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(
            [event["result_status"] for event in alerts[0]["events"]],
            ["error", "success"],
        )

    def test_different_tasks(self):
        self.assertEqual(len(group_findings([create_finding(), create_finding(task_id="other")])), 2)

    def test_different_sessions(self):
        self.assertEqual(len(group_findings([create_finding(), create_finding(session_id="other")])), 2)

    def test_different_targets(self):
        self.assertEqual(
            len(group_findings([create_finding(), create_finding(target_resource="../other.txt")])),
            2,
        )

    def test_incomplete_identifiers(self):
        self.assertEqual(
            len(group_findings([create_finding(task_id=""), create_finding(2, task_id="")])),
            2,
        )

    def test_uncapped_accumulation(self):
        alerts = group_findings([create_finding(task_id=str(index)) for index in range(5)])
        self.assertEqual(calculate_risk_score(alerts), 150)

    def test_medium_band(self):
        alerts = group_findings([create_finding(status="error", task_id=str(index)) for index in range(8)])
        self.assertEqual(classify_risk(alerts), "Medium")

    def test_high_band(self):
        self.assertEqual(classify_risk(group_findings([create_finding()])), "High")

    def test_low_band(self):
        self.assertEqual(
            classify_risk([{"severity": "low", "risk_points": 5}] * 20),
            "Low",
        )

    def test_empty(self):
        self.assertEqual(calculate_risk_score([]), 0)
        self.assertEqual(classify_risk([]), "Low")

    def test_policy_union(self):
        first = create_finding()
        second = create_finding(2)
        second["policies"] = [dict(policy_id="AW-007", policy_name="excessive_tool_usage", severity="medium", reason="Threshold reached")]
        second.update(policy_id="AW-007", severity="medium", risk_points=15, reason="Threshold reached")
        alert = group_findings([first, second])[0]
        self.assertEqual(set(alert["policy_id"].split(", ")), {"AW-001", "AW-007"})
        self.assertEqual(len(alert["events"]), 2)
