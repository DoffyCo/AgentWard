import unittest

from agentward.evaluator import evaluate_records


def event(seq, args=None, status="success", task="task", session="session"):
    return dict(seq=seq, session_id=session, task_id=task, server="git",
                tool_name="git_status", arguments={} if args is None else args,
                result_status=status, target_resource="git:git_status")


def get_aw007_matches(records):
    # Inspect individual events within each grouped alert.
    return {
        event["seq"]: match["severity"]
        for finding in evaluate_records(records)
        for event in finding.get("events", [finding])
        for match in event["policies"]
        if match["policy_id"] == "AW-007"
    }


class TestAW007(unittest.TestCase):

    def test_normal(self):
        self.assertEqual(get_aw007_matches([event(sequence) for sequence in range(1, 5)]), {})

    def test_repeated_thresholds(self):
        self.assertEqual(
            get_aw007_matches([event(sequence) for sequence in range(1, 13)]),
            {5: "medium", 10: "high"},
        )

    def test_task_thresholds(self):
        self.assertEqual(
            get_aw007_matches([event(sequence, {"n": sequence}) for sequence in range(1, 32)]),
            {15: "medium", 30: "high"},
        )

    def test_failure_thresholds(self):
        self.assertEqual(
            get_aw007_matches([event(sequence, status="error") for sequence in range(1, 9)]),
            {3: "medium", 5: "medium", 6: "high"},
        )

    def test_success_resets_failures(self):
        self.assertEqual(
            get_aw007_matches([event(1, status="error"), event(2), event(3, status="error"), event(4, status="error")]),
            {},
        )

    def test_different_operation_resets_failures(self):
        self.assertEqual(
            get_aw007_matches([event(1, status="error"), event(2, {"x": 1}, "error"), event(3, status="error"), event(4, status="error")]),
            {},
        )

    def test_blocked_not_error(self):
        self.assertEqual(get_aw007_matches([event(sequence, status="blocked") for sequence in range(1, 5)]), {})

    def test_blocked_resets_failures(self):
        self.assertEqual(
            get_aw007_matches([event(1, status="error"), event(2, status="blocked"), event(3, status="error"), event(4, status="error")]),
            {},
        )

    def test_different_arguments(self):
        self.assertEqual(get_aw007_matches([event(sequence, {"n": sequence}) for sequence in range(1, 10)]), {})

    def test_argument_key_order(self):
        self.assertEqual(
            get_aw007_matches([event(sequence, {"a": 1, "b": 2} if sequence % 2 else {"b": 2, "a": 1}) for sequence in range(1, 6)]),
            {5: "medium"},
        )

    def test_different_tasks(self):
        self.assertEqual(get_aw007_matches([event(sequence, task=str(sequence % 2)) for sequence in range(1, 9)]), {})

    def test_different_sessions(self):
        self.assertEqual(
            get_aw007_matches([event(sequence, session=str(sequence % 2)) for sequence in range(1, 9)]),
            {},
        )

    def test_out_of_order(self):
        self.assertEqual(
            get_aw007_matches([event(sequence) for sequence in range(10, 0, -1)]),
            {5: "medium", 10: "high"},
        )

    def test_missing_sequence(self):
        self.assertEqual(get_aw007_matches([event(None) for _ in range(6)]), {})

    def test_duplicate_sequence(self):
        self.assertEqual(get_aw007_matches([event(sequence) for sequence in (1, 2, 3, 4, 4, 5)]), {})

    def test_missing_arguments(self):
        records = [event(sequence) for sequence in range(1, 6)]
        for record in records:
            del record["arguments"]
        self.assertEqual(get_aw007_matches(records), {})

    def test_combined_thresholds(self):
        records = [event(sequence, {"n": sequence}) for sequence in range(1, 11)] + [event(sequence) for sequence in range(11, 16)]
        findings = evaluate_records(records)
        self.assertEqual(get_aw007_matches(records), {15: "medium"})
        self.assertEqual(len(findings), 1)
        self.assertIn("Recorded tool calls", findings[0]["reason"])
        self.assertIn("Identical tool calls", findings[0]["reason"])

    def test_highest_severity(self):
        records = [event(sequence, {"n": sequence}) for sequence in range(1, 6)] + [event(sequence) for sequence in range(6, 16)]
        self.assertEqual(get_aw007_matches(records), {10: "medium", 15: "high"})


if __name__ == "__main__":
    unittest.main()
