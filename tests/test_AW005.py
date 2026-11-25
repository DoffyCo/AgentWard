import unittest

from agentward.evaluator import evaluate_records


CONTENT = (
    "Synthetic restricted resource content for testing persistence. "
    "This deliberately long example provides enough text for correlation."
)


def create_read(path="src/checkout.js", **changes):
    record = {
        "session_id": "test-session", "task_id": "test-task", "seq": 1,
        "server": "filesystem", "tool_name": "read_text_file",
        "arguments": {"path": path}, "target_resource": path,
        "result_status": "success", "result_summary": CONTENT,
    }
    record.update(changes)
    return record


def create_write(value=CONTENT, namespace="triage", **changes):
    record = {
        "session_id": "test-session", "task_id": "test-task", "seq": 2,
        "server": "memory", "tool_name": "memory_set",
        "arguments": {"namespace": namespace, "key": "note", "value": value},
        "target_resource": f"memory://{namespace}/note", "result_status": "success",
    }
    record.update(changes)
    return record


def get_aw005_matches(records):
    return [match for finding in evaluate_records(records)
            for match in finding["policies"] if match["policy_id"] == "AW-005"]


class TestAW005(unittest.TestCase):

    def test_restricted_source(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write()])[0]["severity"],
            "high",
        )

    def test_outside_resource(self):
        source = create_read("../data/example.txt", server="git", tool_name="git_show_worktree")
        self.assertEqual(len(get_aw005_matches([source, create_write()])), 1)

    def test_tagged_resource(self):
        self.assertEqual(
            len(get_aw005_matches([create_read("data/customer_sample.csv"), create_write()])),
            1,
        )

    def test_whitespace_normalization(self):
        self.assertEqual(
            len(get_aw005_matches([create_read(), create_write(CONTENT.replace(" ", "\n"))])),
            1,
        )

    def test_truncated_memory_value(self):
        self.assertEqual(
            len(get_aw005_matches([create_read(), create_write(CONTENT[:90])])),
            1,
        )

    def test_truncated_summary(self):
        self.assertEqual(
            len(get_aw005_matches([create_read(result_summary=CONTENT[:90]), create_write()])),
            1,
        )

    def test_unrelated_value(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write("Ordinary task notes")]),
            [],
        )

    def test_short_match(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(CONTENT[:20])]),
            [],
        )

    def test_unclassified_source(self):
        self.assertEqual(
            get_aw005_matches([create_read("README.md"), create_write()]),
            [],
        )

    def test_different_task(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(task_id="other")]),
            [],
        )

    def test_different_session(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(session_id="other")]),
            [],
        )

    def test_later_read(self):
        self.assertEqual(get_aw005_matches([create_read(seq=3), create_write()]), [])

    def test_failed_read(self):
        self.assertEqual(
            get_aw005_matches([create_read(result_status="error"), create_write()]),
            [],
        )

    def test_failed_write(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(result_status="error")])[0]["severity"],
            "medium",
        )

    def test_blocked_write(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(result_status="blocked")])[0]["severity"],
            "medium",
        )

    def test_unknown_write_status(self):
        self.assertEqual(
            get_aw005_matches([create_read(), create_write(result_status="")])[0]["severity"],
            "medium",
        )

    def test_missing_sequence(self):
        self.assertEqual(get_aw005_matches([create_read(), create_write(seq=None)]), [])

    def test_combined_destination_and_persistence(self):
        findings = evaluate_records([create_read(), create_write(namespace="cache")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["policy_id"], "AW-002, AW-005")
        self.assertEqual(findings[0]["risk_points"], 30)


if __name__ == "__main__":
    unittest.main()
