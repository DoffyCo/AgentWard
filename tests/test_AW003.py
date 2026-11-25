import unittest
from agentward.evaluator import evaluate_record, REPO_ROOT


def create_record(path, status="success", server="filesystem", tool="read_text_file", target=None):
    return {
        "session_id": "test-session",
        "task_id": "test-task",
        "server": server,
        "tool_name": tool,
        "arguments": {"path": path},
        "target_resource": path if target is None else target,
        "result_status": status,
        "scenario_tag": "clean",
    }


def get_aw003_matches(record):
    return [match for finding in evaluate_record(record)
            for match in finding["policies"] if match["policy_id"] == "AW-003"]


class TestAW003(unittest.TestCase):
    def test_pci_resource(self):
        matches = get_aw003_matches(create_record("data/customer_sample.csv"))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")
        self.assertIn("PCI", matches[0]["reason"])
        self.assertIn("security-lead", matches[0]["reason"])

    def test_template_resource(self):
        matches = get_aw003_matches(create_record(".env.example"))
        self.assertEqual(matches[0]["severity"], "low")

    def test_failed_access(self):
        matches = get_aw003_matches(create_record("data/customer_sample.csv", "error"))
        self.assertEqual(matches[0]["severity"], "medium")

    def test_blocked_access(self):
        matches = get_aw003_matches(create_record("data/customer_sample.csv", "blocked"))
        self.assertEqual(matches[0]["severity"], "medium")

    def test_unknown_status(self):
        matches = get_aw003_matches(create_record("data/customer_sample.csv", ""))
        self.assertEqual(matches[0]["severity"], "medium")

    def test_absolute_path(self):
        self.assertEqual(len(get_aw003_matches(create_record(str(REPO_ROOT / "data/customer_sample.csv")))), 1)

    def test_normalized_path(self):
        self.assertEqual(len(get_aw003_matches(create_record("data/../data/customer_sample.csv"))), 1)

    def test_unclassified_resource(self):
        self.assertEqual(get_aw003_matches(create_record("src/checkout.js")), [])

    def test_keyword_not_classification(self):
        self.assertEqual(get_aw003_matches(create_record("patient-notes.txt")), [])

    def test_outside_secret(self):
        record = create_record("../data/secret-outside-sandbox.txt", server="git", tool="git_show_worktree")
        self.assertEqual(get_aw003_matches(record), [])
        self.assertIn("AW-001", evaluate_record(record)[0]["policy_id"])

    def test_actual_argument_preferred(self):
        self.assertEqual(len(get_aw003_matches(create_record("data/customer_sample.csv", target="src/checkout.js"))), 1)

    def test_git_worktree(self):
        self.assertEqual(len(get_aw003_matches(create_record(".env.example", server="git", tool="git_show_worktree"))), 1)

    def test_git_diff_explicit_path(self):
        record = create_record(".env.example", server="git", tool="git_diff")
        record["arguments"] = {"ref": "HEAD", "pathspec": ".env.example"}
        self.assertEqual(len(get_aw003_matches(record)), 1)

    def test_unrelated_tool(self):
        self.assertEqual(get_aw003_matches(create_record(".env.example", server="memory", tool="memory_set")), [])


if __name__ == "__main__":
    unittest.main()
