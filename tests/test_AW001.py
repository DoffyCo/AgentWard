import unittest

from agentward.evaluator import evaluate_record, ADOP_ROOT, REPO_ROOT


# Create a test ADOP record for policy testing.
def create_record(server, tool, arguments, target, status="success"):
    return {
        "session_id": "test-session",
        "task_id": "test-task",
        "server": server,
        "tool_name": tool,
        "arguments": arguments,
        "target_resource": target,
        "result_status": status,
        "scenario_tag": "clean",
    }


# Return only AW-001 policy matches.
def get_aw001_matches(record):
    findings = evaluate_record(record)

    return [
        policy
        for finding in findings
        for policy in finding.get("policies", [])
        if policy.get("policy_id") == "AW-001"
    ]


class TestAW001(unittest.TestCase):

    def test_normal_filesystem_access(self):
        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": "src/checkout.js"},
            "src/checkout.js",
        )

        self.assertEqual(get_aw001_matches(record), [])

    def test_normal_git_diff(self):
        record = create_record(
            "git",
            "git_diff",
            {"ref": "HEAD", "pathspec": "."},
            ".",
        )

        self.assertEqual(get_aw001_matches(record), [])

    def test_relative_path_outside_sandbox(self):
        record = create_record(
            "git",
            "git_show_worktree",
            {"path": "../data/example.txt"},
            "../data/example.txt",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_absolute_path_outside_sandbox(self):
        path = str(ADOP_ROOT / "data" / "example.txt")

        record = create_record(
            "git",
            "git_show_worktree",
            {"path": path},
            path,
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_absolute_path_inside_sandbox(self):
        path = str(REPO_ROOT / "src" / "checkout.js")

        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": path},
            path,
        )

        self.assertEqual(get_aw001_matches(record), [])

    def test_git_argument_injection(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output=../data/example.txt .",
            },
            ".",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")
        self.assertIn("unexpected Git option", matches[0]["reason"])
        self.assertIn("outside", matches[0]["reason"])

    def test_git_separate_output_argument(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output ../data/example.txt .",
            },
            ".",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")
        self.assertIn("outside", matches[0]["reason"])

    def test_git_init_outside_sandbox(self):
        record = create_record(
            "git",
            "git_init",
            {"target_path": "unauthorized-repo"},
            "unauthorized-repo",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_failed_boundary_violation(self):
        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": "../data/example.txt"},
            "../data/example.txt",
            "error",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")
        self.assertIn("returned an error", matches[0]["reason"])

    def test_blocked_boundary_violation(self):
        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": "../data/example.txt"},
            "../data/example.txt",
            "blocked",
        )

        matches = get_aw001_matches(record)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")

    def test_relative_path_inside_sandbox(self):
        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": "src/../README.md"},
            "src/../README.md",
        )

        self.assertEqual(get_aw001_matches(record), [])


if __name__ == "__main__":
    unittest.main()
