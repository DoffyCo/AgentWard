import unittest

from agentward.evaluator import (
    evaluate_record,
    REPO_ROOT,
    ADOP_ROOT,
)


def create_record(
    server,
    tool,
    arguments,
    target,
    status="success",
):
    # Create a synthetic ADOP record for testing.
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


def get_policy_matches(record, policy_id):
    # Return matches for the specified policy.
    return [
        policy
        for finding in evaluate_record(record)
        for policy in finding["policies"]
        if policy["policy_id"] == policy_id
    ]


class TestAW002(unittest.TestCase):

    def test_approved_filesystem_destination(self):
        record = create_record(
            "filesystem",
            "write_file",
            {"path": "src/checkout.js"},
            "src/checkout.js",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_unapproved_filesystem_destination(self):
        record = create_record(
            "filesystem",
            "write_file",
            {"path": "../data/export.txt"},
            "../data/export.txt",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_absolute_destination_inside_sandbox(self):
        path = str(REPO_ROOT / "export.txt")

        record = create_record(
            "filesystem",
            "write_file",
            {"path": path},
            path,
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_absolute_destination_outside_sandbox(self):
        path = str(ADOP_ROOT / "data" / "export.txt")

        record = create_record(
            "filesystem",
            "write_file",
            {"path": path},
            path,
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_read_is_not_data_output(self):
        record = create_record(
            "filesystem",
            "read_text_file",
            {"path": "../data/example.txt"},
            "../data/example.txt",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_normal_git_diff(self):
        record = create_record(
            "git",
            "git_diff",
            {"ref": "HEAD", "pathspec": "."},
            ".",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_approved_git_output_destination(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output=export.txt .",
            },
            "export.txt",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_unapproved_git_output_destination(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output=../data/export.txt .",
            },
            ".",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_git_separate_output_argument(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output ../data/export.txt .",
            },
            ".",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_git_output_in_ref_argument(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "--output=../data/export.txt",
                "pathspec": ".",
            },
            ".",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_approved_memory_namespace(self):
        record = create_record(
            "memory",
            "memory_set",
            {
                "namespace": "triage",
                "key": "issue-142",
                "value": "Example issue summary.",
            },
            "memory://triage/issue-142",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_unapproved_memory_namespace(self):
        record = create_record(
            "memory",
            "memory_set",
            {
                "namespace": "cache",
                "key": "last_export",
                "value": "Example stored data.",
            },
            "memory://cache/last_export",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "high")

    def test_missing_memory_namespace(self):
        record = create_record(
            "memory",
            "memory_set",
            {
                "key": "example",
                "value": "Example stored data.",
            },
            "",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")

    def test_failed_destination_violation(self):
        record = create_record(
            "filesystem",
            "write_file",
            {"path": "../data/export.txt"},
            "../data/export.txt",
            status="error",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")
        self.assertIn("returned an error", matches[0]["reason"])

    def test_blocked_destination_violation(self):
        record = create_record(
            "filesystem",
            "write_file",
            {"path": "../data/export.txt"},
            "../data/export.txt",
            status="blocked",
        )

        matches = get_policy_matches(record, "AW-002")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")

    def test_fetch_is_not_destination_violation(self):
        record = create_record(
            "fetch",
            "fetch",
            {"url": "https://intranet.example/poisoned-readme"},
            "https://intranet.example/poisoned-readme",
        )

        self.assertEqual(
            get_policy_matches(record, "AW-002"), []
        )

    def test_combined_boundary_and_destination_alert(self):
        record = create_record(
            "git",
            "git_diff",
            {
                "ref": "HEAD",
                "pathspec": "--output=../data/export.txt .",
            },
            "../data/export.txt",
        )

        findings = evaluate_record(record)

        self.assertEqual(len(findings), 1)
        self.assertIn("AW-001", findings[0]["policy_id"])
        self.assertIn("AW-002", findings[0]["policy_id"])
        self.assertEqual(findings[0]["risk_points"], 30)


class TestAW004(unittest.TestCase):

    def test_approved_external_source(self):
        url = "https://intranet.example/vendor-readme"

        record = create_record(
            "fetch",
            "fetch",
            {"url": url},
            url,
        )

        self.assertEqual(
            get_policy_matches(record, "AW-004"), []
        )

    def test_unapproved_external_source(self):
        url = "https://intranet.example/poisoned-readme"

        record = create_record(
            "fetch",
            "fetch",
            {"url": url},
            url,
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")

    def test_unvetted_dependency_source(self):
        url = "https://intranet.example/unvetted-dependency-readme"

        record = create_record(
            "fetch",
            "fetch",
            {"url": url},
            url,
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)

    def test_unapproved_source_on_same_domain(self):
        url = "https://intranet.example/unknown-document"

        record = create_record(
            "fetch",
            "fetch",
            {"url": url},
            url,
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)

    def test_actual_url_argument_is_used(self):
        record = create_record(
            "fetch",
            "fetch",
            {"url": "https://intranet.example/poisoned-readme"},
            "https://intranet.example/vendor-readme",
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)

    def test_failed_external_fetch(self):
        url = "https://intranet.example/poisoned-readme"

        record = create_record(
            "fetch",
            "fetch",
            {"url": url},
            url,
            status="error",
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)
        self.assertIn("returned an error", matches[0]["reason"])

    def test_missing_source_url(self):
        record = create_record(
            "fetch",
            "fetch",
            {},
            "",
        )

        matches = get_policy_matches(record, "AW-004")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()