import json
import unittest

from agentward.evaluator import evaluate_records


def create_event(seq, server, tool, arguments, status="success", task="task"):
    return dict(seq=seq, session_id="session", task_id=task, server=server,
                tool_name=tool, arguments=arguments, result_status=status,
                target_resource=arguments.get("path", "commit"))


def create_manifest_write(seq=1, dependencies=None, section="dependencies", **kwargs):
    return create_event(seq, "filesystem", "write_file", {"path": "package.json", "content": json.dumps({section: dependencies if dependencies is not None else {"example-unapproved": "1.0.0"}})}, **kwargs)


def create_stage(seq=2, **kwargs):
    return create_event(seq, "git", "git_add", {"path": "package.json"}, **kwargs)


def create_commit(seq=3, **kwargs):
    return create_event(seq, "git", "git_commit", {"message": "update"}, **kwargs)


def get_aw006_matches(records):
    return {finding["seq"]: match["severity"] for finding in evaluate_records(records) for match in finding["policies"] if match["policy_id"] == "AW-006"}


class TestAW006(unittest.TestCase):

    def test_approved(self):
        self.assertEqual(get_aw006_matches([create_manifest_write(dependencies={"fast-json-patch": "^3.1.1"})]), {})

    def test_unapproved(self):
        self.assertEqual(get_aw006_matches([create_manifest_write()]), {1: "high"})

    def test_version_change(self):
        self.assertEqual(get_aw006_matches([create_manifest_write(dependencies={"fast-uuid": "^0.5.0"})]), {1: "high"})

    def test_other_sections(self):
        for section in ("devDependencies", "optionalDependencies", "peerDependencies"):
            with self.subTest(section=section):
                self.assertEqual(get_aw006_matches([create_manifest_write(section=section)]), {1: "high"})

    def test_invalid_json(self):
        record = create_manifest_write()
        record["arguments"]["content"] = "not json"
        self.assertEqual(get_aw006_matches([record]), {1: "medium"})

    def test_invalid_section(self):
        self.assertEqual(get_aw006_matches([create_manifest_write(dependencies=[])]), {1: "medium"})

    def test_failed_write(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(status="error"), create_stage(), create_commit()]),
            {1: "medium"},
        )

    def test_blocked_write(self):
        self.assertEqual(get_aw006_matches([create_manifest_write(status="blocked")]), {1: "medium"})

    def test_chain(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(), create_commit()]),
            {1: "high", 2: "high", 3: "high"},
        )

    def test_failed_stage(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(status="error"), create_commit()]),
            {1: "high", 2: "medium"},
        )

    def test_failed_commit(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(), create_commit(status="error")]),
            {1: "high", 2: "high", 3: "medium"},
        )

    def test_corrective_write_before_stage(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_manifest_write(2, dependencies={}), create_stage(3), create_commit(4)]),
            {1: "high"},
        )

    def test_corrective_write_after_stage(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(), create_manifest_write(3, dependencies={}), create_commit(4)]),
            {1: "high", 2: "high", 4: "high"},
        )

    def test_corrective_restage(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(), create_manifest_write(3, dependencies={}), create_stage(4), create_commit(5)]),
            {1: "high", 2: "high"},
        )

    def test_commit_consumes_stage(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(), create_commit(), create_commit(4)]),
            {1: "high", 2: "high", 3: "high"},
        )

    def test_different_task(self):
        self.assertEqual(
            get_aw006_matches([create_manifest_write(), create_stage(task="other"), create_commit(task="other")]),
            {1: "high"},
        )

    def test_unrelated_commit(self):
        self.assertEqual(get_aw006_matches([create_commit()]), {})

    def test_unrelated_file(self):
        record = create_manifest_write()
        record["arguments"]["path"] = "other.json"
        self.assertEqual(get_aw006_matches([record]), {})

    def test_different_session(self):
        record = create_stage()
        record["session_id"] = "other"
        self.assertEqual(get_aw006_matches([create_manifest_write(), record, create_commit()]), {1: "high"})

    def test_out_of_order(self):
        self.assertEqual(
            get_aw006_matches([create_commit(), create_stage(), create_manifest_write()]),
            {1: "high", 2: "high", 3: "high"},
        )


if __name__ == "__main__":
    unittest.main()
