import json
import unittest
from agentward.evaluator import evaluate_records


def event(seq, server, tool, arguments, status="success", task="task"):
    return dict(seq=seq, session_id="session", task_id=task, server=server,
                tool_name=tool, arguments=arguments, result_status=status,
                target_resource=arguments.get("path", "commit"))


def write(seq=1, deps=None, section="dependencies", **kwargs):
    return event(seq, "filesystem", "write_file", {"path": "package.json", "content": json.dumps({section: deps if deps is not None else {"example-unapproved": "1.0.0"}})}, **kwargs)


def stage(seq=2, **kwargs):
    return event(seq, "git", "git_add", {"path": "package.json"}, **kwargs)


def commit(seq=3, **kwargs):
    return event(seq, "git", "git_commit", {"message": "update"}, **kwargs)


def matches(records):
    return {f["seq"]: m["severity"] for f in evaluate_records(records) for m in f["policies"] if m["policy_id"] == "AW-006"}


class TestAW006(unittest.TestCase):
    def test_approved(self):
        self.assertEqual(matches([write(deps={"fast-json-patch": "^3.1.1"})]), {})

    def test_unapproved(self):
        self.assertEqual(matches([write()]), {1: "high"})

    def test_version_change(self):
        self.assertEqual(matches([write(deps={"fast-uuid": "^0.5.0"})]), {1: "high"})

    def test_other_sections(self):
        for section in ("devDependencies", "optionalDependencies", "peerDependencies"):
            with self.subTest(section=section):
                self.assertEqual(matches([write(section=section)]), {1: "high"})

    def test_invalid_json(self):
        r = write(); r["arguments"]["content"] = "not json"
        self.assertEqual(matches([r]), {1: "medium"})

    def test_invalid_section(self):
        self.assertEqual(matches([write(deps=[])]), {1: "medium"})

    def test_failed_write(self):
        self.assertEqual(matches([write(status="error"), stage(), commit()]), {1: "medium"})

    def test_blocked_write(self):
        self.assertEqual(matches([write(status="blocked")]), {1: "medium"})

    def test_chain(self):
        self.assertEqual(matches([write(), stage(), commit()]), {1: "high", 2: "high", 3: "high"})

    def test_failed_stage(self):
        self.assertEqual(matches([write(), stage(status="error"), commit()]), {1: "high", 2: "medium"})

    def test_failed_commit(self):
        self.assertEqual(matches([write(), stage(), commit(status="error")]), {1: "high", 2: "high", 3: "medium"})

    def test_corrective_write_before_stage(self):
        self.assertEqual(matches([write(), write(2, deps={}), stage(3), commit(4)]), {1: "high"})

    def test_corrective_write_after_stage(self):
        self.assertEqual(matches([write(), stage(), write(3, deps={}), commit(4)]), {1: "high", 2: "high", 4: "high"})

    def test_corrective_restage(self):
        self.assertEqual(matches([write(), stage(), write(3, deps={}), stage(4), commit(5)]), {1: "high", 2: "high"})

    def test_commit_consumes_stage(self):
        self.assertEqual(matches([write(), stage(), commit(), commit(4)]), {1: "high", 2: "high", 3: "high"})

    def test_different_task(self):
        self.assertEqual(matches([write(), stage(task="other"), commit(task="other")]), {1: "high"})

    def test_unrelated_commit(self):
        self.assertEqual(matches([commit()]), {})

    def test_unrelated_file(self):
        r = write(); r["arguments"]["path"] = "other.json"
        self.assertEqual(matches([r]), {})

    def test_different_session(self):
        r = stage(); r["session_id"] = "other"
        self.assertEqual(matches([write(), r, commit()]), {1: "high"})

    def test_out_of_order(self):
        self.assertEqual(matches([commit(), stage(), write()]), {1: "high", 2: "high", 3: "high"})


if __name__ == "__main__":
    unittest.main()
