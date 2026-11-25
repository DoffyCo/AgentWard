import hashlib
import tempfile
import unittest
from pathlib import Path

from agentward.report import generate_audit_report, save_audit_report


class TestAuditReporting(unittest.TestCase):

    def setUp(self):
        self.input_bytes = b'{"session_id":"test"}\n'
        self.findings = [{"rank": 1, "severity": "high", "risk_points": 30,
                          "policy_id": "AW-001", "reason": "Test finding"}]
        self.decisions = {1: {"disposition": "Escalate", "rationale": "Review boundary"}}

    def report(self, reviewer="Reviewer A"):
        return generate_audit_report([], self.findings, self.input_bytes,
                                     "test.jsonl", reviewer, self.decisions)

    def test_review_fields(self):
        report = self.report()
        for value in ('Reviewer: "Reviewer A"', 'Disposition: Escalate',
                      'Rationale: "Review boundary"', 'Review timestamp (UTC):'):
            self.assertIn(value, report)

    def test_input_hash(self):
        self.assertIn(hashlib.sha256(self.input_bytes).hexdigest(), self.report())

    def test_missing_reviewer(self):
        with self.assertRaises(ValueError):
            self.report(" ")

    def test_missing_decision(self):
        self.decisions = {}
        with self.assertRaises(ValueError):
            self.report()

    def test_invalid_disposition(self):
        self.decisions[1]["disposition"] = "Allow"
        with self.assertRaises(ValueError):
            self.report()

    def test_no_alerts(self):
        self.findings = []
        self.decisions = {}
        self.assertIn("No alerts require disposition.", self.report())

    def test_report_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            report_bytes, checksum_bytes = save_audit_report(self.report(), path)
            self.assertEqual(path.read_bytes(), report_bytes)
            self.assertEqual(
                path.with_suffix(".txt.sha256").read_bytes(),
                checksum_bytes,
            )
            self.assertEqual(
                checksum_bytes.decode().split()[0],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            path.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                save_audit_report(self.report(), path)
            self.assertEqual(path.read_bytes(), b"original")

    def test_checksum_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            checksum = path.with_suffix(".txt.sha256")
            checksum.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                save_audit_report(self.report(), path)
            self.assertFalse(path.exists())
            self.assertEqual(checksum.read_bytes(), b"original")
