import unittest
from agentward.evaluator import evaluate_record, group_findings, calculate_risk_score, classify_risk


def event(seq=1, status='success', **changes):
    record = dict(session_id='session', task_id='task', server='filesystem',
                  tool_name='read_text_file', target_resource='../outside.txt',
                  arguments={'path': '../outside.txt'}, result_status=status, seq=seq)
    record.update(changes)
    return evaluate_record(record)[0]


class TestRiskScoring(unittest.TestCase):
    def test_duplicates(self):
        alerts = group_findings([event(1), event(2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['occurrence_count'], 2)
        self.assertEqual(calculate_risk_score(alerts), 30)

    def test_highest_severity(self):
        alerts = group_findings([event(1, 'error'), event(2)])
        self.assertEqual(alerts[0]['severity'], 'high')
        self.assertEqual([e['result_status'] for e in alerts[0]['events']], ['error', 'success'])

    def test_different_tasks(self):
        self.assertEqual(len(group_findings([event(), event(task_id='other')])), 2)

    def test_different_sessions(self):
        self.assertEqual(len(group_findings([event(), event(session_id='other')])), 2)

    def test_different_targets(self):
        self.assertEqual(len(group_findings([event(), event(target_resource='../other.txt')])), 2)

    def test_incomplete_identifiers(self):
        self.assertEqual(len(group_findings([event(task_id=''), event(2, task_id='')])), 2)

    def test_uncapped_accumulation(self):
        alerts = group_findings([event(task_id=str(i)) for i in range(5)])
        self.assertEqual(calculate_risk_score(alerts), 150)

    def test_medium_band(self):
        alerts = group_findings([event(status='error', task_id=str(i)) for i in range(8)])
        self.assertEqual(classify_risk(alerts), 'Medium')

    def test_high_band(self):
        self.assertEqual(classify_risk(group_findings([event()])), 'High')

    def test_low_band(self):
        self.assertEqual(classify_risk([{'severity': 'low', 'risk_points': 5}]*20), 'Low')

    def test_empty(self):
        self.assertEqual(calculate_risk_score([]), 0)
        self.assertEqual(classify_risk([]), 'Low')

    def test_policy_union(self):
        first = event()
        second = event(2)
        second['policies'] = [dict(policy_id='AW-007', policy_name='excessive_tool_usage', severity='medium', reason='Threshold reached')]
        second.update(policy_id='AW-007', severity='medium', risk_points=15, reason='Threshold reached')
        alert = group_findings([first, second])[0]
        self.assertEqual(set(alert['policy_id'].split(', ')), {'AW-001', 'AW-007'})
        self.assertEqual(len(alert['events']), 2)
