import json
import tempfile
import unittest
from pathlib import Path

from windows_event_analyzer import analyze, xml_events


class WindowsEventAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.sample = Path(__file__).resolve().parents[1] / 'data' / 'sample_windows_events.xml'

    def test_windows_event_mapping(self):
        records = list(xml_events(self.sample))
        self.assertEqual(len(records), 12)
        self.assertEqual([row['status'] for row in records].count('failure'), 9)
        self.assertEqual([row['status'] for row in records].count('success'), 2)
        self.assertEqual([row['status'] for row in records].count('locked'), 1)
        self.assertEqual([row['src_ip'] for row in records if row['event_id'] == 4740], ['unknown'])

    def test_detection_and_lockout_alert(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            total, auth, count = analyze(
                self.sample,
                base / 'events.jsonl',
                base / 'auth.jsonl',
                base / 'alerts.json',
            )
            alerts = json.loads((base / 'alerts.json').read_text(encoding='utf-8'))
            self.assertEqual(total, 12)
            self.assertEqual(auth, 10)  # 9 failed + 1 success, excluding local login with no IP
            self.assertEqual(count, 4)
            self.assertEqual(
                {a['rule'] for a in alerts},
                {'brute_force', 'password_spraying', 'success_after_failures', 'account_lockout'},
            )
            self.assertEqual(next(a for a in alerts if a['rule'] == 'account_lockout')['src_ip'], 'unknown')

    def test_no_unknown_ip_auth_correlations(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            analyze(self.sample, base / 'events.jsonl', base / 'auth.jsonl', base / 'alerts.json')
            auth = [json.loads(line) for line in (base / 'auth.jsonl').read_text(encoding='utf-8').splitlines()]
            self.assertTrue(all(item['src_ip'] != 'unknown' for item in auth))


if __name__ == '__main__':
    unittest.main()
