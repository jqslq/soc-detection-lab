import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detector import detect, load_events


class DetectorTests(unittest.TestCase):
    def test_sample_detects_three_scenarios(self):
        events = load_events(Path(__file__).resolve().parents[1] / 'data/sample_auth.jsonl')
        rules = {a['rule'] for a in detect(events)}
        self.assertEqual(rules, {'brute_force', 'password_spraying', 'success_after_failures'})

    def test_benign_is_clean(self):
        events = load_events(Path(__file__).resolve().parents[1] / 'data/benign_auth.jsonl')
        self.assertEqual(detect(events), [])

    def test_missing_fields_raise(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'broken.jsonl'
            path.write_text(json.dumps({'timestamp': '2026-10-15T10:00:00Z'}))
            with self.assertRaises(ValueError):
                load_events(path)


if __name__ == '__main__':
    unittest.main()
