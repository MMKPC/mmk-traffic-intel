import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mmk_traffic_intel.analyzer import analyze, load_records


ROOT = Path(__file__).parents[1]


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ROOT / "fixtures" / "cloudflare.sample.ndjson"
        self.records = load_records(self.fixture)

    def test_loads_ndjson_and_counts_requests(self):
        payload = analyze(self.records)
        self.assertEqual(payload["summary"]["total_requests"], 7)
        self.assertEqual(payload["summary"]["unique_origin_ips"], 3)

    def test_redacts_ips_and_removes_query_strings(self):
        payload = analyze(self.records)
        self.assertTrue(payload["investigation"]["privacy"]["public_safe"])
        serialized = json.dumps(payload)
        self.assertNotIn("198.51.100.7", serialized)
        self.assertNotIn("secret=", serialized)
        self.assertTrue(all(item["origin_ip"].startswith("source_") for item in payload["sessions"]))

    def test_flags_probe_and_keeps_normal_bot_distinct(self):
        payload = analyze(self.records)
        intents = {session["intent"] for session in payload["sessions"]}
        self.assertIn("Active Scanning", intents)
        self.assertIn("Crawler or Bot", intents)
        self.assertIn("Browser Traffic", intents)

    def test_keep_ip_is_explicitly_not_public_safe(self):
        payload = analyze(self.records, keep_ip=True)
        self.assertFalse(payload["investigation"]["privacy"]["public_safe"])
        self.assertTrue(any(item["origin_ip"] == "198.51.100.7" for item in payload["sessions"]))

    def test_enrichment_is_attached_to_pseudonymous_source(self):
        payload = analyze(self.records, enrichment={"198.51.100.7": {"status": "ok", "network_name": "Example"}})
        source = payload["investigation"]["sources"][0]
        self.assertTrue(source["source_id"].startswith("source_"))
        self.assertEqual(source["rdap"]["network_name"], "Example")
        self.assertNotIn("198.51.100.7", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
