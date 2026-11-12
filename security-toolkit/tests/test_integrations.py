import json
import tempfile
import unittest
from pathlib import Path
from integrations import import_file, normalize_record, clean


class IntegrationImportTests(unittest.TestCase):
    def test_nuclei_jsonl_import(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "nuclei.jsonl"
            path.write_text(json.dumps({
                "template-id": "missing-header", "matched-at": "https://demo.local",
                "info": {"name": "Missing header", "severity": "low", "description": "Header absent"}
            }) + "\n", encoding="utf-8")
            rows = import_file("nuclei", path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["severity"], "LOW")

    def test_subfinder_import_is_informational(self):
        row = normalize_record("subfinder", {"host": "sub.example.test"})
        self.assertEqual(row["severity"], "INFORMATIONAL")

    def test_httpx_metadata_is_not_a_vulnerability(self):
        row = normalize_record("httpx", {"url": "https://example.test", "status_code": 200})
        self.assertEqual(row["severity"], "INFORMATIONAL")
        self.assertIn("not a vulnerability", row["description"])

    def test_secrets_are_redacted(self):
        self.assertIn("[REDACTED]", clean("Authorization: Bearer abc123"))

    def test_zap_json_import(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "zap.json"
            path.write_text(json.dumps({"site": [{"@name": "https://demo.local", "alerts": [
                {"alert": "CSP missing", "riskcode": "2", "url": "https://demo.local", "solution": "Set CSP"}
            ]}]}), encoding="utf-8")
            rows = import_file("zap", path)
            self.assertEqual(rows[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
