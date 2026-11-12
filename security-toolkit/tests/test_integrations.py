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


    def test_redacts_common_nested_credentials_and_url_auth(self):
        raw = {"headers": {"Cookie": "session=abc", "Authorization": "Bearer xyz"}, "url": "https://user:pass@example.test"}
        result = clean(raw)
        self.assertNotIn("session=abc", result)
        self.assertNotIn("Bearer xyz", result)
        self.assertNotIn("user:pass@", result)
        self.assertIn("[REDACTED]", result)

    def test_rejects_unknown_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "in.txt"
            path.write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError):
                import_file("unknown", path)

    def test_rejects_malformed_jsonl(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.jsonl"
            path.write_text("{not-json}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid JSON"):
                import_file("nuclei", path)

    def test_markdown_report_uses_real_line_breaks(self):
        report = __import__("integrations").markdown_report("nuclei", [])
        self.assertIn("\\n- Records: 0\\n", report)

    def test_zap_record_limit_is_enforced(self):
        from integrations import parse_zap, MAX_RECORDS
        alerts = [{"alert": "test"} for _ in range(MAX_RECORDS + 1)]
        with self.assertRaisesRegex(ValueError, "10,000"):
            parse_zap({"site": [{"alerts": alerts}]})

if __name__ == "__main__":
    unittest.main()
