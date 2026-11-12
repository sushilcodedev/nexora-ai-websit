import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

import ai_assistant


class LocalApiTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ai_assistant.Handler)
        self.port = self.server.server_address[1]
        self.allowed_hosts = patch.object(ai_assistant, "ALLOWED_HOSTS", {f"127.0.0.1:{self.port}"})
        self.allowed_hosts.start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.allowed_hosts.stop()

    def get_json(self, path):
        with urlopen(self.base + path, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8")), response.headers

    def test_skills_api_lists_registered_skills(self):
        status, data, _ = self.get_json("/api/skills")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["skills"]), 8)

    def test_skill_api_returns_registered_markdown(self):
        status, data, _ = self.get_json("/api/skill?id=security-triage")
        self.assertEqual(status, 200)
        self.assertIn("Security Finding Triage", data["title"])
        self.assertIn("defensive security", data["content"])

    def test_unknown_skill_is_not_found(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(self.base + "/api/skill?id=../../README.md", timeout=3)
        self.assertEqual(error.exception.code, 404)

    def test_integration_registry_api(self):
        status, data, _ = self.get_json("/api/integrations")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(data["integrations"]), 5)

    def test_security_headers_are_present(self):
        _, _, headers = self.get_json("/api/skills")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("Content-Security-Policy", headers)

    def test_untrusted_origin_is_rejected_before_ollama(self):
        request = Request(
            self.base + "/api/analyze",
            data=b'{}',
            headers={"Content-Type": "application/json", "Origin": "https://untrusted.example"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 403)

    def test_unexpected_host_header_is_rejected(self):
        request = Request(self.base + "/api/skills", headers={"Host": "attacker.example"})
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 421)


if __name__ == "__main__":
    unittest.main()
