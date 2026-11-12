import unittest
from nexora_security import ScopeError, is_in_scope, normalize_host, validate_url


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"authorized": [{"domain": "example.com"}], "excluded": ["private.example.com"]}

    def test_exact_domain_is_in_scope(self):
        self.assertTrue(is_in_scope("example.com", self.scope))

    def test_subdomain_is_in_scope(self):
        self.assertTrue(is_in_scope("www.example.com", self.scope))

    def test_lookalike_domain_is_not_in_scope(self):
        self.assertFalse(is_in_scope("example.com.attacker.test", self.scope))

    def test_exclusion_overrides_authorization(self):
        self.assertFalse(is_in_scope("private.example.com", self.scope))
        self.assertFalse(is_in_scope("a.private.example.com", self.scope))

    def test_out_of_scope_url_is_rejected(self):
        with self.assertRaises(ScopeError):
            validate_url("https://outside.test", self.scope)

    def test_non_http_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_url("file:///etc/passwd", self.scope)

    def test_embedded_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_url("https://user:pass@example.com", self.scope)

    def test_wildcard_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_host("*.example.com")


if __name__ == "__main__":
    unittest.main()
