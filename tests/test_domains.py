import unittest

from getip.domains import base_domain, is_noise, matches, normalize_domain


class DomainsTest(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("https://www.Claude.ai/new?x=1"), "claude.ai")
        self.assertEqual(normalize_domain("user@api.example.com:8443"), "api.example.com")
        self.assertEqual(normalize_domain("пример.рф"), "xn--e1afmkfd.xn--p1ai")
        self.assertIsNone(normalize_domain("not a domain"))
        self.assertIsNone(normalize_domain(""))

    def test_matches(self):
        self.assertTrue(matches("api.claude.ai.", "claude.ai"))
        self.assertFalse(matches("notclaude.ai", "claude.ai"))

    def test_base_domain_and_noise(self):
        self.assertEqual(base_domain("cdn.x.example.com"), "example.com")
        self.assertEqual(base_domain("a.b.co.uk"), "b.co.uk")
        self.assertTrue(is_noise("gateway.icloud.com"))
        self.assertTrue(is_noise("1.0.168.192.in-addr.arpa"))
        self.assertFalse(is_noise("claude.ai"))


if __name__ == "__main__":
    unittest.main()
