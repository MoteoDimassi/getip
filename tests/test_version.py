import ast
import os
import re
import unittest

from getip import VERSION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# так getip 1.3 и старше ищут версию в скачанном getip.py
OLD_CLIENT_RE = re.compile(r'^VERSION = "([\d.]+)"', re.M)


class VersionTest(unittest.TestCase):
    def test_launcher_matches_package(self):
        with open(os.path.join(ROOT, "getip.py"), encoding="utf-8") as f:
            text = f.read()
        ast.parse(text)  # старые версии проверяют, что скачанный файл — это Python
        m = OLD_CLIENT_RE.search(text[:8192])  # и читают только первые 8 КБ
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), VERSION)


if __name__ == "__main__":
    unittest.main()
