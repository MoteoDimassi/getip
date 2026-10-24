import ipaddress
import os
import tempfile
import unittest

from getip.config import DEFAULTS
from getip.routes import add_to_bat, read_networks, route_lines, write_bat

net = ipaddress.ip_network


class RoutesTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "Claude.bat")
        self.cfg = dict(DEFAULTS)

    def tearDown(self):
        self.dir.cleanup()

    def test_route_lines(self):
        self.assertEqual(route_lines([net("160.79.104.0/23")], self.cfg),
                         ["route add 160.79.104.0 mask 255.255.254.0 0.0.0.0"])
        self.cfg.update(persistent=True, gw="192.168.1.1")
        self.assertEqual(route_lines([net("34.0.0.0/8")], self.cfg),
                         ["route -p add 34.0.0.0 mask 255.0.0.0 192.168.1.1"])

    def test_write_and_read_back(self):
        write_bat(self.path, route_lines([net("160.79.104.0/23"), net("18.97.0.0/18")], self.cfg))
        with open(self.path, "rb") as f:
            self.assertIn(b"\r\n", f.read())  # .bat — с переводами строк Windows
        self.assertEqual(read_networks(self.path), {net("160.79.104.0/23"), net("18.97.0.0/18")})

    def test_add_to_bat_merges_and_collapses(self):
        write_bat(self.path, route_lines([net("160.79.104.0/24")], self.cfg))
        total = add_to_bat(self.path, [net("160.79.105.0/24"), net("34.149.0.0/16")], self.cfg)
        self.assertEqual(total, 2)
        self.assertEqual(read_networks(self.path), {net("160.79.104.0/23"), net("34.149.0.0/16")})

    def test_add_to_missing_file(self):
        self.assertEqual(add_to_bat(self.path, [net("34.149.0.0/16")], self.cfg), 1)


if __name__ == "__main__":
    unittest.main()
