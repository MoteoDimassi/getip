import unittest

from getip.tunnel import parse_default_interface, parse_second_hop, verdict

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#28            UCSg                utun8
default            192.168.1.1        UGScIg                en0
10.108.176/22      link#28            UCS                 utun8
"""


class TunnelTest(unittest.TestCase):
    def test_default_interface_skips_vpn(self):
        self.assertEqual(parse_default_interface(NETSTAT), "en0")
        self.assertIsNone(parse_default_interface("default link#28 UCSg utun8\n"))

    def test_second_hop(self):
        trace = " 1  192.168.1.1  2.815 ms\n 2  10.75.40.1  102.854 ms\n"
        self.assertEqual(parse_second_hop(trace), "10.75.40.1")
        self.assertIsNone(parse_second_hop(" 1  192.168.1.1  2.8 ms\n 2  *\n"))
        self.assertIsNone(parse_second_hop(""))

    def test_verdict(self):
        isp = {"10.10.29.65"}
        self.assertEqual(verdict("10.10.29.65", isp), "direct")
        self.assertEqual(verdict("10.75.40.1", isp), "tunnel")
        self.assertEqual(verdict(None, isp), "unknown")
        self.assertEqual(verdict("10.75.40.1", set()), "unknown")  # шлюз провайдера не узнали


if __name__ == "__main__":
    unittest.main()
