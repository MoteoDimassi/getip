import unittest

from getip.connections import app_name, connections_of, parse_lsof

# вывод `lsof +c 0 -nP -i -F cfnPT`: Electron-программа, её консольная утилита и браузер
LSOF = """p501
cClaude Helper
f22
PTCP
n10.0.0.5:59692->160.79.104.10:443
TST=ESTABLISHED
TQR=0
TQS=0
f23
PTCP
n10.0.0.5:59700->34.149.66.165:443
TST=SYN_SENT
f24
PTCP
n127.0.0.1:62049->127.0.0.1:5173
TST=ESTABLISHED
f25
PTCP
n*:8080
TST=LISTEN
f26
PUDP
n[2a00:1450:4010::5]:50000->[2a00:1450:4010:c0e::64]:443
p502
cclaude
f10
PTCP
n10.0.0.5:59746->160.79.104.10:443
TST=ESTABLISHED
p503
cGoogle Chrome Helper (Renderer)
f40
PUDP
n[fe80:e::1]:5353->[fe80:e::2]:5353
"""


class ParseLsofTest(unittest.TestCase):
    def setUp(self):
        self.apps = parse_lsof(LSOF)

    def test_helpers_belong_to_the_app(self):
        self.assertEqual(app_name("Claude Helper"), "Claude")
        self.assertEqual(app_name("Google Chrome Helper (Renderer)"), "Google Chrome")
        self.assertIn("Claude", self.apps)

    def test_only_external_connections(self):
        ips = [c.ip for c in self.apps["Claude"]]
        self.assertEqual(ips, ["160.79.104.10", "34.149.66.165", "2a00:1450:4010:c0e::64"])
        self.assertNotIn("Google Chrome", self.apps)  # только локальные адреса

    def test_state_protocol_and_port(self):
        stuck = self.apps["Claude"][1]
        self.assertEqual((stuck.proto, stuck.port, stuck.state), ("TCP", "443", "SYN_SENT"))
        self.assertEqual(stuck.local, "10.0.0.5:59700")
        quic = self.apps["Claude"][2]
        self.assertEqual((quic.proto, quic.state), ("UDP", ""))

    def test_connections_of_prefers_exact_name(self):
        self.assertEqual(len(connections_of("Claude", self.apps)), 3)
        self.assertEqual(len(connections_of("claude", self.apps)), 1)
        self.assertEqual(len(connections_of("CLAUDE", self.apps)), 3)
        self.assertEqual(connections_of("Telegram", self.apps), [])


if __name__ == "__main__":
    unittest.main()
