import ipaddress
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from getip import block
from getip.block import (apply_hosts, apply_pf, clean_block, format_span, net_id, new_blocks, parse_block_target,
                         parse_duration, unsafe_net)

net = ipaddress.ip_network
SRC = os.path.dirname(os.path.dirname(os.path.abspath(block.__file__)))
HOSTS = "##\n# Host Database\n##\n127.0.0.1\tlocalhost\n::1             localhost\n127.0.0.1 screen.studio\n"
RESOLVING = {"example.com", "www.example.com", "api.example.com"}


class FakeSystem:
    """Подменяет системные команды блокировки и помнит, что «включено»: pf, его ссылки, служба."""

    def __init__(self):
        self.pf, self.tokens, self.loaded, self.anchor = False, set(), False, None
        self.boot, self.calls = "{ sec = 1000 }", []

    def __call__(self, cmd, input=None, **kw):
        self.calls.append(cmd)
        rc, so, se = 0, "", ""
        if cmd[:2] == ["sysctl", "-n"]:
            so = self.boot
        elif cmd[:3] == ["pfctl", "-s", "info"]:
            so = "Status: Enabled for 0 days" if self.pf else "Status: Disabled"
        elif cmd[:2] == ["pfctl", "-E"]:
            token = str(1000 + len(self.calls))
            self.tokens.add(token)
            self.pf, se = True, f"pf enabled\nToken : {token}\n"
        elif cmd[:2] == ["pfctl", "-X"]:
            self.tokens.discard(cmd[2])
            self.pf = bool(self.tokens)
        elif cmd[:3] == ["pfctl", "-a", block.PF_ANCHOR]:
            self.anchor = input if cmd[3] == "-f" else None
        elif cmd[:2] == ["launchctl", "print"]:
            rc = 0 if self.loaded else 113
        elif cmd[:2] == ["launchctl", "bootstrap"]:
            self.loaded = True
        elif cmd[:2] == ["launchctl", "bootout"]:
            self.loaded = False
        return subprocess.CompletedProcess(cmd, rc, so, se)

    def ran(self, *prefix):
        return any(c[:len(prefix)] == list(prefix) for c in self.calls)


class BlockSandbox(unittest.TestCase):
    """Пути блокировки — во временной папке, системные команды подменены, «мы — root»."""

    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = os.path.join(tmp, "support")
        paths = dict(BLOCK_DIR=d, BLOCKS_PATH=os.path.join(d, "blocks.json"), HELPER_PKG=os.path.join(d, "getip"),
                     HELPER_LOG=os.path.join(d, "errors.log"), PLIST_PATH=os.path.join(tmp, "blocker.plist"),
                     LOCK_PATH=os.path.join(tmp, "lock"), HOSTS_PATH=os.path.join(tmp, "hosts"))
        for name, value in paths.items():
            self._patch(mock.patch.object(block, name, value))
        with open(paths["HOSTS_PATH"], "w") as f:
            f.write(HOSTS)
        self.sys = FakeSystem()
        self._patch(mock.patch.object(block, "run_quiet", self.sys))
        self._patch(mock.patch.object(block.os, "geteuid", return_value=0))
        self._patch(mock.patch.object(block, "dns_query",
                                      lambda name, server, timeout=2.0: {"1.1.1.1"} if name in RESOLVING else set()))

    def _patch(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)

    def hosts(self):
        with open(block.HOSTS_PATH) as f:
            return f.read()

    def state(self):
        with open(block.BLOCKS_PATH) as f:
            return json.load(f)

    def expire(self, block_id):
        state = self.state()
        for b in state["blocks"]:
            if b["id"] == block_id:
                b["until"] = int(time.time()) - 1
        block.write_file(block.BLOCKS_PATH, json.dumps(state).encode())


class ParseTest(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("30"), 1800)  # просто число — минуты
        self.assertEqual(parse_duration("2ч"), 7200)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("1.5d"), 129600)
        self.assertEqual(parse_duration("90 мин"), 5400)
        for bad in ("30с", "0", "abc", ""):
            self.assertIsNone(parse_duration(bad))

    def test_spans(self):
        self.assertEqual(format_span(59), "1 мин")
        self.assertEqual(format_span(3720), "1 ч 2 мин")
        self.assertEqual(format_span(90000), "1 д 1 ч")

    def test_targets(self):
        self.assertEqual(parse_block_target("https://www.YouTube.com/watch?v=1"), ("site", "youtube.com"))
        self.assertEqual(parse_block_target("1.2.3.4, 5.6.7.0/24"), ("ip", [net("1.2.3.4/32"), net("5.6.7.0/24")]))
        self.assertEqual(parse_block_target("2001:db8::1")[0], "ip")
        self.assertIsNone(parse_block_target(""))
        self.assertIsNone(parse_block_target("не сайт"))

    def test_unsafe_nets(self):
        self.assertIsNotNone(unsafe_net(net("0.0.0.0/0")))
        self.assertIsNotNone(unsafe_net(net("127.0.0.1/32")))
        self.assertIsNotNone(unsafe_net(net("::1/128")))
        self.assertIsNone(unsafe_net(net("8.8.8.8/32")))

    def test_net_id(self):
        self.assertEqual(net_id(net("1.2.3.4/32")), "1.2.3.4")
        self.assertEqual(net_id(net("1.2.3.0/24")), "1.2.3.0/24")

    def test_clean_block_drops_injected_lines(self):
        b = clean_block({"id": "x", "names": ["ok.com", "bad.com\n1.1.1.1 apple.com"], "nets": ["1.2.3.4"]})
        self.assertEqual(b["names"], ["ok.com"])
        self.assertEqual(b["nets"], ["1.2.3.4/32"])
        self.assertIsNone(b["until"])


class HostsTest(BlockSandbox):
    def test_add_and_remove_section(self):
        self.assertTrue(apply_hosts(["example.com"]))
        self.assertTrue(self.hosts().startswith(HOSTS))
        self.assertIn("0.0.0.0 example.com\n:: example.com\n", self.hosts())
        self.assertFalse(apply_hosts(["example.com"]))  # без изменений файл не трогаем
        self.assertTrue(apply_hosts([]))
        self.assertEqual(self.hosts(), HOSTS)
        self.assertFalse(apply_hosts([]))

    def test_unpaired_marker_keeps_user_lines(self):
        with open(block.HOSTS_PATH, "w") as f:
            f.write(HOSTS + block.HOSTS_BEGIN + "\n10.0.0.1 my.server\n")
        for names in (["example.com"], ["example.org"], []):
            apply_hosts(names)
            self.assertIn("10.0.0.1 my.server", self.hosts())
        self.assertNotIn("example.", self.hosts())


class LifecycleTest(BlockSandbox):
    def test_site_then_ip_then_expiry_then_removal(self):
        block.block_op({"add": new_blocks("site", "example.com", 3600)})
        self.assertIn("0.0.0.0 api.example.com", self.hosts())
        self.assertNotIn("mail.example.com", self.hosts())  # несуществующие поддомены не пишем
        self.assertTrue(self.sys.loaded and self.sys.ran("killall", "-HUP", "mDNSResponder"))
        self.assertTrue(os.path.isfile(os.path.join(block.HELPER_PKG, "block.py")))  # служба — на копии пакета
        with open(block.PLIST_PATH, "rb") as f:
            plist = plistlib.load(f)
        self.assertEqual(plist["ProgramArguments"][1:], ["-m", "getip.block", "--apply"])
        self.assertEqual(plist["WorkingDirectory"], block.BLOCK_DIR)
        self.assertFalse(self.sys.pf)  # без IP брандмауэр не включаем

        self.sys.calls.clear()
        block.block_op({"add": new_blocks("site", "example.com", 3600)})
        self.assertFalse(self.sys.ran("killall") or self.sys.ran("launchctl", "bootstrap"))

        block.block_op({"add": new_blocks("ip", [net("1.2.3.4/32"), net("2001:db8::/32")], 0)})
        self.assertEqual(len(self.sys.tokens), 1)
        self.assertIn("1.2.3.4/32", self.sys.anchor)
        self.assertEqual(sorted(b["id"] for b in self.state()["blocks"]), ["1.2.3.4", "2001:db8::/32", "example.com"])

        self.sys.calls.clear()
        block.apply_blocks_now()
        self.assertFalse(self.sys.ran("pfctl", "-E"))  # служба не берёт лишних ссылок на pf

        self.sys.pf, self.sys.tokens, self.sys.anchor, self.sys.boot = False, set(), None, "{ sec = 2000 }"
        block.apply_blocks_now()  # после перезагрузки служба возвращает правила
        self.assertTrue(self.sys.pf and "1.2.3.4/32" in self.sys.anchor)

        self.expire("example.com")
        block.apply_blocks_now()
        self.assertEqual(self.hosts(), HOSTS)
        self.assertIn("1.2.3.4/32", self.sys.anchor)

        block.block_op({"remove": ["1.2.3.4", "2001:db8::/32"]})
        self.assertFalse(self.sys.pf or self.sys.tokens or self.sys.anchor)
        self.assertFalse(self.sys.loaded or os.path.exists(block.PLIST_PATH) or os.path.exists(block.BLOCK_DIR))
        # «-F all» и «-F states» сбросили бы соединения всех программ, а не только наш якорь
        flushes = [c[c.index("-F") + 1] for c in self.sys.calls if c[0] == "pfctl" and "-F" in c]
        self.assertTrue(flushes)
        self.assertFalse({"all", "states"} & set(flushes))

    def test_not_root(self):
        with mock.patch.object(block.os, "geteuid", return_value=501):
            with self.assertRaises(RuntimeError):
                block.block_op({"remove": []})


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("pfctl"), "нужен pfctl из macOS")
class PfSyntaxTest(unittest.TestCase):
    def test_rules_parse(self):
        rules = []
        fake = lambda cmd, input=None, **kw: (rules.append(input) if input else None,
                                              subprocess.CompletedProcess(cmd, 0, "", "Token : 1"))[1]
        with mock.patch.object(block, "run_quiet", fake):
            apply_pf({}, ["1.2.3.4/32", "5.6.0.0/16", "2001:db8::/32"])
        # pfctl -n только проверяет правила и ничего не загружает — root не нужен
        r = subprocess.run(["pfctl", "-a", block.PF_ANCHOR, "-n", "-f", "-"], input=rules[0],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class RootEntryTest(unittest.TestCase):
    def test_module_runs_as_main(self):
        # так модуль запускают sudo и служба launchd: python3 -m getip.block из папки с пакетом
        r = subprocess.run([sys.executable, "-m", "getip.block"], cwd=SRC, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("--apply | --op", r.stderr)


if __name__ == "__main__":
    unittest.main()
