import ipaddress
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from getip import block, bypass, bypass_service
from getip.bypass import Route
from getip.bypass_service import load_nets, needs_update, publish, sync_routes
from tests.test_block import FakeSystem

net = ipaddress.ip_network
SRC = os.path.dirname(os.path.dirname(os.path.abspath(bypass_service.__file__)))
OLD_GW, GW = "192.168.1.1", "192.168.2.1"  # роутер сети, где маршрут добавили, и роутер сети, где Mac сейчас
QRATOR = net("178.248.234.0/23")
TG = net("149.154.160.0/20")


class FakeRoutes:
    """Таблица маршрутов системы: route add и route delete меняют её, как в macOS."""

    def __init__(self, table=None):
        self.table, self.calls, self.broken = dict(table or {}), [], set()  # broken — подсети, где route падает

    def __call__(self, cmd):
        self.calls.append(cmd)
        op, kind, target = cmd[2], cmd[3], cmd[4]
        n = net(target + "/32" if kind == "-host" else target)
        if n in self.broken:
            return False, "route: writing to routing socket: Network is unreachable"
        if op == "add":
            if n in self.table:
                return False, f"add net {target}: gateway {cmd[5]}: File exists"
            self.table[n] = cmd[5]
            return True, ""
        if n not in self.table:
            return False, "route: writing to routing socket: not in table"
        del self.table[n]
        return True, ""


@mock.patch.object(bypass.sys, "platform", "darwin")
class SyncTest(unittest.TestCase):
    def test_moves_route_to_current_router(self):
        # Mac перешёл в другую сеть: маршрут остался на роутер прежней — подсеть не открывается совсем
        run = FakeRoutes({QRATOR: OLD_GW})
        self.assertEqual(sync_routes([QRATOR], [QRATOR], dict(run.table), GW, run), {})
        self.assertEqual(run.table[QRATOR], GW)

    def test_without_router_removes_routes(self):
        run = FakeRoutes({QRATOR: OLD_GW, net("10.0.0.0/8"): "link#29"})
        sync_routes([QRATOR, TG], [QRATOR, TG], dict(run.table), None, run)
        self.assertEqual(run.table, {net("10.0.0.0/8"): "link#29"})  # маршрут VPN не трогаем

    def test_working_routes_untouched(self):
        run = FakeRoutes({QRATOR: GW})
        sync_routes([QRATOR], [QRATOR], dict(run.table), GW, run)
        self.assertEqual(run.calls, [])

    def test_dropped_nets_are_removed(self):
        run = FakeRoutes({QRATOR: GW, TG: GW})
        sync_routes([QRATOR], [QRATOR, TG], dict(run.table), GW, run)
        self.assertEqual(run.table, {QRATOR: GW})


class ServiceSandbox(unittest.TestCase):
    """Пути службы — во временной папке, системные команды подменены, «мы — root»."""

    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = os.path.join(tmp, "support")
        for name, value in dict(SERVICE_DIR=d, NETS_PATH=os.path.join(d, "routes.json"),
                                HELPER_PKG=os.path.join(d, "getip"), HELPER_LOG=os.path.join(d, "errors.log"),
                                PLIST_PATH=os.path.join(tmp, "bypass.plist"),
                                LOCK_PATH=os.path.join(tmp, "lock")).items():
            self._patch(mock.patch.object(bypass_service, name, value))
        self.sys = FakeSystem()
        self._patch(mock.patch.object(block, "run_quiet", self.sys))
        self.routes = FakeRoutes()
        self.gw = (GW, "en0")
        self._patch(mock.patch.object(bypass_service, "run_root", self.routes))
        self._patch(mock.patch.object(bypass_service, "system_table", lambda: dict(self.routes.table)))
        self._patch(mock.patch.object(bypass_service, "physical_route", lambda: self.gw))
        self._patch(mock.patch.object(bypass_service.os, "geteuid", return_value=0))
        self._patch(mock.patch.object(bypass.sys, "platform", "darwin"))

    def _patch(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)


class LifecycleTest(ServiceSandbox):
    def test_service_follows_router(self):
        bypass_service.set_nets([QRATOR, TG])
        self.assertEqual(load_nets(), [TG, QRATOR])
        self.assertEqual(self.routes.table, {QRATOR: GW, TG: GW})
        self.assertTrue(self.sys.loaded)
        self.assertTrue(os.path.isfile(os.path.join(bypass_service.HELPER_PKG, "bypass_service.py")))
        with open(bypass_service.PLIST_PATH, "rb") as f:
            plist = plistlib.load(f)
        self.assertEqual(plist["ProgramArguments"][1:], ["-m", "getip.bypass_service", "--apply"])
        self.assertEqual(plist["WorkingDirectory"], bypass_service.SERVICE_DIR)
        self.assertTrue(plist["RunAtLoad"] and plist["StartInterval"] and plist["WatchPaths"])

        # Mac ушёл из сети — маршруты через прежний роутер никуда не ведут, служба их убирает
        self.gw = None
        bypass_service.apply_now()
        self.assertEqual(self.routes.table, {})

        # и возвращает уже через роутер новой сети
        self.gw = ("172.20.10.1", "en0")
        bypass_service.apply_now()
        self.assertEqual(self.routes.table, {QRATOR: "172.20.10.1", TG: "172.20.10.1"})

        # маршрут остался на роутер прежней сети (так и сломались сайты) — служба переводит его
        self.routes.table[QRATOR] = OLD_GW
        self.gw = (GW, "en0")
        bypass_service.apply_now()
        self.assertEqual(self.routes.table[QRATOR], GW)

        bypass_service.set_nets([QRATOR])
        self.assertEqual(self.routes.table, {QRATOR: GW})  # подсеть убрали из списка — и из системы

        bypass_service.set_nets([])
        self.assertEqual(self.routes.table, {})
        self.assertFalse(self.sys.loaded or os.path.exists(bypass_service.PLIST_PATH)
                         or os.path.exists(bypass_service.SERVICE_DIR))

    def test_failed_add_is_left_to_service(self):
        # маршрут не добавился — эту ошибку getip уже показал сам, а служба повторит попытку
        self.routes.broken.add(TG)
        bypass_service.set_nets([QRATOR, TG])
        self.assertEqual(load_nets(), [TG, QRATOR])
        self.routes.broken.clear()
        bypass_service.apply_now()
        self.assertEqual(self.routes.table, {QRATOR: GW, TG: GW})

    def test_failed_removal_is_reported(self):
        bypass_service.set_nets([QRATOR, TG])
        self.routes.broken.add(TG)
        with self.assertRaisesRegex(RuntimeError, "149.154.160.0/20"):
            bypass_service.set_nets([])
        self.assertFalse(bypass_service.running())

    def test_not_root(self):
        with mock.patch.object(bypass_service.os, "geteuid", return_value=501):
            with self.assertRaises(RuntimeError):
                bypass_service.set_nets([])

    def test_broken_list(self):
        os.makedirs(bypass_service.SERVICE_DIR)
        with open(bypass_service.NETS_PATH, "w") as f:
            f.write('["178.248.234.0/23", "мусор", 5, "2001:db8::/32"]')
        self.assertEqual(load_nets(), [QRATOR])


class PublishTest(ServiceSandbox):
    def setUp(self):
        super().setUp()
        self._patch(mock.patch.object(bypass_service, "SUPPORTED", True))
        self.list = [Route(QRATOR, "getcourse.ru", "site"), Route(TG, "Telegram", "app", True)]

    def test_needs_update(self):
        self.assertTrue(needs_update(self.list))        # маршруты есть, а служба о них не знает
        self.assertFalse(needs_update(self.list[1:]))   # только выключенные — службе нечего держать
        bypass_service.set_nets([QRATOR])
        self.assertFalse(needs_update(self.list))       # выключенная запись службе не нужна
        self.assertTrue(needs_update([]))               # служба держит маршрут, которого нет в списке

    def test_publish_sends_enabled_nets(self):
        self.assertIsNone(publish(self.list))
        cmd = self.sys.calls[-1]
        self.assertEqual(cmd[-3:], ["getip.bypass_service", "--set", json.dumps([str(QRATOR)])])

    def test_publish_skips_when_in_sync(self):
        bypass_service.set_nets([QRATOR])
        self.sys.calls.clear()
        self.assertIsNone(publish(self.list))
        self.assertEqual(self.sys.calls, [])

    def test_stop_turns_entries_off(self):
        path = os.path.join(bypass_service.SERVICE_DIR + "-user", "bypass.json")
        bypass.save_routes(self.list, path)

        def helper(cmd, **kw):  # sudo python3 -m getip.bypass_service --set … — выполняем тут же
            if "getip.bypass_service" in cmd:
                bypass_service.set_nets(json.loads(cmd[-1]))
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return self.sys(cmd, **kw)

        with mock.patch.object(block, "run_quiet", helper):
            self.assertIsNone(publish(self.list))
            self.assertTrue(bypass_service.running())
            self.assertEqual(self.routes.table, {QRATOR: GW})
            self.routes.table[TG] = GW  # маршрут, о котором служба не знает, тоже уходит
            bypass.save_routes([self.list[0], self.list[1]._replace(off=False)], path)
            self.assertIsNone(bypass_service.stop(path))
        self.assertFalse(bypass_service.running())
        self.assertEqual(self.routes.table, {})
        left = bypass.load_routes(path)
        self.assertEqual([r.net for r in left], [QRATOR, TG])  # записи остались в списке, но выключены
        self.assertTrue(all(r.off for r in left))
        self.assertFalse(needs_update(left))  # и служба не просит включить себя снова

    def test_publish_reports_error(self):
        fail = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "sudo: a password is required\n")
        with mock.patch.object(block, "run_quiet", fail):
            self.assertEqual(publish(self.list), "sudo: a password is required")


class RootEntryTest(unittest.TestCase):
    def test_module_runs_as_main(self):
        # так модуль запускают sudo и служба launchd: python3 -m getip.bypass_service из папки с пакетом
        r = subprocess.run([sys.executable, "-m", "getip.bypass_service"], cwd=SRC, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("--apply | --set", r.stderr)


if __name__ == "__main__":
    unittest.main()
