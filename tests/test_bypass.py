import ipaddress
import os
import tempfile
import unittest
from unittest import mock

from getip import bypass
from getip.bypass import (Route, add_routes, apply, group_routes, load_routes, parse_ip_route,
                          parse_netstat, remove_routes, route_state, save_routes, switch, to_delete,
                          toggle_plan, withdraw)
from getip.tunnel import parse_default_route

net = ipaddress.ip_network
GW = "192.168.1.1"

# так выглядит `netstat -rn -f inet` на macOS с включённым VPN и маршрутами мимо него
NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#28            UCSg                utun8
default            192.168.1.1        UGScIg                en0
1.1.1.1            link#28            UHWIig              utun8
10.108.177.221     10.108.177.221     UH                  utun8
104.16/13          192.168.1.1        UGSc                  en0
127                127.0.0.1          UCS                   lo0
149.154.160/20     10.0.0.1           UGSc                  en0
160.79.104/23      192.168.1.1        UGSc                  en0
192.168.1          link#6             UCS                   en0      !
192.168.1.1        50:ff:20:bc:95:91  UHLWIir               en0   1184
95.161.64.5        192.168.1.1        UGHS                  en0
"""

IP_ROUTE = """default via 192.168.1.1 dev wlan0 proto dhcp metric 600
0.0.0.0/1 via 10.8.0.1 dev tun0
104.16.0.0/13 via 192.168.1.1 dev wlan0
95.161.64.5 via 192.168.1.1 dev wlan0
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.52
"""


class FakeRun:
    """Подменяет запуск команд: запоминает их и отвечает заготовленными ошибками."""

    def __init__(self, errors=None):
        self.calls, self.errors = [], list(errors or [])

    def __call__(self, cmd):
        self.calls.append(cmd)
        err = self.errors.pop(0) if self.errors else ""
        return not err, err


class TableTest(unittest.TestCase):
    def test_netstat_short_addresses(self):
        table = parse_netstat(NETSTAT)
        self.assertEqual(table[net("104.16.0.0/13")], GW)
        self.assertEqual(table[net("160.79.104.0/23")], GW)
        self.assertEqual(table[net("149.154.160.0/20")], "10.0.0.1")
        self.assertEqual(table[net("95.161.64.5/32")], GW)
        self.assertEqual(table[net("127.0.0.0/8")], "127.0.0.1")
        self.assertEqual(table[net("192.168.1.0/24")], "link#6")

    def test_netstat_skips_cache_and_scoped(self):
        table = parse_netstat(NETSTAT)
        self.assertNotIn(net("1.1.1.1/32"), table)      # W — кэш адреса
        self.assertNotIn(net("192.168.1.1/32"), table)  # W, I — запись ARP
        self.assertEqual(len(table), 7)

    def test_ip_route(self):
        table = parse_ip_route(IP_ROUTE)
        self.assertEqual(table, {net("0.0.0.0/1"): "10.8.0.1", net("104.16.0.0/13"): GW,
                                 net("95.161.64.5/32"): GW})

    def test_default_route_skips_vpn(self):
        self.assertEqual(parse_default_route(NETSTAT), (GW, "en0"))
        self.assertIsNone(parse_default_route("default link#28 UCSg utun8\n"))

    def test_route_state(self):
        table = parse_netstat(NETSTAT)
        self.assertEqual(route_state(net("104.16.0.0/13"), table, GW), "on")
        self.assertEqual(route_state(net("149.154.160.0/20"), table, GW), "stale")  # шлюз другой сети
        self.assertEqual(route_state(net("34.36.0.0/16"), table, GW), "off")
        self.assertEqual(route_state(net("104.16.0.0/13"), table, None), "stale")   # нет подключения

    def test_vpn_routes_are_not_deleted(self):
        table = parse_netstat(NETSTAT)
        nets = [net("104.16.0.0/13"), net("192.168.1.0/24"), net("34.36.0.0/16")]
        self.assertEqual(to_delete(nets, table), [net("104.16.0.0/13")])


class ListTest(unittest.TestCase):
    def setUp(self):
        self.routes = [Route(net("160.79.104.0/23"), "claude.ai", "site"),
                       Route(net("104.16.0.0/13"), "claude.ai", "site"),
                       Route(net("104.16.0.0/13"), "Telegram", "app")]

    def test_add_skips_known_and_covered(self):
        routes, added = add_routes(self.routes, "claude.ai", "site",
                                   [net("104.18.0.0/16"), net("160.79.104.0/23"), net("34.36.57.0/24")])
        self.assertEqual(added, [net("34.36.57.0/24")])
        self.assertEqual(len(routes), 4)

    def test_add_does_not_merge_with_old(self):
        # 160.79.106.0/23 рядом со старой 160.79.104.0/23, но склеивать их в /22 нельзя:
        # в системе остался бы маршрут /23, которого нет в списке
        _, added = add_routes(self.routes, "claude.ai", "site", [net("160.79.106.0/23")])
        self.assertEqual(added, [net("160.79.106.0/23")])

    def test_same_net_for_other_source_is_added(self):
        _, added = add_routes(self.routes, "Telegram", "app", [net("160.79.104.0/23")])
        self.assertEqual(added, [net("160.79.104.0/23")])

    def test_remove_keeps_shared_route(self):
        left, gone = remove_routes(self.routes, self.routes[1:2])  # 104.16/13 нужна ещё и Telegram
        self.assertEqual(len(left), 2)
        self.assertEqual(gone, [])
        left, gone = remove_routes(self.routes, self.routes)
        self.assertEqual((left, gone), ([], [net("104.16.0.0/13"), net("160.79.104.0/23")]))

    def test_groups_keep_order(self):
        groups = group_routes(self.routes)
        self.assertEqual([(s, k, len(items)) for s, k, items in groups],
                         [("claude.ai", "site", 2), ("Telegram", "app", 1)])

    def test_switch_off_keeps_route_needed_by_other(self):
        routes, nets = switch(self.routes, self.routes[:2], True)
        self.assertTrue(routes[0].off and routes[1].off and not routes[2].off)
        self.assertEqual(nets, [net("160.79.104.0/23")])  # 104.16/13 ещё нужна Telegram
        routes, nets = switch(routes, routes[2:], True)
        self.assertEqual(nets, [net("104.16.0.0/13")])    # теперь не нужна никому

    def test_switch_on_matches_by_key(self):
        routes, _ = switch(self.routes, self.routes[:1], True)
        # записи из старого списка (ещё без признака «выключена») находят свою пару
        routes, nets = switch(routes, self.routes[:1], False)
        self.assertEqual(routes, self.routes)
        self.assertEqual(nets, [net("160.79.104.0/23")])

    def test_remove_ignores_disabled_neighbours(self):
        routes, _ = switch(self.routes, self.routes[2:], True)  # Telegram выключен
        _, gone = remove_routes(routes, routes[1:2])
        self.assertEqual(gone, [net("104.16.0.0/13")])  # выключенной записи маршрут не нужен


class TogglePlanTest(unittest.TestCase):
    def test_plan(self):
        table = {net("104.16.0.0/13"): GW}
        on = Route(net("104.16.0.0/13"), "claude.ai", "site")
        lost = Route(net("34.36.0.0/16"), "claude.ai", "site")
        off = Route(net("160.79.104.0/23"), "claude.ai", "site", True)
        self.assertEqual(toggle_plan([on], table, GW), "off")
        self.assertEqual(toggle_plan([off], table, GW), "on")
        self.assertEqual(toggle_plan([lost], table, GW), "restore")
        self.assertEqual(toggle_plan([on, off], table, GW), "on")
        # после перезагрузки сначала возвращаем включённые, выключенные не трогаем
        self.assertEqual(toggle_plan([on, lost, off], table, GW), "restore")
        self.assertEqual(toggle_plan([on], table, None), "restore")  # нет подключения к роутеру


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "getip", "bypass.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_round_trip(self):
        routes = [Route(net("104.16.0.0/13"), "Telegram", "app"),
                  Route(net("1.2.3.0/24"), "a.ru", "site", True)]
        save_routes(routes, self.path)
        self.assertEqual(load_routes(self.path), routes)
        with open(self.path) as f:
            self.assertEqual(f.read().count('"off"'), 1)  # у включённых записей признака нет

    def test_missing_and_broken(self):
        self.assertEqual(load_routes(self.path), [])
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write('[{"net": "1.2.3.0/24", "source": "a.ru", "kind": "site"}, {"net": "мусор"}, 5]')
        self.assertEqual(load_routes(self.path), [Route(net("1.2.3.0/24"), "a.ru", "site")])


@mock.patch.object(bypass.sys, "platform", "darwin")
class CommandsTest(unittest.TestCase):
    def test_apply_skips_active_routes(self):
        run = FakeRun()
        failed = apply([net("104.16.0.0/13"), net("34.36.0.0/16"), net("95.161.64.9/32")], GW,
                       parse_netstat(NETSTAT), run)
        self.assertEqual(failed, {})
        self.assertEqual(run.calls, [["route", "-n", "add", "-net", "34.36.0.0/16", GW],
                                     ["route", "-n", "add", "-host", "95.161.64.9", GW]])

    def test_apply_replaces_existing_route(self):
        run = FakeRun(["add net 149.154.160.0/20: gateway 192.168.1.1: File exists"])
        failed = apply([net("149.154.160.0/20")], GW, {}, run)
        self.assertEqual(failed, {})
        self.assertEqual([c[2] for c in run.calls], ["add", "delete", "add"])

    def test_apply_reports_errors(self):
        run = FakeRun(["Network is unreachable"])
        self.assertEqual(apply([net("34.36.0.0/16")], GW, {}, run),
                         {net("34.36.0.0/16"): "Network is unreachable"})

    def test_withdraw_only_present_routes(self):
        run = FakeRun(["route: writing to routing socket: not in table"])
        failed = withdraw([net("104.16.0.0/13"), net("34.36.0.0/16")], parse_netstat(NETSTAT), run)
        self.assertEqual(failed, {})  # маршрут успел пропасть сам — это не ошибка
        self.assertEqual(run.calls, [["route", "-n", "delete", "-net", "104.16.0.0/13"]])


@mock.patch.object(bypass.sys, "platform", "linux")
class LinuxCommandsTest(unittest.TestCase):
    def test_commands(self):
        run = FakeRun()
        apply([net("34.36.0.0/16")], GW, {}, run)
        withdraw([net("104.16.0.0/13")], parse_ip_route(IP_ROUTE), run)
        self.assertEqual(run.calls, [["ip", "route", "replace", "34.36.0.0/16", "via", GW],
                                     ["ip", "route", "del", "104.16.0.0/13"]])


if __name__ == "__main__":
    unittest.main()
