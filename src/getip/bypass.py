"""Маршруты мимо VPN на этом компьютере: список исключений и таблица маршрутов системы.

VPN на компьютере забирает себе маршрут по умолчанию, но более точный маршрут главнее:
подсеть, направленная через шлюз роутера (192.168.1.1 на en0), идёт мимо VPN. Список таких
подсетей getip хранит сам — системные маршруты пропадают после перезагрузки и смены сети,
а по списку их можно включить заново.

Модуль ничего не печатает, а команды выполняет переданная функция run, поэтому всё,
кроме самого запуска команд, проверяют тесты."""
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import namedtuple

from .config import CONFIG_PATH
from .tunnel import is_ip

BYPASS_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "bypass.json")
KINDS = {"site": "сайт", "app": "программа"}

# net — подсеть (ip_network), source — сайт или программа, ради которых её добавили, kind — site / app
Route = namedtuple("Route", "net source kind")


def load_routes(path=BYPASS_PATH):
    """Список исключений из файла; испорченные записи пропускаем."""
    try:
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
    except (OSError, ValueError):
        return []
    routes = []
    for row in rows if isinstance(rows, list) else []:
        try:
            routes.append(Route(ipaddress.ip_network(row["net"]), row["source"], row["kind"]))
        except (KeyError, TypeError, ValueError):
            pass
    return routes


def save_routes(routes, path=BYPASS_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = [{"net": str(r.net), "source": r.source, "kind": r.kind} for r in routes]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def add_routes(routes, source, kind, nets):
    """Дописывает подсети сайта или программы. Те, что у неё уже есть или входят в её подсети,
    пропускает. Старые подсети с новыми не склеиваем: иначе в системе остались бы маршруты,
    которых нет в списке. Возвращает (новый список, добавленные подсети)."""
    own = [r.net for r in routes if (r.source, r.kind) == (source, kind)]
    added = [n for n in nets if not any(n.subnet_of(o) for o in own)]
    return routes + [Route(n, source, kind) for n in added], added


def remove_routes(routes, chosen):
    """Убирает выбранные записи. Возвращает (оставшиеся, подсети, которые больше никому не нужны) —
    маршрут подсети, которая нужна ещё и другому сайту или программе, остаётся в системе."""
    chosen = set(chosen)
    left = [r for r in routes if r not in chosen]
    return left, sorted({r.net for r in chosen} - {r.net for r in left})


def group_routes(routes):
    """[(источник, вид, [записи])] в порядке, в котором источники появились в списке."""
    groups = {}
    for r in routes:
        groups.setdefault((r.source, r.kind), []).append(r)
    return [(source, kind, items) for (source, kind), items in groups.items()]


def _short_net(text):
    """Адрес из netstat: «104.16/13» — это 104.16.0.0/13, «192.168.1» — 192.168.1.0/24."""
    addr, _, length = text.partition("/")
    octets = addr.split(".")
    if len(octets) > 4 or not all(o.isdigit() for o in octets) or (length and not length.isdigit()):
        return None
    try:
        return ipaddress.ip_network(".".join(octets + ["0"] * (4 - len(octets))) + "/"
                                    + (length or str(8 * len(octets))), strict=False)
    except ValueError:
        return None


def parse_netstat(text):
    """{подсеть: шлюз} из `netstat -rn -f inet` (macOS). Кэш адресов (флаг W) и маршруты,
    привязанные к одному интерфейсу (I), на остальной трафик не влияют — их пропускаем."""
    table = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or "W" in parts[2] or "I" in parts[2]:
            continue
        net = _short_net(parts[0])
        if net:
            table[net] = parts[1]
    return table


def parse_ip_route(text):
    """{подсеть: шлюз} из `ip -4 route show` (Linux)."""
    table = {}
    for line in text.splitlines():
        m = re.match(r"([\d.]+(?:/\d+)?) via (\S+)", line)
        if m:
            try:
                table[ipaddress.ip_network(m.group(1), strict=False)] = m.group(2)
            except ValueError:
                pass
    return table


def system_table():
    """{подсеть: шлюз} — маршруты системы прямо сейчас."""
    darwin = sys.platform == "darwin"
    cmd = ["netstat", "-rn", "-f", "inet"] if darwin else ["ip", "-4", "route", "show"]
    try:
        text = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        text = ""
    return parse_netstat(text) if darwin else parse_ip_route(text)


def route_state(net, table, gw):
    """on — подсеть идёт через шлюз роутера, stale — через шлюз другой сети (её сменили),
    off — маршрута нет: после перезагрузки или его удалили."""
    via = table.get(net)
    if gw and via == gw:
        return "on"
    return "stale" if via and is_ip(via) else "off"


def _target(net):
    return ["-host", str(net.network_address)] if net.prefixlen == 32 else ["-net", str(net)]


def add_command(net, gw):
    if sys.platform == "darwin":
        return ["route", "-n", "add", *_target(net), gw]
    return ["ip", "route", "replace", str(net), "via", gw]


def delete_command(net):
    if sys.platform == "darwin":
        return ["route", "-n", "delete", *_target(net)]
    return ["ip", "route", "del", str(net)]


def run_root(cmd):
    """Команда от администратора: пароль sudo уже должен быть введён. Возвращает (успех, ошибка)."""
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    try:
        r = subprocess.run(sudo + cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def to_add(nets, table, gw):
    """Подсети, которые ещё не идут через шлюз роутера."""
    return [n for n in nets if route_state(n, table, gw) != "on"]


def to_delete(nets, table):
    """Подсети, маршруты которых через какой-нибудь шлюз есть в системе. Маршруты самого VPN
    (через его интерфейс, без адреса шлюза) не трогаем."""
    return [n for n in nets if is_ip(table.get(n, ""))]


def apply(nets, gw, table, run=run_root):
    """Направляет подсети через шлюз роутера. Возвращает {подсеть: ошибка} для тех, что не вышло."""
    failed = {}
    for net in to_add(nets, table, gw):
        ok, err = run(add_command(net, gw))
        if not ok and "exists" in err:  # маршрут к этой подсети уже есть, но через другой шлюз
            run(delete_command(net))
            ok, err = run(add_command(net, gw))
        if not ok:
            failed[net] = err
    return failed


def withdraw(nets, table, run=run_root):
    """Удаляет маршруты подсетей из системы. Возвращает {подсеть: ошибка} для тех, что не вышло."""
    failed = {}
    for net in to_delete(nets, table):
        ok, err = run(delete_command(net))
        if not ok and "not in table" not in err:  # маршрут уже пропал сам — это не ошибка
            failed[net] = err
    return failed
