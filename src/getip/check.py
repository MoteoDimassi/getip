"""Режим проверки: идёт ли трафик программы через VPN-туннель роутера.

Раз в секунду смотрим соединения программы. Для каждого нового адреса узнаём, куда
его отправляет роутер (tunnel.py), и подсеть провайдера — чтобы сразу предложить
маршрут. Соединения, которые несколько секунд висят в SYN_SENT, отмечаем: программа
стучится, а сервер не отвечает — так обычно выглядит блокировка."""
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .connections import connections_of, lsof_connections
from .lookup import lookup_prefix
from .routes import route_lines
from .style import bold, cyan, dim, green, red, yellow
from .term import out
from .texts import CHECK, print_tips
from .tunnel import RouterPaths
from .widgets import Live, wait_for_stop

STUCK_SECONDS = 3  # столько секунд без ответа на подключение — считаем соединение зависшим

MARKS = {"tunnel": green("✔"), "direct": yellow("→"), "unknown": dim("?"), "ipv6": yellow("!")}


class Address:
    """Адрес, к которому подключалась программа, и что о нём узнали."""

    def __init__(self, ip):
        self.ip = ip
        self.protos, self.ports = set(), set()
        self.verdict = None     # tunnel / direct / unknown / ipv6; None — ещё проверяем
        self.hop = None         # второй узел трассировки
        self.net, self.asn = None, "?"
        self.stuck = False


class CheckResult:
    def __init__(self, target):
        self.target = target
        self.addrs = {}  # ip -> Address

    def count(self, verdict):
        return sum(a.verdict == verdict for a in self.addrs.values())

    def stuck(self):
        return [a for a in self.addrs.values() if a.stuck]

    def missing(self):
        """Адреса, которые роутер отправляет мимо туннеля."""
        return sorted((a for a in self.addrs.values() if a.verdict == "direct"),
                      key=lambda a: ipaddress.ip_address(a.ip))

    def networks(self):
        return sorted(ipaddress.collapse_addresses({a.net for a in self.missing() if a.net}))


def describe(addr):
    if addr.verdict == "tunnel":
        return green("туннель") + dim(f"  через {addr.hop}")
    if addr.verdict == "direct":
        return yellow("напрямую") + dim(f"  через провайдера {addr.hop}")
    if addr.verdict == "ipv6":
        return yellow("IPv6") + dim("  маршруты .bat действуют только на IPv4")
    return dim("путь не определить: узел не ответил")


def row(addr, protos, ports):
    where = "/".join(sorted(protos)) + " :" + ",".join(sorted(ports, key=lambda p: int(p) if p.isdigit() else 0)[:3])
    net = f"  {addr.net}  AS{addr.asn}" if addr.net else ""
    return f"  {MARKS[addr.verdict]} {addr.ip:<15} {dim(where.ljust(14))} {describe(addr)}{dim(net)}"


def run_check(target, cfg, tips=False):
    """Следит за соединениями программы, пока не нажмут Enter, и печатает итог. Возвращает CheckResult."""
    result = CheckResult(target)
    paths = RouterPaths()
    out(f"  {bold(CHECK[0])} · {cyan(target)}\n\n")
    if tips:
        print_tips("check")
        out("\n")
    live = Live()
    live.start("ищу шлюз провайдера…")
    try:
        paths.prepare()
    except RuntimeError as e:
        live.stop()
        out(f"  {red('✖')} {e}\n")
        return result
    if paths.isp_hops:
        live.log(f"  {dim('Шлюз провайдера:')} {', '.join(sorted(paths.isp_hops))}"
                 f" {dim('— адреса, которые роутер передаёт другому узлу, считаю туннелем.')}\n")
    else:
        live.log(f"  {yellow('!')} Шлюз провайдера не отвечает на трассировку: путь адресов не определить,"
                 f" но зависшие соединения покажу.\n")

    lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=8)
    syn_since = {}   # соединение -> когда его впервые увидели в SYN_SENT
    local_vpn = []   # VPN-интерфейс компьютера, если программа ходит через него

    def status():
        with lock:
            addrs = list(result.addrs.values())
        n = lambda v: sum(a.verdict == v for a in addrs)
        live.set(f"слежу за {target} · адресов: {len(addrs)}" + (f" (проверяю {n(None)})" if n(None) else "")
                 + f" · туннель: {n('tunnel')} · напрямую: {n('direct')}"
                 f" · зависли: {sum(a.stuck for a in addrs)} · Enter — закончить")

    def inspect(addr):
        if ":" in addr.ip:
            addr.verdict = "ipv6"
        else:
            iface = paths.local_vpn(addr.ip)
            with lock:
                first = bool(iface) and not local_vpn
                if first:
                    local_vpn.append(iface)
            if first:
                live.log(f"  {yellow('!')} Программа сейчас ходит через VPN на компьютере ({iface}),"
                         f" роутер её трафик не видит.\n    {dim('Куда отправил бы её роутер, всё равно покажу.')}"
                         f" {dim('Зависшие соединения появятся, только если выключить VPN на компьютере.')}")
            addr.net, addr.asn = lookup_prefix(addr.ip, cfg["exact"])
            addr.verdict, addr.hop = paths.classify(addr.ip)
        with lock:
            protos, ports = list(addr.protos), list(addr.ports)
        live.log(row(addr, protos, ports))
        status()

    def tick():
        now = time.time()
        waiting = set()
        for c in connections_of(target, lsof_connections()):
            with lock:
                addr = result.addrs.get(c.ip)
                new = addr is None
                if new:
                    addr = result.addrs[c.ip] = Address(c.ip)
                addr.protos.add(c.proto)
                addr.ports.add(c.port)
            if new:
                pool.submit(inspect, addr)
            if c.state == "SYN_SENT":
                key = (c.local, c.ip, c.port)
                waiting.add(key)
                if now - syn_since.setdefault(key, now) >= STUCK_SECONDS and not addr.stuck:
                    addr.stuck = True
                    live.log(f"  {red('✖')} {addr.ip}:{c.port} {red('не отвечает')}"
                             f" {dim(f'— программа ждёт подключения уже {STUCK_SECONDS}+ сек (SYN_SENT)')}")
        for key in set(syn_since) - waiting:
            del syn_since[key]
        status()

    try:
        wait_for_stop(tick, 1)
    except KeyboardInterrupt:
        live.log(f"  {yellow('■')} остановлено")
    finally:
        live.set("дожидаюсь проверки адресов…")
        pool.shutdown(wait=True)
        live.stop()
    print_summary(result, cfg, local_vpn)
    return result


def print_summary(result, cfg, local_vpn):
    if not result.addrs:
        out(f"\n  {red('✖')} {result.target} не открыла ни одного соединения. Проверьте название программы"
            f" и пользуйтесь ею во время проверки.\n")
        return
    stuck, missing = result.stuck(), result.missing()
    counts = [f"{green('✔')} через туннель: {result.count('tunnel')}",
              f"{yellow('→')} напрямую: {result.count('direct')}"]
    counts += [f"{dim('?')} не определить: {result.count('unknown')}"] if result.count("unknown") else []
    counts += [f"{yellow('!')} IPv6: {result.count('ipv6')}"] if result.count("ipv6") else []
    counts += [f"{red('✖')} зависли: {len(stuck)}"]
    out(f"\n  {bold('Итог')} · {cyan(result.target)} · адресов: {len(result.addrs)}\n  " + "   ".join(counts) + "\n")

    if stuck:
        out(f"\n  {red('Зависшие соединения')} {dim('— сервер так и не ответил на подключение:')}\n")
        hints = {"direct": "идёт мимо туннеля — похоже на блокировку, пустите этот адрес через VPN",
                 "tunnel": "не отвечает даже через туннель — дело не в маршрутах"}
        for a in stuck:
            out(f"    {a.ip:<15} {dim(hints.get(a.verdict, ''))}\n")
    if missing:
        out(f"\n  {yellow('Мимо туннеля')} {dim('— эти адреса роутер отправляет напрямую:')}\n")
        for a in missing:
            out(f"    {a.ip:<15} {dim(str(a.net) + '  AS' + a.asn)}\n")
        out(f"\n  {dim('Если без них программа не работает, добавьте маршруты:')}\n")
        out("".join(f"    {r}\n" for r in route_lines(result.networks(), cfg)))
    if result.count("ipv6"):
        out(f"\n  {yellow('!')} Программа ходит и по IPv6, а маршруты .bat действуют только на IPv4.\n"
            f"    {dim('Отключите IPv6 на роутере или настройте для этих адресов маршруты IPv6.')}\n")
    if not missing and not stuck and not result.count("unknown"):
        out(f"\n  {green('✔')} Все адреса программы роутер отправляет в туннель.\n")
    if local_vpn:
        out(f"\n  {yellow('!')} Во время проверки программа ходила через VPN на компьютере ({local_vpn[0]}).\n"
            f"    {dim('Чтобы увидеть, работает ли она через роутер, выключите его и проверьте ещё раз.')}\n")
