"""Куда роутер отправляет трафик к адресу: в VPN-туннель или напрямую провайдеру.

Смотрим второй узел трассировки. Первый — сам роутер, второй — тот, кому роутер
передал пакет: для адресов из списка VPN это сервер туннеля, для остальных — шлюз
провайдера. Шлюз провайдера узнаём по контрольным адресам, которые через VPN не идут.

Трассировку пускаем через интерфейс, которым компьютер подключён к роутеру (en0),
поэтому VPN на самом компьютере проверке не мешает."""
import ipaddress
import re
import shutil
import subprocess
import sys
import threading

REFERENCE_IPS = ("77.88.8.8", "77.88.8.1")  # DNS Яндекса: российские адреса в туннель не заворачивают
VPN_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap", "wg")
HOP_RE = re.compile(r"^\s*2\s+(\S+)", re.M)


def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def parse_default_interface(netstat_text):
    """Интерфейс маршрута по умолчанию через роутер из `netstat -rn -f inet`; VPN-интерфейсы пропускаем."""
    for line in netstat_text.splitlines():
        parts = line.split()
        if (len(parts) >= 4 and parts[0] == "default" and _is_ip(parts[1])
                and not parts[3].startswith(VPN_PREFIXES)):
            return parts[3]
    return None


def parse_second_hop(traceroute_text):
    """Адрес второго узла из вывода traceroute или None, если он не ответил."""
    m = HOP_RE.search(traceroute_text)
    return m.group(1) if m and m.group(1) != "*" else None


def verdict(hop, isp_hops):
    """tunnel — роутер передал пакет не провайдеру, direct — провайдеру, unknown — узел не ответил."""
    if hop is None or not isp_hops:
        return "unknown"
    return "direct" if hop in isp_hops else "tunnel"


def physical_interface():
    """Интерфейс, которым компьютер подключён к роутеру, — даже когда на нём включён свой VPN."""
    if sys.platform == "darwin":
        return parse_default_interface(_run(["netstat", "-rn", "-f", "inet"]))
    for line in _run(["ip", "-4", "route", "show", "default"]).splitlines():
        m = re.search(r"\bdev (\S+)", line)
        if m and " via " in line and not m.group(1).startswith(VPN_PREFIXES):
            return m.group(1)
    return None


def system_interface(ip):
    """Интерфейс, через который компьютер сам отправит пакет к ip."""
    if sys.platform == "darwin":
        m = re.search(r"interface:\s*(\S+)", _run(["route", "-n", "get", ip]))
    else:
        m = re.search(r"\bdev (\S+)", _run(["ip", "route", "get", ip]))
    return m.group(1) if m else None


def second_hop(ip, iface):
    return parse_second_hop(_run(["traceroute", "-n", "-m", "2", "-q", "1", "-w", "1", "-i", iface, ip],
                                 timeout=8))


class RouterPaths:
    """Определяет путь адресов через роутер. Перед classify нужно один раз вызвать prepare."""

    def __init__(self):
        self.iface = None       # интерфейс к роутеру (en0)
        self.isp_hops = set()   # второй узел на пути к контрольным адресам — шлюз провайдера
        self._cache = {}
        self._lock = threading.Lock()

    def prepare(self):
        """Находит интерфейс к роутеру и шлюз провайдера. RuntimeError — если проверить не выйдет."""
        if not shutil.which("traceroute"):
            raise RuntimeError("Не найдена программа traceroute — установите её "
                               "(Linux: sudo apt install traceroute)")
        self.iface = physical_interface()
        if not self.iface:
            raise RuntimeError("Не нашёл подключение к роутеру: нет маршрута по умолчанию через Wi-Fi или кабель")
        self.isp_hops = {h for h in (second_hop(ip, self.iface) for ip in REFERENCE_IPS) if h}

    def classify(self, ip):
        """(вердикт, второй узел) для адреса; результат запоминается."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        hop = second_hop(ip, self.iface) or second_hop(ip, self.iface)  # ответ мог потеряться — ещё раз
        result = (verdict(hop, self.isp_hops), hop)
        with self._lock:
            self._cache[ip] = result
        return result

    def local_vpn(self, ip):
        """Имя VPN-интерфейса на компьютере, если пакеты к ip уходят через него, иначе None."""
        iface = system_interface(ip)
        return iface if iface and iface != self.iface and iface.startswith(VPN_PREFIXES) else None
