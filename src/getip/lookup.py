"""Внешние источники: DNS-серверы, журналы сертификатов crt.sh, подсети провайдеров и геолокация
из RIPEstat, внешний адрес компьютера (сервер Яндекса для замера скорости)."""
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .domains import matches

RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "77.88.8.8"]
RIPE_URL = "https://stat.ripe.net/data/network-info/data.json?resource={}"
GEO_URL = "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={}"
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
MAX_CRT_NAMES = 300
IP_HOST = "ipv4-internet.yandex.net"  # отвечает адресом, с которого пришёл запрос; российский — роутеры шлют его напрямую
IP_BOUND_IF = 25                      # macOS: сокет ходит только через заданный интерфейс, мимо VPN


def dns_query(name, server, timeout=2.0):
    """A-запрос напрямую к DNS-серверу (в обход системного кэша)."""
    try:
        tid = random.randint(0, 0xFFFF)
        question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
        packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 53))
            data = s.recv(4096)
        if struct.unpack(">H", data[:2])[0] != tid or data[3] & 0x0F:
            return set()
        pos, ips = 12 + len(question) + 4, set()
        for _ in range(struct.unpack(">H", data[6:8])[0]):
            while data[pos] and data[pos] & 0xC0 != 0xC0:
                pos += data[pos] + 1
            pos += 2 if data[pos] else 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.add(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
        return ips
    except (OSError, struct.error, IndexError):
        return set()


def resolve_everywhere(name):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)}
    except OSError:
        ips = set()
    for server in RESOLVERS:
        ips |= dns_query(name, server)
    return ips


def resolve_system(names):
    """{ip: имя} по системному DNS — те адреса, что получит браузер. Имя — первое из names, где адрес нашёлся."""
    def one(name):
        try:
            return {i[4][0] for i in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)}
        except OSError:
            return set()

    found = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        for name, ips in zip(names, ex.map(one, names)):
            for ip in sorted(ips):
                found.setdefault(ip, name)
    return found


def public_ip(iface=None, timeout=5):
    """Внешний адрес, с которым компьютер видят сайты: обычным путём или через интерфейс iface
    (en0 — мимо VPN; так умеет только macOS). None — не узнали."""
    if iface and sys.platform != "darwin":
        return None
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        if iface:
            raw.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(iface))
        raw.connect((socket.gethostbyname(IP_HOST), 443))
        with ssl.create_default_context().wrap_socket(raw, server_hostname=IP_HOST) as s:
            s.sendall(f"GET /api/v0/ip HTTP/1.0\r\nHost: {IP_HOST}\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        m = re.search(rb'"(\d{1,3}(?:\.\d{1,3}){3})"', data.partition(b"\r\n\r\n")[2])
        return m.group(1).decode() if m else None
    except (OSError, ValueError):
        return None
    finally:
        raw.close()


def geo(ip):
    """«RU, Voronezh» — где адрес по базе MaxMind GeoLite (данные RIPEstat). По таким базам сайты
    и определяют страну. None — не узнали."""
    try:
        with urllib.request.urlopen(GEO_URL.format(ip), timeout=10) as r:
            locations = [loc for res in json.load(r)["data"]["located_resources"] for loc in res["locations"]]
        return ", ".join(x for x in (locations[0].get("country"), locations[0].get("city")) if x) or None
    except Exception:
        return None


def crtsh_names(domain):
    req = urllib.request.Request(CRTSH_URL.format(domain), headers={"User-Agent": "getip"})
    with urllib.request.urlopen(req, timeout=40) as r:
        rows = json.load(r)
    names = set()
    for row in rows:
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if matches(n, domain):
                names.add(n)
    return sorted(names, key=len)[:MAX_CRT_NAMES]


_prefix_cache = {}


def lookup_prefix(ip, exact):
    """Подсеть, которую анонсирует провайдер (BGP), по данным RIPEstat."""
    if exact:
        return ipaddress.ip_network(f"{ip}/32"), "-"
    if ip not in _prefix_cache:
        try:
            with urllib.request.urlopen(RIPE_URL.format(ip), timeout=10) as r:
                data = json.load(r)["data"]
            net = ipaddress.ip_network(data["prefix"])
            if net.version != 4:
                raise ValueError("не IPv4")
            _prefix_cache[ip] = (net, ",".join(data.get("asns") or []) or "?")
        except Exception:
            return ipaddress.ip_network(f"{ip}/32"), "?"
    return _prefix_cache[ip]
