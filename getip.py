#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""getip — находит IP-подсети сайта и сохраняет их в <сайт>.bat с командами `route add`.

  getip                  интерактивное меню
  getip claude.ai        быстрое сканирование, сразу создаёт claude.ai.bat
  getip claude.ai -d     глубокое сканирование (поддомены из сертификатов + опрос DNS)
  getip claude.ai -s     слушать DNS-трафик, пока вы пользуетесь сайтом (нужен sudo)
  getip -A Claude        отслеживать соединения программы (без DNS и без sudo)
"""
import argparse
import atexit
import ipaddress
import json
import os
import random
import re
import select
import shlex
import socket
import struct
import subprocess
import sys
import termios
import textwrap
import threading
import time
import tty
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.2.0"
CONFIG_PATH = os.path.expanduser("~/.config/getip/config.json")
DEFAULTS = {"gw": "0.0.0.0", "persistent": False, "exact": False,
            "out_dir": "", "deep_seconds": 60, "last_domain": ""}

RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "77.88.8.8"]
SUBDOMAINS = ["", "www.", "api.", "app.", "cdn.", "static.", "assets.", "media.", "img.",
              "images.", "auth.", "login.", "accounts.", "ws.", "m.", "mobile.", "mail.",
              "status.", "docs.", "support.", "help.", "blog.", "files.", "upload.", "video."]
RIPE_URL = "https://stat.ripe.net/data/network-info/data.json?resource={}"
CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
MAX_CRT_NAMES = 300

Q_RE = re.compile(r"q: A\? (\S+)")
A_RE = re.compile(r"\sA (\d{1,3}(?:\.\d{1,3}){3})\b")
ROUTE_RE = re.compile(r"route\s+(?:-p\s+)?add\s+(\S+)\s+mask\s+(\S+)", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")

# ─── оформление ──────────────────────────────────────────────────────────────

TTY = sys.stdout.isatty() and sys.stdin.isatty()
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _paint(code):
    return lambda s: f"\033[{code}m{s}\033[0m" if USE_COLOR else str(s)


bold, dim, cyan, green, yellow, red = (_paint(c) for c in ("1", "2", "36", "32", "33", "31"))

LOGO = ["┌─┐┌─┐┌┬┐┬┌─┐",
        "│ ┬├┤  │ │├─┘",
        "└─┘└─┘ ┴ ┴┴  "]


def out(s=""):
    sys.stdout.write(s)
    sys.stdout.flush()


def term_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 100


def cursor(show):
    if TTY:
        out("\033[?25h" if show else "\033[?25l")


atexit.register(cursor, True)


def header(title=""):
    if TTY:
        out("\033[H\033[2J\033[3J")
    out("\n")
    for line in LOGO:
        out("  " + bold(cyan(line)) + "\n")
    out("  " + dim(f"IP-подсети сайта → route add · v{VERSION}") + "\n\n")
    if title:
        out("  " + bold(title) + "\n\n")


PASTE_END = b"\x1b[201~"
RU_KEYS = {"й": "q", "о": "j", "л": "k"}  # те же клавиши в русской раскладке


def _drain(fd, wait):
    data = b""
    while select.select([fd], [], [], wait)[0]:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
    return data


def read_key(timeout=None):
    """Одна клавиша: 'up', 'down', 'enter', 'esc', символ, None по таймауту
    или ('paste', текст) — если в окно вставили текст или перетащили папку."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd, termios.TCSANOW)  # TCSANOW: не выбрасывать уже нажатые клавиши
        out("\033[?2004h")  # bracketed paste: вставка приходит одним куском
        if not select.select([fd], [], [], timeout)[0]:
            return None
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            if not select.select([fd], [], [], 0.05)[0]:
                return "esc"
            # читаем ровно одну последовательность, чтобы быстрые нажатия не слипались
            seq = os.read(fd, 1)
            if seq in (b"[", b"O"):
                while True:
                    c = os.read(fd, 1)
                    seq += c
                    if not c or 0x40 <= c[0] <= 0x7E:
                        break
            if seq == b"[200~":
                data = b""
                while PASTE_END not in data and select.select([fd], [], [], 1)[0]:
                    data += os.read(fd, 4096)
                return ("paste", data.split(PASTE_END)[0].decode(errors="ignore"))
            if seq[:1] in (b"[", b"O"):
                return {b"A": "up", b"B": "down", b"C": "right", b"D": "left"}.get(seq[-1:], "esc")
            return "esc"
        if ch in (b"/", b"~", b"'", b'"'):
            rest = _drain(fd, 0.03)
            if rest:  # путь пришёл пачкой символов — значит, перетащили или вставили
                return ("paste", (ch + rest).decode(errors="ignore"))
        if ch in (b"\r", b"\n"):
            return "enter"
        if ch[0] >= 0xC0:
            ch += os.read(fd, 1 if ch[0] < 0xE0 else 2)
        key = ch.decode(errors="ignore").lower()
        return RU_KEYS.get(key, key)
    finally:
        out("\033[?2004l")
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def parse_dropped_path(text):
    """Путь из перетащенной в терминал папки: '/a/My\\ Folder', '/a/b' в кавычках, file://."""
    s = (text or "").strip()
    if s.startswith("file://"):
        s = urllib.parse.unquote(urllib.parse.urlparse(s).path)
    elif not os.path.exists(os.path.expanduser(s)):
        try:
            parts = shlex.split(s)
        except ValueError:
            parts = []
        s = parts[0] if parts else s
    s = os.path.abspath(os.path.expanduser(s)) if s else ""
    if os.path.isfile(s):
        s = os.path.dirname(s)
    return s if s and os.path.isdir(s) else None


def menu(title, items, body="", index=0, footer="↑↓ выбор · → или Enter — открыть · ← — назад",
         on_paste=None, details=None):
    """items: [(название, подсказка)] или функция, их возвращающая (body — тоже).
    on_paste(текст) вызывается при вставке/перетаскивании и возвращает строку-уведомление.
    details(индекс) — подробное описание выбранного пункта, показывается под списком.
    Возвращает индекс пункта или None."""
    cursor(False)
    notice = ""
    while True:
        rows = items() if callable(items) else items
        text_body = body() if callable(body) else body
        width = max(len(label) for label, _ in rows)
        header(title)
        if text_body:
            out(text_body.rstrip("\n") + "\n\n")
        for i, (label, hint) in enumerate(rows):
            text = label.ljust(width)
            if i == index:
                out(f"  {cyan('❯')} {bold(cyan(text))}")
            else:
                out(f"    {text}")
            out(f"   {dim(hint)}\n" if hint else "\n")
        if notice:
            out("\n  " + notice + "\n")
        text_details = details(index) if details else ""
        if text_details:
            out("\n  " + dim("─" * min(80, term_width() - 4)) + "\n" + text_details.rstrip("\n") + "\n")
        out("\n  " + dim(footer) + "\n")
        key = read_key()
        notice = ""
        if isinstance(key, tuple):
            notice = on_paste(key[1]) if on_paste else ""
        elif key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key in ("enter", "right", "l"):
            return index
        elif key in ("q", "esc", "left"):
            return None
        elif key and key.isdigit() and 1 <= int(key) <= len(rows):
            return int(key) - 1


def ask(prompt, default=""):
    cursor(True)
    hint = f" {dim('[' + default + ']')}" if default else ""
    try:
        value = input(f"  {cyan('?')} {prompt}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        out("\n")
        return None
    return value or default


def pause(text="Нажмите любую клавишу…"):
    out("\n  " + dim(text))
    cursor(False)
    read_key()


def pretty(path):
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path


class Live:
    """Строка-спиннер внизу и лог над ней; лог можно писать из разных потоков."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.lock = threading.Lock()
        self.status = ""
        self.frame = 0
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None

    def _draw(self):
        if TTY and self.running:
            out(f"\r\033[K  {cyan(self.FRAMES[self.frame % len(self.FRAMES)])} {dim(self.status)}")

    def _spin(self):
        while not self.stop_event.wait(0.1):
            with self.lock:
                self.frame += 1
                self._draw()

    def start(self, status):
        self.status, self.running = status, True
        cursor(False)
        if TTY:
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()

    def set(self, status):
        with self.lock:
            self.status = status
            self._draw()

    def log(self, msg):
        with self.lock:
            out(("\r\033[K" if TTY else "") + msg + "\n")
            self._draw()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join()
        with self.lock:
            self.running = False
            if TTY:
                out("\r\033[K")


# ─── настройки ───────────────────────────────────────────────────────────────

def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def out_dir(cfg):
    return os.path.abspath(os.path.expanduser(cfg["out_dir"] or os.getcwd()))


# ─── сеть ────────────────────────────────────────────────────────────────────

def normalize_domain(text):
    s = (text or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s)[0].split("@")[-1].split(":")[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode()
    except UnicodeError:
        return None
    return s if DOMAIN_RE.match(s) else None


def matches(name, domain):
    name = name.rstrip(".").lower()
    return name == domain or name.endswith("." + domain)


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


# ─── сбор адресов ────────────────────────────────────────────────────────────

# системные домены macOS, которые светятся в любом трафике — их не показываем
NOISE_DOMAINS = {"apple.com", "icloud.com", "apple-dns.net", "aaplimg.com", "mzstatic.com",
                 "apple.news", "cdn-apple.com", "icloud-content.com", "apple-cloudkit.com",
                 "itunes.com", "push.apple.com"}

# Описание режимов простым языком: (заголовок, текст). Строки текста, начинающиеся
# с цифры, — шаги инструкции, их перенос выравнивается под текст шага.
TIPS = {
    "quick": [
        ("Что делает", "Спрашивает у нескольких DNS-серверов адреса сайта и его популярных "
                       "поддоменов (www, api, cdn и т.п.)."),
        ("Что делать вам", "Ничего особенного: введите адрес сайта и подождите около 10 секунд."),
        ("Когда подходит", "Для простых сайтов и быстрой проверки. Может пропустить часть адресов — "
                           "для полного списка используйте «Слушать трафик»."),
    ],
    "deep": [
        ("Что делает", "Находит все известные поддомены сайта в открытых журналах SSL-сертификатов "
                       "и опрашивает их по кругу, собирая адреса, которые сайт меняет со временем."),
        ("Что делать вам", "Введите адрес сайта и подождите. По умолчанию опрос идёт 60 секунд, "
                           "время меняется в настройках. Остановить раньше — Ctrl+C."),
        ("Ограничение", "Не видит чужие сервисы, которыми пользуется сайт (CDN, вход, оплата) — "
                        "для них используйте «Слушать трафик»."),
    ],
    "sniff": [
        ("Что делает", "Следит, к каким серверам обращается ваш браузер, пока вы пользуетесь "
                       "сайтом, и сам повторно опрашивает найденные имена. Самый полный способ."),
        ("Что делать вам",
         "1. Отключите в браузере «Безопасный DNS» (Chrome: Настройки → Конфиденциальность "
         "и безопасность → Безопасность).\n"
         "2. Откройте сайт в окне инкогнито и пройдите по нужным разделам: вход, рабочие "
         "страницы, загрузка файлов, оплата.\n"
         "3. Подождите 2–3 минуты и нажмите Enter. Перезагружать страницу не нужно.\n"
         "4. Отметьте в списке чужие домены, без которых сайт не работает."),
        ("Важно", "Нужен пароль администратора. Вход в аккаунт на сайте не мешает: getip видит "
                  "только имена серверов, а не ваши данные."),
    ],
    "app": [
        ("Что делает", "Следит за сетевыми соединениями выбранной программы (Claude, Telegram…) "
                       "и записывает адреса её серверов напрямую, без DNS."),
        ("Что делать вам", "Запустите программу, выберите её в списке и активно пользуйтесь: "
                           "открывайте разделы, отправляйте сообщения, загружайте файлы. "
                           "Затем нажмите Enter."),
        ("Важно", "Пароль не нужен. Нет программы в списке — сделайте в ней что-нибудь "
                  "и выберите «Обновить список»."),
    ],
}


def render_tips(mode):
    width = max(40, min(90, term_width() - 6))
    lines = []
    for title, text in TIPS[mode]:
        lines.append("  " + bold(cyan(title)))
        for para in text.split("\n"):
            indent = "     " if para[:1].isdigit() else "    "
            for line in textwrap.wrap(para, width, initial_indent="    ", subsequent_indent=indent):
                lines.append(line)
    return "\n".join(lines) + "\n"


def print_tips(mode):
    out(render_tips(mode))


def base_domain(name):
    """Домен второго уровня: cdn.x.example.com → example.com, a.b.co.uk → b.co.uk."""
    parts = name.split(".")
    n = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in (
        "co", "com", "net", "org", "gov", "edu", "ac") else 2
    return ".".join(parts[-n:])


def is_noise(name):
    return name.endswith((".arpa", ".local")) or base_domain(name) in NOISE_DOMAINS


def safe_filename(name):
    return re.sub(r'[\\/:*?"<>|]+', "_", name).strip() or "getip"


class Collector:
    """IP по именам хостов. В итог попадают IP сайта и отмеченных чужих доменов."""

    def __init__(self, target, cfg, log, include_all=False):
        self.target, self.cfg, self.log, self.include_all = target, cfg, log, include_all
        self.ip_names = {}      # ip -> имена хостов, где его видели
        self.ip_net = {}        # ip -> подсеть провайдера
        self.file_nets = set()  # подсети из существующего .bat (режим «дополнить»)
        self.extra = set()      # отмеченные чужие домены
        self.names = set()      # имена из трафика — их опрашиваем повторно
        self.closed = False
        self.lock = threading.Lock()

    def is_site(self, name):
        return self.include_all or matches(name, self.target)

    def included(self, names):
        return any(self.is_site(n) or base_domain(n) in self.extra for n in names)

    def add(self, ip, name):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        with self.lock:
            if self.closed or not addr.is_global:
                return
            if ip in self.ip_names:
                self.ip_names[ip].add(name)
                return
            self.ip_names[ip] = {name}
            known = next((n for n in set(self.ip_net.values()) | self.file_nets if addr in n), None)
        site = self.is_site(name)
        if known:
            with self.lock:
                self.ip_net[ip] = known
            if site:
                self.log(f"  {dim('·')} {ip:<15} {dim(name)}  {dim('уже в ' + str(known))}")
            return
        net, asn = lookup_prefix(ip, self.cfg["exact"])
        with self.lock:
            self.ip_net[ip] = net
        if site:
            self.log(f"  {green('+')} {ip:<15} {name}  {dim('→')} {cyan(str(net))}  {dim('AS' + asn)}")
        else:
            self.log("  " + dim(f"○ {ip:<15} {name}  → {net}  (чужой домен)"))

    def load_bat(self, path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            for a, m in ROUTE_RE.findall(f.read()):
                try:
                    self.file_nets.add(ipaddress.ip_network(f"{a}/{m}", strict=False))
                except ValueError:
                    pass

    def included_ips(self):
        with self.lock:
            return [ip for ip, names in self.ip_names.items() if self.included(names)]

    def third_party(self):
        """{чужой домен: {имена}} — всё, что видели в трафике кроме самого сайта."""
        groups = {}
        with self.lock:
            for names in self.ip_names.values():
                for n in names:
                    if not self.is_site(n):
                        groups.setdefault(base_domain(n), set()).add(n)
        return groups

    def networks(self):
        ips = self.included_ips()
        nets = {self.ip_net[ip] for ip in ips if ip in self.ip_net} | self.file_nets
        return sorted(ipaddress.collapse_addresses(nets))

    def routes(self):
        cmd = "route -p add" if self.cfg["persistent"] else "route add"
        return [f"{cmd} {n.network_address} mask {n.netmask} {self.cfg['gw']}" for n in self.networks()]


def wait_for_stop(tick, every):
    """Вызывает tick() каждые `every` сек, пока не нажмут Enter / q (или Ctrl+C)."""
    next_tick = 0
    while True:
        if time.time() >= next_tick:
            tick()
            next_tick = time.time() + every
        if TTY:
            if read_key(0.3) in ("enter", "q", "esc"):
                return
        else:
            time.sleep(0.3)


def scan_names(col, names, live, label):
    ex = ThreadPoolExecutor(max_workers=32)
    try:
        futures = {ex.submit(resolve_everywhere, n): n for n in names}
        for done, fut in enumerate(as_completed(futures), 1):
            live.set(f"{label}: {done}/{len(names)} имён · IP найдено: {len(col.ip_names)} · Ctrl+C — стоп")
            for ip in sorted(fut.result()):
                col.add(ip, futures[fut])
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def quick_scan(col, live):
    scan_names(col, [s + col.target for s in SUBDOMAINS], live, "опрос DNS")


def deep_scan(col, live):
    live.set("ищу поддомены в журналах сертификатов (crt.sh)…")
    try:
        found = crtsh_names(col.target)
        live.log(f"  {dim('ℹ')} в сертификатах найдено поддоменов: {len(found)}")
    except Exception as e:
        found = []
        live.log(f"  {yellow('!')} crt.sh недоступен ({e}), сканирую только основные поддомены")
    names = list(dict.fromkeys([s + col.target for s in SUBDOMAINS] + found))
    deadline, n = time.time() + col.cfg["deep_seconds"], 1
    while True:
        scan_names(col, names, live, f"проход {n}")
        left = deadline - time.time()
        if left <= 0:
            return
        live.set(f"жду следующий проход ({int(left)} сек осталось) · IP: {len(col.ip_names)} · Ctrl+C — стоп")
        time.sleep(min(10, left))
        n += 1


def sniff(col, live):
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    if sudo:
        out(f"  {yellow('🔒')} Для прослушивания трафика нужен пароль администратора.\n")
        cursor(True)
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            raise RuntimeError("sudo не получен")
    if sys.platform == "darwin":
        # сбрасываем системный DNS-кэш, чтобы приложения заново спросили адреса
        subprocess.run(sudo + ["dscacheutil", "-flushcache"], capture_output=True)
        subprocess.run(sudo + ["killall", "-HUP", "mDNSResponder"], capture_output=True)
    iface = "all" if sys.platform == "darwin" else "any"
    proc = subprocess.Popen(sudo + ["tcpdump", "-l", "-n", "-vvv", "-i", iface, "udp src port 53"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    col.names.update({col.target, "www." + col.target})
    stop = threading.Event()
    rounds = [0]

    def status():
        live.set(f"слушаю · имён: {len(col.names)} · IP сайта: {len(col.included_ips())}"
                 f" · опросов: {rounds[0]} · Enter — закончить")

    def reader():
        for line in proc.stdout:
            q = Q_RE.search(line)
            if not q:
                continue
            name = q.group(1).rstrip(".").lower()
            if is_noise(name):
                continue
            with col.lock:
                col.names.add(name)
            for ip in A_RE.findall(line):
                col.add(ip, name)
            status()

    def repoll():
        # браузер кэширует DNS, поэтому сами переспрашиваем все увиденные имена по кругу
        while not stop.wait(10 if rounds[0] else 0):
            with col.lock:
                names = sorted(col.names, key=lambda n: (not col.is_site(n), n))[:200]
            ex = ThreadPoolExecutor(max_workers=16)
            try:
                for name, ips in zip(names, ex.map(resolve_everywhere, names)):
                    if stop.is_set():
                        return
                    for ip in ips:
                        col.add(ip, name)
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
            rounds[0] += 1
            status()

    def tick():
        if proc.poll() is not None:
            raise RuntimeError("tcpdump остановился: " + proc.stderr.read().strip()[-200:])

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=repoll, daemon=True).start()
    out(f"  {dim('Откройте')} {bold(col.target)} {dim('в браузере и пройдите по нужным разделам.')}\n")
    out(f"  {dim('«Безопасный DNS» в браузере должен быть выключен. Перезагружать страницу не нужно.')}\n\n")
    live.start("слушаю…")
    status()
    try:
        wait_for_stop(tick, 0.3)
    finally:
        stop.set()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def app_name(command):
    """«Google Chrome Helper (Renderer)» → «Google Chrome»: помощники считаем частью программы."""
    return re.split(r" Helper\b| Networking\b|\.app\b", command)[0].strip()


def lsof_connections():
    """{приложение: [(ip, порт)]} — установленные соединения ваших программ."""
    r = subprocess.run(["lsof", "+c", "0", "-nP", "-i", "-F", "cn"],
                       capture_output=True, text=True, errors="replace")
    apps, cmd = {}, None
    for line in r.stdout.splitlines():
        kind, value = line[:1], line[1:]
        if kind == "c":
            cmd = app_name(value)
        elif kind == "n" and "->" in value and cmd:
            remote = value.split("->", 1)[1]
            if remote.startswith("["):
                continue  # IPv6
            ip, _, port = remote.rpartition(":")
            try:
                if ipaddress.ip_address(ip).is_global:
                    apps.setdefault(cmd, []).append((ip, port))
            except ValueError:
                pass
    return apps


def app_scan(col, live):
    polls = [0]

    def tick():
        apps = lsof_connections()
        # точное имя важнее: «Claude» (программа) и «claude» (консольная утилита) — разные
        conns = apps.get(col.target) or next(
            (v for k, v in apps.items() if k.lower() == col.target.lower()), [])
        for ip, port in conns:
            col.add(ip, f"{col.target} :{port}")
        polls[0] += 1
        live.set(f"слежу за {col.target} · соединений сейчас: {len(conns)} · IP: {len(col.ip_names)}"
                 f" · проверок: {polls[0]} · Enter — закончить")

    out(f"  {dim('Пользуйтесь')} {bold(col.target)} {dim('— открывайте разделы, отправляйте сообщения.')}\n\n")
    live.start(f"слежу за {col.target}…")
    wait_for_stop(tick, 2)


def checklist(title, rows, checked, body=""):
    """rows: [(ключ, подсказка)]. Пробел — отметить, a — все/ничего, Enter — готово."""
    checked, index = set(checked), 0
    width = max(len(k) for k, _ in rows)
    cursor(False)
    while True:
        header(title)
        if body:
            out(body.rstrip("\n") + "\n\n")
        height = max(5, os.get_terminal_size().lines - 18) if TTY else len(rows)
        start = min(max(0, index - height // 2), max(0, len(rows) - height))
        if start:
            out("  " + dim(f"  ↑ ещё {start}") + "\n")
        for i in range(start, min(len(rows), start + height)):
            key, hint = rows[i]
            box = green("◉") if key in checked else dim("○")
            label = bold(cyan(key.ljust(width))) if i == index else key.ljust(width)
            out(f"  {cyan('❯') if i == index else ' '} {box} {label}   {dim(hint)}\n")
        if start + height < len(rows):
            out("  " + dim(f"  ↓ ещё {len(rows) - start - height}") + "\n")
        out("\n  " + dim("↑↓ выбор · Пробел — отметить · a — все/ничего · Enter — готово") + "\n")
        key = read_key()
        if isinstance(key, tuple):
            continue
        if key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key == " ":
            checked ^= {rows[index][0]}
        elif key in ("a", "ф"):
            checked = set() if len(checked) == len(rows) else {k for k, _ in rows}
        elif key in ("enter", "q", "esc"):
            return checked


def choose_extras(col, remembered):
    groups = col.third_party()
    rows = [(d, f"имён: {len(n)} — " + ", ".join(sorted(n, key=len)[:2]) + ("…" if len(n) > 2 else ""))
            for d, n in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    body = ("  " + dim(f"Кроме {col.target} браузер обращался к этим доменам. Отметьте те, без которых")
            + "\n  " + dim("сайт не работает: CDN, API, вход, оплата, хранилище файлов. Рекламу, аналитику")
            + "\n  " + dim("и сайты из других вкладок отмечать не нужно. Выбор запомнится для этого сайта."))
    return checklist(f"Чужие домены · {col.target}", rows, set(remembered) & set(groups), body)


def remember_extras(cfg, target, extras):
    # сохраняем только выбор доменов, не трогая ключи командной строки этого запуска
    saved = load_config()
    saved.setdefault("extras", {})[target] = sorted(extras)
    save_config(saved)
    cfg.setdefault("extras", {})[target] = sorted(extras)


MODES = {
    "quick": ("Быстрое сканирование", "DNS-запросы к основным поддоменам, ~10 сек"),
    "deep": ("Глубокое сканирование", "поддомены из сертификатов + повторный опрос"),
    "sniff": ("Слушать трафик", "вы пользуетесь сайтом в браузере, getip записывает (sudo)"),
    "app": ("Отслеживать приложение", "соединения выбранной программы, без DNS"),
}
SCANNERS = {"quick": quick_scan, "deep": deep_scan, "sniff": sniff, "app": app_scan}


def bat_path(cfg, target):
    return os.path.join(out_dir(cfg), safe_filename(target) + ".bat")


def run_scan(target, mode, cfg, append=False, tips=False):
    """Сканирует сайт или приложение и пишет <имя>.bat. Возвращает (путь или None, коллектор)."""
    path = bat_path(cfg, target)
    live = Live()
    col = Collector(target, cfg, live.log, include_all=(mode == "app"))
    if append and os.path.exists(path):
        col.load_bat(path)
    out(f"  {bold(MODES[mode][0])} · {cyan(target)}"
        + (f" {dim('(дополняю ' + str(len(col.file_nets)) + ' подсетей из файла)')}" if col.file_nets else "")
        + "\n\n")
    if tips:
        print_tips(mode)
        out("\n")
    if mode in ("quick", "deep"):
        live.start("запускаю…")
    try:
        SCANNERS[mode](col, live)
    except KeyboardInterrupt:
        live.log(f"  {yellow('■')} остановлено")
    except RuntimeError as e:
        live.log(f"  {red('✖')} {e}")
    finally:
        live.stop()
        col.closed = True

    if mode == "sniff" and TTY and col.third_party():
        col.extra = choose_extras(col, cfg.get("extras", {}).get(target, []))
        remember_extras(cfg, target, col.extra)
        header()
        out(f"  {bold(MODES[mode][0])} · {cyan(target)}\n")

    if not col.networks():
        out(f"\n  {red('✖')} Не найдено ни одного адреса — проверьте адрес сайта.\n")
        return None, col
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(col.routes()) + "\n")
    extra = f" {dim('(+ ' + ', '.join(sorted(col.extra)) + ')')}" if col.extra else ""
    out(f"\n  {green('✔')} {len(col.included_ips())} IP → {bold(str(len(col.networks())))} подсетей{extra}"
        f" · сохранено в {bold(pretty(path))}\n")
    return path, col


# ─── интерактивный режим ─────────────────────────────────────────────────────

def show_file(path):
    """Печатает содержимое файла прямо в терминале, с номерами строк."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    name = os.path.basename(path)
    out(f"\n  {dim('──')} {bold(name)} {dim('· ' + str(len(lines)) + ' строк ' + '─' * 20)}\n")
    for n, line in enumerate(lines, 1):
        out(f"  {dim(str(n).rjust(3) + ' │')} {line}\n")
    out(f"  {dim('─' * (len(name) + 34))}\n")


def after_scan(path, col):
    """Экран после сканирования: горячие клавиши, любая другая — продолжить."""
    hint = (f"  {bold(cyan('o'))} {dim('открыть папку')}   {bold(cyan('v'))} {dim('показать файл')}   "
            f"{bold(cyan('c'))} {dim('скопировать')}   {dim('любая другая клавиша — продолжить')}\n")
    out("\n" + hint)
    cursor(False)
    while True:
        key = read_key()
        if isinstance(key, tuple):
            continue
        if key in ("o", "щ"):
            subprocess.run(["open", "-R", path])
            out(f"  {green('✔')} {dim('Открыл папку в Finder')}\n")
        elif key in ("v", "м"):
            show_file(path)
            out("\n" + hint)
        elif key in ("c", "с"):
            subprocess.run(["pbcopy"], input="\r\n".join(col.routes()) + "\r\n", text=True)
            out(f"  {green('✔')} {dim('Команды скопированы в буфер обмена')}\n")
        else:
            return


def drop_folder(cfg, text):
    """Папку перетащили в окно меню — делаем её папкой для файлов."""
    path = parse_dropped_path(text)
    if not path:
        return f"{red('✖')} Это не папка: {text.strip()}"
    cfg["out_dir"] = path
    save_config(cfg)
    return f"{green('✔')} Файлы теперь сохраняются в {bold(pretty(path))}"


def settings_menu(cfg):
    on = lambda v: green("вкл") if v else dim("выкл")
    items = lambda: [
        ("Шлюз", cfg["gw"]),
        ("Постоянные маршруты", on(cfg["persistent"]) + dim("  route -p add")),
        ("Только точные IP (/32)", on(cfg["exact"]) + dim("  без расширения до подсети")),
        ("Папка для файлов", pretty(cfg["out_dir"]) if cfg["out_dir"] else "текущая папка терминала"),
        ("Глубокое сканирование", f"{cfg['deep_seconds']} сек"),
        ("Назад", ""),
    ]
    index = 0
    while True:
        index = menu("Настройки", items, index=index, on_paste=lambda t: drop_folder(cfg, t),
                     body="  " + dim("Совет: перетащите папку в это окно, чтобы сохранять файлы туда."))
        if index is None or index == 5:
            return
        if index == 0:
            v = ask("Шлюз (IP)", cfg["gw"])
            try:
                cfg["gw"] = str(ipaddress.IPv4Address(v)) if v else cfg["gw"]
            except ValueError:
                pass
        elif index == 1:
            cfg["persistent"] = not cfg["persistent"]
        elif index == 2:
            cfg["exact"] = not cfg["exact"]
        elif index == 3:
            header("Папка для файлов")
            out("  " + dim("Перетащите папку в окно (или введите путь) и нажмите Enter.") + "\n")
            out("  " + dim("Пусто — оставить как есть, «-» — сохранять в текущую папку терминала.") + "\n\n")
            v = ask("Папка")
            if v == "-":
                cfg["out_dir"] = ""
            elif v:
                path = parse_dropped_path(v)
                if path:
                    cfg["out_dir"] = path
                else:
                    out(f"\n  {red('✖')} Такой папки нет: {v}\n")
                    pause()
        elif index == 4:
            v = ask("Сколько секунд опрашивать DNS", str(cfg["deep_seconds"]))
            if v and v.isdigit():
                cfg["deep_seconds"] = max(10, int(v))
        save_config(cfg)


def pick_app():
    """Список программ с открытыми соединениями; возвращает имя выбранной или None."""
    body = render_tips("app")
    while True:
        apps = lsof_connections()
        rows = [("↻ Обновить список", "")] + [
            (name, f"соединений: {len(conns)}")
            for name, conns in sorted(apps.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))]
        i = menu(MODES["app"][0], rows, body=body)
        if i is None:
            return None
        if i > 0:
            return rows[i][0]


def confirm_exit():
    i = menu("Выйти из getip?", [("Нет, остаться", ""), ("Да, выйти", "")],
             footer="↑↓ выбор · → или Enter — подтвердить · ← — назад")
    return i == 1


def interactive(cfg):
    keys = list(MODES)
    items = [MODES[k] for k in keys] + [("Настройки", ""), ("Открыть папку с файлами", ""), ("Выход", "")]
    index = 0
    while True:
        body = lambda: ("  " + dim("Файлы сохраняются в: ") + pretty(out_dir(cfg)) + "\n"
                        "  " + dim("Перетащите папку в это окно, чтобы сохранять файлы туда."))
        i = menu("Главное меню", items, body=body, index=index, on_paste=lambda t: drop_folder(cfg, t),
                 details=lambda n: render_tips(keys[n]) if n < len(keys) else "",
                 footer="↑↓ выбор · → или Enter — открыть · ← — выход")
        if i is None or i == len(items) - 1:
            index = i if i is not None else index
            if confirm_exit():
                break
            continue
        index = i
        if i < len(keys):
            mode = keys[i]
            if mode == "app":
                target = pick_app()
                if not target:
                    continue
            else:
                header(MODES[mode][0])
                print_tips(mode)
                out("\n  " + dim("Введите адрес и нажмите Enter · Ctrl+C — назад в меню") + "\n\n")
                raw = ask("Адрес сайта", cfg["last_domain"])
                if raw is None:
                    continue
                target = normalize_domain(raw)
                if not target:
                    out(f"  {red('✖')} Не похоже на адрес сайта. Пример: claude.ai\n")
                    pause()
                    continue
                cfg["last_domain"] = target
                save_config(cfg)
            append = False
            if os.path.exists(bat_path(cfg, target)):
                choice = menu(f"Файл {os.path.basename(bat_path(cfg, target))} уже существует", [
                    ("Дополнить", "добавить новые подсети к старым"),
                    ("Перезаписать", "начать с чистого листа"),
                ])
                if choice is None:
                    continue
                append = choice == 0
            header()
            path, col = run_scan(target, mode, cfg, append)
            if path:
                after_scan(path, col)
            else:
                pause()
        elif i == len(keys):
            settings_menu(cfg)
        elif i == len(keys) + 1:
            os.makedirs(out_dir(cfg), exist_ok=True)
            subprocess.run(["open", out_dir(cfg)])
    if TTY:
        out("\033[H\033[2J\033[3J")
    out(f"  {cyan('getip')} {dim('— до встречи!')}\n")


# ─── командная строка ────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="getip",
        description="Находит IP-подсети сайта и сохраняет их в <сайт>.bat (route add …). "
                    "Без аргументов открывает меню.")
    p.add_argument("sites", nargs="*", help="адреса сайтов, напр. claude.ai")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-d", "--deep", action="store_true", help="глубокое сканирование")
    g.add_argument("-s", "--sniff", action="store_true", help="слушать DNS-трафик (sudo)")
    g.add_argument("-A", "--app", metavar="ПРИЛОЖЕНИЕ",
                   help="отслеживать соединения программы, напр. -A Claude")
    p.add_argument("-t", "--time", type=int, help="длительность глубокого сканирования, сек")
    p.add_argument("-a", "--append", action="store_true", help="дополнить существующий .bat")
    p.add_argument("-o", "--out", help="папка для .bat (по умолчанию — текущая)")
    p.add_argument("-g", "--gw", help="шлюз в командах route (по умолчанию 0.0.0.0)")
    p.add_argument("-p", "--persistent", action="store_true", help="писать route -p add")
    p.add_argument("--exact", action="store_true", help="только точные IP (/32)")
    p.add_argument("-v", "--version", action="version", version=f"getip {VERSION}")
    args = p.parse_args()

    cfg = load_config()
    if not args.sites and not args.app:
        if not TTY:
            p.print_help()
            return
        try:
            interactive(cfg)
        except KeyboardInterrupt:
            out("\n")
        return

    # ключи командной строки действуют только на этот запуск и не сохраняются
    cfg.update({k: v for k, v in (("out_dir", args.out), ("gw", args.gw), ("deep_seconds", args.time)) if v})
    cfg["persistent"] |= args.persistent
    cfg["exact"] |= args.exact
    if args.app:
        targets, mode = [args.app], "app"
    else:
        mode = "deep" if args.deep else "sniff" if args.sniff else "quick"
        targets = []
        for site in args.sites:
            domain = normalize_domain(site)
            if domain:
                targets.append(domain)
            else:
                out(f"  {red('✖')} «{site}» не похоже на адрес сайта\n")
    for target in targets:
        out("\n")
        path, col = run_scan(target, mode, cfg, args.append, tips=mode in ("sniff", "app"))
        if path:
            out("\n" + "\n".join("  " + r for r in col.routes()) + "\n\n")


if __name__ == "__main__":
    main()
