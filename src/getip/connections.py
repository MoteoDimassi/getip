"""Сетевые соединения программ по данным lsof."""
import ipaddress
import re
import subprocess
from collections import namedtuple

# proto — TCP/UDP, local — «адрес:порт» на компьютере, state — состояние TCP (ESTABLISHED, SYN_SENT…)
Connection = namedtuple("Connection", "proto local ip port state")


def app_name(command):
    """«Google Chrome Helper (Renderer)» → «Google Chrome»: помощники считаем частью программы."""
    return re.split(r" Helper\b| Networking\b|\.app\b", command)[0].strip()


def parse_lsof(text):
    """{программа: [Connection]} из вывода `lsof -F cfnPT` — только соединения с внешними адресами.

    lsof пишет поля построчно: p и c — процесс, затем для каждого файла f, P (протокол),
    n («локальный->удалённый» адрес) и T (ST=состояние). Соединение собираем, когда
    начинается следующий файл или процесс."""
    apps, cmd, fields = {}, None, {}

    def flush():
        name = fields.get("n", "")
        if cmd and "->" in name:
            local, remote = name.split("->", 1)
            ip, _, port = remote.rpartition(":")
            ip = ip.strip("[]")  # IPv6 lsof пишет в квадратных скобках
            try:
                external = ipaddress.ip_address(ip).is_global
            except ValueError:
                external = False
            if external:
                apps.setdefault(cmd, []).append(
                    Connection(fields.get("P", "?"), local, ip, port, fields.get("ST", "")))
        fields.clear()

    for line in text.splitlines():
        kind, value = line[:1], line[1:]
        if kind in ("p", "c", "f"):
            flush()
            if kind == "p":
                cmd = None
            elif kind == "c":
                cmd = app_name(value)
        elif kind == "T":
            key, _, state = value.partition("=")
            fields[key] = state
        elif kind in ("P", "n"):
            fields[kind] = value
    flush()
    return apps


def lsof_connections():
    """{программа: [Connection]} — соединения ваших программ с внешними адресами прямо сейчас."""
    r = subprocess.run(["lsof", "+c", "0", "-nP", "-i", "-F", "cfnPT"],
                       capture_output=True, text=True, errors="replace")
    return parse_lsof(r.stdout)


def connections_of(target, apps):
    # точное имя важнее: «Claude» (программа) и «claude» (консольная утилита) — разные
    return apps.get(target) or next((v for k, v in apps.items() if k.lower() == target.lower()), [])
