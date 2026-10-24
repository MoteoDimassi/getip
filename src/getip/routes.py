"""Файлы <имя>.bat с командами `route add`: чтение и запись."""
import ipaddress
import os
import re

from .config import out_dir

ROUTE_RE = re.compile(r"route\s+(?:-p\s+)?add\s+(\S+)\s+mask\s+(\S+)", re.I)


def safe_filename(name):
    return re.sub(r'[\\/:*?"<>|]+', "_", name).strip() or "getip"


def bat_path(cfg, target):
    return os.path.join(out_dir(cfg), safe_filename(target) + ".bat")


def read_networks(path):
    """Подсети из команд route add в файле."""
    nets = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for a, m in ROUTE_RE.findall(f.read()):
            try:
                nets.add(ipaddress.ip_network(f"{a}/{m}", strict=False))
            except ValueError:
                pass
    return nets


def route_lines(nets, cfg):
    cmd = "route -p add" if cfg["persistent"] else "route add"
    return [f"{cmd} {n.network_address} mask {n.netmask} {cfg['gw']}" for n in nets]


def write_bat(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")


def add_to_bat(path, nets, cfg):
    """Дописывает подсети к тем, что уже есть в файле. Возвращает, сколько подсетей стало в файле."""
    old = read_networks(path) if os.path.exists(path) else set()
    merged = sorted(ipaddress.collapse_addresses(old | set(nets)))
    write_bat(path, route_lines(merged, cfg))
    return len(merged)
