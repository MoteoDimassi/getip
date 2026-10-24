"""Сбор IP-адресов и подсетей, из которых получается <имя>.bat."""
import ipaddress
import threading

from .domains import base_domain, matches
from .lookup import lookup_prefix
from .routes import read_networks, route_lines
from .style import cyan, dim, green


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
        self.file_nets |= read_networks(path)

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
        return route_lines(self.networks(), self.cfg)
