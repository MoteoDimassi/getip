"""Командная строка.

  getip                  интерактивное меню
  getip claude.ai        быстрое сканирование, сразу создаёт claude.ai.bat
  getip claude.ai -d     глубокое сканирование (поддомены из сертификатов + опрос DNS)
  getip claude.ai -s     слушать DNS-трафик, пока вы пользуетесь сайтом (нужен sudo)
  getip -A Claude        отслеживать соединения программы (без DNS и без sudo)
  getip -C Claude        проверить, идёт ли трафик программы через туннель роутера
"""
import argparse

from . import VERSION
from .check import run_check
from .config import load_config
from .domains import normalize_domain
from .interactive import interactive
from .scans import run_scan
from .style import red
from .term import TTY, out


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
    g.add_argument("-C", "--check", metavar="ПРИЛОЖЕНИЕ",
                   help="проверить, идёт ли трафик программы через туннель роутера, напр. -C Claude")
    p.add_argument("-t", "--time", type=int, help="длительность глубокого сканирования, сек")
    p.add_argument("-a", "--append", action="store_true", help="дополнить существующий .bat")
    p.add_argument("-o", "--out", help="папка для .bat (по умолчанию — текущая)")
    p.add_argument("-g", "--gw", help="шлюз в командах route (по умолчанию 0.0.0.0)")
    p.add_argument("-p", "--persistent", action="store_true", help="писать route -p add")
    p.add_argument("--exact", action="store_true", help="только точные IP (/32)")
    p.add_argument("-v", "--version", action="version", version=f"getip {VERSION}")
    args = p.parse_args()

    cfg = load_config()
    if not args.sites and not args.app and not args.check:
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
    if args.check:
        out("\n")
        run_check(args.check, cfg, tips=True)
        out("\n")
        return
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
