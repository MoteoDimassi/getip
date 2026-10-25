"""Командная строка.

  getip                  интерактивное меню
  getip claude.ai        быстрое сканирование, сразу создаёт claude.ai.bat
  getip claude.ai -d     глубокое сканирование (поддомены из сертификатов + опрос DNS)
  getip claude.ai -s     слушать DNS-трафик, пока вы пользуетесь сайтом (нужен sudo)
  getip -A Claude        отслеживать соединения программы (без DNS и без sudo)
  getip -C Claude        проверить, идёт ли трафик программы через туннель роутера
  getip -b               маршруты мимо VPN: включить, выключить, удалить
  getip -x youtube.com --for 1h   заблокировать сайт или IP на этом Mac (нужен sudo)
  getip -u youtube.com   снять блокировку (-u all — снять все), getip --blocks — что заблокировано
"""
import argparse
import sys

from . import VERSION
from .block_menu import block_cli
from .bypass_menu import routes_screen
from .check import run_check
from .config import load_config
from .domains import normalize_domain
from .interactive import interactive
from .scans import run_scan
from .style import red
from .term import CLEAR, TTY, out


def main():
    p = argparse.ArgumentParser(
        prog="getip",
        description="Находит IP-подсети сайта и сохраняет их в <сайт>.bat (route add …). "
                    "Без аргументов открывает меню.")
    p.add_argument("sites", nargs="*", help="адреса сайтов, напр. claude.ai (для -x и -u — также IP)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-d", "--deep", action="store_true", help="глубокое сканирование")
    g.add_argument("-s", "--sniff", action="store_true", help="слушать DNS-трафик (sudo)")
    g.add_argument("-A", "--app", metavar="ПРИЛОЖЕНИЕ",
                   help="отслеживать соединения программы, напр. -A Claude")
    g.add_argument("-C", "--check", metavar="ПРИЛОЖЕНИЕ",
                   help="проверить, идёт ли трафик программы через туннель роутера, напр. -C Claude")
    g.add_argument("-b", "--bypass", action="store_true",
                   help="маршруты мимо VPN: включить, выключить, удалить")
    g.add_argument("-x", "--block", action="store_true",
                   help="заблокировать сайты или IP на этом Mac (sudo), напр. -x youtube.com --for 1h")
    g.add_argument("-u", "--unblock", action="store_true", help="снять блокировку (all — со всех)")
    g.add_argument("--blocks", action="store_true", help="показать, что сейчас заблокировано")
    p.add_argument("--for", dest="duration", metavar="СРОК",
                   help="срок блокировки: 30m, 2h, 1d (по умолчанию — навсегда)")
    p.add_argument("-t", "--time", type=int, help="длительность глубокого сканирования, сек")
    p.add_argument("-a", "--append", action="store_true", help="дополнить существующий .bat")
    p.add_argument("-o", "--out", help="папка для .bat (по умолчанию — текущая)")
    p.add_argument("-g", "--gw", help="шлюз в командах route (по умолчанию 0.0.0.0)")
    p.add_argument("-p", "--persistent", action="store_true", help="писать route -p add")
    p.add_argument("--exact", action="store_true", help="только точные IP (/32)")
    p.add_argument("-v", "--version", action="version", version=f"getip {VERSION}")
    args = p.parse_args()

    cfg = load_config()
    if args.bypass:
        if not TTY:
            p.error("список маршрутов мимо VPN открывается только в окне терминала")
        try:
            routes_screen()
        except KeyboardInterrupt:
            pass
        out(CLEAR)
        return
    if args.block or args.unblock or args.blocks:
        try:
            block_cli(args)
        except RuntimeError as e:
            out(f"  {red('✖')} {e}\n")
            sys.exit(1)
        except KeyboardInterrupt:
            out("\n")
            sys.exit(130)
        return
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
