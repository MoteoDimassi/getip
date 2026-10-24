"""Режимы сбора адресов в <имя>.bat: быстрый, глубокий, прослушивание DNS и слежка за программой.

Каждый режим — функция (collector, live): складывает найденные IP в collector,
а ход работы пишет в live. collect запускает режим, run_scan — ещё и сохраняет результат.
ask_site и pick_app — экраны выбора сайта и программы для режимов."""
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .collector import Collector
from .config import load_config, save_config
from .connections import connections_of, lsof_connections
from .domains import is_noise, normalize_domain
from .lookup import crtsh_names, resolve_everywhere
from .routes import bat_path, write_bat
from .style import bold, cyan, dim, green, pretty, red, yellow
from .term import TTY, header, out
from .texts import MODES, TIPS_COLUMNS, print_tips, render_tips
from .widgets import Live, ask, checklist, get_sudo, menu, pause, wait_for_stop

SUBDOMAINS = ["", "www.", "api.", "app.", "cdn.", "static.", "assets.", "media.", "img.",
              "images.", "auth.", "login.", "accounts.", "ws.", "m.", "mobile.", "mail.",
              "status.", "docs.", "support.", "help.", "blog.", "files.", "upload.", "video."]

Q_RE = re.compile(r"q: A\? (\S+)")
A_RE = re.compile(r"\sA (\d{1,3}(?:\.\d{1,3}){3})\b")


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
    if sudo and not get_sudo("Для прослушивания трафика нужен пароль администратора."):
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


def app_scan(col, live):
    polls = [0]

    def tick():
        conns = [c for c in connections_of(col.target, lsof_connections()) if ":" not in c.ip]  # только IPv4
        for c in conns:
            col.add(c.ip, f"{col.target} :{c.port}")
        polls[0] += 1
        live.set(f"слежу за {col.target} · соединений сейчас: {len(conns)} · IP: {len(col.ip_names)}"
                 f" · проверок: {polls[0]} · Enter — закончить")

    out(f"  {dim('Пользуйтесь')} {bold(col.target)} {dim('— открывайте разделы, отправляйте сообщения.')}\n\n")
    live.start(f"слежу за {col.target}…")
    wait_for_stop(tick, 2)


SCANNERS = {"quick": quick_scan, "deep": deep_scan, "sniff": sniff, "app": app_scan}


def ask_site(cfg, title, tips):
    """Экран ввода адреса сайта; возвращает домен или None."""
    header(title)
    print_tips(tips)
    out("\n  " + dim("Введите адрес и нажмите Enter · Ctrl+C — назад в меню") + "\n\n")
    raw = ask("Адрес сайта", cfg["last_domain"])
    if raw is None:
        return None
    target = normalize_domain(raw)
    if not target:
        out(f"  {red('✖')} Не похоже на адрес сайта. Пример: claude.ai\n")
        pause()
        return None
    cfg["last_domain"] = target
    save_config(cfg)
    return target


def pick_app(title, tips):
    """Список программ с открытыми соединениями; возвращает имя выбранной или None."""
    body = lambda: render_tips(tips)  # функция: если окно вырастет, текст перенесётся по новой ширине
    while True:
        apps = lsof_connections()
        rows = [("↻ Обновить список", "")] + [
            (name, f"соединений: {len(conns)}")
            for name, conns in sorted(apps.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))]
        i = menu(title, rows, body=body, columns=TIPS_COLUMNS)
        if i is None:
            return None
        if i > 0:
            return rows[i][0]


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


def collect(target, mode, cfg, bat=None, tips=False):
    """Собирает адреса сайта или приложения, ничего не сохраняя. bat — файл, подсети
    которого дополняем. Возвращает коллектор."""
    live = Live()
    col = Collector(target, cfg, live.log, include_all=(mode == "app"))
    if bat and os.path.exists(bat):
        col.load_bat(bat)
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
    return col


def run_scan(target, mode, cfg, append=False, tips=False):
    """Сканирует сайт или приложение и пишет <имя>.bat. Возвращает (путь или None, коллектор)."""
    path = bat_path(cfg, target)
    col = collect(target, mode, cfg, path if append else None, tips)
    if not col.networks():
        out(f"\n  {red('✖')} Не найдено ни одного адреса — проверьте адрес сайта.\n")
        return None, col
    write_bat(path, col.routes())
    extra = f" {dim('(+ ' + ', '.join(sorted(col.extra)) + ')')}" if col.extra else ""
    out(f"\n  {green('✔')} {len(col.included_ips())} IP → {bold(str(len(col.networks())))} подсетей{extra}"
        f" · сохранено в {bold(pretty(path))}\n")
    return path, col
