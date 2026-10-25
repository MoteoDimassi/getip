"""Блокировка сайтов и IP на этом Mac — на время или навсегда.

Сайт закрываем строками в /etc/hosts, IP — таблицей брандмауэра pf в собственном якоре
com.apple/getip: /etc/pf.conf уже подключает все якоря com.apple/*, системные правила и VPN
не затрагиваются. Менять hosts и pf может только root, поэтому изменения выполняет этот же
модуль, запущенный через sudo: python3 -m getip.block --op. Фоновая служба launchd раз в 30 сек
запускает его с --apply: снимает истёкшие блокировки и возвращает правила pf после перезагрузки,
а когда блокировок не остаётся, удаляет сама себя. Служба запускает копию пакета в папке,
принадлежащей root, а не файлы пользователя.

Модуль ничего не печатает (кроме ошибок в stderr при запуске от root): экраны — в block_menu.py,
а всё, кроме самих системных команд, проверяют тесты."""
import fcntl
import ipaddress
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from .domains import DOMAIN_RE, normalize_domain
from .lookup import RESOLVERS, dns_query
from .scans import SUBDOMAINS

SUPPORTED = sys.platform == "darwin"
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCK_DIR = "/Library/Application Support/getip"
BLOCKS_PATH = os.path.join(BLOCK_DIR, "blocks.json")
HELPER_PKG = os.path.join(BLOCK_DIR, "getip")  # копия пакета для службы: root не запускает файлы пользователя
HELPER_LOG = os.path.join(BLOCK_DIR, "errors.log")
DAEMON = "com.getip.blocker"
PLIST_PATH = f"/Library/LaunchDaemons/{DAEMON}.plist"
LOCK_PATH = "/var/run/getip-blocks.lock"
HOSTS_PATH = "/etc/hosts"
HOSTS_BEGIN, HOSTS_END = "# >>> getip block (managed by getip, do not edit)", "# <<< getip block"
PF_ANCHOR = "com.apple/getip"


def parse_duration(text):
    """«30» (минуты), «45м», «2ч», «1д», «90m», «2h» → секунды или None."""
    m = re.fullmatch(r"(\d+(?:[.,]\d+)?)\s*([a-zа-яё]*)", (text or "").strip().lower())
    if not m:
        return None
    unit = {"": 60, "m": 60, "м": 60, "h": 3600, "ч": 3600, "d": 86400, "д": 86400}.get(m.group(2)[:1])
    secs = int(float(m.group(1).replace(",", ".")) * unit) if unit else 0
    return secs if secs >= 60 else None


def format_span(secs):
    """3720 → «1 ч 2 мин»; округляем вверх до минуты."""
    mins = max(1, -(-int(secs) // 60))
    if mins < 60:
        return f"{mins} мин"
    h, m = divmod(mins, 60)
    if h < 24:
        return f"{h} ч" + (f" {m} мин" if m else "")
    d, h = divmod(h, 24)
    return f"{d} д" + (f" {h} ч" if h else "")


def format_left(until):
    return f"ещё {format_span(until - time.time())}" if until else "навсегда"


def parse_block_target(text):
    """«1.2.3.4 5.6.0.0/16» → ("ip", [сети]), «youtube.com» → ("site", домен), иначе None."""
    parts = [p for p in re.split(r"[\s,;]+", (text or "").strip()) if p]
    if not parts:
        return None
    try:
        return "ip", [ipaddress.ip_network(p, strict=False) for p in parts]
    except ValueError:
        domain = normalize_domain(text)
        return ("site", domain) if domain else None


def unsafe_net(net):
    """Почему эту сеть закрывать нельзя, или None."""
    if net.prefixlen < (8 if net.version == 4 else 16):
        return "слишком большая подсеть — закроется почти весь интернет"
    if net.overlaps(ipaddress.ip_network("127.0.0.0/8" if net.version == 4 else "::1/128")):
        return "это адрес самого компьютера"
    return None


def net_id(net):
    """Как показывать сеть: одиночный адрес — без «/32»."""
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def site_names(domain):
    """Имена для hosts: сам сайт, www и существующие популярные поддомены (hosts не знает
    масок вида *.site). DNS спрашиваем напрямую — системный ответ мог подменить наш же hosts."""
    names = [s + domain for s in SUBDOMAINS]
    with ThreadPoolExecutor(max_workers=32) as ex:
        found = list(ex.map(lambda n: dns_query(n, RESOLVERS[0]) or dns_query(n, RESOLVERS[1]), names))
    return sorted({domain, "www." + domain} | {n for n, ips in zip(names, found) if ips},
                  key=lambda n: (n != domain, n))


def new_blocks(kind, value, secs):
    """Блокировки сайта (value — домен) или сетей (value — список) на secs секунд, 0 — навсегда."""
    until = int(time.time()) + secs if secs else None
    if kind == "site":
        return [{"id": value, "names": site_names(value), "nets": [], "until": until}]
    return [{"id": net_id(n), "names": [], "nets": [str(n)], "until": until} for n in value]


def load_blocks():
    try:
        with open(BLOCKS_PATH, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    state.setdefault("blocks", [])
    return state


def active_blocks(state):
    now = time.time()
    return [b for b in state["blocks"] if not b.get("until") or b["until"] > now]


def clean_block(b):
    """Блокировка из командной строки → безопасный вид: в hosts и pf попадут только
    настоящие имена и сети, без переводов строк и прочих сюрпризов."""
    return {"id": str(b["id"])[:200],
            "names": [n for n in b.get("names", []) if DOMAIN_RE.match(n)],
            "nets": [str(ipaddress.ip_network(n, strict=False)) for n in b.get("nets", [])],
            "until": int(b["until"]) if b.get("until") else None}


def run_quiet(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def write_file(path, data, mode=0o644):
    """Атомарно записывает байты, если они отличаются от текущих. True — если записал."""
    try:
        with open(path, "rb") as f:
            if f.read() == data:
                return False
    except OSError:
        pass
    tmp = path + ".getip-tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def apply_hosts(names):
    """Переписывает раздел getip в /etc/hosts, не трогая остальное. True — если файл изменился."""
    path = os.path.realpath(HOSTS_PATH)
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        lines = f.read().splitlines()
    keep, found, i = [], False, 0
    while i < len(lines):
        if lines[i].strip() == HOSTS_BEGIN:
            # раздел — от начала до ближайшего конца; начало без пары (файл правили руками) не трогаем
            nxt = next((j for j in range(i + 1, len(lines)) if lines[j].strip() in (HOSTS_BEGIN, HOSTS_END)), None)
            if nxt is not None and lines[nxt].strip() == HOSTS_END:
                found, i = True, nxt + 1
                continue
        keep.append(lines[i])
        i += 1
    if not found and not names:
        return False
    while keep and not keep[-1].strip():
        keep.pop()
    if names:
        keep += ["", HOSTS_BEGIN] + [f"{ip} {n}" for n in names for ip in ("0.0.0.0", "::")] + [HOSTS_END]
    return write_file(path, ("\n".join(keep) + "\n").encode("utf-8", "surrogateescape"))


def flush_dns():
    run_quiet(["dscacheutil", "-flushcache"])
    run_quiet(["killall", "-HUP", "mDNSResponder"])


def apply_pf(state, nets):
    """Загружает закрытые сети в наш якорь pf. pf включаем через -E: macOS считает такие
    ссылки, и наше выключение (-X) не выключит pf тому, кто им тоже пользуется (VPN и т.п.).
    Соединения с закрытыми адресами pf молча отбрасывает: программа ждёт до своего таймаута."""
    boot = run_quiet(["sysctl", "-n", "kern.boottime"]).stdout.strip()
    if state.get("boot") != boot:  # после перезагрузки старая ссылка уже недействительна
        state.pop("pf_token", None)
        state["boot"] = boot
    if not nets:
        if state.pop("pf_loaded", False):
            # только правила и таблицу якоря: «-F all» сбросил бы и чужие соединения (состояния pf общие)
            run_quiet(["pfctl", "-a", PF_ANCHOR, "-F", "rules"])
            run_quiet(["pfctl", "-a", PF_ANCHOR, "-F", "Tables"])
        if state.get("pf_token"):
            run_quiet(["pfctl", "-X", state.pop("pf_token")])
        return
    rules = f"table <getip> persist {{ {', '.join(nets)} }}\nblock return out quick to <getip>\n"
    r = run_quiet(["pfctl", "-a", PF_ANCHOR, "-f", "-"], input=rules)
    if r.returncode:
        raise RuntimeError("pfctl не принял правила: " + r.stderr.strip()[-200:])
    state["pf_loaded"] = True
    if not state.get("pf_token") or "Status: Enabled" not in run_quiet(["pfctl", "-s", "info"]).stdout:
        r = run_quiet(["pfctl", "-E"])
        m = re.search(r"Token\s*:\s*(\d+)", r.stdout + r.stderr)
        if not m:
            raise RuntimeError("не удалось включить брандмауэр pf: " + r.stderr.strip()[-200:])
        state["pf_token"] = m.group(1)


def sync_package(src, dst):
    """Копирует .py-файлы пакета из src в dst, лишние .py в dst удаляет."""
    os.makedirs(dst, mode=0o755, exist_ok=True)
    names = {n for n in os.listdir(src) if n.endswith(".py")}
    for name in names:
        with open(os.path.join(src, name), "rb") as f:
            write_file(os.path.join(dst, name), f.read())
    for name in set(os.listdir(dst)) - names:
        if name.endswith(".py"):
            os.remove(os.path.join(dst, name))


def install_daemon():
    os.makedirs(BLOCK_DIR, mode=0o755, exist_ok=True)
    sync_package(PKG_DIR, HELPER_PKG)
    # системный Python надёжнее Homebrew: тот при обновлении меняет путь к интерпретатору
    python = "/usr/bin/python3" if run_quiet(["xcode-select", "-p"]).returncode == 0 else sys.executable
    plist = plistlib.dumps({"Label": DAEMON, "ProgramArguments": [python, "-m", "getip.block", "--apply"],
                            "WorkingDirectory": BLOCK_DIR, "RunAtLoad": True, "StartInterval": 30,
                            "StandardErrorPath": HELPER_LOG})
    if write_file(PLIST_PATH, plist) or run_quiet(["launchctl", "print", f"system/{DAEMON}"]).returncode:
        run_quiet(["launchctl", "bootout", f"system/{DAEMON}"])
        for _ in range(5):  # bootout завершается не мгновенно, и bootstrap сразу после него может не пройти
            r = run_quiet(["launchctl", "bootstrap", "system", PLIST_PATH])
            if r.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("не удалось запустить службу getip: " + r.stderr.strip()[-200:])


def uninstall_daemon():
    try:
        os.remove(PLIST_PATH)
    except OSError:
        pass
    shutil.rmtree(BLOCK_DIR, ignore_errors=True)
    run_quiet(["launchctl", "bootout", f"system/{DAEMON}"])  # последним: служба может выключать сама себя


def apply_blocks(state):
    """Снимает истёкшие блокировки и приводит hosts и pf в соответствие со списком."""
    state["blocks"] = active_blocks(state)
    apply_pf(state, sorted({n for b in state["blocks"] for n in b["nets"]}))
    if apply_hosts(sorted({n for b in state["blocks"] for n in b["names"]})):
        flush_dns()
    if state["blocks"]:
        write_file(BLOCKS_PATH, json.dumps(state, ensure_ascii=False, indent=1).encode())
    else:
        uninstall_daemon()


def block_op(op):
    """От root (--op): {"add": [блокировки], "remove": [id]}."""
    if os.geteuid() != 0:
        raise RuntimeError("нужны права администратора")
    add = [clean_block(b) for b in op.get("add", [])]
    drop = {b["id"] for b in add} | set(op.get("remove", []))
    with open(LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load_blocks()
        state["blocks"] = [b for b in state["blocks"] if b["id"] not in drop] + add
        if active_blocks(state):
            install_daemon()
        apply_blocks(state)


def apply_blocks_now():
    """От root (--apply), запуск службой launchd."""
    try:
        if os.path.getsize(HELPER_LOG) > 1_000_000:
            open(HELPER_LOG, "w").close()
    except OSError:
        pass
    with open(LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        apply_blocks(load_blocks())


def block_admin(op):
    """Передаёт изменение блокировок этому модулю, запущенному через sudo (пароль уже должен
    быть введён). Пакет ищется по папке, из которой он запущен сейчас."""
    cmd = [sys.executable, "-m", "getip.block", "--op", json.dumps(op)]
    r = run_quiet(cmd if os.geteuid() == 0 else ["sudo", "-n"] + cmd, cwd=os.path.dirname(PKG_DIR))
    if r.returncode:
        raise RuntimeError((r.stderr.strip().splitlines() or ["неизвестная ошибка"])[-1])


def main(argv):
    """python3 -m getip.block --op JSON (через sudo) или --apply (служба launchd)."""
    try:
        if argv[:1] == ["--apply"]:
            apply_blocks_now()
        elif argv[:1] == ["--op"] and len(argv) == 2:
            block_op(json.loads(argv[1]))
        else:
            raise RuntimeError("запуск: python3 -m getip.block --apply | --op JSON")
    except Exception as e:
        # у службы stderr — это журнал, туда пишем время; у sudo-помощника его читает getip
        print((time.strftime("%Y-%m-%d %H:%M:%S ") if argv[:1] == ["--apply"] else "") + str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
