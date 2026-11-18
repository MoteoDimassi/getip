"""Служба «Мимо VPN»: держит маршруты списка на роутере, к которому Mac подключён сейчас.

Маршрут мимо VPN указывает на конкретный роутер (192.168.1.1). Когда Mac переходит в другую сеть,
macOS такой маршрут не убирает, а роутера прежней сети в новой нет — и подсеть перестаёт открываться
совсем, с VPN и без. Поэтому служба launchd при каждой смене сети (меняется /etc/resolv.conf) и раз
в 15 сек сверяет маршруты: переводит их на роутер текущей сети, без подключения к роутеру убирает,
а после перезагрузки возвращает.

Служба знает только включённые подсети: их копию getip передаёт этому же модулю, запущенному через
sudo (python3 -m getip.bypass_service --set), при каждом изменении списка. Копия и пакет, который
запускает служба, лежат в папке root, а не в файлах пользователя. Когда подсетей не остаётся,
модуль убирает их маршруты и удаляет службу."""
import fcntl
import ipaddress
import json
import os
import shutil
import sys
import time

from . import block
from .bypass import BYPASS_PATH, apply, load_routes, run_root, save_routes, system_table, wanted, withdraw
from .tunnel import physical_route

SUPPORTED = sys.platform == "darwin"
SERVICE_DIR = "/Library/Application Support/getip-bypass"  # не в папке службы блокировки: та удаляет её целиком
NETS_PATH = os.path.join(SERVICE_DIR, "routes.json")
HELPER_PKG = os.path.join(SERVICE_DIR, "getip")
HELPER_LOG = os.path.join(SERVICE_DIR, "errors.log")
DAEMON = "com.getip.bypass"
PLIST_PATH = f"/Library/LaunchDaemons/{DAEMON}.plist"
LOCK_PATH = "/var/run/getip-bypass.lock"
WATCH_PATHS = ["/private/var/run/resolv.conf"]  # configd переписывает его при каждой смене сети
INTERVAL = 15


def parse_nets(rows):
    """Подсети IPv4 из списка строк или подсетей; остальное пропускаем (число 5 ip_network принял бы за 0.0.0.5)."""
    nets = set()
    for row in rows if isinstance(rows, list) else []:
        try:
            n = ipaddress.ip_network(row) if isinstance(row, (str, ipaddress.IPv4Network)) else None
        except ValueError:
            n = None
        if n and n.version == 4:
            nets.add(n)
    return sorted(nets)


def load_nets(path=None):
    """Подсети, маршруты которых держит служба."""
    try:
        with open(path or NETS_PATH, encoding="utf-8") as f:
            return parse_nets(json.load(f))
    except (OSError, ValueError):
        return []


def sync_routes(nets, old, table, gw, run=run_root):
    """Приводит маршруты системы к списку nets. old — подсети, которые служба держала до этого:
    маршруты тех, что из списка ушли, убирает. Без подключения к роутеру убирает и маршруты списка:
    через роутер прежней сети они никуда не ведут. Возвращает {подсеть: ошибка}."""
    failed = withdraw(sorted(set(old) - set(nets)), table, run)
    failed.update(apply(nets, gw, table, run) if gw else withdraw(nets, table, run))
    return failed


def install_daemon():
    os.makedirs(SERVICE_DIR, mode=0o755, exist_ok=True)
    block.sync_package(block.PKG_DIR, HELPER_PKG)
    block.load_daemon(DAEMON, PLIST_PATH, {
        "ProgramArguments": [block.daemon_python(), "-m", "getip.bypass_service", "--apply"],
        "WorkingDirectory": SERVICE_DIR, "RunAtLoad": True, "StartInterval": INTERVAL,
        "WatchPaths": WATCH_PATHS, "StandardErrorPath": HELPER_LOG})


def uninstall_daemon():
    try:
        os.remove(PLIST_PATH)
    except OSError:
        pass
    shutil.rmtree(SERVICE_DIR, ignore_errors=True)
    block.run_quiet(["launchctl", "bootout", f"system/{DAEMON}"])  # последним: служба может выключать сама себя


def sync_now(nets, old):
    gw = physical_route()
    return sync_routes(nets, old, system_table(), gw[0] if gw else None, run_root)


def errors(failed):
    return "; ".join(f"{n}: {err}" for n, err in sorted(failed.items()))


def set_nets(nets):
    """От root (--set): служба держит маршруты этих подсетей, пустой список — убрать службу."""
    if os.geteuid() != 0:
        raise RuntimeError("нужны права администратора")
    nets = parse_nets(nets)
    with open(LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = load_nets()
        if nets:
            install_daemon()
            block.write_file(NETS_PATH, json.dumps([str(n) for n in nets], indent=1).encode())
        try:
            failed = sync_now(nets, old)
        finally:
            if not nets:
                uninstall_daemon()
    # не добавленный маршрут getip уже показал сам, а служба повторит попытку; не убранный — повторять некому
    lost = {n: err for n, err in failed.items() if n not in nets}
    if lost:
        raise RuntimeError("не удалось убрать маршруты: " + errors(lost))


def apply_now():
    """От root (--apply), запуск службой launchd."""
    try:
        if os.path.getsize(HELPER_LOG) > 1_000_000:
            open(HELPER_LOG, "w").close()
    except OSError:
        pass
    with open(LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        nets = load_nets()
        failed = sync_now(nets, nets)
    if failed:
        raise RuntimeError(errors(failed))


def service_nets(routes):
    return sorted(wanted(routes))


def running():
    return os.path.exists(PLIST_PATH)


def needs_update(routes):
    """True — служба держит не те подсети, что включены в списке (или её нет, а они есть)."""
    nets = service_nets(routes)
    return SUPPORTED and (load_nets() != nets or running() != bool(nets))


def publish(routes):
    """Передаёт службе включённые подсети списка (пароль sudo уже должен быть введён).
    Возвращает ошибку или None."""
    if not needs_update(routes):
        return None
    cmd = [sys.executable, "-m", "getip.bypass_service", "--set",
           json.dumps([str(n) for n in service_nets(routes)])]
    r = block.run_quiet(cmd if os.geteuid() == 0 else ["sudo", "-n"] + cmd, cwd=os.path.dirname(block.PKG_DIR))
    if r.returncode:
        return (r.stderr.strip().splitlines() or ["неизвестная ошибка"])[-1]
    return None


def stop(path=BYPASS_PATH):
    """Останавливает службу (пароль sudo уже должен быть введён): её маршруты уходят из системы,
    а записи списка остаются выключенными — их можно включить снова, и служба вернётся.
    Возвращает ошибку или None."""
    routes = load_routes(path)
    # и маршруты, о которых служба не знала (например, не обновилась в прошлый раз)
    failed = withdraw(service_nets(routes), system_table(), run_root)
    off = [r._replace(off=True) for r in routes]
    err = publish(off)
    if not err:
        save_routes(off, path)
    return "; ".join(filter(None, [err, failed and "не удалось убрать маршруты: " + errors(failed)])) or None


def main(argv):
    """python3 -m getip.bypass_service --set JSON (через sudo) или --apply (служба launchd)."""
    try:
        if argv[:1] == ["--apply"]:
            apply_now()
        elif argv[:1] == ["--set"] and len(argv) == 2:
            set_nets(json.loads(argv[1]))
        else:
            raise RuntimeError("запуск: python3 -m getip.bypass_service --apply | --set JSON")
    except Exception as e:
        print((time.strftime("%Y-%m-%d %H:%M:%S ") if argv[:1] == ["--apply"] else "") + str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
