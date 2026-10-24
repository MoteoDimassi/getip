"""Обновления: в фоне узнаём, есть ли на GitHub версия новее, и ставим её тем же
установщиком, что и при первой установке (install.sh), — других способов ставить getip нет."""
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from . import VERSION
from .style import bold, cyan, dim, green, pretty, red
from .term import cursor, header, out
from .widgets import pause

RAW_URL = "https://raw.githubusercontent.com/MoteoDimassi/getip/main"
UPDATE_URL = os.environ.get("GETIP_UPDATE_URL", RAW_URL + "/src/getip/__init__.py")
INSTALL_URL = os.environ.get("GETIP_INSTALL_URL", RAW_URL + "/install.sh")
INSTALL_CMD = f"curl -fsSL {RAW_URL}/install.sh | sh"
VERSION_RE = re.compile(r'^VERSION = "([\d.]+)"', re.M)


def parse_version(v):
    return tuple(int(x) for x in v.split(".") if x.isdigit())


class UpdateCheck:
    """Один раз за запуск, в фоне, узнаёт, есть ли на GitHub версия новее.
    Ошибки сети молча игнорируются — без интернета getip работает как обычно."""

    def __init__(self):
        self.latest = None
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": "getip",
                                                              "Range": "bytes=0-8191"})
            with urllib.request.urlopen(req, timeout=5) as r:
                head = r.read(8192).decode("utf-8", "ignore")
            m = VERSION_RE.search(head)
            if m and parse_version(m.group(1)) > parse_version(VERSION):
                self.latest = m.group(1)
        except Exception:
            pass


def run_installer(bin_dir):
    """Скачивает install.sh и ставит свежий getip в bin_dir (пакет — рядом, в ../share/getip)."""
    req = urllib.request.Request(INSTALL_URL, headers={"User-Agent": "getip"})
    with urllib.request.urlopen(req, timeout=30) as r:
        script = r.read()
    with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as f:
        f.write(script)
    try:
        env = dict(os.environ, GETIP_BIN=bin_dir, GETIP_FORCE_DOWNLOAD="1")
        subprocess.run(["sh", f.name], env=env, check=True)
    finally:
        os.unlink(f.name)


def self_update(version):
    """Ставит новую версию поверх текущей и перезапускает getip."""
    header(f"Обновление до {version}")
    launcher = os.path.realpath(sys.argv[0])
    if os.path.basename(launcher) != "getip":
        # запуск из папки с кодом (python3 getip.py) — её обновляют через git, а не установщиком
        out(f"  {dim('getip запущен из')} {pretty(launcher)}{dim(', а не из установленной копии.')}\n"
            f"  {dim('Обновите код командой')} {cyan('git pull')} {dim('или установите getip:')}\n"
            f"  {cyan(INSTALL_CMD)}\n")
        pause()
        return
    out(f"  {dim('Скачиваю новую версию…')}\n")
    try:
        run_installer(os.path.dirname(launcher))
    except Exception as e:
        out(f"\n  {red('✖')} Не получилось обновиться: {e}\n")
        out(f"  {dim('Обновите вручную командой:')}\n  {cyan(INSTALL_CMD)}\n")
        pause()
        return
    out(f"  {green('✔')} Обновлено до версии {bold(version)}. Перезапускаю…\n")
    time.sleep(1)
    cursor(True)
    os.execv(sys.executable, [sys.executable, launcher])
