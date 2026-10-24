#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""getip — запускалка. Сам код — в пакете src/getip, здесь только поиск пакета и запуск.

Пакет ищется рядом в репозитории (src/getip) или там, куда его ставит install.sh:
~/.local/bin/getip → ~/.local/share/getip/getip.

getip 1.3 и старше обновляются, скачивая только этот файл, — поэтому здесь есть
VERSION (по нему они узнают о новой версии), а без пакета запускалка ставит его сама."""
VERSION = "2.0.0"  # держите равной src/getip/__init__.py — это проверяет tests/test_version.py

import os
import subprocess
import sys
import tempfile
import urllib.request

INSTALL_URL = os.environ.get("GETIP_INSTALL_URL",
                             "https://raw.githubusercontent.com/MoteoDimassi/getip/main/install.sh")
HERE = os.path.dirname(os.path.realpath(__file__))
PLACES = [os.path.join(HERE, "src"),                              # склонированный репозиторий
          os.path.join(os.path.dirname(HERE), "share", "getip")]  # установка: <bin>/../share/getip


def find_package():
    return next((p for p in PLACES if os.path.isfile(os.path.join(p, "getip", "__init__.py"))), None)


def install_package():
    """Скачивает install.sh и ставит пакет рядом с этой запускалкой."""
    with urllib.request.urlopen(INSTALL_URL, timeout=30) as r:
        script = r.read()
    with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as f:
        f.write(script)
    try:
        env = dict(os.environ, GETIP_BIN=HERE, GETIP_FORCE_DOWNLOAD="1", GETIP_BOOTSTRAPPED="1")
        subprocess.run(["sh", f.name], env=env, check=True)
    finally:
        os.unlink(f.name)


base = find_package()
if base is None:
    if os.environ.get("GETIP_BOOTSTRAPPED"):
        sys.exit(f"getip: пакет не найден ни в одной из папок: {', '.join(PLACES)}")
    print("  getip: доустанавливаю новую версию…", flush=True)  # execv ниже не сбрасывает буфер вывода
    try:
        install_package()
    except Exception as e:
        sys.exit(f"  Не получилось доустановить getip ({e}). Установите заново:\n"
                 f"  curl -fsSL {INSTALL_URL} | sh")
    # установщик заменил и эту запускалку — запускаем её заново, с теми же аргументами
    os.environ["GETIP_BOOTSTRAPPED"] = "1"
    os.execv(sys.executable, [sys.executable, os.path.realpath(__file__)] + sys.argv[1:])

sys.path.insert(0, base)
from getip.cli import main  # noqa: E402 — пакет становится виден только после строки выше

main()
