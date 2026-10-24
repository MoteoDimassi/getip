"""Цвета и мелкие помощники оформления. Только собирают строки, ничего не печатают."""
import os
import re
import sys

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _paint(code):
    return lambda s: f"\033[{code}m{s}\033[0m" if USE_COLOR else str(s)


bold, dim, cyan, green, yellow, red = (_paint(c) for c in ("1", "2", "36", "32", "33", "31"))


def visible(s):
    """Текст без цветовых кодов — то, что реально видно на экране."""
    return ANSI_RE.sub("", s)


def pretty(path):
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path
