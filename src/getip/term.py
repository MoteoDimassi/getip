"""Терминал: вывод, заголовок экрана, клавиши, вставка текста и перетаскивание папок."""
import atexit
import os
import select
import shlex
import sys
import termios
import time
import tty
import urllib.parse

from . import VERSION
from .style import bold, cyan, dim

TTY = sys.stdout.isatty() and sys.stdin.isatty()
CLEAR = "\033[H\033[2J\033[3J"

LOGO = ["┌─┐┌─┐┌┬┐┬┌─┐",
        "│ ┬├┤  │ │├─┘",
        "└─┘└─┘ ┴ ┴┴  "]


def out(s=""):
    sys.stdout.write(s)
    sys.stdout.flush()


def term_size():
    """(колонки, строки) окна; без терминала — широкое и бесконечно высокое окно."""
    try:
        return os.get_terminal_size()
    except OSError:
        return os.terminal_size((100, 1000))


def term_width():
    return term_size().columns


class WindowFit:
    """Увеличивает окно терминала, чтобы меню помещалось целиком, а потом возвращает прежний размер.

    Размер меняет последовательность CSI 8;строки;колонки t. Её понимают Terminal.app и iTerm2,
    остальные терминалы (tmux, встроенные в редакторы, окно на весь экран) молча её пропускают —
    тогда getip больше не просит, а меню просто обрезает подсказки под окно."""
    WAIT = 0.8  # столько ждём, пока терминал поменяет размер

    def __init__(self):
        self.enabled = False
        self.original = None  # размер окна до первой подгонки
        self.fitted = None    # размер, который получился после последней подгонки
        self.ignored = False  # терминал не послушался — больше не просим
        self.asked = set()    # о таких размерах уже просили: окно могло упереться в край экрана

    def grow(self, columns, lines):
        """Увеличивает окно хотя бы до columns×lines, никогда не уменьшает. True — размер изменился."""
        if not (self.enabled and TTY) or self.ignored:
            return False
        size = term_size()
        want = (max(size.columns, columns), max(size.lines, lines))
        if want == tuple(size) or want in self.asked:
            return False
        self.asked.add(want)
        out(f"\033[8;{want[1]};{want[0]}t")
        new = self._settle(size)
        if new == size:
            self.ignored = True
            return False
        if self.original is None:
            self.original = size
        self.fitted = new
        return True

    def _settle(self, old):
        """Ждёт, пока размер окна изменится и перестанет меняться (окно может расти в несколько шагов)."""
        deadline = time.time() + self.WAIT
        size = term_size()
        while size == old and time.time() < deadline:
            time.sleep(0.03)
            size = term_size()
        while size != old and time.time() < deadline + 1:
            time.sleep(0.1)
            again = term_size()
            if again == size:
                break
            size = again
        return size

    def restore(self):
        """Возвращает размер окна, каким он был до подгонки, — если с тех пор его не меняли руками."""
        if self.original and TTY and term_size() == self.fitted:
            out(f"\033[8;{self.original.lines};{self.original.columns}t")
        self.original = self.fitted = None
        self.asked.clear()


window = WindowFit()


def cursor(show):
    if TTY:
        out("\033[?25h" if show else "\033[?25l")


atexit.register(cursor, True)


def header_text(title="", compact=False):
    """Шапка экрана. compact — одна строка без логотипа, для низкого окна терминала."""
    if compact:
        return f"\n  {bold(cyan('getip'))} {dim('v' + VERSION)}" + (f"  {bold(title)}" if title else "") + "\n\n"
    text = "\n" + "".join("  " + bold(cyan(line)) + "\n" for line in LOGO)
    text += "  " + dim(f"IP-подсети сайта → route add · v{VERSION}") + "\n\n"
    if title:
        text += "  " + bold(title) + "\n\n"
    return text


def header(title="", compact=False):
    if TTY:
        out(CLEAR)
    out(header_text(title, compact))


PASTE_END = b"\x1b[201~"
RU_KEYS = {"й": "q", "о": "j", "л": "k"}  # те же клавиши в русской раскладке


def _drain(fd, wait):
    data = b""
    while select.select([fd], [], [], wait)[0]:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
    return data


def read_key(timeout=None):
    """Одна клавиша: 'up', 'down', 'enter', 'esc', 'backspace', 'delete', символ, None по таймауту
    или ('paste', текст) — если в окно вставили текст или перетащили папку."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd, termios.TCSANOW)  # TCSANOW: не выбрасывать уже нажатые клавиши
        out("\033[?2004h")  # bracketed paste: вставка приходит одним куском
        if not select.select([fd], [], [], timeout)[0]:
            return None
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            if not select.select([fd], [], [], 0.05)[0]:
                return "esc"
            # читаем ровно одну последовательность, чтобы быстрые нажатия не слипались
            seq = os.read(fd, 1)
            if seq in (b"[", b"O"):
                while True:
                    c = os.read(fd, 1)
                    seq += c
                    if not c or 0x40 <= c[0] <= 0x7E:
                        break
            if seq == b"[200~":
                data = b""
                while PASTE_END not in data and select.select([fd], [], [], 1)[0]:
                    data += os.read(fd, 4096)
                return ("paste", data.split(PASTE_END)[0].decode(errors="ignore"))
            if seq == b"[3~":
                return "delete"  # Fn+Delete на Mac
            if seq[:1] in (b"[", b"O"):
                return {b"A": "up", b"B": "down", b"C": "right", b"D": "left"}.get(seq[-1:], "esc")
            return "esc"
        if ch in (b"/", b"~", b"'", b'"'):
            rest = _drain(fd, 0.03)
            if rest:  # путь пришёл пачкой символов — значит, перетащили или вставили
                return ("paste", (ch + rest).decode(errors="ignore"))
        if ch in (b"\r", b"\n"):
            return "enter"
        if ch in (b"\x7f", b"\x08"):
            return "backspace"  # клавиша Delete (⌫) на Mac
        if ch[0] >= 0xC0:
            ch += os.read(fd, 1 if ch[0] < 0xE0 else 2)
        key = ch.decode(errors="ignore").lower()
        return RU_KEYS.get(key, key)
    finally:
        out("\033[?2004l")
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def parse_dropped_path(text):
    """Путь из перетащенной в терминал папки: '/a/My\\ Folder', '/a/b' в кавычках, file://."""
    s = (text or "").strip()
    if s.startswith("file://"):
        s = urllib.parse.unquote(urllib.parse.urlparse(s).path)
    elif not os.path.exists(os.path.expanduser(s)):
        try:
            parts = shlex.split(s)
        except ValueError:
            parts = []
        s = parts[0] if parts else s
    s = os.path.abspath(os.path.expanduser(s)) if s else ""
    if os.path.isfile(s):
        s = os.path.dirname(s)
    return s if s and os.path.isdir(s) else None
