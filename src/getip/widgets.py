"""Экранные элементы: меню, список с галочками, вопрос, пауза, строка-спиннер."""
import os
import re
import threading
import time

from .style import bold, cyan, dim, green, visible
from .term import CLEAR, TTY, cursor, header, header_text, out, read_key, term_size, window

MIN_DETAILS = 6  # если под подсказку остаётся меньше строк, шапку меню сворачиваем в одну строку


def screen_rows(text, columns):
    """Сколько строк окна займёт text: длинные строки переносятся; после финального \\n курсор
    стоит на новой строке — она тоже считается."""
    return sum(max(1, -(-len(visible(line)) // columns)) for line in text.split("\n"))


def fit_details(text, height):
    """Подсказка ровно в height строк. Короткая дополняется пустыми строками, длинная обрезается —
    по границе раздела, если получится, — и заканчивается многоточием. Так подсказка
    не двигает меню и не заставляет терминал прокручивать экран."""
    lines = text.rstrip("\n").split("\n") if text.strip() else []
    if height <= 0:
        return []
    if len(lines) > height:
        keep = height - 1  # последняя строка — многоточие
        # заголовок раздела — строка с отступом в два пробела, текст раздела — в четыре
        starts = [i for i in range(1, keep + 1) if re.match(r"  \S", visible(lines[i]))]
        lines = lines[:starts[-1] if starts else keep] + ["  " + dim("…")]
    return lines + [""] * (height - len(lines))


def compose(title, rows, body, index, notice, footer, details, size):
    """Кадр меню под окно size. details — подсказки ко всем пунктам (или пустой список).
    Возвращает (кадр, (колонки, строки)) — второе — окно, в котором всё видно без обрезки."""
    width = max(len(label) for label, _ in rows)
    listing = ""
    for i, (label, hint) in enumerate(rows):
        text = label.ljust(width)
        listing += f"  {cyan('❯')} {bold(cyan(text))}" if i == index else f"    {text}"
        listing += f"   {dim(hint)}\n" if hint else "\n"
    screen = (body.rstrip("\n") + "\n\n" if body else "") + listing
    # уведомление встаёт на место строки с клавишами, чтобы ничего не сдвигать; строку под
    # курсор не оставляем (он всё равно скрыт) — так экран ровно заполняет окно
    bottom = "\n  " + (notice or dim(footer))
    top, block = header_text(title), ""
    # ширину считаем по пунктам меню, а не по тексту над ними: там бывает длинный путь к папке
    need_columns = max(len(visible(line)) for line in (top + listing + bottom).split("\n")) + 2
    need_lines = screen_rows(top + screen + bottom, size.columns)
    if details:
        rule = "\n  " + dim("─" * min(80, size.columns - 4)) + "\n"
        tallest = max(len(d.rstrip("\n").split("\n")) for d in details)
        need_lines += 2 + tallest  # линия с отступом над подсказкой и сама подсказка
        for compact in (False, True):
            top = header_text(title, compact)
            room = size.lines - screen_rows(top + screen + rule + bottom, size.columns)
            if room >= min(tallest, MIN_DETAILS):
                break
        height = min(tallest, room)
        if height > 0:
            block = rule + "\n".join(fit_details(details[index], height)) + "\n"
    return top + screen + block + bottom, (need_columns, need_lines)


def menu(title, items, body="", index=0, footer="↑↓ выбор · → или Enter — открыть · ← — назад",
         on_paste=None, details=None, columns=0):
    """items: [(название, подсказка)] или функция, их возвращающая (body — тоже).
    on_paste(текст) вызывается при вставке/перетаскивании и возвращает строку-уведомление.
    details(индекс) — подробное описание выбранного пункта, показывается под списком
    в области одной высоты для всех пунктов, чтобы меню не прыгало.
    columns — ширина окна, при которой тексты меню выглядят как задумано. Если подгонка окна
    включена (term.window), окно растёт до неё и до высоты, при которой всё видно целиком.
    Возвращает индекс пункта или None."""
    cursor(False)
    notice = ""
    shown = None
    # если пункты или текст вычисляются на лету, раз в полсекунды проверяем, не изменились ли они
    dynamic = callable(items) or callable(body)
    while True:
        rows = items() if callable(items) else items
        text_body = body() if callable(body) else body
        texts = [details(i) for i in range(len(rows))] if details else []
        size = term_size()
        frame = (tuple(rows), text_body, index, notice, tuple(texts), tuple(size))
        if frame != shown:
            screen, need = compose(title, rows, text_body, index, notice, footer, texts, size)
            wide = max(columns, need[0])
            # сначала ширина, потом высота: в узком окне тексты переносятся сильнее, и высота,
            # посчитанная заранее, вышла бы больше нужной
            if window.grow(wide, size.lines if wide > size.columns else need[1]):
                continue  # окно выросло — тексты переносятся по-новому, собираем кадр заново
            shown = frame
            out((CLEAR if TTY else "") + screen)
        key = read_key(0.5 if dynamic else None)
        if key is None:
            continue
        notice = ""
        if isinstance(key, tuple):
            notice = on_paste(key[1]) if on_paste else ""
        elif key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key in ("enter", "right", "l"):
            return _leave(index)
        elif key in ("q", "esc", "left"):
            return _leave(None)
        elif key and key.isdigit() and 1 <= int(key) <= len(rows):
            return _leave(int(key) - 1)


def _leave(choice):
    # меню заканчивается на строке с клавишами, без перевода строки. Стираем её: следующий
    # вывод (например, вопрос в настройках) встанет на её место, а экран не прокрутится
    out("\r\033[K")
    return choice


def checklist(title, rows, checked, body=""):
    """rows: [(ключ, подсказка)]. Пробел — отметить, a — все/ничего, Enter — готово."""
    checked, index = set(checked), 0
    width = max(len(k) for k, _ in rows)
    cursor(False)
    while True:
        header(title)
        if body:
            out(body.rstrip("\n") + "\n\n")
        height = max(5, os.get_terminal_size().lines - 18) if TTY else len(rows)
        start = min(max(0, index - height // 2), max(0, len(rows) - height))
        if start:
            out("  " + dim(f"  ↑ ещё {start}") + "\n")
        for i in range(start, min(len(rows), start + height)):
            key, hint = rows[i]
            box = green("◉") if key in checked else dim("○")
            label = bold(cyan(key.ljust(width))) if i == index else key.ljust(width)
            out(f"  {cyan('❯') if i == index else ' '} {box} {label}   {dim(hint)}\n")
        if start + height < len(rows):
            out("  " + dim(f"  ↓ ещё {len(rows) - start - height}") + "\n")
        out("\n  " + dim("↑↓ выбор · Пробел — отметить · a — все/ничего · Enter — готово") + "\n")
        key = read_key()
        if isinstance(key, tuple):
            continue
        if key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key == " ":
            checked ^= {rows[index][0]}
        elif key in ("a", "ф"):
            checked = set() if len(checked) == len(rows) else {k for k, _ in rows}
        elif key in ("enter", "q", "esc"):
            return checked


def ask(prompt, default=""):
    cursor(True)
    hint = f" {dim('[' + default + ']')}" if default else ""
    try:
        value = input(f"  {cyan('?')} {prompt}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        out("\n")
        return None
    return value or default


def pause(text="Нажмите любую клавишу…"):
    out("\n  " + dim(text))
    cursor(False)
    read_key()


class Live:
    """Строка-спиннер внизу и лог над ней; лог можно писать из разных потоков."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.lock = threading.Lock()
        self.status = ""
        self.frame = 0
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None

    def _draw(self):
        if TTY and self.running:
            out(f"\r\033[K  {cyan(self.FRAMES[self.frame % len(self.FRAMES)])} {dim(self.status)}")

    def _spin(self):
        while not self.stop_event.wait(0.1):
            with self.lock:
                self.frame += 1
                self._draw()

    def start(self, status):
        self.status, self.running = status, True
        cursor(False)
        if TTY:
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()

    def set(self, status):
        with self.lock:
            self.status = status
            self._draw()

    def log(self, msg):
        with self.lock:
            out(("\r\033[K" if TTY else "") + msg + "\n")
            self._draw()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join()
        with self.lock:
            self.running = False
            if TTY:
                out("\r\033[K")


def wait_for_stop(tick, every):
    """Вызывает tick() каждые `every` сек, пока не нажмут Enter / q (или Ctrl+C)."""
    next_tick = 0
    while True:
        if time.time() >= next_tick:
            tick()
            next_tick = time.time() + every
        if TTY:
            if read_key(0.3) in ("enter", "q", "esc"):
                return
        else:
            time.sleep(0.3)
