"""Интерактивный режим: главное меню и его экраны."""
import ipaddress
import os
import subprocess

from . import VERSION
from .block import SUPPORTED as BLOCK_SUPPORTED
from .block_menu import block_menu, entry_hint
from .bypass_menu import bypass_menu
from .check import run_check
from .config import out_dir, save_config
from .routes import add_to_bat, bat_path, route_lines
from .scans import ask_site, pick_app, run_scan
from .style import bold, cyan, dim, green, pretty, red
from .term import TTY, cursor, header, out, parse_dropped_path, read_key, window
from .texts import BLOCK_ENTRY, BYPASS_ENTRY, CHECK, MODES, TIPS_COLUMNS, render_tips
from .update import UpdateCheck, self_update
from .widgets import ask, confirm, menu, pause


def show_file(path):
    """Печатает содержимое файла прямо в терминале, с номерами строк."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    name = os.path.basename(path)
    out(f"\n  {dim('──')} {bold(name)} {dim('· ' + str(len(lines)) + ' строк ' + '─' * 20)}\n")
    for n, line in enumerate(lines, 1):
        out(f"  {dim(str(n).rjust(3) + ' │')} {line}\n")
    out(f"  {dim('─' * (len(name) + 34))}\n")


def hotkeys(actions):
    """actions: [(клавиши, подпись, действие)]. Любая другая клавиша — продолжить.
    Если действие вернуло True, подсказка с клавишами печатается заново."""
    hint = ("  " + "   ".join(f"{bold(cyan(keys[0]))} {dim(label)}" for keys, label, _ in actions)
            + f"   {dim('любая другая клавиша — продолжить')}\n")
    out("\n" + hint)
    cursor(False)
    while True:
        key = read_key()
        if isinstance(key, tuple):
            continue
        action = next((fn for keys, _, fn in actions if key in keys), None)
        if action is None:
            return
        if action():
            out("\n" + hint)


def copy_routes(lines):
    subprocess.run(["pbcopy"], input="\r\n".join(lines) + "\r\n", text=True)
    out(f"  {green('✔')} {dim('Команды скопированы в буфер обмена')}\n")


def after_scan(path, col):
    """Экран после сканирования: горячие клавиши, любая другая — продолжить."""
    def reveal():
        subprocess.run(["open", "-R", path])
        out(f"  {green('✔')} {dim('Открыл папку в Finder')}\n")

    def view():
        show_file(path)
        return True

    hotkeys([(("o", "щ"), "открыть папку", reveal),
             (("v", "м"), "показать файл", view),
             (("c", "с"), "скопировать", lambda: copy_routes(col.routes()))])


def after_check(cfg, result):
    """Экран после проверки: адреса мимо туннеля можно дописать в <программа>.bat или скопировать."""
    nets = result.networks()
    if not nets:
        pause()
        return
    path = bat_path(cfg, result.target)

    def save():
        total = add_to_bat(path, nets, cfg)
        out(f"  {green('✔')} {dim('Дописал в')} {bold(pretty(path))} {dim('· подсетей в файле: ' + str(total))}\n")

    hotkeys([(("s", "ы"), "дописать в " + os.path.basename(path), save),
             (("c", "с"), "скопировать", lambda: copy_routes(route_lines(nets, cfg)))])


def drop_folder(cfg, text):
    """Папку перетащили в окно меню — делаем её папкой для файлов."""
    path = parse_dropped_path(text)
    if not path:
        return f"{red('✖')} Это не папка: {text.strip()}"
    cfg["out_dir"] = path
    save_config(cfg)
    return f"{green('✔')} Файлы теперь сохраняются в {bold(pretty(path))}"


def settings_menu(cfg):
    on = lambda v: green("вкл") if v else dim("выкл")
    items = lambda: [
        ("Шлюз", cfg["gw"]),
        ("Постоянные маршруты", on(cfg["persistent"]) + dim("  route -p add")),
        ("Только точные IP (/32)", on(cfg["exact"]) + dim("  без расширения до подсети")),
        ("Папка для файлов", pretty(cfg["out_dir"]) if cfg["out_dir"] else "текущая папка терминала"),
        ("Глубокое сканирование", f"{cfg['deep_seconds']} сек"),
        ("Подгонять размер окна", on(cfg["fit_window"]) + dim("  увеличивать окно, чтобы подсказки помещались")),
        ("Назад", ""),
    ]
    index = 0
    while True:
        index = menu("Настройки", items, index=index, on_paste=lambda t: drop_folder(cfg, t),
                     body="  " + dim("Совет: перетащите папку в это окно, чтобы сохранять файлы туда."))
        if index is None or index == 6:
            return
        if index == 0:
            v = ask("Шлюз (IP)", cfg["gw"])
            try:
                cfg["gw"] = str(ipaddress.IPv4Address(v)) if v else cfg["gw"]
            except ValueError:
                pass
        elif index == 1:
            cfg["persistent"] = not cfg["persistent"]
        elif index == 2:
            cfg["exact"] = not cfg["exact"]
        elif index == 3:
            header("Папка для файлов")
            out("  " + dim("Перетащите папку в окно (или введите путь) и нажмите Enter.") + "\n")
            out("  " + dim("Пусто — оставить как есть, «-» — сохранять в текущую папку терминала.") + "\n\n")
            v = ask("Папка")
            if v == "-":
                cfg["out_dir"] = ""
            elif v:
                path = parse_dropped_path(v)
                if path:
                    cfg["out_dir"] = path
                else:
                    out(f"\n  {red('✖')} Такой папки нет: {v}\n")
                    pause()
        elif index == 4:
            v = ask("Сколько секунд опрашивать DNS", str(cfg["deep_seconds"]))
            if v and v.isdigit():
                cfg["deep_seconds"] = max(10, int(v))
        elif index == 5:
            cfg["fit_window"] = not cfg["fit_window"]
            if not cfg["fit_window"]:
                window.restore()  # выключили — сразу возвращаем окну прежний размер
            window.enabled, window.ignored = cfg["fit_window"], False
        save_config(cfg)


def confirm_exit():
    return confirm("Выйти из getip?", "Да, выйти", "Нет, остаться")


def scan_flow(cfg, mode):
    """Выбор сайта или программы, сканирование и экран с результатом."""
    if mode == "app":
        target = pick_app(MODES["app"][0], "app")
    else:
        target = ask_site(cfg, MODES[mode][0], mode)
    if not target:
        return
    append = False
    if os.path.exists(bat_path(cfg, target)):
        choice = menu(f"Файл {os.path.basename(bat_path(cfg, target))} уже существует", [
            ("Дополнить", "добавить новые подсети к старым"),
            ("Перезаписать", "начать с чистого листа"),
        ])
        if choice is None:
            return
        append = choice == 0
    header()
    path, col = run_scan(target, mode, cfg, append)
    if path:
        after_scan(path, col)
    else:
        pause()


def check_flow(cfg):
    target = pick_app(CHECK[0], "check")
    if not target:
        return
    header()
    after_check(cfg, run_check(target, cfg))


def interactive(cfg):
    update = UpdateCheck()  # проверка в фоне; пункт «Обновить» появится, когда придёт ответ
    update_label = lambda: f"⬆ Обновить до {update.latest}"

    def entries():
        """Пункты меню: (название, подсказка, действие)."""
        rows = [(label, hint, ("scan", mode)) for mode, (label, hint) in MODES.items()]
        rows += [(*CHECK, ("check", None)),
                 (*BYPASS_ENTRY, ("bypass", None))]
        if BLOCK_SUPPORTED:
            rows.append((BLOCK_ENTRY[0], entry_hint(), ("block", None)))
        rows += [("Настройки", "", ("settings", None)),
                 ("Открыть папку с файлами", "", ("folder", None))]
        if update.latest:
            rows.append((update_label(), f"сейчас у вас {VERSION}", ("update", None)))
        return rows + [("Выход", "", ("exit", None))]

    def body():
        text = ("  " + dim("Файлы сохраняются в: ") + pretty(out_dir(cfg)) + "\n"
                "  " + dim("Перетащите папку в это окно, чтобы сохранять файлы туда."))
        if update.latest:
            text += f"\n\n  {green('⬆')} Вышла новая версия {bold(update.latest)} — выберите «Обновить» в меню."
        return text

    def details(n):
        action, arg = entries()[n][2]
        if action == "scan":
            return render_tips(arg)
        if action in ("check", "bypass", "block"):
            return render_tips(action)
        if action == "update":
            return (f"  {bold(cyan('Что делает'))}\n    Скачает getip {update.latest} с GitHub и перезапустит"
                    f" программу.\n    Настройки и сохранённые файлы останутся на месте.\n")
        return ""

    index = 0
    window.enabled = cfg["fit_window"]
    try:
        while True:
            i = menu("Главное меню", lambda: [row[:2] for row in entries()], body=body, index=index,
                     on_paste=lambda t: drop_folder(cfg, t), details=details, columns=TIPS_COLUMNS,
                     footer="↑↓ выбор · → или Enter — открыть · ← — выход")
            action, arg = entries()[i][2] if i is not None else ("exit", None)
            index = i if i is not None else index
            if action == "exit":
                if confirm_exit():
                    break
            elif action == "scan":
                scan_flow(cfg, arg)
            elif action == "check":
                check_flow(cfg)
            elif action == "bypass":
                bypass_menu(cfg)
            elif action == "block":
                block_menu(cfg)
            elif action == "settings":
                settings_menu(cfg)
            elif action == "folder":
                os.makedirs(out_dir(cfg), exist_ok=True)
                subprocess.run(["open", out_dir(cfg)])
            elif action == "update":
                window.restore()  # перед перезапуском — новая версия подгонит окно сама
                self_update(update.latest)
    finally:
        window.restore()
    if TTY:
        out("\033[H\033[2J\033[3J")
    out(f"  {cyan('getip')} {dim('— до встречи!')}\n")
