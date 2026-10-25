"""Раздел «Блокировка»: сайты и IP, закрытые на этом Mac на время или навсегда.

Экран раздела показывает, что сейчас заблокировано и сколько осталось; отсюда же блокировку
добавляют и снимают. Те же действия есть в командной строке: getip -x, -u, --blocks.
Сама блокировка — в block.py."""
import os

from .block import (PLIST_PATH, SUPPORTED, active_blocks, block_admin, format_left, format_span,
                    load_blocks, net_id, new_blocks, parse_block_target, parse_duration, unsafe_net)
from .style import bold, dim, green, red, yellow
from .term import header, out
from .texts import BLOCK, BLOCK_ENTRY, TIPS_COLUMNS, print_tips, render_tips
from .widgets import Live, ask, get_sudo, menu, pause

SUDO_REASON = "Нужен пароль администратора: блокировка меняет /etc/hosts и брандмауэр."
DURATIONS = [("15 минут", 15 * 60), ("1 час", 3600), ("3 часа", 3 * 3600), ("Сутки", 86400),
             ("Своё время…", -1), ("Навсегда", 0)]


def entry_hint():
    """Подсказка к пункту главного меню: сколько сейчас заблокировано."""
    n = len(active_blocks(load_blocks()))
    return f"заблокировано: {n} · сайты и IP на этом Mac" if n else BLOCK_ENTRY[1]


def render_blocks():
    blocks = sorted(active_blocks(load_blocks()), key=lambda b: b["id"])
    if not blocks:
        return "  " + dim("Сейчас ничего не заблокировано.") + "\n"
    width = max(len(b["id"]) for b in blocks)
    lines = ["  " + bold("Заблокировано:")]
    for b in blocks:
        kind = f"сайт, имён: {len(b['names'])}" if b["names"] else "IP"
        left = yellow(format_left(b["until"])) if b["until"] else format_left(None)
        lines.append(f"    {b['id'].ljust(width)}   {dim(kind.ljust(14))} {left}")
    return "\n".join(lines) + "\n"


def admin(op):
    if not get_sudo(SUDO_REASON):
        raise RuntimeError("пароль не введён — ничего не изменилось")
    block_admin(op)


def block_targets(kind, value, secs):
    """Блокирует сайт или сети на secs секунд (0 — навсегда) и печатает итог."""
    if kind == "site":
        live = Live()
        live.start(f"ищу поддомены {value}…")
        try:
            blocks = new_blocks(kind, value, secs)
        finally:
            live.stop()
    else:
        blocks = new_blocks(kind, value, secs)
    first = not os.path.exists(PLIST_PATH)
    admin({"add": blocks})
    span = f"на {format_span(secs)}" if secs else "навсегда"
    for b in blocks:
        how = (f"hosts, имён: {len(b['names'])} — " + ", ".join(b["names"][:3])
               + ("…" if len(b["names"]) > 3 else "")) if b["names"] else "брандмауэр pf"
        out(f"  {green('✔')} {bold(b['id'])} заблокирован {span}  {dim('· ' + how)}\n")
    if kind == "site":
        out("  " + dim("Уже открытые вкладки могут работать, пока браузер не переподключится —") + "\n"
            "  " + dim("если сайт ещё открывается, перезапустите браузер.") + "\n")
    if first and os.path.exists(PLIST_PATH):
        out("  " + dim("macOS может показать уведомление о новом фоновом объекте — это служба getip:") + "\n"
            "  " + dim("она снимает временные блокировки и возвращает постоянные после перезагрузки.") + "\n")


def unblock(ids):
    admin({"remove": ids})
    out(f"  {green('✔')} Доступ открыт: {', '.join(ids)}\n")


def ask_duration(what):
    """Срок блокировки в секундах: 0 — навсегда, None — передумали."""
    what = what if len(what) <= 40 else what[:39] + "…"
    i = menu(f"На сколько заблокировать {what}?", [(label, "") for label, _ in DURATIONS],
             footer="↑↓ выбор · → или Enter — выбрать · ← — назад")
    if i is None:
        return None
    secs = DURATIONS[i][1]
    if secs < 0:
        header("Своё время")
        out("  " + dim("Число — это минуты. Можно указать единицы: 90м, 2ч, 1д.") + "\n\n")
        secs = parse_duration(ask("На сколько") or "")
        if not secs:
            out(f"  {red('✖')} Не понял срок. Примеры: 45, 90м, 2ч, 1д\n")
            pause()
            return None
    return secs


def block_flow():
    header(BLOCK["add"][0])
    print_tips("block")
    out("\n  " + dim("Введите адрес и нажмите Enter · Ctrl+C — назад") + "\n\n")
    raw = ask("Сайт, сервер или IP")
    if not raw:
        return
    target = parse_block_target(raw)
    if not target:
        out(f"  {red('✖')} Не похоже ни на сайт, ни на IP. Примеры: youtube.com, 1.2.3.4, 1.2.3.0/24\n")
        pause()
        return
    kind, value = target
    bad = [(n, unsafe_net(n)) for n in value if unsafe_net(n)] if kind == "ip" else []
    if bad:
        out(f"  {red('✖')} {bad[0][0]}: {bad[0][1]}\n")
        pause()
        return
    secs = ask_duration(value if kind == "site" else ", ".join(net_id(n) for n in value))
    if secs is None:
        return
    header(BLOCK["add"][0])
    block_targets(kind, value, secs)
    pause()


def unblock_flow():
    blocks = sorted(active_blocks(load_blocks()), key=lambda b: b["id"])
    if not blocks:
        return
    rows = [(b["id"], format_left(b["until"])) for b in blocks]
    if len(blocks) > 1:
        rows.append(("Снять все", ""))
    i = menu(BLOCK["remove"][0], rows, footer="↑↓ выбор · → или Enter — снять · ← — назад")
    if i is None:
        return
    header(BLOCK["remove"][0])
    unblock([b["id"] for b in blocks] if i == len(blocks) else [blocks[i]["id"]])
    pause()


def block_menu(cfg):
    """Раздел «Блокировка»: что заблокировано, добавить, снять."""
    def rows():
        n = len(active_blocks(load_blocks()))
        return ([BLOCK["add"]] + ([(BLOCK["remove"][0], BLOCK["remove"][1].format(n))] if n else [])
                + [("Назад", "")])

    index = 0
    while True:
        index = menu(BLOCK_ENTRY[0], rows, body=render_blocks, index=index,
                     details=lambda n: render_tips("block") if n == 0 else "", columns=TIPS_COLUMNS)
        current = rows()
        label = current[index][0] if index is not None and index < len(current) else "Назад"
        if label == "Назад":
            return
        try:
            if label == BLOCK["add"][0]:
                block_flow()
            else:
                unblock_flow()
        except RuntimeError as e:
            out(f"\n  {red('✖')} {e}\n")
            pause()
        except KeyboardInterrupt:
            out("\n")


def block_cli(args):
    """getip -x цели [--for срок] · getip -u цели|all · getip --blocks."""
    if args.blocks:
        out(render_blocks())
        return
    if not SUPPORTED:
        raise RuntimeError("блокировка работает только на macOS")
    if not args.sites:
        raise RuntimeError("укажите сайт или IP, напр. " + ("getip -u youtube.com (или all)" if args.unblock
                                                           else "getip -x youtube.com --for 1h"))
    if args.unblock:
        active = [b["id"] for b in active_blocks(load_blocks())]
        if args.sites == ["all"]:
            ids = active
            if not ids and os.path.exists(PLIST_PATH):
                admin({"remove": []})  # служба осталась от истёкших блокировок — уберём её
            if not ids:
                out("  " + dim("Сейчас ничего не заблокировано.") + "\n")
        else:
            ids = []
            for s in args.sites:
                t = parse_block_target(s)
                if not t:
                    ids.append(s)
                elif t[0] == "site":
                    ids.append(t[1])
                else:
                    ids += [net_id(n) for n in t[1]]
            for missing in [i for i in ids if i not in active]:
                out(f"  {yellow('!')} {missing} не заблокирован\n")
            ids = [i for i in ids if i in active]
        if ids:
            unblock(ids)
        return
    secs = parse_duration(args.duration) if args.duration else 0
    if secs is None:
        raise RuntimeError(f"не понял срок «{args.duration}», примеры: 30m, 2h, 1d")
    targets = []
    for s in args.sites:
        t = parse_block_target(s)
        if not t:
            raise RuntimeError(f"«{s}» не похоже ни на сайт, ни на IP")
        for n in t[1] if t[0] == "ip" else []:
            if unsafe_net(n):
                raise RuntimeError(f"{n}: {unsafe_net(n)}")
        targets.append(t)
    for kind, value in targets:
        block_targets(kind, value, secs)
