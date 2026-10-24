"""Раздел «Мимо VPN»: сайты и программы, которые ходят через роутер в обход VPN на компьютере.

Сайт или программу выбирают так же, как для .bat, и адреса собирают те же режимы (scans.py).
Найденные подсети направляются через шлюз роутера и попадают в список (bypass.py). На экране
списка маршруты включают и выключают, удаляют по одному или все сразу."""
from .bypass import (KINDS, add_routes, apply, group_routes, load_routes, remove_routes, route_key,
                     route_state, save_routes, switch, system_table, to_add, to_delete, toggle_plan,
                     withdraw)
from .scans import ask_site, collect, pick_app
from .style import bold, cyan, dim, green, red, yellow
from .term import CLEAR, TTY, cursor, header, header_text, out, read_key, term_size
from .texts import BYPASS, BYPASS_ENTRY, MODES, TIPS_COLUMNS, render_tips
from .tunnel import physical_route
from .widgets import confirm, get_sudo, menu, pause

SUDO_REASON = "Чтобы менять маршруты, нужен пароль администратора."
SHOW_NETS = 12   # столько подсетей показываем в вопросах, остальные — строкой «… и ещё»
BIG_PREFIX = 16  # подсеть крупнее /16 уводит мимо VPN и чужие сайты — предупреждаем
SITE_MODES = ("quick", "deep", "sniff")
LIST_KEYS = ("↑↓ выбор · Пробел — отметить · a — все/ничего · r — включить/выключить · ← — назад",
             "⌫ — удалить отмеченные · x — удалить весь список")


def gateway_line(gw):
    if gw:
        return f"  {dim('Мимо VPN — значит через роутер')} {gw[0]} {dim('(' + gw[1] + ')')}"
    return f"  {red('✖')} Нет подключения к роутеру: маршруты мимо VPN сейчас не действуют"


def nets_text(nets):
    """Подсети столбиком, не больше SHOW_NETS строк; крупные отмечены."""
    lines = [f"    {n}" + (f"  {yellow('крупная подсеть')}" if n.prefixlen < BIG_PREFIX else "")
             for n in nets[:SHOW_NETS]]
    if len(nets) > SHOW_NETS:
        lines.append("    " + dim(f"… и ещё подсетей: {len(nets) - SHOW_NETS}"))
    return "\n".join(lines)


def chosen_text(chosen):
    """Выбранные записи по сайтам и программам, не больше SHOW_NETS подсетей."""
    lines, shown = [], 0
    for source, kind, items in group_routes(chosen):
        take = items[:SHOW_NETS - shown]
        if not take:
            break
        lines.append(f"    {bold(source)} {dim(KINDS[kind])}")
        lines += [f"      {r.net}" + (dim("  выключен") if r.off else "") for r in take]
        shown += len(take)
    if len(chosen) > shown:
        lines.append("    " + dim(f"… и ещё подсетей: {len(chosen) - shown}"))
    return "\n".join(lines)


def offer(target, kind, nets):
    """После сбора адресов: показывает новые подсети и по согласию пускает их мимо VPN."""
    if not nets:
        out(f"\n  {red('✖')} Не найдено ни одного адреса — пускать мимо VPN нечего.\n")
        pause()
        return
    gw = physical_route()
    if not gw:
        out(f"\n  {red('✖')} Не нашёл подключение к роутеру: нет маршрута по умолчанию через Wi-Fi или кабель.\n")
        pause()
        return
    routes, added = add_routes(load_routes(), target, kind, nets)
    # сайт добавляют ещё раз — значит, он нужен мимо VPN: выключенные его записи тоже включаем
    routes, mine = switch(routes, [r for r in routes if (r.source, r.kind) == (target, kind)], False)
    table = system_table()
    need = to_add(mine, table, gw[0])
    if not need:
        save_routes(routes)
        out(f"\n  {green('✔')} {bold(target)} уже идёт мимо VPN: все найденные подсети в списке и действуют.\n")
        pause()
        return

    body = gateway_line(gw) + "\n\n"
    if added:
        body += f"  {dim('Новые подсети')} {bold(target)}{dim(':')}\n{nets_text(added)}\n"
    again = len(need) - len(added)
    if len(mine) > len(added):
        body += "\n  " + dim(f"Уже в списке: {len(mine) - len(added)}"
                             + (f", из них включу заново: {again}" if again else "")) + "\n"
    if any(n.prefixlen < BIG_PREFIX for n in added):
        body += (f"\n  {yellow('!')} {dim('Крупные подсети уведут мимо VPN и другие сайты этих провайдеров.')}"
                 f"\n    {dim('Чтобы брать только точные адреса, включите «Только точные IP» в настройках.')}\n")
    if not confirm(f"Пустить {target} мимо VPN?", "Да, пустить мимо VPN", "Нет, не надо",
                   body=body, default_yes=True):
        return
    if not get_sudo(SUDO_REASON):
        out(f"\n  {red('✖')} Пароль не введён — маршруты не добавлены.\n")
        pause()
        return
    failed = apply(need, gw[0], table)
    save_routes(routes)
    if len(need) > len(failed):
        out(f"\n  {green('✔')} {bold(target)} идёт мимо VPN · подсетей через роутер: {len(need) - len(failed)}\n")
    for net, err in failed.items():
        out(f"  {red('✖')} {net}  {dim(err)}\n")
    if failed:
        out("    " + dim("Эти подсети остались в списке — включите их клавишей r в «Маршруты мимо VPN».") + "\n")
    pause()


def choose_method(target):
    i = menu(f"Как искать адреса {target}", [MODES[m] for m in SITE_MODES],
             details=lambda n: render_tips(SITE_MODES[n]), columns=TIPS_COLUMNS)
    return None if i is None else SITE_MODES[i]


def site_flow(cfg):
    target = ask_site(cfg, BYPASS["site"][0], "bypass_site")
    mode = target and choose_method(target)
    if not mode:
        return
    header()
    offer(target, "site", collect(target, mode, cfg).networks())


def app_flow(cfg):
    target = pick_app(BYPASS["app"][0], "bypass_app")
    if not target:
        return
    header()
    offer(target, "app", collect(target, "app", cfg).networks())


def list_rows(routes):
    """Строки экрана списка: ("group", (источник, вид, записи)), за ней её ("route", запись)."""
    rows = []
    for group in group_routes(routes):
        rows.append(("group", group))
        rows += [("route", r) for r in group[2]]
    return rows


def row_keys(row):
    """Записи, к которым относится строка: у заголовка — вся группа."""
    kind, data = row
    return {route_key(r) for r in data[2]} if kind == "group" else {route_key(data)}


def state_text(r, table, gw, others):
    """Состояние записи. others — другие включённые сайты и программы с той же подсетью."""
    if r.off:
        return dim("○ выключен") + (dim("  · подсеть всё равно мимо VPN: нужна для " + ", ".join(others))
                                    if others else "")
    state = route_state(r.net, table, gw[0] if gw else None)
    also = dim("  · нужна и для " + ", ".join(others)) if others else ""
    if state == "on":
        return green("✔ мимо VPN") + also
    if state == "stale":
        return yellow(f"! через шлюз прежней сети {table[r.net]}") + dim(" — r, чтобы включить") + also
    return yellow("! не действует") + dim(" — r, чтобы включить") + also


def row_text(row, current, marked, table, gw, sources):
    pointer = cyan("❯") if current else " "
    kind, data = row
    if kind == "group":
        source, what, items = data
        n = sum(route_key(r) in marked for r in items)
        box = green("◉") if n == len(items) else yellow("◐") if n else dim("○")
        name = bold(cyan(source)) if current else bold(source)
        off = sum(r.off for r in items)
        return (f"  {pointer} {box} {name}   {dim(KINDS[what] + ' · подсетей: ' + str(len(items)))}"
                + (dim(f" · выключено: {off}") if off else ""))
    box = green("◉") if route_key(data) in marked else dim("○")
    net = str(data.net).ljust(18)
    others = [s for s in sources[data.net] if s != data.source]
    label = bold(cyan(net)) if current else dim(net) if data.off else net
    return f"  {pointer}   {box} {label} {state_text(data, table, gw, others)}"


def draw_list(routes, rows, marked, index, notice, gw, table):
    # считаем записи — те же строки, что на экране
    enabled = [r for r in routes if not r.off]
    on = sum(route_state(r.net, table, gw[0] if gw else None) == "on" for r in enabled)
    top = header_text(BYPASS["list"][0]) + gateway_line(gw) + "\n"
    if routes:
        off = len(routes) - len(enabled)
        top += "  " + dim(f"Подсетей: {len(routes)} · действуют: {on}" + (f" · выключено: {off}" if off else "")) + "\n"
        if len(enabled) > on and gw:
            top += (f"  {yellow('!')} Не действуют после перезагрузки или смены сети: {len(enabled) - on}"
                    f" {dim('— a, затем r, чтобы вернуть')}\n")
    top += "\n"
    keys = LIST_KEYS if routes else ("← — назад",)
    bottom = "\n" + (f"  {notice}\n" if notice else "") + "\n".join("  " + dim(k) for k in keys)
    if not routes:
        body = "  " + dim("Список пуст. Добавьте сайт или программу в разделе «Мимо VPN».") + "\n"
    else:
        # строки «↑ ещё» и «↓ ещё» тоже занимают место
        height = max(3, term_size().lines - top.count("\n") - bottom.count("\n") - 3) if TTY else len(rows)
        start = min(max(0, index - height // 2), max(0, len(rows) - height))
        sources = {}  # подсеть -> включённые сайты и программы, которым она нужна
        for r in routes:
            sources.setdefault(r.net, [])
            if not r.off:
                sources[r.net].append(r.source)
        lines = ["  " + dim(f"  ↑ ещё {start}")] if start else []
        lines += [row_text(rows[i], i == index, marked, table, gw, sources)
                  for i in range(start, min(len(rows), start + height))]
        if start + height < len(rows):
            lines.append("  " + dim(f"  ↓ ещё {len(rows) - start - height}"))
        body = "\n".join(lines) + "\n"
    # без перевода строки в конце: экран ровно заполняет окно и не прокручивается
    out((CLEAR if TTY else "") + top + body + bottom)


def delete(routes, chosen, title, text):
    """Удаляет выбранные записи, если пользователь подтвердит. Возвращает строку-уведомление."""
    if not confirm(title, "Да, удалить", "Нет, оставить", body=f"  {dim(text)}\n{chosen_text(chosen)}"):
        return dim("Ничего не удалено")
    _, gone = remove_routes(routes, chosen)
    table = system_table()
    if to_delete(gone, table) and not get_sudo(SUDO_REASON):
        return f"{red('✖')} Пароль не введён — ничего не удалено"
    failed = withdraw(gone, table)
    # маршрут, который не удалось убрать из системы, оставляем и в списке — иначе его не найти
    removed = [r for r in chosen if r.net not in failed]
    save_routes(remove_routes(routes, removed)[0])
    note = f"{green('✔')} Удалено из списка: {len(removed)}"
    if failed:
        note += f"   {red('✖')} не удалось убрать из системы: {len(failed)} — {next(iter(failed.values()))}"
    return note


def toggle(routes, chosen, gw, table):
    """Клавиша r: выключает работающие записи или включает остальные (см. toggle_plan).
    Возвращает строку-уведомление."""
    plan = toggle_plan(chosen, table, gw[0] if gw else None)
    if plan == "restore":
        chosen = [r for r in chosen if not r.off]
    off = plan == "off"
    if not off and not gw:
        return f"{red('✖')} Нет подключения к роутеру — включать не через что"
    new, nets = switch(routes, chosen, off)
    need = to_delete(nets, table) if off else to_add(nets, table, gw[0])
    if need:
        out("\n")
        if not get_sudo(SUDO_REASON):
            return f"{red('✖')} Пароль не введён — ничего не изменилось"
    failed = withdraw(nets, table) if off else apply(nets, gw[0], table)
    if off and failed:  # маршрут остался в системе — пусть и запись остаётся включённой
        new, _ = switch(new, [r for r in chosen if r.net in failed], False)
    save_routes(new)
    done = len(need) - len(failed) if plan == "restore" else sum(r.net not in failed for r in chosen)
    note = {"off": f"{green('✔')} Выключено: {done} {dim('— снова через VPN, в списке остались')}",
            "on": f"{green('✔')} Включено: {done} {dim('— мимо VPN')}",
            "restore": f"{green('✔')} Возвращено в систему: {done}"}[plan]
    if failed:
        note += f"   {red('✖')} не вышло: {len(failed)} — {next(iter(failed.values()))}"
    return note


def routes_screen():
    """Все маршруты мимо VPN: пробел отмечает, r включает и выключает, ⌫ удаляет отмеченные, x — весь список."""
    marked, index, notice = set(), 0, ""  # marked — ключи записей (route_key)
    while True:
        routes, gw, table = load_routes(), physical_route(), system_table()
        rows = list_rows(routes)
        marked &= {route_key(r) for r in routes}
        index = min(index, max(0, len(rows) - 1))
        cursor(False)
        draw_list(routes, rows, marked, index, notice, gw, table)
        key = read_key()
        notice = ""
        if isinstance(key, tuple):
            continue
        if key in ("q", "esc", "left"):
            out("\r\033[K")
            return
        if not rows:
            continue
        chosen = [r for r in routes if route_key(r) in marked]
        if key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key == " ":
            items = row_keys(rows[index])
            marked = marked - items if items <= marked else marked | items
        elif key in ("a", "ф"):
            every = {route_key(r) for r in routes}
            marked = set() if marked == every else every
        elif key in ("r", "к"):
            # отмеченные, а если ничего не отмечено — строка под курсором
            current = row_keys(rows[index])
            notice = toggle(routes, chosen or [r for r in routes if route_key(r) in current], gw, table)
        elif key in ("backspace", "delete", "d", "в"):
            if chosen:
                notice = delete(routes, chosen, "Удалить отмеченные маршруты?",
                                f"Отмечено: {len(chosen)}. Эти подсети снова пойдут через VPN:")
            else:
                notice = f"{yellow('!')} Сначала отметьте маршруты пробелом"
        elif key in ("x", "ч"):
            notice = delete(routes, routes, "Удалить все маршруты мимо VPN?",
                            f"Сайтов и программ: {len(group_routes(routes))}, подсетей: {len(routes)}."
                            f" Все они снова пойдут через VPN:")


def bypass_menu(cfg):
    """Раздел «Мимо VPN»: сайт, программа и список маршрутов."""
    flows = (site_flow, app_flow, lambda _: routes_screen())
    tips = ("bypass_site", "bypass_app", "bypass_list")
    index = 0
    while True:
        count = len(load_routes())
        rows = [BYPASS["site"], BYPASS["app"],
                (BYPASS["list"][0], f"подсетей: {count} · {BYPASS['list'][1]}"), ("Назад", "")]
        i = menu(BYPASS_ENTRY[0], rows, body=gateway_line(physical_route()), index=index,
                 details=lambda n: render_tips(tips[n]) if n < len(tips) else "", columns=TIPS_COLUMNS)
        if i is None or i == len(tips):
            return
        index = i
        flows[i](cfg)
