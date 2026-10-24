"""Раздел «Мимо VPN»: сайты и программы, которые ходят через роутер в обход VPN на компьютере.

Сайт или программу выбирают так же, как для .bat, и адреса собирают те же режимы (scans.py).
Найденные подсети направляются через шлюз роутера и попадают в список (bypass.py). На экране
списка маршруты удаляют по одному или все сразу и включают заново после перезагрузки."""
from .bypass import (KINDS, add_routes, apply, group_routes, load_routes, remove_routes, route_state,
                     save_routes, system_table, to_add, to_delete, withdraw)
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
LIST_KEYS = ("↑↓ выбор · Пробел — отметить · a — все/ничего · r — включить заново · ← — назад",
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
        lines += [f"      {r.net}" for r in take]
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
    mine = [r.net for r in routes if (r.source, r.kind) == (target, kind)]
    table = system_table()
    need = to_add(mine, table, gw[0])
    if not need:
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
        out("    " + dim("Эти подсети остались в списке — включите их заново в «Маршруты мимо VPN».") + "\n")
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


def state_text(net, table, gw):
    state = route_state(net, table, gw[0] if gw else None)
    if state == "on":
        return green("✔ мимо VPN")
    if state == "stale":
        return yellow(f"↻ через шлюз прежней сети {table[net]}") + dim(" — r, чтобы включить заново")
    return yellow("○ не действует") + dim(" — r, чтобы включить")


def row_text(row, current, marked, table, gw, sources):
    pointer = cyan("❯") if current else " "
    kind, data = row
    if kind == "group":
        source, what, items = data
        n = sum(r in marked for r in items)
        box = green("◉") if n == len(items) else yellow("◐") if n else dim("○")
        name = bold(cyan(source)) if current else bold(source)
        return f"  {pointer} {box} {name}   {dim(KINDS[what] + ' · подсетей: ' + str(len(items)))}"
    box = green("◉") if data in marked else dim("○")
    net = str(data.net).ljust(18)
    others = [s for s in sources[data.net] if s != data.source]
    also = dim("  · нужна и для " + ", ".join(others)) if others else ""
    return f"  {pointer}   {box} {bold(cyan(net)) if current else net} {state_text(data.net, table, gw)}{also}"


def draw_list(routes, rows, marked, index, notice, gw, table):
    nets = {r.net for r in routes}
    on = sum(route_state(n, table, gw[0] if gw else None) == "on" for n in nets)
    top = header_text(BYPASS["list"][0]) + gateway_line(gw)
    top += (dim(f" · подсетей: {len(nets)} · действуют: {on}") if routes else "") + "\n\n"
    keys = LIST_KEYS if routes else ("← — назад",)
    bottom = "\n" + (f"  {notice}\n" if notice else "") + "\n".join("  " + dim(k) for k in keys)
    if not routes:
        body = "  " + dim("Список пуст. Добавьте сайт или программу в разделе «Мимо VPN».") + "\n"
    else:
        # строки «↑ ещё» и «↓ ещё» тоже занимают место
        height = max(3, term_size().lines - top.count("\n") - bottom.count("\n") - 3) if TTY else len(rows)
        start = min(max(0, index - height // 2), max(0, len(rows) - height))
        sources = {}
        for r in routes:
            sources.setdefault(r.net, []).append(r.source)
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
    chosen = [r for r in routes if r in set(chosen)]
    if not confirm(title, "Да, удалить", "Нет, оставить", body=f"  {dim(text)}\n{chosen_text(chosen)}"):
        return dim("Ничего не удалено")
    _, gone = remove_routes(routes, chosen)
    table = system_table()
    if to_delete(gone, table) and not get_sudo(SUDO_REASON):
        return f"{red('✖')} Пароль не введён — ничего не удалено"
    failed = withdraw(gone, table)
    # маршрут, который не удалось убрать из системы, оставляем и в списке — иначе его не найти
    removed = {r for r in chosen if r.net not in failed}
    save_routes([r for r in routes if r not in removed])
    note = f"{green('✔')} Удалено из списка: {len(removed)}"
    if failed:
        note += f"   {red('✖')} не удалось убрать из системы: {len(failed)} — {next(iter(failed.values()))}"
    return note


def reapply(routes, gw, table):
    """Включает заново маршруты, которых нет в системе (после перезагрузки или смены сети)."""
    if not gw:
        return f"{red('✖')} Нет подключения к роутеру — включать не через что"
    need = to_add(sorted({r.net for r in routes}), table, gw[0])
    if not need:
        return f"{green('✔')} Все маршруты и так действуют"
    out("\n")
    if not get_sudo(SUDO_REASON):
        return f"{red('✖')} Пароль не введён — ничего не включено"
    failed = apply(need, gw[0], table)
    note = f"{green('✔')} Включено заново: {len(need) - len(failed)}"
    if failed:
        note += f"   {red('✖')} не вышло: {len(failed)} — {next(iter(failed.values()))}"
    return note


def routes_screen():
    """Все маршруты мимо VPN: пробел отмечает, ⌫ удаляет отмеченные, x — весь список, r — включает заново."""
    marked, index, notice = set(), 0, ""
    while True:
        routes, gw, table = load_routes(), physical_route(), system_table()
        rows = list_rows(routes)
        marked &= set(routes)
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
        if key in ("up", "k"):
            index = (index - 1) % len(rows)
        elif key in ("down", "j"):
            index = (index + 1) % len(rows)
        elif key == " ":
            kind, data = rows[index]
            items = set(data[2]) if kind == "group" else {data}
            marked = marked - items if items <= marked else marked | items
        elif key in ("a", "ф"):
            marked = set() if marked == set(routes) else set(routes)
        elif key in ("backspace", "delete", "d", "в"):
            if marked:
                notice = delete(routes, marked, "Удалить отмеченные маршруты?",
                                f"Отмечено: {len(marked)}. Эти подсети снова пойдут через VPN:")
            else:
                notice = f"{yellow('!')} Сначала отметьте маршруты пробелом"
        elif key in ("x", "ч"):
            notice = delete(routes, routes, "Удалить все маршруты мимо VPN?",
                            f"Сайтов и программ: {len(group_routes(routes))}, подсетей: {len({r.net for r in routes})}."
                            f" Все они снова пойдут через VPN:")
        elif key in ("r", "к"):
            notice = reapply(routes, gw, table)


def bypass_menu(cfg):
    """Раздел «Мимо VPN»: сайт, программа и список маршрутов."""
    flows = (site_flow, app_flow, lambda _: routes_screen())
    tips = ("bypass_site", "bypass_app", "bypass_list")
    index = 0
    while True:
        count = len({r.net for r in load_routes()})
        rows = [BYPASS["site"], BYPASS["app"],
                (BYPASS["list"][0], f"подсетей: {count} · {BYPASS['list'][1]}"), ("Назад", "")]
        i = menu(BYPASS_ENTRY[0], rows, body=gateway_line(physical_route()), index=index,
                 details=lambda n: render_tips(tips[n]) if n < len(tips) else "", columns=TIPS_COLUMNS)
        if i is None or i == len(tips):
            return
        index = i
        flows[i](cfg)
