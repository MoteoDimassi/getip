#!/bin/sh
# Установщик getip.
#   Установить или обновить:  curl -fsSL https://raw.githubusercontent.com/MoteoDimassi/getip/main/install.sh | sh
#   Удалить:                  curl -fsSL https://raw.githubusercontent.com/MoteoDimassi/getip/main/install.sh | sh -s -- --uninstall
#
# Ставит две вещи: пакет с кодом в ~/.local/share/getip/getip и запускалку ~/.local/bin/getip.
# Этим же скриптом getip обновляет сам себя.
set -e

REPO="${GETIP_REPO:-MoteoDimassi/getip}"
BRANCH="${GETIP_BRANCH:-main}"
ARCHIVE="${GETIP_ARCHIVE:-https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH}"
BIN="${GETIP_BIN:-$HOME/.local/bin}"
DATA="$(dirname "$BIN")/share/getip"   # запускалка ищет пакет именно здесь: <bin>/../share/getip
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

if [ -t 1 ]; then C='\033[36m'; G='\033[32m'; R='\033[31m'; D='\033[2m'; N='\033[0m'; else C=; G=; R=; D=; N=; fi
say()  { printf "  %b\n" "$*"; }
fail() { say "${R}✖${N} $*"; exit 1; }

if [ "$1" = "--uninstall" ]; then
    rm -f "$BIN/getip"
    rm -rf "$DATA"
    rm -rf "$HOME/.config/getip"
    say "${G}✔${N} getip удалён"
    exit 0
fi

printf "\n"
say "${C}┌─┐┌─┐┌┬┐┬┌─┐${N}"
say "${C}│ ┬├┤  │ │├─┘${N}  установка"
say "${C}└─┘└─┘ ┴ ┴┴  ${N}"
printf "\n"

case "$(uname -s)" in
    Darwin|Linux) ;;
    *) fail "getip работает на macOS и Linux" ;;
esac

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys' >/dev/null 2>&1; then
    if [ "$(uname -s)" = "Darwin" ]; then
        fail "Нужен Python 3. Выполните ${C}xcode-select --install${N}, затем запустите установку снова."
    fi
    fail "Нужен Python 3. Установите его (например, ${C}sudo apt install python3${N}) и запустите установку снова."
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
    || fail "Нужен Python 3.9 или новее, у вас $(python3 -V 2>&1)"

# Код берём из склонированного репозитория (запуск ./install.sh) или архивом с GitHub
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
script_dir=""
# при `curl … | sh` $0 — это «sh», а не файл; локальную копию берём только при запуске ./install.sh
if [ -f "$0" ] && [ "${0##*/}" = "install.sh" ]; then script_dir="$(cd "$(dirname "$0")" && pwd)"; fi
if [ -n "$script_dir" ] && [ -f "$script_dir/src/getip/__init__.py" ] && [ -z "$GETIP_FORCE_DOWNLOAD" ]; then
    src="$script_dir"
else
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$ARCHIVE" -o "$tmp/getip.tar.gz" || fail "Не удалось скачать $ARCHIVE"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tmp/getip.tar.gz" "$ARCHIVE" || fail "Не удалось скачать $ARCHIVE"
    else
        fail "Нужен curl или wget"
    fi
    tar -xzf "$tmp/getip.tar.gz" -C "$tmp" || fail "Скачанный архив повреждён, попробуйте ещё раз"
    src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
fi
[ -f "$src/getip.py" ] && [ -f "$src/src/getip/__init__.py" ] \
    && python3 -c "import ast, pathlib, sys
files = [pathlib.Path(sys.argv[1])] + sorted(pathlib.Path(sys.argv[2]).rglob('*.py'))
for f in files: ast.parse(f.read_text(encoding='utf-8'))" "$src/getip.py" "$src/src/getip" \
    || fail "Скачанные файлы повреждены, попробуйте ещё раз"

# Пакет собираем рядом и подменяем переименованием, чтобы старый и новый код не смешались
mkdir -p "$BIN" "$(dirname "$DATA")"
rm -rf "$DATA.new" "$DATA.old"
mkdir -p "$DATA.new"
cp -R "$src/src/getip" "$DATA.new/getip"
find "$DATA.new" -name __pycache__ -type d -prune -exec rm -rf {} +
if [ -d "$DATA" ]; then mv "$DATA" "$DATA.old"; fi
mv "$DATA.new" "$DATA"
rm -rf "$DATA.old"

cp "$src/getip.py" "$BIN/getip.new"
chmod 755 "$BIN/getip.new"
mv -f "$BIN/getip.new" "$BIN/getip"
say "${G}✔${N} getip $("$BIN/getip" --version | cut -d' ' -f2) установлен в ${D}$BIN/getip${N}"

# Добавляем ~/.local/bin в PATH, если его там нет
case ":$PATH:" in
    *":$BIN:"*) ready=1 ;;
    *)
        ready=0
        case "${SHELL##*/}" in
            zsh)  rc="$HOME/.zshrc" ;;
            bash) if [ "$(uname -s)" = "Darwin" ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
            *)    rc="$HOME/.profile" ;;
        esac
        if [ "$BIN" = "$HOME/.local/bin" ] && ! grep -qs '.local/bin' "$rc"; then
            printf '\n# getip\n%s\n' "$PATH_LINE" >> "$rc"
            say "${G}✔${N} Папка ${D}$BIN${N} добавлена в PATH (${D}$rc${N})"
        fi
        ;;
esac

printf "\n"
if [ "$ready" = 1 ]; then
    say "Готово! Запустите: ${C}getip${N}"
else
    say "Готово! Откройте новое окно терминала и запустите: ${C}getip${N}"
fi
printf "\n"
