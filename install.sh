#!/bin/sh
# Установщик getip.
#   Установить или обновить:  curl -fsSL https://raw.githubusercontent.com/MoteoDimassi/getip/main/install.sh | sh
#   Удалить:                  curl -fsSL https://raw.githubusercontent.com/MoteoDimassi/getip/main/install.sh | sh -s -- --uninstall
set -e

REPO="${GETIP_REPO:-MoteoDimassi/getip}"
BRANCH="${GETIP_BRANCH:-main}"
URL="https://raw.githubusercontent.com/$REPO/$BRANCH/getip.py"
BIN="${GETIP_BIN:-$HOME/.local/bin}"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

if [ -t 1 ]; then C='\033[36m'; G='\033[32m'; R='\033[31m'; D='\033[2m'; N='\033[0m'; else C=; G=; R=; D=; N=; fi
say()  { printf "  %b\n" "$*"; }
fail() { say "${R}✖${N} $*"; exit 1; }

if [ "$1" = "--uninstall" ]; then
    rm -f "$BIN/getip"
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

# Скачиваем во временный файл и ставим, только если загрузка прошла целиком
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
script_dir=""
# при `curl … | sh` $0 — это «sh», а не файл; локальную копию берём только при запуске ./install.sh
if [ -f "$0" ] && [ "${0##*/}" = "install.sh" ]; then script_dir="$(cd "$(dirname "$0")" && pwd)"; fi
if [ -n "$script_dir" ] && [ -f "$script_dir/getip.py" ] && [ -z "$GETIP_FORCE_DOWNLOAD" ]; then
    cp "$script_dir/getip.py" "$tmp"          # запуск из склонированного репозитория
elif command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$tmp" || fail "Не удалось скачать $URL"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp" "$URL" || fail "Не удалось скачать $URL"
else
    fail "Нужен curl или wget"
fi
grep -q "getip" "$tmp" && python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$tmp" \
    || fail "Скачанный файл повреждён, попробуйте ещё раз"

mkdir -p "$BIN"
mv "$tmp" "$BIN/getip"
chmod 755 "$BIN/getip"
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
