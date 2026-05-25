#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DST="/usr/local/bin/vaultsign"
DESKTOP_DST="/usr/share/applications/io.github.dem0n1337.vaultsign.desktop"
ICON_DST="/usr/share/icons/hicolor/scalable/apps/vaultsign.svg"
METAINFO_DST="/usr/share/metainfo/io.github.dem0n1337.vaultsign.metainfo.xml"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use: sudo bash install.sh)"
    exit 1
fi

# --- Uninstall ---
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
    echo "Uninstalling VaultSign..."
    rm -f "$BIN_DST" "$DESKTOP_DST" "$ICON_DST" "$METAINFO_DST"
    rm -f /usr/share/man/man1/vaultsign.1.gz
    for size in 16 24 32 48 64 128 256 512; do
        rm -f "/usr/share/icons/hicolor/${size}x${size}/apps/vaultsign.png"
    done
    gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
    echo "Done. (per-user config in ~/.config/vaultsign left intact)"
    exit 0
fi

# --- Build if no prebuilt binary present ---
BIN_SRC="${SCRIPT_DIR}/build/bin/vaultsign"
if [ ! -x "$BIN_SRC" ]; then
    echo "No prebuilt binary at ${BIN_SRC}; building with Wails..."
    command -v wails >/dev/null 2>&1 || {
        echo "Error: 'wails' CLI not found. Install it with:"
        echo "  go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        exit 1
    }
    ( cd "$SCRIPT_DIR" && wails build -tags webkit2_41 -clean )
fi

echo "Installing VaultSign..."
install -Dm755 "$BIN_SRC" "$BIN_DST"
install -Dm644 "${SCRIPT_DIR}/vaultsign.desktop" "$DESKTOP_DST"
install -Dm644 "${SCRIPT_DIR}/icons/vaultsign.svg" "$ICON_DST"
install -Dm644 "${SCRIPT_DIR}/packaging/io.github.dem0n1337.vaultsign.metainfo.xml" "$METAINFO_DST"
[ -f "${SCRIPT_DIR}/vaultsign.1" ] && install -Dm644 "${SCRIPT_DIR}/vaultsign.1" /usr/share/man/man1/vaultsign.1
for size in 16 24 32 48 64 128 256 512; do
    src="${SCRIPT_DIR}/icons/vaultsign-${size}.png"
    [ -f "$src" ] && install -Dm644 "$src" "/usr/share/icons/hicolor/${size}x${size}/apps/vaultsign.png"
done
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

echo "Installed: $BIN_DST"
echo "Run 'vaultsign' or launch it from your application menu."
