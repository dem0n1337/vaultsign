#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_INSTALL_DIR="/opt/vaultsign"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use: sudo bash install.sh)"
    exit 1
fi

# --- Uninstall ---
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
    INSTALL_DIR="${2:-${DEFAULT_INSTALL_DIR}}"
    INSTALL_DIR="$(realpath -m "${INSTALL_DIR}")"

    echo "Uninstalling VaultSign..."

    rm -f /usr/local/bin/vaultsign
    echo "  Removed /usr/local/bin/vaultsign"

    rm -f /usr/share/applications/vaultsign.desktop
    echo "  Removed desktop file"

    for size in 16 24 32 48 64 128 256 512; do
        rm -f "/usr/share/icons/hicolor/${size}x${size}/apps/vaultsign.png"
    done
    rm -f /usr/share/icons/hicolor/scalable/apps/vaultsign.svg
    gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
    echo "  Removed icons"

    rm -f /usr/share/man/man1/vaultsign.1.gz
    echo "  Removed man page"

    if [ -d "${INSTALL_DIR}" ]; then
        rm -rf "${INSTALL_DIR}"
        echo "  Removed ${INSTALL_DIR}"
    fi

    echo ""
    echo "VaultSign uninstalled."
    echo "User config (~/.config/vaultsign) was NOT removed."
    echo "To remove it: rm -rf ~/.config/vaultsign"
    exit 0
fi

# --- Install ---

# Support --path flag for non-interactive installs
if [ "${1:-}" = "--path" ] || [ "${1:-}" = "-p" ]; then
    INSTALL_DIR="${2:-${DEFAULT_INSTALL_DIR}}"
else
    echo "VaultSign Installer"
    echo "==================="
    echo ""
    echo "Where would you like to install VaultSign?"
    echo ""
    echo "  1) ${DEFAULT_INSTALL_DIR} (default)"
    echo "  2) Custom path"
    echo ""
    read -rp "Choose [1/2] (default: 1): " choice

    case "${choice}" in
        2)
            read -rp "Enter installation path: " custom_path
            INSTALL_DIR="${custom_path}"
            ;;
        *)
            INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
            ;;
    esac
fi

# Resolve to absolute path
INSTALL_DIR="$(realpath -m "${INSTALL_DIR}")"

echo ""
echo "Installing VaultSign to ${INSTALL_DIR}..."

# Create install directory and copy application files
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/vaultsign_gui.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/vault_backend.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/config.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/cert_utils.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/tray.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/tray_helper.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/updater.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/logger.py" "${INSTALL_DIR}/"
echo "  Copied application files to ${INSTALL_DIR}/"

# Copy icons directory
mkdir -p "${INSTALL_DIR}/icons"
cp "${SCRIPT_DIR}"/icons/* "${INSTALL_DIR}/icons/"
echo "  Copied icons to ${INSTALL_DIR}/icons/"

# Generate entry script with correct path
cat > "${INSTALL_DIR}/vaultsign" <<ENTRY
#!/bin/bash
exec /usr/bin/python3 "${INSTALL_DIR}/vaultsign_gui.py" "\$@"
ENTRY
chmod +x "${INSTALL_DIR}/vaultsign"
echo "  Generated entry script ${INSTALL_DIR}/vaultsign"

# Create symlink in /usr/local/bin
ln -sf "${INSTALL_DIR}/vaultsign" /usr/local/bin/vaultsign
echo "  Created symlink /usr/local/bin/vaultsign -> ${INSTALL_DIR}/vaultsign"

# Generate and install desktop file with correct Exec path
cat > /usr/share/applications/vaultsign.desktop <<DESKTOP
[Desktop Entry]
Name=VaultSign
Comment=HashiCorp Vault & OpenBao OIDC Authentication & SSH Key Signing
Exec=${INSTALL_DIR}/vaultsign
Icon=vaultsign
Terminal=false
Type=Application
Categories=Utility;Security;
Keywords=vault;ssh;authentication;oidc;openbao;
DESKTOP
echo "  Installed desktop file to /usr/share/applications/vaultsign.desktop"

# Install icons at all sizes
for size in 16 24 32 48 64 128 256 512; do
    icon_dir="/usr/share/icons/hicolor/${size}x${size}/apps"
    icon_file="${SCRIPT_DIR}/icons/vaultsign-${size}.png"
    if [ -f "${icon_file}" ]; then
        mkdir -p "$icon_dir"
        cp "${icon_file}" "$icon_dir/vaultsign.png"
    fi
done
echo "  Installed icons (16-512px) to /usr/share/icons/hicolor/"

# Install SVG as scalable fallback
mkdir -p /usr/share/icons/hicolor/scalable/apps
cp "${SCRIPT_DIR}/icons/vaultsign.svg" /usr/share/icons/hicolor/scalable/apps/vaultsign.svg
echo "  Installed scalable icon"

# Update icon cache
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

# Install man page
if [ -f "${SCRIPT_DIR}/vaultsign.1" ]; then
    mkdir -p /usr/share/man/man1
    cp "${SCRIPT_DIR}/vaultsign.1" /usr/share/man/man1/vaultsign.1
    gzip -f /usr/share/man/man1/vaultsign.1
    echo "  Installed man page (man vaultsign)"
fi

echo ""
echo "VaultSign installed successfully to ${INSTALL_DIR}"
echo "Run 'vaultsign' to start the application."
echo ""
echo "To uninstall: sudo bash install.sh --uninstall"
