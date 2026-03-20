#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use: sudo bash install.sh)"
    exit 1
fi

echo "Installing VaultSign..."

# Create symlink in /usr/local/bin
ln -sf "$SCRIPT_DIR/vaultsign" /usr/local/bin/vaultsign
echo "  Created symlink /usr/local/bin/vaultsign -> $SCRIPT_DIR/vaultsign"

# Copy desktop file to applications directory
cp "$SCRIPT_DIR/vaultsign.desktop" /usr/share/applications/vaultsign.desktop
echo "  Installed desktop file to /usr/share/applications/vaultsign.desktop"

# Install icon
mkdir -p /usr/share/icons/hicolor/scalable/apps
cp "$SCRIPT_DIR/icons/vaultsign.svg" /usr/share/icons/hicolor/scalable/apps/vaultsign.svg
echo "  Installed icon to /usr/share/icons/hicolor/scalable/apps/vaultsign.svg"

# Update icon cache
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

echo "VaultSign installed successfully."
