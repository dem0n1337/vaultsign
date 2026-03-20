#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing VaultSign..."

# Create symlink in /usr/local/bin
ln -sf "$SCRIPT_DIR/vaultsign" /usr/local/bin/vaultsign
echo "  Created symlink /usr/local/bin/vaultsign -> $SCRIPT_DIR/vaultsign"

# Copy desktop file to applications directory
cp "$SCRIPT_DIR/vaultsign.desktop" /usr/share/applications/vaultsign.desktop
echo "  Installed desktop file to /usr/share/applications/vaultsign.desktop"

echo "VaultSign installed successfully."
