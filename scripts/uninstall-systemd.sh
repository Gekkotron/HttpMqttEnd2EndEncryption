#!/usr/bin/env bash
# Uninstall the systemd service+timer installed by install-systemd.sh.
#
# Usage:  sudo scripts/uninstall-systemd.sh
#
# Stops and disables the timer + service, removes the unit files from
# /etc/systemd/system, wipes any drop-in override directories, and reloads
# systemd. Journal logs are kept — clear them yourself with
# `journalctl --rotate && journalctl --vacuum-time=1s` if you want them gone.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs sudo (writes to /etc/systemd/system/)." >&2
    exit 1
fi

DEST_DIR="/etc/systemd/system"
SERVICE_NAME="encryption-gateway-health.service"
TIMER_NAME="encryption-gateway-health.timer"

echo "Uninstalling encryption-gateway-health service+timer from $DEST_DIR"

# Stop + disable the timer first so it can't re-trigger the service mid-uninstall.
for unit in "$TIMER_NAME" "$SERVICE_NAME"; do
    if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        systemctl disable --now "$unit" 2>/dev/null || true
        systemctl stop "$unit" 2>/dev/null || true
    fi
done

# Remove unit files + drop-in override directories.
removed_any=0
for f in "$SERVICE_NAME" "$TIMER_NAME"; do
    if [[ -f "$DEST_DIR/$f" ]]; then
        rm -f "$DEST_DIR/$f"
        echo "  removed $DEST_DIR/$f"
        removed_any=1
    fi
    if [[ -d "$DEST_DIR/$f.d" ]]; then
        rm -rf "$DEST_DIR/$f.d"
        echo "  removed $DEST_DIR/$f.d/"
        removed_any=1
    fi
done

systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" "$TIMER_NAME" 2>/dev/null || true

if [[ $removed_any -eq 0 ]]; then
    echo "Nothing to remove — units were not installed."
else
    echo
    echo "Done. Verify with:"
    echo "  systemctl status $TIMER_NAME    # should say 'not-found'"
    echo "  systemctl status $SERVICE_NAME  # should say 'not-found'"
fi
