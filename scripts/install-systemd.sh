#!/usr/bin/env bash
# Install the systemd service+timer that runs the health check periodically.
#
# Usage:  sudo scripts/install-systemd.sh
#
# Uses the current working directory as the repo path, the invoking user as
# the service user (SUDO_USER when run via sudo), and the current $PYTHON_BIN
# (or a project ./.venv/bin/python if present) as the interpreter.
#
# Rerun this script after moving the repo or changing the interpreter — it
# rewrites the installed unit files.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs sudo (writes to /etc/systemd/system/)." >&2
    exit 1
fi

REPO_DIR="${REPO_DIR:-$(pwd)}"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$USER}}"

if [[ -x "$REPO_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="${PYTHON_BIN:-$REPO_DIR/.venv/bin/python}"
else
    PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
fi

TEMPLATE_DIR="$REPO_DIR/scripts/systemd"
DEST_DIR="/etc/systemd/system"
SERVICE_NAME="encryption-gateway-health.service"
TIMER_NAME="encryption-gateway-health.timer"

for f in "$SERVICE_NAME" "$TIMER_NAME"; do
    if [[ ! -f "$TEMPLATE_DIR/$f" ]]; then
        echo "Missing template: $TEMPLATE_DIR/$f" >&2
        exit 1
    fi
done

echo "Installing to $DEST_DIR"
echo "  REPO_DIR    = $REPO_DIR"
echo "  USER        = $SERVICE_USER"
echo "  PYTHON_BIN  = $PYTHON_BIN"

# Substitute placeholders and write to /etc/systemd/system.
for f in "$SERVICE_NAME" "$TIMER_NAME"; do
    sed \
        -e "s|{{REPO_DIR}}|$REPO_DIR|g" \
        -e "s|{{USER}}|$SERVICE_USER|g" \
        -e "s|{{PYTHON_BIN}}|$PYTHON_BIN|g" \
        "$TEMPLATE_DIR/$f" > "$DEST_DIR/$f"
done

systemctl daemon-reload
systemctl enable --now "$TIMER_NAME"

echo
echo "Installed. Useful commands:"
echo "  systemctl status $TIMER_NAME"
echo "  systemctl list-timers | grep encryption-gateway-health"
echo "  journalctl -u $SERVICE_NAME -f          # follow logs"
echo "  systemctl start $SERVICE_NAME           # trigger a run now"
echo "  systemctl disable --now $TIMER_NAME     # stop the periodic runs"
