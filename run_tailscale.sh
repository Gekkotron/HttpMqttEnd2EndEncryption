#!/bin/bash
# This script exposes your Python end-to-end encryption server (running on port 10000)
# to the public internet using Tailscale Funnel.
#
# Prerequisites:
# - Tailscale must be installed and authenticated on this machine.
# - Funnel must be enabled for your Tailscale account.
# - Your Python server (e.g., server.py) must be running and listening on port 10000.
#
# Usage:
#   1. Start your Python server: python3 server.py
#   2. Run this script: ./run_tailscale.sh
#   3. The public HTTPS URL will be shown in the output of 'tailscale funnel list'.

tailscale funnel 10000 -bg