#!/bin/bash
# install-all.sh — one-shot installer for SSH-WS + Web Panel
#
# Usage:
#   bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) <WS_PORT> <PANEL_PORT> <SSL_PORT>
#
# Example:
#   bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) 80 2053 443
#
# $1 = WebSocket port for the SSH-WS service (default: 8880)
# $2 = Port for the Web Panel (default: 2053)
# $3 = SSH+SSL (stunnel/TLS) port (default: none — skips SSL setup if blank)

set -e

REPO_BASE="https://raw.githubusercontent.com/Shangyi69/ssh-ws/main"
WS_PORT="${1:-8880}"
PANEL_PORT="${2:-2053}"
SSL_PORT="${3:-}"

GREEN='\033[1;32m'; CYAN='\033[1;36m'; NC='\033[0m'

echo -e "${CYAN}[*] Step 1/2 — Installing SSH-WS service on port ${WS_PORT}...${NC}"
bash <(wget -qO- "${REPO_BASE}/install.sh") "${WS_PORT}" "${SSL_PORT}"

echo -e "${CYAN}[*] Step 2/2 — Installing Web Panel on port ${PANEL_PORT}...${NC}"
bash <(wget -qO- "${REPO_BASE}/install-panel.sh") "${PANEL_PORT}"

echo -e "${GREEN}[+] All done. SSH-WS + Web Panel installed successfully.${NC}"
