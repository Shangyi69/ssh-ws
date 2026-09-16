#!/bin/bash
# install-all.sh
# Usage: bash install-all.sh <WS_PORT> <PANEL_PORT>
# Example: bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) 80 2053

set -e
REPO_BASE="https://raw.githubusercontent.com/Shangyi69/ssh-ws/main"
WS_PORT="${1:-8880}"
PANEL_PORT="${2:-2053}"
SSL_PORT="${3:-}"

GREEN='\033[1;32m'; CYAN='\033[1;36m'; NC='\033[0m'

echo -e "${CYAN}[1/3] SSH-WS (port ${WS_PORT})...${NC}"
bash <(wget -qO- "${REPO_BASE}/install.sh") "${WS_PORT}" "${SSL_PORT}"

echo -e "${CYAN}[2/3] Web Panel (port ${PANEL_PORT})...${NC}"
bash <(wget -qO- "${REPO_BASE}/install-panel.sh") "${PANEL_PORT}"

echo -e "${CYAN}[3/3] UDP Auth Proxy...${NC}"
wget -qO /root/udp/udp-auth-proxy.py "${REPO_BASE}/udp-auth-proxy.py"
bash <(wget -qO- "${REPO_BASE}/install-udp-proxy.sh")

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  အကုန်ပြီးပါပြီ${NC}"
echo -e "${GREEN}  SSH+WS : port ${WS_PORT}${NC}"
echo -e "${GREEN}  Panel  : port ${PANEL_PORT}${NC}"
echo -e "${GREEN}  UDP    : port 36712 (SSH auth)${NC}"
echo -e "${GREEN}=========================================${NC}"
