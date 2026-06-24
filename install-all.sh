#!/bin/bash
#--------------------------------------------------------
# 1-click installer: core SSH+WS system + Web panel
#--------------------------------------------------------
set -e
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[[ "$EUID" -ne 0 ]] && { echo -e "${RED}[x] root user နဲ့ run ပါ${NC}"; exit 1; }

REPO="raw.githubusercontent.com/Shangyi69/ssh-ws/main"

WS_PORT="${1:-}"
PANEL_PORT="${2:-}"

if [[ -z "$WS_PORT" ]]; then
    read -rp "WebSocket port ဘယ်ဟာသုံးမလဲ (e.g. 80): " WS_PORT
fi
[[ -z "$WS_PORT" ]] && WS_PORT=80

if [[ -z "$PANEL_PORT" ]]; then
    read -rp "Web panel port (default 2053, Enter ဖိရင် default): " PANEL_PORT
fi
[[ -z "$PANEL_PORT" ]] && PANEL_PORT=2053

echo -e "${YELLOW}[1/2] Core SSH+WS system install (port ${WS_PORT})...${NC}"
bash <(wget -qO- "${REPO}/install.sh") "$WS_PORT"

echo -e "${YELLOW}[2/2] Web panel install (port ${PANEL_PORT})...${NC}"
bash <(wget -qO- "${REPO}/install-panel.sh") "$PANEL_PORT"

IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  အားလုံး Install ပြီးပါပြီ!${NC}"
echo -e "${GREEN}  WS port    : ${WS_PORT}${NC}"
echo -e "${GREEN}  Panel URL  : http://${IP}:${PANEL_PORT}${NC}"
echo -e "${GREEN}  Panel login: admin / admin123 (ချက်ချင်းပြောင်းပါ)${NC}"
echo -e "${GREEN}  CLI menu   : menu${NC}"
echo -e "${GREEN}=========================================${NC}"
