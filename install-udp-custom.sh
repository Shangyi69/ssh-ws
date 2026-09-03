#!/bin/bash
#--------------------------------------------------------
# install-udp-custom.sh
#
# Installs the udp-custom binary + config that are already sitting in
# THIS folder (same directory as this script) into /root/udp/ and wires
# up the systemd service. Does NOT download anything from the internet —
# it only operates on files you already have locally.
#
# Usage (run from inside the udp-custom/ folder):
#   bash install-udp-custom.sh
#--------------------------------------------------------
set -e

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'

[[ "$EUID" -ne 0 ]] && { echo -e "${RED}[x] root user နဲ့ run ပါ (sudo bash install-udp-custom.sh)${NC}"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- sanity checks on the local files before touching anything ----
for f in udp-custom config.json udp-custom.service; do
    if [[ ! -f "$SCRIPT_DIR/$f" ]]; then
        echo -e "${RED}[x] $f ကို ဒီ folder ထဲမှာ မတွေ့ပါ (${SCRIPT_DIR})${NC}"
        echo -e "${RED}    zip ထဲက udp-custom/ folder အတိုင်း run ထားလား ပြန်စစ်ပါ${NC}"
        exit 1
    fi
done

if ! file "$SCRIPT_DIR/udp-custom" | grep -q "ELF"; then
    echo -e "${RED}[x] udp-custom file က valid ELF binary မဟုတ်ပါ — download/copy အထပ်ထပ် ပျက်နေနိုင်ပါတယ်${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] /root/udp/ ထဲ install လုပ်နေသည်...${NC}"
mkdir -p /root/udp
cp "$SCRIPT_DIR/udp-custom"  /root/udp/udp-custom
cp "$SCRIPT_DIR/config.json" /root/udp/config.json
chmod +x /root/udp/udp-custom

# permission sanity check — this exact bug (missing +x -> 203/EXEC) was
# hit during real deployment, see TROUBLESHOOTING.md item #2
if [[ ! -x /root/udp/udp-custom ]]; then
    echo -e "${RED}[x] chmod +x မအောင်မြင်ပါ — filesystem noexec mount ဖြစ်နိုင်ပါတယ်${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] systemd service ရေးနေသည်...${NC}"
cp "$SCRIPT_DIR/udp-custom.service" /etc/systemd/system/udp-custom.service

systemctl daemon-reload
systemctl enable --now udp-custom.service

sleep 2
if systemctl is-active --quiet udp-custom.service; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  UDP Custom install ပြီးပါပြီ!${NC}"
    LISTEN_PORT=$(grep -oP '(?<="listen": ":)\d+' /root/udp/config.json 2>/dev/null || echo "?")
    echo -e "${GREEN}  Port : ${LISTEN_PORT}${NC}"
    echo -e "${GREEN}  Status : active (running)${NC}"
    echo -e "${GREEN}  User account : SSH-WS menu (option 1) ကနေ create ထားတဲ့ account ကို ပဲသုံးပါ${NC}"
    echo -e "${GREEN}=========================================${NC}"
else
    echo -e "${RED}[!] service start မအောင်မြင်ပါ — log ကြည့်ပါ:${NC}"
    echo "    journalctl -u udp-custom -n 50 --no-pager"
    exit 1
fi
