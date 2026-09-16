#!/bin/bash
# install-udp-proxy.sh
# UDP Auth Proxy ထည့်သွင်းခြင်း
# udp-custom ကို internal port 36713 သို့ ရွှေ့
# proxy က port 36712 မှာ SSH auth စစ်ပြီး forward လုပ်မည်

set -e
GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# 1) paramiko ထည့်
echo -e "${YELLOW}[*] paramiko install...${NC}"
pip install paramiko -q --break-system-packages 2>/dev/null || \
pip3 install paramiko -q --break-system-packages 2>/dev/null || true

# 2) proxy script ကူး
echo -e "${YELLOW}[*] proxy script ကူး...${NC}"
mkdir -p /root/udp
cp "$(dirname "$0")/udp-auth-proxy.py" /root/udp/udp-auth-proxy.py
chmod +x /root/udp/udp-auth-proxy.py

# 3) udp-custom ကို port 36713 (internal) သို့ ပြောင်း
echo -e "${YELLOW}[*] udp-custom config → port 36713 (internal)...${NC}"
cat > /root/udp/config.json << 'CFGEOF'
{
  "listen": "127.0.0.1:36713",
  "stream_buffer": 4194304,
  "receive_buffer": 8388608,
  "auth": {
    "mode": "none"
  }
}
CFGEOF

# 4) udp-custom service update
cat > /etc/systemd/system/udp-custom.service << 'SVCEOF'
[Unit]
Description=UDP Custom Core (internal :36713)
After=network.target

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
SVCEOF

# 5) udp-auth-proxy service
cat > /etc/systemd/system/udp-auth-proxy.service << 'SVCEOF'
[Unit]
Description=UDP Auth Proxy (SSH auth → udp-custom)
After=network.target udp-custom.service

[Service]
User=root
Type=simple
Environment=UDP_PROXY_PORT=36712
Environment=UDP_BACKEND_PORT=36713
ExecStart=/usr/bin/python3 /root/udp/udp-auth-proxy.py
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
SVCEOF

# 6) reload + start
echo -e "${YELLOW}[*] services restart...${NC}"
systemctl daemon-reload
systemctl restart udp-custom
systemctl enable --now udp-auth-proxy
systemctl restart udp-auth-proxy

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  UDP Auth Proxy ပြီးပါပြီ${NC}"
echo -e "${GREEN}  Proxy  : :36712 (SSH auth စစ်)${NC}"
echo -e "${GREEN}  Backend: :36713 (internal only)${NC}"
echo -e "${GREEN}  Auth   : SSH username + password${NC}"
echo -e "${GREEN}=========================================${NC}"
