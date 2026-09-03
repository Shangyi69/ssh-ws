=========================================
 SSH-WS + UDP Custom — Setup Guide (VPS)
=========================================

folder ၂ ခု ပါပါတယ်:
  ssh-ws/       -> SSH+WebSocket server + Web Panel
  udp-custom/   -> UDP Custom (binary + config + service, ePro Dev Team)

-----------------------------------------
STEP 1 — VPS ပေါ်ကို upload
-----------------------------------------
ဒီ folder (ssh-ws-setup) တစ်ခုလုံးကို zip ချုပ်ပြီး FileZilla/WinSCP
(သို့) hosting provider ရဲ့ File Manager နဲ့ VPS ရဲ့ /root/ ထဲ upload လုပ်ပါ။

  cd /root
  unzip ssh-ws-setup.zip

-----------------------------------------
STEP 2 — SSH-WS + Panel install
-----------------------------------------
  cd /root/ssh-ws-setup/ssh-ws
  chmod +x install.sh install-panel.sh
  bash install.sh 8880 443 7300
  bash install-panel.sh 2053

  (8880=WS port, 443=SSL port, 7300=UDPGW port(badvpn, optional),
   2053=Panel port)

Install ပြီးရင် "menu" ရိုက်ပြီး user create လုပ်ပါ (option 1)

-----------------------------------------
STEP 3 — UDP Custom install
-----------------------------------------
NOTE: install-all.sh / install.sh only sets up SSH-WS + optional
badvpn-udpgw (menu option 9). The genuine ePro udp-custom binary
(menu option 10) is ALWAYS a separate step — it does not get installed
automatically by install-all.sh, even if you passed a 4th port argument.

  cd /root/ssh-ws-setup/udp-custom
  bash install-udp-custom.sh

  (ဒါက ဒီ folder ထဲက udp-custom/config.json/udp-custom.service ကို
   /root/udp/ ထဲ copy လုပ်ပြီး chmod +x + systemd service အောင်မြင်စွာ
   start လုပ်ပေးပါလိမ့်မယ် — internet ကနေ ဘာမှ download မလုပ်ပါ)

  Alternative — if working directly on the VPS from the GitHub repo
  instead of this local zip:
    mkdir -p /root/udp
    wget -O /root/udp/udp-custom  https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/udp-custom
    wget -O /root/udp/config.json https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/config.json
    wget -O /etc/systemd/system/udp-custom.service https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/udp-custom.service
    chmod +x /root/udp/udp-custom
    systemctl daemon-reload
    systemctl enable --now udp-custom.service

-----------------------------------------
STEP 4 — status ပြန်စစ်ချင်ရင်
-----------------------------------------
  menu
  -> option 10 (udp-custom.service Status)

-----------------------------------------
Client app (HTTP Custom) setup
-----------------------------------------
  Method       : UDP Custom
  Server       : <VPS IP>
  Port         : 36712   (config.json ရဲ့ "listen" value)
  Username/Pass: menu ကနေ create ထားတဲ့ SSH user (option 1)

  Note: "1-65535" ဆိုတဲ့ port range ကို config.json ထဲ ထည့်စရာ မလိုပါ —
  listen port (36712) ချည်းသာ တကယ်အလုပ်လုပ်ပါတယ်။

-----------------------------------------
Error တက်ရင်
-----------------------------------------
  journalctl -u udp-custom -n 50 --no-pager
  journalctl -u udp-custom -f              (live log, connect လုပ်နေတုန်း)

  ဒီ output တွေကို ကူးပြီး TROUBLESHOOTING.md ထဲက pattern တွေနဲ့
  တိုက်ဆိုင်ကြည့်ပါ။
