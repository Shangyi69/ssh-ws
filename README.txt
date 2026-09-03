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
STEP 3 — UDP Custom install (manual)
-----------------------------------------
  mkdir -p /root/udp
  cp /root/ssh-ws-setup/udp-custom/udp-custom     /root/udp/udp-custom
  cp /root/ssh-ws-setup/udp-custom/config.json    /root/udp/config.json
  chmod +x /root/udp/udp-custom          <-- IMPORTANT, အောက်က note ကြည့်ပါ

  cp /root/ssh-ws-setup/udp-custom/udp-custom.service /etc/systemd/system/udp-custom.service
  systemctl daemon-reload
  systemctl enable --now udp-custom.service
  systemctl status udp-custom.service      (active (running) ဆိုရင် OK)

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
