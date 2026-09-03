=========================================
 SSH-WS + UDP Custom — Setup Guide (VPS)
=========================================

folder ၂ ခု ပါပါတယ်:
  ssh-ws/       -> SSH+WebSocket server + Web Panel
  udp-custom/   -> UDP Custom (binary + config + service)

-----------------------------------------
STEP 1 — VPS ပေါ်ကို file အားလုံး upload
-----------------------------------------
ဒီ folder (ssh-ws-setup) တစ်ခုလုံးကို FileZilla/WinSCP နဲ့
VPS ရဲ့ /root/ ထဲ upload လုပ်ပါ။
(VPS ကို root user နဲ့ SSH ဝင်ပြီး လုပ်ပါ)

-----------------------------------------
STEP 2 — SSH-WS + Panel install
-----------------------------------------
VPS terminal မှာ ဒီအတိုင်း run ပါ:

  cd /root/ssh-ws-setup/ssh-ws
  chmod +x install.sh install-panel.sh
  bash install.sh 8880 443 7300
  bash install-panel.sh 2053

  ("8880" = WS port, "443" = SSL port, "7300" = UDPGW port,
   "2053" = Panel port — ပြောင်းလိုချင်ရင် ကိုယ်တိုင် ပြောင်းလို့ရ)

Install ပြီးရင် "menu" လို့ ရိုက်ပြီး user account create လုပ်ပါ
(option 1 ကို ရွေးပါ)

-----------------------------------------
STEP 3 — UDP Custom install (manual)
-----------------------------------------
  mkdir -p /root/udp
  cp /root/ssh-ws-setup/udp-custom/udp-custom /root/udp/udp-custom
  cp /root/ssh-ws-setup/udp-custom/config.json /root/udp/config.json
  chmod +x /root/udp/udp-custom

  cp /root/ssh-ws-setup/udp-custom/udp-custom.service /etc/systemd/system/udp-custom.service
  systemctl daemon-reload
  systemctl enable --now udp-custom.service

  systemctl status udp-custom.service
  (ဒီနေရာမှာ "active (running)" စာလုံးစိမ်းစိမ်းကို တွေ့ရင် အောင်မြင်ပါပြီ)

-----------------------------------------
STEP 4 — status ပြန်စစ်ချင်ရင်
-----------------------------------------
  menu
  -> option 10 ရွေးပါ (udp-custom.service Status)

-----------------------------------------
Client app (HTTP Custom) setup
-----------------------------------------
  Server IP   : (VPS ရဲ့ IP)
  SSH User/Pass : menu ကနေ create လုပ်ထားတဲ့ user
  UDP method  : zip ထဲက config.json အတိုင်း (port 36712)

-----------------------------------------
Error တက်ရင်
-----------------------------------------
  journalctl -u udp-custom -n 50 --no-pager
  ဒီ command ရဲ့ output ကို ကူးပြီး ပြန်မေးနိုင်ပါတယ်
