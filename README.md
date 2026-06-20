# SSH + WebSocket Account Manager

## Install (VPS ပေါ်မှာ root နဲ့ run ပါ)

```bash
chmod +x install.sh
./install.sh 8880
```
(`8880` ကို မိမိချိတ်ဆက်ချင်တဲ့ custom port နဲ့ အလိုအလျောက် ပြောင်းပါ။ run ရင် port မထည့်ထားရင် prompt က မေးပါမယ်)

Install ပြီးရင်:
- SSH ကို port 22 အတွင်းပိုင်းမှာ ဆက်ထားပြီး `ws-proxy.py` က သင်ရွေးထားတဲ့ port ပေါ်မှာ WebSocket handshake ခံပြီး SSH traffic ကို forward ပေးပါတယ်။ Client app (HTTP Injector/NPV/KPN Tunnel စသည်) ထဲမှာ SSH Host=server IP, SSH Port=22, Payload/WS Port=ရွေးထားတဲ့ custom port နဲ့ setup လုပ်ပါ။
- `ws-proxy.service` နဲ့ `ws-limiter.service` ဆိုတဲ့ systemd service နှစ်ခု run နေပါမယ် (boot တိုင်း auto-start)။

## Daily use

```bash
menu
```

Menu ထဲမှာ:
1. Create User – username/password/သက်တမ်း/device limit ထည့်
2. Delete User
3. Renew User – သက်တမ်းတိုး
4. Check Online – user တစ်ယောက်စီ ဘယ်နှစ်ချိတ်ဆက်နေလဲ
5. Check Data Usage (GB) – user တစ်ယောက်စီ data သုံးထားတာ
6. Set/Check Device Limit
7/8. Banned IP list / Unban

## Device limit + auto-ban ဘယ်လိုအလုပ်လုပ်လဲ

- User account create တုန်းက limit (e.g. `1`) ထည့်ထားရင်, `ws-limiter.service` က 5 စက္ကန့်တစ်ခါ active session တွေကို scan လုပ်ပါတယ်။
- Limit ထက်ပိုပြီး ချိတ်ဆက်လာရင် (ဥပမာ device 2 ခုချိတ်ရင်) **အသစ်ဆုံးချိတ်ဆက်မှု**ကို kill လုပ်ပြီး ၄င်း device ရဲ့ real IP ကို `iptables DROP` နဲ့ ban လုပ်ပါတယ် (ပထမဆုံးချိတ်ထားတဲ့ device ကို မထိခိုက်ပါ)။
- Banned IP စာရင်းကို `/etc/ws-ssh/banned_ips.list` မှာ သိမ်းထားပြီး `menu` အောက်က option 8 နဲ့ unban လုပ်နိုင်ပါတယ်။

## သိထားရမှာများ (limitations)

- **Data usage (GB)** ကို `iptables owner` module နဲ့ user ရဲ့ **OUTPUT (server→client) traffic** ကိုသာ count ထားတာဖြစ်ပြီး, download+upload နှစ်ခုကို အတိအကျ ခွဲမတိုင်းတာနိုင်ပါ (နှစ်ဖက်စလုံး အတိအကျ လိုချင်ရင် `cgroup net_cls` based accounting လိုအပ်ပါမယ် — ပိုပြီး setup ရှုပ်ထွေးပါမယ်)။
- WebSocket handshake က "any request → 101" ဆိုတဲ့ ရိုးရှင်းတဲ့ fake-WS style ဖြစ်ပြီး, payload/header validation မလုပ်ပါ (client app အများစုနဲ့ အလုပ်လုပ်ပါမယ်)။
- Real client IP tracking က `ws-proxy.py` ရေးထားတဲ့ `/var/run/ws-ssh/active_conns.json` ကို sshd session (`ss -tnp`) နဲ့ port-correlate လုပ်ပြီး ရှာတာဖြစ်ပါတယ် — service ၂ခုလုံး run နေမှ အလုပ်လုပ်ပါမယ်။
- Firewall (ufw) active ထားရင် install script က ရွေးထားတဲ့ port ကို auto allow လုပ်ပေးပါတယ်; cloud provider ရဲ့ Security Group/Firewall ပေါ်မှာတော့ ကိုယ်တိုင် port ဖွင့်ပေးရပါမယ်။

## Service status / log

```bash
systemctl status ws-proxy
systemctl status ws-limiter
journalctl -u ws-limiter -f
```
