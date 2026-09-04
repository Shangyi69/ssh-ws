# SSH-WS + UDP Custom Panel

## ဖိုင်များ

| File | ရှင်းလင်းချက် |
|------|--------------|
| `install.sh` | SSH+WebSocket main install |
| `install-panel.sh` | Web panel install (UDP integrated) |
| `install-all.sh` | install.sh + install-panel.sh တွဲ run |
| `udp/udp-custom-linux-amd64` | UDP Custom binary |
| `udp/config.json` | UDP default config |

## Install အဆင့်

```bash
# 1) SSH+WS core install
bash install.sh

# 2) Panel install (UDP Custom ပါ တွဲထည့်)
bash install-panel.sh
```

သို့မဟုတ် တစ်ကြိမ်တည်း:
```bash
bash install-all.sh
```

## Panel ကနေ UDP Control

- Dashboard → **UDP Custom** section → start/stop, port ပြောင်း
- User card → **UDP ထည့်** → ထို user ရဲ့ SSH password ကို UDP passwords[] ထဲ ထည့်
- User card → **UDP ဖျက်** → UDP passwords[] ထဲ ဖျက်

## UDP Client Config

```
Host: <server-ip>
Port: 36712 (default)
Auth: username:password  (SSH user/pass နဲ့ တူညီ)
```
