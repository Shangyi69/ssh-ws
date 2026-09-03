# SSH-WS — SSH over WebSocket + Web Panel

A lightweight SSH-over-WebSocket tunneling service for Linux, with
per-user device limits, account expiry, a web dashboard for day-to-day
account management, and optional UDP Custom (UDPGW / ePro udp-custom)
support.

Dev: Phoe Shan

---

## 🚀 One-Click Install

Copy-paste this whole block into your VPS terminal (root):

```bash
# ---- SSH-WS + Web Panel ----
bash <(wget -qO- https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) 80 2053 443 7300

# ---- UDP Custom (genuine ePro binary — always a separate step) ----
mkdir -p /root/udp
wget -O /root/udp/udp-custom  https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/udp-custom
wget -O /root/udp/config.json https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/config.json
wget -O /etc/systemd/system/udp-custom.service https://raw.githubusercontent.com/Shangyi69/ssh-ws/main/udp-custom.service

chmod +x /root/udp/udp-custom
systemctl daemon-reload
systemctl enable --now udp-custom.service
systemctl status udp-custom.service
```

Arguments for `install-all.sh`: `<WS_PORT> <PANEL_PORT> <SSL_PORT> <UDPGW_PORT>`
— defaults: `8880 2053 443 7300` (edit the numbers above to change any of
them).

After both blocks finish, run `menu` to create your first user (option 1).

> ⚠️ **Important:** `install-all.sh` only installs SSH-WS + the web panel
> + optional `badvpn-udpgw` (`menu` option 9). The genuine ePro
> `udp-custom` binary (`menu` option 10) is **always** a separate step —
> it is never auto-installed by `install-all.sh`, even if you pass a 4th
> port argument to it. Run the second command block above explicitly.

---

## What's included

| File | Purpose |
|---|---|
| `install.sh` | Installs the WebSocket→SSH proxy (`ws-proxy.py`), the account manager (`menu`), the device-limit/expiry enforcer daemon (`limiter.sh`), and optionally `badvpn-udpgw`. |
| `install-panel.sh` | Installs the web dashboard (Flask app + systemd service) for managing accounts from a browser. |
| `install-all.sh` | Convenience wrapper — runs `install.sh` then `install-panel.sh` in one go. |
| `udp-custom` | Genuine ePro Dev Team UDP Custom binary — compatible with the HTTP Custom app's "UDP Custom" method. |
| `config.json` | Config for `udp-custom` (listen port, buffers, auth mode). |
| `udp-custom.service` | systemd unit for `udp-custom`. |
| `install-udp-custom.sh` | Local installer for `udp-custom` — copies files from the same folder into `/root/udp/`, sets permissions, and starts the service. Use this if you downloaded the repo as a zip instead of fetching files individually via `wget`. |

---

## Menu (`menu` command)

| Option | Action |
|---|---|
| 1 | Create User |
| 2 | Delete User |
| 3 | Renew User |
| 4 | User Info List |
| 5 | Check Online + IP List |
| 6 | Check Data Usage (GB) |
| 7 | Set/Check Device Limit |
| 8 | Kick User |
| 9 | UDP Custom (UDPGW/badvpn) Status/Restart |
| 10 | udp-custom.service Status (read-only) |

---

## Client app (HTTP Custom) setup

```
Method       : UDP Custom
Server       : <VPS IP>
Port         : 36712   (from config.json "listen")
Username/Pass: created via `menu` option 1 — same account as SSH login
```

> Note: some UDP-Custom account cards print a "port 1-65535" line. This
> is just display text, not a real feature — only the single `listen`
> port in `config.json` actually works. See `TROUBLESHOOTING.md`.

---

## Something not working?

See **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** — covers the actual
issues hit during real deployment and their fixes:
- `udp-custom.service` stuck on STOPPED / config not found
- `status=203/EXEC` crash loop (missing `chmod +x`)
- Client stuck on "Connecting attempt 1, 2, 3…" — full 3-layer debug
  path (firewall → packet capture → auth log)
- The "port 1-65535" claim explained
- `install-all.sh` not installing the genuine `udp-custom` service

---

## Contact / Credits

- UDP Custom binary: ePro Dev Team
- SSH-WS, panel, and integration: Phoe Shan
