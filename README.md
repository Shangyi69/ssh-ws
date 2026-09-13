# SSH-WS — SSH over WebSocket + Web Panel

A lightweight SSH-over-WebSocket tunneling service for Linux, with per-user
device limits, account expiry, and a web dashboard for day-to-day account
management.

**Dev: Phoe Shan**

---

## What's included

| File | Purpose |
|---|---|
| `install.sh` | Installs the WebSocket→SSH proxy (`ws-proxy.py`), the CLI account manager (`menu`), and the device-limit/expiry enforcer daemon (`limiter.sh`). |
| `install-panel.sh` | Installs the web dashboard (Flask app + systemd service) for managing accounts from a browser. |
| `install-all.sh` | One-shot wrapper that runs both installers back to back. |

All three are plain bash scripts — no Docker, no extra package manager beyond
what's already on a standard Debian/Ubuntu server.

---

## Requirements

- A Debian/Ubuntu VPS with root access
- `sshd` already installed and running on port 22
- Python 3 (for the proxy and the web panel)
- Outbound internet access to download the scripts

---

## Installation

### Option A — One-shot install (recommended)

```bash
bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) <WS_PORT> <PANEL_PORT>
```

Example — WebSocket service on port `80`, web panel on port `2053`:

```bash
bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-all.sh) 80 2053
```

### Option B — Install each part separately

```bash
# 1. SSH-WS service (replace 80 with whatever port you want clients to connect to)
bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install.sh) 80

# 2. Web panel (replace 2053 with whatever port you want the dashboard on)
bash <(wget -qO- raw.githubusercontent.com/Shangyi69/ssh-ws/main/install-panel.sh) 2053
```

If you omit the port argument, each script will either prompt you for it
(`install.sh`) or fall back to a default of `2053` (`install-panel.sh`).

After installation, all services run under `systemd` and restart
automatically on reboot or crash:

```bash
systemctl status ws-proxy.service
systemctl status ws-limiter.service
systemctl status ws-panel.service
```

---

## CLI account management (`menu`)

Run `menu` from any shell on the server to open the interactive account
manager (menu text is in Burmese):

```
1) Create User
2) Delete User
3) Renew User
4) User Info List
5) Check Online + IP List
6) Check Data Usage (GB)
7) Set/Check Device Limit
8) Kick User (force disconnect all sessions)
0) Exit
```

- **Create User** — sets a username, password, expiry date, and device limit.
- **Renew User** — extends the expiry date *and* clears any leftover PAM
  login lockout / password lock from the account's expired period, so the
  user can reconnect immediately.
- **Kick User** — force-disconnects every active session for that user.

---

## Web Panel

Open `http://<server-ip>:<PANEL_PORT>` in a browser and log in with the
admin credentials created during install (shown at the end of the
`install-panel.sh` output).

### Dashboard

- **Summary cards** — total users, currently online, active (not expired),
  and expired ("Ended") counts at a glance.
- **Search bar** — filter the user table by username instantly.
- **User table** — username, password (click to copy), expiry date, device
  limit, online count, connected IPs, data usage, and per-user actions:
  - **Renew** — extend expiry (also clears PAM lockouts, same as the CLI).
  - **Limit** — change the device limit.
  - **Kick** — force-disconnect all of that user's sessions.
  - **Delete** — remove the account entirely.
- Expired users are highlighted in red with an `EXPIRED` badge.

### Automatic device-limit enforcement

A background thread inside the panel checks every user's online session
count against their configured device limit every few seconds. If a user
exceeds their limit, the panel automatically performs the same action as
clicking **Kick** — no manual intervention needed. This runs for as long as
the panel service is active (24/7, restarted automatically by `systemd`).

### Account settings

- **Change Password** — change the panel admin's own login username/password
  from the dashboard.

---

## Notes on device limits and expiry

- Device-limit enforcement and the panel's auto-kick run independently and
  use the exact same underlying action (`pkill -9 -u <user>`), so behavior
  is consistent whether triggered automatically or by clicking a button.
- Renewing an expired account clears both:
  - the `chage` account-expiry date, and
  - any PAM failed-login lockout / password lock (`!` prefix in
    `/etc/shadow`) left over from the expired period.

  If an account was locked *before* this fix was applied, unlock it once
  manually:

  ```bash
  passwd -u <username>
  ```

---

## Uninstalling

```bash
systemctl disable --now ws-proxy.service ws-limiter.service ws-panel.service
rm -f /usr/local/bin/menu /usr/local/bin/limiter.sh
rm -rf /opt/ws-proxy /opt/ws-panel /etc/ws-ssh
```

(Existing Linux user accounts created via `menu` are not removed
automatically — delete them with `userdel -r <username>` if needed.)
