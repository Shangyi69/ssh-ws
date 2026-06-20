#!/bin/bash
#--------------------------------------------------------
# SSH + WebSocket account-management installer
# Creates: /usr/local/bin/ws-proxy.py (WS<->SSH forwarder)
#          /usr/local/bin/menu        (admin menu)
#          /usr/local/bin/limiter.sh  (device-limit + auto-ban daemon)
#--------------------------------------------------------
set -e

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[[ "$EUID" -ne 0 ]] && { echo -e "${RED}[x] root user နဲ့ run ပါ${NC}"; exit 1; }

if [[ -n "$1" ]]; then
    WS_PORT="$1"
else
    read -rp "WebSocket port ဘယ်ဟာသုံးမလဲ (e.g. 8880): " WS_PORT
fi
[[ -z "$WS_PORT" ]] && { echo -e "${RED}[x] port ထည့်ပါ${NC}"; exit 1; }

echo -e "${YELLOW}[*] Package update / install...${NC}"
apt update -y
apt install -y openssh-server python3 iptables jq net-tools iproute2 cron >/dev/null

echo -e "${YELLOW}[*] sshd config...${NC}"
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q '^AllowTcpForwarding' /etc/ssh/sshd_config || echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

mkdir -p /etc/ws-ssh/limit /var/run/ws-ssh
touch /etc/ws-ssh/banned_ips.list

echo -e "${YELLOW}[*] writing ws-proxy.py ...${NC}"
cat <<'PYEOF' > /usr/local/bin/ws-proxy.py
#!/usr/bin/env python3
"""
ws-proxy.py
SSH-over-WebSocket forwarder.
Listens on WS_PORT, does a minimal HTTP/WebSocket handshake (accepts any
request, answers 101), then bridges raw bytes to 127.0.0.1:SSH_PORT.

While a connection is active it records {local_ephemeral_port: {ip, ts}}
into STATE_FILE so that limiter.sh can later match an established
sshd<->127.0.0.1 session (seen via `ss -tnp`) back to the real client IP.
"""

import asyncio
import json
import os
import sys
import time

WS_PORT = int(os.environ.get("WS_PORT", "8880"))
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
STATE_FILE = "/var/run/ws-ssh/active_conns.json"

_lock = asyncio.Lock()


async def _load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


async def _save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


async def _register(port, ip):
    async with _lock:
        state = await _load_state()
        state[str(port)] = {"ip": ip, "ts": time.time()}
        await _save_state(state)


async def _unregister(port):
    async with _lock:
        state = await _load_state()
        state.pop(str(port), None)
        await _save_state(state)


async def _relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(client_reader, client_writer):
    peer = client_writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    # --- minimal WS handshake: accept any initial HTTP request, answer 101.
    # If the first bytes don't look like an HTTP request, treat them as
    # already being SSH traffic and just forward them through untouched.
    try:
        first = await asyncio.wait_for(client_reader.read(4096), timeout=5)
    except asyncio.TimeoutError:
        first = b""

    leftover = b""
    if first.startswith(b"GET") or b"HTTP/1." in first[:64]:
        client_writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n\r\n"
        )
        await client_writer.drain()
    else:
        leftover = first

    # --- connect to local sshd
    try:
        ssh_reader, ssh_writer = await asyncio.open_connection("127.0.0.1", SSH_PORT)
    except OSError:
        client_writer.close()
        return

    local_port = ssh_writer.get_extra_info("sockname")[1]
    await _register(local_port, client_ip)

    if leftover:
        ssh_writer.write(leftover)
        await ssh_writer.drain()

    try:
        await asyncio.gather(
            _relay(client_reader, ssh_writer),
            _relay(ssh_reader, client_writer),
        )
    finally:
        await _unregister(local_port)
        for w in (client_writer, ssh_writer):
            try:
                w.close()
            except Exception:
                pass


async def main():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, "w") as f:
            json.dump({}, f)

    server = await asyncio.start_server(handle_client, "0.0.0.0", WS_PORT)
    print(f"[ws-proxy] listening on 0.0.0.0:{WS_PORT} -> 127.0.0.1:{SSH_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

PYEOF
chmod +x /usr/local/bin/ws-proxy.py

echo -e "${YELLOW}[*] writing menu ...${NC}"
cat <<'MENUEOF' > /usr/local/bin/menu
#!/bin/bash
# menu - SSH+WebSocket account management
LIMIT_DIR="/etc/ws-ssh/limit"
BANLOG="/etc/ws-ssh/banned_ips.list"
GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'

mkdir -p "$LIMIT_DIR"
touch "$BANLOG"

pause() { read -rp "Enter ဖိ၍ menu သို့ ပြန်သွားရန်..." _; }

create_user() {
    read -rp "Username: " user
    if id "$user" &>/dev/null; then
        echo -e "${RED}[!] '$user' user ရှိနှင့်ပြီးပါပြီ${NC}"; return
    fi
    read -rp "Password: " pass
    read -rp "သက်တမ်း (ရက်ပေါင်း, e.g. 30): " days
    read -rp "Device limit (တစ်ချိန်တည်းချိတ်ခွင့် အရေအတွက်, e.g. 1): " limit
    exp=$(date -d "+${days} days" +%Y-%m-%d)

    useradd -M -N -s /usr/sbin/nologin -e "$exp" "$user"
    echo "$user:$pass" | chpasswd

    uid=$(id -u "$user")
    iptables -A OUTPUT -m owner --uid-owner "$uid" -m comment --comment "wsdata-$user" -j ACCEPT
    echo "$limit" > "$LIMIT_DIR/$user"

    echo -e "${GREEN}[+] User ဖန်တီးပြီးပါပြီ${NC}"
    echo "    Username : $user"
    echo "    Password : $pass"
    echo "    Expire   : $exp"
    echo "    Limit    : $limit device(s)"
}

delete_user() {
    read -rp "ဖျက်မည့် Username: " user
    if ! id "$user" &>/dev/null; then
        echo -e "${RED}[!] '$user' မရှိပါ${NC}"; return
    fi
    uid=$(id -u "$user")
    pkill -9 -u "$user" 2>/dev/null
    iptables -D OUTPUT -m owner --uid-owner "$uid" -m comment --comment "wsdata-$user" -j ACCEPT 2>/dev/null
    userdel -f "$user" 2>/dev/null
    rm -f "$LIMIT_DIR/$user"
    echo -e "${GREEN}[+] '$user' ကို ဖျက်ပြီးပါပြီ${NC}"
}

renew_user() {
    read -rp "Renew မည့် Username: " user
    if ! id "$user" &>/dev/null; then
        echo -e "${RED}[!] '$user' မရှိပါ${NC}"; return
    fi
    read -rp "ထပ်ထည့်မည့်ရက်ပေါင်း (e.g. 30): " days
    exp=$(date -d "+${days} days" +%Y-%m-%d)
    chage -E "$exp" "$user"
    echo -e "${GREEN}[+] '$user' အသက်တမ်းသစ် -> $exp${NC}"
}

check_online() {
    printf "%-18s %-10s %-10s\n" "USERNAME" "ONLINE" "LIMIT"
    echo "--------------------------------------------"
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        limit=$(cat "$f")
        online=$(ps aux | grep "sshd: $user" | grep -v grep | wc -l)
        printf "%-18s %-10s %-10s\n" "$user" "$online" "$limit"
    done
}

check_usage() {
    printf "%-18s %-12s\n" "USERNAME" "USAGE(GB)"
    echo "----------------------------------"
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        bytes=$(iptables -L OUTPUT -v -n -x 2>/dev/null | grep "wsdata-$user" | awk '{sum+=$2} END {print sum+0}')
        gb=$(awk -v b="$bytes" 'BEGIN { printf "%.3f", b/1024/1024/1024 }')
        printf "%-18s %-12s\n" "$user" "$gb"
    done
    echo -e "${YELLOW}[note] Output (server->client) traffic ကိုသာ count ထားသည် (rough estimate)${NC}"
}

set_limit() {
    read -rp "Username: " user
    if [[ ! -f "$LIMIT_DIR/$user" ]]; then
        echo -e "${RED}[!] '$user' managed user မဟုတ်ပါ${NC}"; return
    fi
    cur=$(cat "$LIMIT_DIR/$user")
    echo "လက်ရှိ limit: $cur"
    read -rp "Limit အသစ်: " newlimit
    echo "$newlimit" > "$LIMIT_DIR/$user"
    echo -e "${GREEN}[+] '$user' limit -> $newlimit${NC}"
}

list_banned() {
    echo -e "${CYAN}Banned IP list:${NC}"
    if [[ -s "$BANLOG" ]]; then cat "$BANLOG"; else echo "(empty)"; fi
}

unban_ip() {
    read -rp "Unban မည့် IP: " ip
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    sed -i "\|^$ip\$|d" "$BANLOG"
    echo -e "${GREEN}[+] $ip ကို unban ပြီးပါပြီ${NC}"
}

while true; do
    clear
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${CYAN}       SSH + WEBSOCKET ACCOUNT MENU       ${NC}"
    echo -e "${CYAN}=========================================${NC}"
    echo " 1) Create User"
    echo " 2) Delete User"
    echo " 3) Renew User"
    echo " 4) Check Online"
    echo " 5) Check Data Usage (GB)"
    echo " 6) Set/Check Device Limit"
    echo " 7) Banned IP list"
    echo " 8) Unban IP"
    echo " 0) Exit"
    echo -e "${CYAN}=========================================${NC}"
    read -rp "ရွေးပါ [0-8]: " opt
    echo
    case "$opt" in
        1) create_user ;;
        2) delete_user ;;
        3) renew_user ;;
        4) check_online ;;
        5) check_usage ;;
        6) set_limit ;;
        7) list_banned ;;
        8) unban_ip ;;
        0) exit 0 ;;
        *) echo -e "${RED}မှားနေပါသည်${NC}" ;;
    esac
    echo
    pause
done

MENUEOF
chmod +x /usr/local/bin/menu

echo -e "${YELLOW}[*] writing limiter.sh ...${NC}"
cat <<'LIMEOF' > /usr/local/bin/limiter.sh
#!/bin/bash
# limiter.sh - runs as a daemon (systemd), polls every few seconds.
# For each managed user, counts active sshd sessions (correlated to the
# real client IP via /var/run/ws-ssh/active_conns.json written by
# ws-proxy.py). If a user has more active sessions than their configured
# limit, the newest excess sessions are killed and their IP is banned.

LIMIT_DIR="/etc/ws-ssh/limit"
STATE_FILE="/var/run/ws-ssh/active_conns.json"
BANLOG="/etc/ws-ssh/banned_ips.list"
POLL_SECONDS="${POLL_SECONDS:-5}"

mkdir -p "$LIMIT_DIR"
touch "$BANLOG"

is_banned() {
    grep -qxF "$1" "$BANLOG" 2>/dev/null
}

ban_ip() {
    local ip="$1"
    [[ -z "$ip" || "$ip" == "unknown" || "$ip" == "127.0.0.1" ]] && return
    if ! is_banned "$ip"; then
        iptables -I INPUT -s "$ip" -j DROP
        echo "$ip" >> "$BANLOG"
        logger -t ws-ssh-limiter "banned IP $ip (device limit exceeded)"
    fi
}

one_pass() {
    [[ -d "$LIMIT_DIR" ]] || return
    [[ -f "$STATE_FILE" ]] || return

    # username -> "port:pid:ts:ip" lines
    declare -A sessions

    while read -r line; do
        # ss -H -tnp output, established conns where local port is 22
        local_addr=$(awk '{print $4}' <<< "$line")
        peer_addr=$(awk '{print $5}' <<< "$line")
        [[ "$local_addr" != *:22 ]] && continue

        peer_port="${peer_addr##*:}"
        pid=$(grep -oP 'pid=\K[0-9]+' <<< "$line")
        [[ -z "$pid" ]] && continue

        user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
        [[ -z "$user" ]] && continue
        [[ -f "$LIMIT_DIR/$user" ]] || continue

        ip=$(jq -r --arg p "$peer_port" '.[$p].ip // "unknown"' "$STATE_FILE" 2>/dev/null)
        ts=$(jq -r --arg p "$peer_port" '.[$p].ts // 0' "$STATE_FILE" 2>/dev/null)

        sessions["$user"]+="$pid:$ts:$ip"$'\n'
    done < <(ss -H -tnp state established '( sport = :22 )' 2>/dev/null)

    for user in "${!sessions[@]}"; do
        limit=$(cat "$LIMIT_DIR/$user" 2>/dev/null)
        [[ -z "$limit" ]] && continue

        # sort this user's sessions oldest-first, keep $limit, kill the rest
        mapfile -t lines < <(echo -n "${sessions[$user]}" | sort -t: -k2 -n)
        count=${#lines[@]}
        [[ "$count" -le "$limit" ]] && continue

        excess=$(( count - limit ))
        for ((i = count - excess; i < count; i++)); do
            entry="${lines[$i]}"
            pid="${entry%%:*}"
            ip="${entry##*:}"
            kill -9 "$pid" 2>/dev/null
            ban_ip "$ip"
            logger -t ws-ssh-limiter "user=$user limit=$limit exceeded -> killed pid=$pid ip=$ip"
        done
    done
}

while true; do
    one_pass
    sleep "$POLL_SECONDS"
done

LIMEOF
chmod +x /usr/local/bin/limiter.sh

echo -e "${YELLOW}[*] systemd services ...${NC}"
cat <<EOF > /etc/systemd/system/ws-proxy.service
[Unit]
Description=SSH over WebSocket proxy
After=network.target ssh.service

[Service]
Environment=WS_PORT=${WS_PORT}
Environment=SSH_PORT=22
ExecStart=/usr/bin/python3 /usr/local/bin/ws-proxy.py
Restart=always
RuntimeDirectory=ws-ssh

[Install]
WantedBy=multi-user.target
EOF

cat <<'EOF' > /etc/systemd/system/ws-limiter.service
[Unit]
Description=SSH-WS per-user device limiter / auto-ban
After=network.target

[Service]
ExecStart=/usr/local/bin/limiter.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ws-proxy.service
systemctl enable --now ws-limiter.service

# allow the chosen port through ufw if it's active
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${WS_PORT}"/tcp
fi

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Install ပြီးပါပြီ!${NC}"
echo -e "${GREEN}  WebSocket port : ${WS_PORT}${NC}"
echo -e "${GREEN}  Menu command   : menu${NC}"
echo -e "${GREEN}=========================================${NC}"
