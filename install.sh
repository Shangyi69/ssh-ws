#!/bin/bash
#--------------------------------------------------------
# SSH + WebSocket account-management installer
# Creates: /usr/local/bin/ws-proxy.py (WS<->SSH forwarder)
#          /usr/local/bin/menu        (admin menu)
#          /usr/local/bin/limiter.sh  (device-limit + expiry enforcer daemon)
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

mkdir -p /etc/ws-ssh/limit /etc/ws-ssh/info /var/run/ws-ssh

echo -e "${YELLOW}[*] writing ws-proxy.py ...${NC}"
cat <<'PYEOF' > /usr/local/bin/ws-proxy.py
#!/usr/bin/env python3
"""
ws-proxy.py  —  SSH-over-WebSocket forwarder (robust edition)

* SO_REUSEADDR + SO_REUSEPORT  → fast restart, no "port in use" crash
* Per-connection exception isolation → one bad client never kills the server
* Graceful SIGTERM/SIGINT handling → cleans up state file on shutdown
* Automatic state-file GC → stale entries removed every 60 s
* sshd connect retry → tolerates a brief sshd restart without dropping proxy
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="[ws-proxy] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ws-proxy")

WS_PORT   = int(os.environ.get("WS_PORT",  "8880"))
SSH_PORT  = int(os.environ.get("SSH_PORT", "22"))
STATE_FILE = "/var/run/ws-ssh/active_conns.json"
GC_INTERVAL = 60   # seconds between state-file garbage-collection passes

_lock = asyncio.Lock()
_shutdown = False


# ── state file helpers ────────────────────────────────────────────────────────

def _load_state_sync():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state_sync(state):
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        log.warning("state save failed: %s", e)


async def _register(port, ip):
    async with _lock:
        state = _load_state_sync()
        state[str(port)] = {"ip": ip, "ts": time.time()}
        _save_state_sync(state)


async def _unregister(port):
    async with _lock:
        state = _load_state_sync()
        state.pop(str(port), None)
        _save_state_sync(state)


async def _gc_state():
    """Remove entries older than 24 h (safety net for leaked entries)."""
    while not _shutdown:
        await asyncio.sleep(GC_INTERVAL)
        async with _lock:
            state = _load_state_sync()
            cutoff = time.time() - 86400
            cleaned = {k: v for k, v in state.items() if v.get("ts", 0) > cutoff}
            if len(cleaned) != len(state):
                _save_state_sync(cleaned)
                log.info("gc: removed %d stale entries", len(state) - len(cleaned))


# ── relay ─────────────────────────────────────────────────────────────────────

async def _relay(reader, writer, label=""):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        log.debug("relay %s: %s", label, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── client handler ────────────────────────────────────────────────────────────

async def handle_client(client_reader, client_writer):
    peer = client_writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    local_port = None

    try:
        # ── WebSocket / plain-SSH handshake ──────────────────────────────
        try:
            first = await asyncio.wait_for(client_reader.read(4096), timeout=10)
        except asyncio.TimeoutError:
            log.debug("handshake timeout from %s", client_ip)
            return

        if not first:
            return

        leftover = b""
        if first.startswith(b"GET") or b"HTTP/1." in first[:64]:
            try:
                client_writer.write(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n\r\n"
                )
                await client_writer.drain()
            except Exception:
                return
        else:
            leftover = first

        # ── connect to sshd (retry once on transient failure) ────────────
        ssh_reader = ssh_writer = None
        for attempt in range(2):
            try:
                ssh_reader, ssh_writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", SSH_PORT), timeout=5
                )
                break
            except Exception as e:
                if attempt == 0:
                    await asyncio.sleep(0.5)
                else:
                    log.warning("sshd connect failed for %s: %s", client_ip, e)
                    return

        local_port = ssh_writer.get_extra_info("sockname")[1]
        await _register(local_port, client_ip)

        if leftover:
            try:
                ssh_writer.write(leftover)
                await ssh_writer.drain()
            except Exception:
                return

        # ── bidirectional relay ──────────────────────────────────────────
        await asyncio.gather(
            _relay(client_reader, ssh_writer, "c→s"),
            _relay(ssh_reader,   client_writer, "s→c"),
        )

    except Exception as e:
        log.debug("handle_client %s: %s", client_ip, e)
    finally:
        if local_port is not None:
            await _unregister(local_port)
        for w in [client_writer] + ([ssh_writer] if 'ssh_writer' in dir() and ssh_writer else []):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass


# ── main ──────────────────────────────────────────────────────────────────────

async def main():
    global _shutdown
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    if not os.path.exists(STATE_FILE):
        _save_state_sync({})

    loop = asyncio.get_running_loop()

    def _on_signal():
        global _shutdown
        _shutdown = True
        log.info("shutdown signal received")
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass  # Windows

    # SO_REUSEADDR + SO_REUSEPORT via reuse_port=True
    try:
        server = await asyncio.start_server(
            handle_client, "0.0.0.0", WS_PORT,
            reuse_address=True,
            reuse_port=True,
        )
    except OSError as e:
        log.error("cannot bind port %d: %s", WS_PORT, e)
        sys.exit(1)

    asyncio.ensure_future(_gc_state())

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("listening on %s  →  127.0.0.1:%d", addrs, SSH_PORT)

    async with server:
        await server.serve_forever()

    # cleanup on shutdown
    _save_state_sync({})
    log.info("state file cleared, exiting")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass

PYEOF
chmod +x /usr/local/bin/ws-proxy.py

echo -e "${YELLOW}[*] writing menu ...${NC}"
cat <<'MENUEOF' > /usr/local/bin/menu
#!/bin/bash
# menu - SSH+WebSocket account management
LIMIT_DIR="/etc/ws-ssh/limit"
INFO_DIR="/etc/ws-ssh/info"
ONLINE_FILE="/var/run/ws-ssh/online_ips.json"
GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'

mkdir -p "$LIMIT_DIR" "$INFO_DIR"

pause() { read -rp "Enter ဖိ၍ menu သို့ ပြန်သွားရန်..." _; }

select_user() {
    mapfile -t users < <(ls "$LIMIT_DIR" 2>/dev/null | sort)
    if [[ ${#users[@]} -eq 0 ]]; then
        echo -e "${RED}[!] Managed user မရှိသေးပါ${NC}" >&2
        return 1
    fi
    echo "User list:" >&2
    local i=1
    for u in "${users[@]}"; do
        printf "  %2d) %s\n" "$i" "$u" >&2
        ((i++))
    done
    read -rp "Number ရွေးပါ: " num
    if ! [[ "$num" =~ ^[0-9]+$ ]] || (( num < 1 || num > ${#users[@]} )); then
        echo -e "${RED}[!] မှားနေပါသည်${NC}" >&2
        return 1
    fi
    echo "${users[$((num-1))]}"
}

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
    echo "$pass" > "$INFO_DIR/$user"
    chmod 600 "$INFO_DIR/$user"

    echo -e "${GREEN}[+] User ဖန်တီးပြီးပါပြီ${NC}"
    echo "    Username : $user"
    echo "    Password : $pass"
    echo "    Expire   : $exp"
    echo "    Limit    : $limit device(s)"
}

delete_user() {
    user=$(select_user) || return
    [[ -z "$user" ]] && return
    uid=$(id -u "$user" 2>/dev/null)
    pkill -9 -u "$user" 2>/dev/null
    [[ -n "$uid" ]] && iptables -D OUTPUT -m owner --uid-owner "$uid" -m comment --comment "wsdata-$user" -j ACCEPT 2>/dev/null
    userdel -f "$user" 2>/dev/null
    rm -f "$LIMIT_DIR/$user" "$INFO_DIR/$user"
    echo -e "${GREEN}[+] '$user' ကို ဖျက်ပြီးပါပြီ${NC}"
}

renew_user() {
    user=$(select_user) || return
    [[ -z "$user" ]] && return
    read -rp "ထပ်ထည့်မည့်ရက်ပေါင်း (e.g. 30): " days
    exp=$(date -d "+${days} days" +%Y-%m-%d)
    chage -E "$exp" "$user"
    # Clear any PAM failed-login lockout left over from connection attempts
    # made while the account was expired (chage -E alone does not reset this).
    faillock --user "$user" --reset 2>/dev/null
    pam_tally2 --user "$user" --reset >/dev/null 2>&1
    echo -e "${GREEN}[+] '$user' အသက်တမ်းသစ် -> $exp${NC}"
}

check_online() {
    printf "%-18s %-6s %-6s %s\n" "USERNAME" "ONLINE" "LIMIT" "IP LIST"
    echo "------------------------------------------------------------"
    local now
    now=$(date +%s)
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        limit=$(cat "$f")
        online=$(ps aux | grep "sshd: $user" | grep -v grep | grep -v "\[priv\]" | wc -l)
        ip_list="-"
        if [[ -f "$ONLINE_FILE" ]]; then
            ip_list=$(jq -r --arg u "$user" \
                '.[$u]? // [] | [.[].ip] | join(", ")' "$ONLINE_FILE" 2>/dev/null)
            [[ -z "$ip_list" ]] && ip_list="-"
        fi
        # Check expired
        exp=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')
        expired=0
        if [[ "$exp" != "-" && "$exp" != "never" && -n "$exp" ]]; then
            exp_epoch=$(date -d "$exp" +%s 2>/dev/null) || exp_epoch=0
            (( exp_epoch > 0 && exp_epoch <= now )) && expired=1
        fi
        if (( expired )); then
            printf "${RED}%-18s %-6s %-6s %s  [EXPIRED]${NC}\n" "$user" "$online" "$limit" "$ip_list"
        else
            printf "%-18s %-6s %-6s %s\n" "$user" "$online" "$limit" "$ip_list"
        fi
    done
}

user_info_list() {
    printf "%-14s %-14s %-12s %-8s\n" "USERNAME" "PASSWORD" "EXPIRE" "ONLINE"
    echo "--------------------------------------------------------"
    local now
    now=$(date +%s)
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        pass=$(cat "$INFO_DIR/$user" 2>/dev/null); [[ -z "$pass" ]] && pass="-"
        exp=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')
        [[ -z "$exp" ]] && exp="-"
        online=$(ps aux | grep "sshd: $user" | grep -v grep | grep -v "\[priv\]" | wc -l)
        # Check if expired
        expired=0
        if [[ "$exp" != "-" && "$exp" != "never" ]]; then
            exp_epoch=$(date -d "$exp" +%s 2>/dev/null) || exp_epoch=0
            (( exp_epoch > 0 && exp_epoch <= now )) && expired=1
        fi
        if (( expired )); then
            printf "${RED}%-14s %-14s %-12s %-8s  [EXPIRED]${NC}\n" "$user" "$pass" "$exp" "$online"
        else
            printf "%-14s %-14s %-12s %-8s\n" "$user" "$pass" "$exp" "$online"
        fi
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
    echo -e "${YELLOW}[note] Output traffic ကိုသာ count ထားသည်${NC}"
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

kick_user() {
    user=$(select_user) || return
    [[ -z "$user" ]] && return
    pkill -9 -u "$user" 2>/dev/null
    echo -e "${GREEN}[+] '$user' ရဲ့ session အားလုံး kick ပြီးပါပြီ${NC}"
}

while true; do
    clear
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${CYAN}       SSH + WEBSOCKET ACCOUNT MENU       ${NC}"
    echo -e "${CYAN}=========================================${NC}"
    echo " 1) Create User"
    echo " 2) Delete User"
    echo " 3) Renew User"
    echo " 4) User Info List"
    echo " 5) Check Online + IP List"
    echo " 6) Check Data Usage (GB)"
    echo " 7) Set/Check Device Limit"
    echo " 8) Kick User (force disconnect all sessions)"
    echo " 0) Exit"
    echo -e "${CYAN}=========================================${NC}"
    read -rp "ရွေးပါ [0-8]: " opt
    echo
    case "$opt" in
        1) create_user ;;
        2) delete_user ;;
        3) renew_user ;;
        4) user_info_list ;;
        5) check_online ;;
        6) check_usage ;;
        7) set_limit ;;
        8) kick_user ;;
        0) exit 0 ;;
        *) echo -e "${RED}မှားနေပါသည်${NC}" ;;
    esac
    echo
    pause
done

MENUEOF
chmod +x /usr/local/bin/menu
ln -sf /usr/local/bin/menu /usr/bin/menu

echo -e "${YELLOW}[*] writing limiter.sh ...${NC}"
cat <<'LIMEOF' > /usr/local/bin/limiter.sh
#!/bin/bash
# limiter.sh - daemon: device-limit enforcer + expiry killer
#
# Strategy: NO IP ban. Instead, keep the OLDEST session(s) up to the
# configured limit and immediately kill any newer excess connections.
# Result: existing session stays stable; new connection gets dropped.
#
# online_ips.json is written every poll cycle for the web panel.
# Format: {"username": [{"ip":"x.x.x.x","pid":1234,"ts":1234567890}, ...]}

LIMIT_DIR="/etc/ws-ssh/limit"
STATE_FILE="/var/run/ws-ssh/active_conns.json"
ONLINE_FILE="/var/run/ws-ssh/online_ips.json"
POLL_SECONDS="${POLL_SECONDS:-3}"


mkdir -p "$LIMIT_DIR" "$(dirname "$STATE_FILE")"

kill_expired() {
    [[ -d "$LIMIT_DIR" ]] || return
    local now user exp_str exp_epoch
    now=$(date +%s)
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        exp_str=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')
        [[ -z "$exp_str" || "$exp_str" == "never" ]] && continue
        exp_epoch=$(date -d "$exp_str" +%s 2>/dev/null) || continue
        if (( exp_epoch <= now )); then
            pkill -9 -u "$user" 2>/dev/null && \
                logger -t ws-ssh-limiter "user=$user expired -> disconnected"
        fi
    done
}

one_pass() {
    [[ -d "$LIMIT_DIR" ]] || return

    declare -A sessions   # user -> newline-separated "ts|pid|ip" entries

    # Parse: ESTAB 0 0 127.0.0.1:22  127.0.0.1:EPORT  users:(("sshd",pid=NNN,...))
    while IFS= read -r line; do
        local_addr=$(awk '{print $4}' <<< "$line")
        peer_addr=$(awk '{print $5}'  <<< "$line")
        [[ "$local_addr" == *:22 ]] || continue

        eport="${peer_addr##*:}"
        [[ "$eport" =~ ^[0-9]+$ ]] || continue

        pid=$(grep -oP 'pid=\K[0-9]+' <<< "$line" | head -1)
        [[ -z "$pid" ]] && continue

        user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d '[:space:]')
        [[ -z "$user" ]] && continue
        [[ -f "$LIMIT_DIR/$user" ]] || continue

        # Real client IP + connect time from ws-proxy state file
        real_ip="unknown"; ts="0"
        if [[ -f "$STATE_FILE" ]]; then
            real_ip=$(jq -r --arg p "$eport" '.[$p].ip // "unknown"' "$STATE_FILE" 2>/dev/null)
            ts=$(jq -r       --arg p "$eport" '.[$p].ts // 0'       "$STATE_FILE" 2>/dev/null)
            [[ -z "$real_ip" ]] && real_ip="unknown"
        fi

        sessions["$user"]+="${ts}|${pid}|${real_ip}"$'\n'
    done < <(ss -H -tnp state established '( sport = :22 )' 2>/dev/null)

    # ── Write online_ips.json (for panel / menu) ─────────────────────────
    {
        printf '{\n'
        local comma=0
        for user in "${!sessions[@]}"; do
            [[ $comma -eq 1 ]] && printf ',\n'
            comma=1
            printf '  "%s": [\n' "$user"
            local cfirst=1
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                IFS='|' read -r ts pid ip <<< "$entry"
                [[ $cfirst -eq 0 ]] && printf ',\n'
                cfirst=0
                printf '    {"ip":"%s","pid":%s,"ts":%s}' "$ip" "$pid" "$ts"
            done <<< "${sessions[$user]}"
            printf '\n  ]'
        done
        printf '\n}\n'
    } > "${ONLINE_FILE}.tmp" 2>/dev/null && mv "${ONLINE_FILE}.tmp" "$ONLINE_FILE"

    # ── Enforce limits: same action as Panel/Menu "Kick" button ───────────
    # If a user has MORE active sessions than their device limit, kick ALL
    # of that user's sessions immediately (pkill -9 -u user) — identical to
    # clicking "Kick" in the panel. This loop runs every POLL_SECONDS, 24/7,
    # so it's effectively an automatic "Kick" click whenever the limit is
    # exceeded. The user can simply reconnect down to their allowed count.
    for user in "${!sessions[@]}"; do
        limit=$(cat "$LIMIT_DIR/$user" 2>/dev/null)
        [[ "$limit" =~ ^[0-9]+$ ]] || continue

        count=$(printf '%s' "${sessions[$user]}" | grep -c '^[^[:space:]]')
        [[ $count -le $limit ]] && continue

        if pkill -9 -u "$user" 2>/dev/null; then
            logger -t ws-ssh-limiter \
                "user=$user limit=$limit count=$count -> auto-kicked ALL sessions (over limit)"
        fi
    done
}

while true; do
    kill_expired
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
Description=SSH-WS per-user device limiter / expiry enforcer
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
