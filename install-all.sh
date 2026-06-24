#!/bin/bash
#--------------------------------------------------------
# 1-click installer: core SSH+WS system + Web panel
#--------------------------------------------------------
set -e
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[[ "$EUID" -ne 0 ]] && { echo -e "${RED}[x] root user နဲ့ run ပါ${NC}"; exit 1; }

REPO="raw.githubusercontent.com/Shangyi69/ssh-ws/main"

WS_PORT="${1:-}"
PANEL_PORT="${2:-}"

if [[ -z "$WS_PORT" ]]; then
    read -rp "WebSocket port ဘယ်ဟာသုံးမလဲ (e.g. 80): " WS_PORT
fi
[[ -z "$WS_PORT" ]] && WS_PORT=80

if [[ -z "$PANEL_PORT" ]]; then
    read -rp "Web panel port (default 2053, Enter ဖိရင် default): " PANEL_PORT
fi
[[ -z "$PANEL_PORT" ]] && PANEL_PORT=2053

echo -e "${YELLOW}[1/2] Core SSH+WS system install (port ${WS_PORT})...${NC}"
bash <(wget -qO- "${REPO}/install.sh") "$WS_PORT"

echo -e "${YELLOW}[2/2] Web panel install (port ${PANEL_PORT})...${NC}"
bash <(wget -qO- "${REPO}/install-panel.sh") "$PANEL_PORT"

IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  စနစ်တစ်ခုလုံးကို အောင်မြင်စွာ တပ်ဆင်ပြီးပါပြီ။${NC}"
echo -e "${GREEN}  WebSocket Port: $WS_PORT${NC}"
echo -e "${GREEN}  Web Panel URL : http://$IP:$PANEL_PORT${NC}"
echo -e "${GREEN}=========================================${NC}"
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
INFO_DIR="/etc/ws-ssh/info"
BANLOG="/etc/ws-ssh/banned_ips.list"
GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'

mkdir -p "$LIMIT_DIR" "$INFO_DIR"
touch "$BANLOG"

pause() { read -rp "Enter ဖိ၍ menu သို့ ပြန်သွားရန်..." _; }

# Lists managed usernames with numbers (to stderr), reads a selection,
# echoes the chosen username to stdout (so callers do: user=$(select_user)).
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
    echo -e "${GREEN}[+] '$user' အသက်တမ်းသစ် -> $exp${NC}"
}

check_online() {
    printf "%-18s %-10s %-10s\n" "USERNAME" "ONLINE" "LIMIT"
    echo "--------------------------------------------"
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        limit=$(cat "$f")
        # ပြင်ဆင်ချက် - [priv] ပါသော process အပိုများကြောင့် ၂ ဆမပေါ်စေရန် ဖယ်ထုတ်ရေတွက်ခြင်း
        online=$(ps aux | grep "sshd: $user" | grep -v grep | grep -v "\[priv\]" | wc -l)
        printf "%-18s %-10s %-10s\n" "$user" "$online" "$limit"
    done
}

user_info_list() {
    printf "%-14s %-14s %-12s %-8s\n" "USERNAME" "PASSWORD" "EXPIRE" "ONLINE"
    echo "--------------------------------------------------------"
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        user=$(basename "$f")
        pass=$(cat "$INFO_DIR/$user" 2>/dev/null)
        [[ -z "$pass" ]] && pass="-"
        exp=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/ {print $2}')
        [[ -z "$exp" ]] && exp="-"
        # ပြင်ဆင်ချက် - [priv] ပါသော process အပိုများကြောင့် ၂ ဆမပေါ်စေရန် ဖယ်ထုတ်ရေတွက်ခြင်း
        online=$(ps aux | grep "sshd: $user" | grep -v grep | grep -v "\[priv\]" | wc -l)
        printf "%-14s %-14s %-12s %-8s\n" "$user" "$pass" "$exp" "$online"
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
    echo " 4) User Info List (username/password/expire/online)"
    echo " 5) Check Online"
    echo " 6) Check Data Usage (GB)"
    echo " 7) Set/Check Device Limit"
    echo " 8) Banned IP list"
    echo " 9) Unban IP"
    echo " 0) Exit"
    echo -e "${CYAN}=========================================${NC}"
    read -rp "ရွေးပါ [0-9]: " opt
    echo
    case "$opt" in
        1) create_user ;;
        2) delete_user ;;
        3) renew_user ;;
        4) user_info_list ;;
        5) check_online ;;
        6) check_usage ;;
        7) set_limit ;;
        8) list_banned ;;
        9) unban_ip ;;
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

kill_expired() {
    [[ -d "$LIMIT_DIR" ]] || return
    local now
    now=$(date +%s)
    for f in "$LIMIT_DIR"/*; do
        [[ -e "$f" ]] || continue
        local user exp_str exp_epoch
        user=$(basename "$f")
        exp_str=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/ {print $2}')
        [[ -z "$exp_str" || "$exp_str" == "never" ]] && continue
        exp_epoch=$(date -d "$exp_str" +%s 2>/dev/null) || continue
        if (( exp_epoch <= now )); then
            if pkill -9 -u "$user" 2>/dev/null; then
                logger -t ws-ssh-limiter "user=$user expired ($exp_str) -> disconnected"
            fi
        fi
    done
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

        # ပြင်ဆင်ချက် - IP မသိရလျှင် ss ထဲမှ Peer IP လိပ်စာကို တိုက်ရိုက်ရယူရန်
        if [[ "$ip" == "unknown" || -z "$ip" ]]; then
            ip="${peer_addr%:*}"
        fi

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
            
            # ပြင်ဆင်ချက် - Format အလိုက် တကယ့် client IP အမှန်ကို သေချာစွာ ရယူခြင်း
            rest="${entry#*:}"
            ip="${rest#*:}"
            
            kill -9 "$pid" 2>/dev/null
            if [[ -n "$ip" && "$ip" != "unknown" && "$ip" != "127.0.0.1" ]]; then
                ban_ip "$ip"
            fi
            logger -t ws-ssh-limiter "user=$user limit=$limit exceeded -> killed pid=$pid ip=$ip"
        done
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
Description=SSH-WS per-user device limiter / expiry enforcer / auto-ban
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
