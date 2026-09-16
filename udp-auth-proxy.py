#!/usr/bin/env python3
"""
udp-auth-proxy.py
=================
UDP Custom အတွက် SSH auth proxy။

Flow:
  HTTP Custom (UDP) → udp-auth-proxy :36712
                           ↓
                  SSH auth (localhost:22) စစ်မည်
                  expire? → chage စစ်
                  limit?  → LIMIT_DIR စစ်
                  online? → ONLINE_FILE စစ်
                           ↓
                  udp-custom :36713 (internal)

UDP Custom "passwords" mode format: "user:pass"
Proxy က first packet ထဲက credential ကို ဖတ်ပြီး SSH စစ်မည်။
Auth OK → udp-custom ဆီ forward လုပ်မည်။
Auth FAIL → connection ပိတ်မည်။
"""

import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [udp-proxy] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("udp-proxy")

# ── Config ────────────────────────────────────────────────────────────────────
LISTEN_HOST  = "0.0.0.0"
LISTEN_PORT  = int(os.environ.get("UDP_PROXY_PORT", "36712"))
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = int(os.environ.get("UDP_BACKEND_PORT", "36713"))

LIMIT_DIR    = "/etc/ws-ssh/limit"
INFO_DIR     = "/etc/ws-ssh/info"
ONLINE_FILE  = "/var/run/ws-ssh/online_ips.json"

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_expire(user):
    try:
        out = subprocess.run(
            ["chage", "-l", user], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            if "Account expires" in line:
                val = line.split(":", 1)[1].strip()
                return None if val in ("never", "") else val
    except Exception:
        pass
    return None

def is_expired(exp_str):
    if not exp_str:
        return False
    for fmt in ("%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(exp_str.strip(), fmt) < datetime.now()
        except ValueError:
            pass
    return False

def get_limit(user):
    try:
        return int(open(os.path.join(LIMIT_DIR, user)).read().strip())
    except Exception:
        return None

def get_online_count(user):
    try:
        if not os.path.exists(ONLINE_FILE):
            return 0
        data = json.load(open(ONLINE_FILE))
        return len(data.get(user, []))
    except Exception:
        return 0

def ssh_auth(user, password):
    """SSH auth — paramiko မရှိရင် SSH process နဲ့ စစ်"""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("127.0.0.1", port=22, username=user, password=password,
                  timeout=5, allow_agent=False, look_for_keys=False)
        c.close()
        return True
    except Exception:
        return False

def check_user(user, password):
    """
    Return (ok, reason)
    """
    # 1) SSH password စစ်
    if not ssh_auth(user, password):
        return False, "auth_fail"

    # 2) expire စစ်
    exp = get_expire(user)
    if is_expired(exp):
        return False, "expired"

    # 3) limit စစ်
    limit = get_limit(user)
    if limit is not None:
        online = get_online_count(user)
        if online >= limit:
            return False, f"over_limit({online}/{limit})"

    return True, "ok"

# ── UDP Proxy ─────────────────────────────────────────────────────────────────
# UDP Custom protocol:
#   Client → Server first packet contains auth header:
#   [2 bytes: username len][username][2 bytes: password len][password][rest...]
#
# After auth OK, we relay all UDP packets between client ↔ backend.

class UDPProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        # client_addr → backend_transport
        self.sessions = {}
        # client_addr → authenticated bool
        self.authed = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr not in self.authed:
            # First packet — parse credential
            ok, user, password, payload = self._parse_auth(data)
            if not ok:
                log.warning(f"{addr} → bad packet format")
                return
            auth_ok, reason = check_user(user, password)
            if not auth_ok:
                log.warning(f"{addr} user={user} → {reason}")
                return
            log.info(f"{addr} user={user} → authenticated OK")
            self.authed[addr] = (user, password)
            # Create backend connection
            asyncio.ensure_future(self._open_backend(addr, payload))
        else:
            # Forward to backend
            if addr in self.sessions:
                self.sessions[addr].sendto(data, (BACKEND_HOST, BACKEND_PORT))

    def _parse_auth(self, data):
        """
        UDP Custom first packet:
        Format: user\npassword\n  (newline separated, rest is payload)
        Some clients send: user:password\n
        Try both.
        """
        try:
            text = data.split(b"\x00")[0].decode("utf-8", errors="ignore")
            if "\n" in text:
                parts = text.split("\n", 2)
                user = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""
                payload = data
                if ":" in user and not password:
                    user, password = user.split(":", 1)
                return True, user, password, payload
            if ":" in text.split("\n")[0]:
                cred, *_ = text.split("\n")
                user, password = cred.strip().split(":", 1)
                return True, user, password, data
        except Exception:
            pass
        return False, "", "", b""

    async def _open_backend(self, client_addr, initial_data):
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: BackendProtocol(self, client_addr),
            remote_addr=(BACKEND_HOST, BACKEND_PORT),
        )
        self.sessions[client_addr] = transport
        transport.sendto(initial_data)


class BackendProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy, client_addr):
        self.proxy = proxy
        self.client_addr = client_addr

    def datagram_received(self, data, addr):
        # Reply from backend → forward to client
        if self.proxy.transport:
            self.proxy.transport.sendto(data, self.client_addr)

    def error_received(self, exc):
        log.error(f"backend error: {exc}")

    def connection_lost(self, exc):
        self.proxy.sessions.pop(self.client_addr, None)
        self.proxy.authed.pop(self.client_addr, None)


# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        UDPProxyProtocol,
        local_addr=(LISTEN_HOST, LISTEN_PORT),
    )
    log.info(f"UDP Auth Proxy listening :{LISTEN_PORT} → backend :{BACKEND_PORT}")
    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
