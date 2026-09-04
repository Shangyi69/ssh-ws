#!/bin/bash
#--------------------------------------------------------
# SSH+WS Web Panel installer (X-ui style)
# Requires: the main ssh-ws install.sh should already be installed
# (this only adds the web panel on top of /etc/ws-ssh/* data)
#--------------------------------------------------------
set -e
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[[ "$EUID" -ne 0 ]] && { echo -e "${RED}[x] root user နဲ့ run ပါ${NC}"; exit 1; }

PANEL_PORT="${1:-2053}"

echo -e "${YELLOW}[*] Package install...${NC}"
apt update -y
apt install -y python3 python3-pip >/dev/null
pip3 install -q flask werkzeug psutil --break-system-packages 2>/dev/null || pip3 install -q flask werkzeug psutil

mkdir -p /opt/ws-panel/templates /etc/ws-ssh/panel /etc/ws-ssh/limit /etc/ws-ssh/info

echo -e "${YELLOW}[*] writing app.py ...${NC}"
cat <<'APPEOF' > /opt/ws-panel/app.py
#!/usr/bin/env python3
"""ws-panel: lightweight X-ui style web panel for the SSH+WebSocket account
manager. Reuses the same on-disk data the CLI `menu` uses, so both stay in
sync (/etc/ws-ssh/limit, /etc/ws-ssh/info)."""

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import psutil
except ImportError:
    psutil = None

LIMIT_DIR = "/etc/ws-ssh/limit"
INFO_DIR = "/etc/ws-ssh/info"
PANEL_DIR = "/etc/ws-ssh/panel"
AUTH_FILE = os.path.join(PANEL_DIR, "auth.json")
SECRET_FILE = os.path.join(PANEL_DIR, "secret.key")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

# Services / ports this panel keeps an eye on. "port" is used for a raw TCP
# reachability check (works even if the process isn't a systemd unit, e.g.
# stunnel might be skipped during install); "service" is the systemd unit
# name used to get a proper active/inactive verdict when available.
WATCHED_SERVICES = [
    {"key": "ssh", "label": "SSH (22)", "port": 22, "service": "ssh"},
    {"key": "ssh_alt", "label": "SSH (22) [sshd]", "port": 22, "service": "sshd"},
    {"key": "ws_proxy", "label": "SSH+WS", "port": int(os.environ.get("WS_PORT", "8880")), "service": "ws-proxy"},
    {"key": "ws_ssl", "label": "SSH+SSL (443)", "port": int(os.environ.get("SSL_PORT", "443")), "service": "ws-ssl"},
    {"key": "ws_limiter", "label": "Limiter", "port": None, "service": "ws-limiter"},
    {"key": "udp_custom", "label": "UDP Custom", "port": int(os.environ.get("UDP_PORT", "36712")), "service": "udp-custom"},
]

UDP_DIR = "/root/udp"
UDP_BIN = "/root/udp/udp-custom"
UDP_CFG = "/root/udp/config.json"

app = Flask(__name__)


def ensure_dirs():
    for d in (LIMIT_DIR, INFO_DIR, PANEL_DIR):
        os.makedirs(d, exist_ok=True)


def get_secret_key():
    ensure_dirs()
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE) as f:
        return f.read().strip()


def load_auth():
    ensure_dirs()
    if not os.path.exists(AUTH_FILE):
        default = {"username": "admin", "password_hash": generate_password_hash("admin123")}
        save_auth(default)
        return default
    with open(AUTH_FILE) as f:
        return json.load(f)


def save_auth(data):
    ensure_dirs()
    with open(AUTH_FILE, "w") as f:
        json.dump(data, f)
    os.chmod(AUTH_FILE, 0o600)


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*a, **kw)

    return wrapper


def get_expire(user):
    try:
        out = subprocess.run(["chage", "-l", user], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if line.strip().startswith("Account expires"):
                val = line.split(":", 1)[1].strip()
                return val
    except Exception:
        pass
    return "-"


def is_expired(expire_str):
    """Return True if account is expired."""
    if not expire_str or expire_str in ("-", "never"):
        return False
    try:
        from datetime import datetime
        exp = datetime.strptime(expire_str.strip(), "%b %d, %Y")
        return exp < datetime.now()
    except Exception:
        try:
            from datetime import datetime
            exp = datetime.strptime(expire_str.strip(), "%Y-%m-%d")
            return exp < datetime.now()
        except Exception:
            return False


ONLINE_FILE = "/var/run/ws-ssh/online_ips.json"

def get_online_count(user):
    try:
        out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5).stdout
        needle = f"sshd: {user}"
        return sum(1 for line in out.splitlines() if needle in line and "grep" not in line and "[priv]" not in line)
    except Exception:
        return 0


def get_online_ips(user):
    """Return list of real client IPs from limiter's online_ips.json"""
    try:
        if not os.path.exists(ONLINE_FILE):
            return []
        with open(ONLINE_FILE) as f:
            data = json.load(f)
        sessions = data.get(user, [])
        return [s.get("ip", "unknown") for s in sessions if s.get("ip") and s.get("ip") != "unknown"]
    except Exception:
        return []


# --------------------------------------------------------------- traffic ----
# Per-user traffic is tagged in iptables with a comment so we can find it
# again: "wsdata-{user}-out" for upload (server -> client, OUTPUT chain) and
# "wsdata-{user}-in" for download (client -> server, INPUT chain). Older
# installs only ever created the "-out"-less legacy rule
# ("wsdata-{user}", no suffix) which is upload-only, so both the legacy tag
# and the new tags are recognised for backward compatibility.

def _uid_of(user):
    try:
        return subprocess.run(["id", "-u", user], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""


def ensure_traffic_rules(user):
    """Make sure both the OUTPUT (upload) and INPUT (download) counters
    exist for a user. Safe to call repeatedly (checks -C before -A) so it
    can be used both at user-creation time and as a one-off backfill for
    users created by an older version of this panel that only had the
    OUTPUT rule."""
    uid = _uid_of(user)
    if not uid:
        return
    rules = [
        ("OUTPUT", f"wsdata-{user}-out"),
        ("INPUT", f"wsdata-{user}-in"),
    ]
    for chain, comment in rules:
        check = subprocess.run(
            ["iptables", "-C", chain, "-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            capture_output=True,
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-A", chain, "-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
                capture_output=True,
            )


def remove_traffic_rules(user, uid):
    """Delete both directions' counters plus the legacy no-suffix rule."""
    if not uid:
        return
    targets = [
        ("OUTPUT", f"wsdata-{user}-out"),
        ("INPUT", f"wsdata-{user}-in"),
        ("OUTPUT", f"wsdata-{user}"),  # legacy upload-only rule
    ]
    for chain, comment in targets:
        subprocess.run(
            ["iptables", "-D", chain, "-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            capture_output=True,
        )


def _chain_bytes(chain, comment):
    try:
        out = subprocess.run(
            ["iptables", "-L", chain, "-v", "-n", "-x"], capture_output=True, text=True, timeout=5
        ).stdout
        total = 0
        for line in out.splitlines():
            if comment in line:
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    total += int(parts[1])
        return total
    except Exception:
        return 0


def human_bytes(n):
    """
    Format a byte count into a clear, human-readable string with an
    auto-selected unit — e.g. 512 -> "512 B", 104857600 -> "100 MB",
    1073741824 -> "1 GB", 1099511627776 -> "1 TB".
    Uses 1 decimal place except for whole numbers, so "1 GB" not "1.0 GB"
    but "2.4 GB" when it isn't a round number.
    """
    n = float(n or 0)
    units = [("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024), ("B", 1)]
    for label, size in units:
        if n >= size or label == "B":
            val = n / size
            if val == int(val):
                return f"{int(val)} {label}"
            return f"{val:.1f} {label}"
    return "0 B"


def get_usage_bytes(user):
    """Total traffic (upload + download) for a user, in raw bytes.

    Upload  = OUTPUT chain, comment wsdata-{user}-out (new) or
              wsdata-{user} (legacy, upload-only rule from older installs).
    Download = INPUT chain, comment wsdata-{user}-in.
    """
    upload_bytes = _chain_bytes("OUTPUT", f"wsdata-{user}-out")
    if upload_bytes == 0:
        # fall back to the legacy untagged-direction rule so existing
        # installs don't suddenly show 0 usage after upgrading the panel
        upload_bytes = _chain_bytes("OUTPUT", f"wsdata-{user}")
    download_bytes = _chain_bytes("INPUT", f"wsdata-{user}-in")
    return upload_bytes + download_bytes


def get_usage_gb(user):
    """Backward-compat: total traffic in GB (float, 3dp). Prefer
    get_usage_bytes()+human_bytes() for display; this is kept for any
    code/sorting that wants a plain numeric GB value."""
    return round(get_usage_bytes(user) / 1024 / 1024 / 1024, 3)


def get_usage_detail_gb(user):
    """Usage detail broken out by direction, both as raw bytes and as a
    clear human-readable string (100MB / 1GB / 10GB / 1TB style) for the
    detail view."""
    upload_bytes = _chain_bytes("OUTPUT", f"wsdata-{user}-out") or _chain_bytes("OUTPUT", f"wsdata-{user}")
    download_bytes = _chain_bytes("INPUT", f"wsdata-{user}-in")
    total_bytes = upload_bytes + download_bytes
    return {
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "total_bytes": total_bytes,
        "upload_fmt": human_bytes(upload_bytes),
        "download_fmt": human_bytes(download_bytes),
        "total_fmt": human_bytes(total_bytes),
        # kept for backward compat with any existing caller expecting *_gb
        "upload_gb": round(upload_bytes / 1024 / 1024 / 1024, 3),
        "download_gb": round(download_bytes / 1024 / 1024 / 1024, 3),
        "total_gb": round(total_bytes / 1024 / 1024 / 1024, 3),
    }


def user_exists(user):
    return subprocess.run(["id", user], capture_output=True).returncode == 0


def kick_user(user):
    """Forcefully disconnect ALL sessions for a user — the exact same action
    as clicking 'Kick' in the dashboard. Shared by the manual API route and
    the automatic background enforcer below."""
    subprocess.run(["pkill", "-9", "-u", user])


def list_users():
    ensure_dirs()
    rows = []
    for user in sorted(os.listdir(LIMIT_DIR)):
        limit_path = os.path.join(LIMIT_DIR, user)
        if not os.path.isfile(limit_path):
            continue
        try:
            limit = open(limit_path).read().strip()
        except Exception:
            limit = "-"
        info_path = os.path.join(INFO_DIR, user)
        password = open(info_path).read().strip() if os.path.exists(info_path) else "-"
        exp = get_expire(user)
        usage_bytes = get_usage_bytes(user)
        rows.append(
            {
                "username": user,
                "password": password,
                "expire": exp,
                "expired": is_expired(exp),
                "limit": limit,
                "online": get_online_count(user),
                "online_ips": get_online_ips(user),
                "usage_bytes": usage_bytes,
                "usage_fmt": human_bytes(usage_bytes),
            }
        )
    return rows


# ------------------------------------------------------- system monitor ----

def get_system_stats():
    """CPU / RAM / Disk usage as percentages, plus a couple of raw figures
    for context. Uses psutil when it's available (installed by the panel's
    installer); falls back to /proc and shutil.disk_usage otherwise so the
    dashboard still works on a minimal box without the dependency."""
    stats = {"cpu_percent": 0.0, "ram_percent": 0.0, "ram_used_gb": 0.0, "ram_total_gb": 0.0,
             "disk_percent": 0.0, "disk_used_gb": 0.0, "disk_total_gb": 0.0}

    if psutil is not None:
        try:
            stats["cpu_percent"] = round(psutil.cpu_percent(interval=0.3), 1)
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            stats["ram_percent"] = round(vm.percent, 1)
            stats["ram_used_gb"] = round(vm.used / 1024 / 1024 / 1024, 2)
            stats["ram_total_gb"] = round(vm.total / 1024 / 1024 / 1024, 2)
        except Exception:
            pass
        try:
            du = psutil.disk_usage("/")
            stats["disk_percent"] = round(du.percent, 1)
            stats["disk_used_gb"] = round(du.used / 1024 / 1024 / 1024, 2)
            stats["disk_total_gb"] = round(du.total / 1024 / 1024 / 1024, 2)
        except Exception:
            pass
        return stats

    # ---- fallback path (no psutil) ----
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        cores = os.cpu_count() or 1
        stats["cpu_percent"] = round(min(load1 / cores * 100, 100), 1)
    except Exception:
        pass
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                meminfo[k.strip()] = int(v.strip().split()[0])  # kB
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", 0)
        used = max(total - avail, 0)
        if total:
            stats["ram_percent"] = round(used / total * 100, 1)
            stats["ram_used_gb"] = round(used / 1024 / 1024, 2)
            stats["ram_total_gb"] = round(total / 1024 / 1024, 2)
    except Exception:
        pass
    try:
        du = shutil.disk_usage("/")
        stats["disk_percent"] = round(du.used / du.total * 100, 1)
        stats["disk_used_gb"] = round(du.used / 1024 / 1024 / 1024, 2)
        stats["disk_total_gb"] = round(du.total / 1024 / 1024 / 1024, 2)
    except Exception:
        pass
    return stats


# -------------------------------------------------------- service check ----

def _systemd_is_active(unit):
    """Return True/False/None (None = unit not found / systemctl unavailable,
    as opposed to a definite down state)."""
    try:
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        state = r.stdout.strip()
        if state == "active":
            return True
        if state in ("inactive", "failed", "activating", "deactivating"):
            return False
        return None
    except Exception:
        return None


def _port_is_open(port, host="127.0.0.1", timeout=2):
    if not port:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def get_services_status():
    """Check each watched service/port. A service is reported 'up' if either
    the systemd unit is active OR (when there's no matching unit / systemd
    isn't in play) the port is reachable — so this still works for the
    optional ws-ssl unit that isn't installed unless the operator chose an
    SSL port during install."""
    results = []
    for svc in WATCHED_SERVICES:
        systemd_state = _systemd_is_active(svc["service"]) if svc.get("service") else None
        port_state = _port_is_open(svc.get("port")) if svc.get("port") else None

        if systemd_state is None and port_state is None:
            # neither check gave us anything meaningful (e.g. optional
            # service not installed) — skip it instead of showing a
            # misleading red warning
            if svc.get("port") is None and systemd_state is None:
                # still show it as unknown/not-installed rather than hiding,
                # unless it's a genuinely optional unit with no unit file
                pass

        is_up = bool(systemd_state) or bool(port_state)
        # only mark "down" (red) if we got at least one definite signal;
        # if both checks are None, treat as "not installed" rather than down
        known = systemd_state is not None or port_state is not None
        results.append({
            "key": svc["key"],
            "label": svc["label"],
            "up": is_up,
            "known": known,
        })

    # de-duplicate ssh / sshd into a single "SSH" row (different distros
    # name the unit differently; whichever one resolves wins)
    merged = []
    seen_ssh = None
    for r in results:
        if r["key"] in ("ssh", "ssh_alt"):
            if seen_ssh is None:
                r["label"] = "SSH (22)"
                seen_ssh = r
                merged.append(r)
            else:
                if r["up"] or r["known"]:
                    seen_ssh["up"] = seen_ssh["up"] or r["up"]
                    seen_ssh["known"] = seen_ssh["known"] or r["known"]
        else:
            merged.append(r)
    return merged


# ---------------------------------------------------------------- auth ----

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        auth = load_auth()
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == auth["username"] and check_password_hash(auth["password_hash"], p):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Username/Password မှားနေပါသည်")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------- dashboard ----

@app.route("/")
@login_required
def dashboard():
    users = list_users()
    stats = {
        "total": len(users),
        "online": sum(1 for u in users if u["online"] > 0),
        "ended": sum(1 for u in users if u["expired"]),
    }
    stats["active"] = stats["total"] - stats["ended"]
    return render_template(
        "dashboard.html",
        users=users,
        stats=stats,
        panel_user=load_auth()["username"],
        sys_stats=get_system_stats(),
        services=get_services_status(),
    )


@app.route("/api/sysstats")
@login_required
def api_sysstats():
    return jsonify(ok=True, stats=get_system_stats(), services=get_services_status())


@app.route("/api/usage/<username>")
@login_required
def api_usage(username):
    if not USERNAME_RE.match(username) or not user_exists(username):
        return jsonify(ok=False, error="User မရှိပါ"), 400
    return jsonify(ok=True, **get_usage_detail_gb(username))


@app.route("/api/create", methods=["POST"])
@login_required
def api_create():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    password = data.get("password") or ""
    try:
        days = int(data.get("days", 30))
        limit = int(data.get("limit", 1))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="days/limit must be numbers"), 400

    if not USERNAME_RE.match(user):
        return jsonify(ok=False, error="Username မှားနေပါသည် (a-z,0-9,_,- only)"), 400
    if not password:
        return jsonify(ok=False, error="Password ထည့်ပါ"), 400
    if user_exists(user):
        return jsonify(ok=False, error="User ရှိနှင့်ပြီးပါပြီ"), 400

    exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    try:
        subprocess.run(["useradd", "-M", "-N", "-s", "/usr/sbin/nologin", "-e", exp, user], check=True)
        subprocess.run(["chpasswd"], input=f"{user}:{password}\n", text=True, check=True)
        ensure_traffic_rules(user)
    except subprocess.CalledProcessError as e:
        return jsonify(ok=False, error=f"system command failed: {e}"), 500

    ensure_dirs()
    with open(os.path.join(LIMIT_DIR, user), "w") as f:
        f.write(str(limit))
    with open(os.path.join(INFO_DIR, user), "w") as f:
        f.write(password)
    os.chmod(os.path.join(INFO_DIR, user), 0o600)
    return jsonify(ok=True, expire=exp)


@app.route("/api/delete", methods=["POST"])
@login_required
def api_delete():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    if not USERNAME_RE.match(user):
        return jsonify(ok=False, error="bad username"), 400

    if user_exists(user):
        uid = _uid_of(user)
        subprocess.run(["pkill", "-9", "-u", user])
        remove_traffic_rules(user, uid)
        subprocess.run(["userdel", "-f", user])

    for d in (LIMIT_DIR, INFO_DIR):
        p = os.path.join(d, user)
        if os.path.exists(p):
            os.remove(p)
    return jsonify(ok=True)


@app.route("/api/kick", methods=["POST"])
@login_required
def api_kick():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    if not USERNAME_RE.match(user) or not user_exists(user):
        return jsonify(ok=False, error="User မရှိပါ"), 400
    kick_user(user)
    return jsonify(ok=True)


@app.route("/api/renew", methods=["POST"])
@login_required
def api_renew():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    try:
        days = int(data.get("days", 30))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="days must be a number"), 400

    if not USERNAME_RE.match(user) or not user_exists(user):
        return jsonify(ok=False, error="User မရှိပါ"), 400

    exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    r = subprocess.run(["chage", "-E", exp, user])
    if r.returncode != 0:
        return jsonify(ok=False, error="renew failed"), 500
    # Unlock the password (strip a leading "!" in /etc/shadow, if present)
    # and clear any PAM failed-login lockout — either can be left behind
    # from the time the account was expired, and chage -E alone won't
    # clear them.
    for cmd in (
        ["passwd", "-u", user],
        ["faillock", "--user", user, "--reset"],
        ["pam_tally2", "--user", user, "--reset"],
    ):
        try:
            subprocess.run(cmd, capture_output=True)
        except FileNotFoundError:
            pass
    return jsonify(ok=True, expire=exp)


@app.route("/api/setlimit", methods=["POST"])
@login_required
def api_setlimit():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    if not USERNAME_RE.match(user) or not os.path.exists(os.path.join(LIMIT_DIR, user)):
        return jsonify(ok=False, error="User မရှိပါ"), 400
    try:
        limit = int(data.get("limit"))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="limit must be a number"), 400
    with open(os.path.join(LIMIT_DIR, user), "w") as f:
        f.write(str(limit))
    return jsonify(ok=True)


@app.route("/api/changepassword", methods=["POST"])
@login_required
def api_changepassword():
    data = request.get_json(force=True) or {}
    newuser = (data.get("username") or "").strip()
    newpass = data.get("password") or ""
    if len(newpass) < 6:
        return jsonify(ok=False, error="Password အနည်းဆုံး 6 လုံးရှိရပါမယ်"), 400
    cur = load_auth()
    auth = {"username": newuser or cur["username"], "password_hash": generate_password_hash(newpass)}
    save_auth(auth)
    session.clear()
    return jsonify(ok=True)


# ================================================================ UDP Custom ====

def udp_config_load():
    """Load /root/udp/config.json; return dict (with defaults if missing)."""
    defaults = {"listen": ":36712", "stream_buffer": 33554432, "receive_buffer": 83886080,
                "auth": {"mode": "passwords", "passwords": []}}
    try:
        with open(UDP_CFG) as f:
            return json.load(f)
    except Exception:
        return defaults

def udp_config_save(cfg):
    os.makedirs(UDP_DIR, exist_ok=True)
    with open(UDP_CFG, "w") as f:
        json.dump(cfg, f, indent=2)

def udp_passwords():
    """Return list of password strings from config."""
    cfg = udp_config_load()
    auth = cfg.get("auth", {})
    if auth.get("mode") == "passwords":
        return auth.get("passwords", [])
    return []

def udp_set_passwords(passwords):
    cfg = udp_config_load()
    cfg.setdefault("auth", {})
    cfg["auth"]["mode"] = "passwords"
    cfg["auth"]["passwords"] = passwords
    udp_config_save(cfg)
    # Restart service to apply
    subprocess.run(["systemctl", "restart", "udp-custom"], capture_output=True)

@app.route("/api/udp/status")
@login_required
def api_udp_status():
    """Return udp-custom service status and current port."""
    svc = subprocess.run(["systemctl", "is-active", "udp-custom"],
                         capture_output=True, text=True).stdout.strip()
    cfg = udp_config_load()
    listen = cfg.get("listen", ":36712")
    port = listen.split(":")[-1] if ":" in listen else listen
    passwords = udp_passwords()
    return jsonify(ok=True, active=(svc == "active"), port=port,
                   passwords=passwords, user_count=len(passwords))

@app.route("/api/udp/toggle", methods=["POST"])
@login_required
def api_udp_toggle():
    """Start or stop udp-custom service."""
    svc = subprocess.run(["systemctl", "is-active", "udp-custom"],
                         capture_output=True, text=True).stdout.strip()
    if svc == "active":
        subprocess.run(["systemctl", "stop", "udp-custom"])
        return jsonify(ok=True, active=False)
    else:
        subprocess.run(["systemctl", "start", "udp-custom"])
        return jsonify(ok=True, active=True)

@app.route("/api/udp/setport", methods=["POST"])
@login_required
def api_udp_setport():
    data = request.get_json(force=True) or {}
    try:
        port = int(data.get("port", 0))
        if not (1024 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Port မှားနေပါသည် (1024-65535)"), 400
    cfg = udp_config_load()
    cfg["listen"] = f":{port}"
    udp_config_save(cfg)
    subprocess.run(["systemctl", "restart", "udp-custom"], capture_output=True)
    return jsonify(ok=True, port=port)

@app.route("/api/udp/adduser", methods=["POST"])
@login_required
def api_udp_adduser():
    """Add a password to udp-custom auth list (uses SSH user's password)."""
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not user or not password:
        return jsonify(ok=False, error="username/password ထည့်ပါ"), 400
    # Store as "username:password" so we can identify per user
    entry = f"{user}:{password}"
    passwords = udp_passwords()
    # Remove old entry for same user if exists
    passwords = [p for p in passwords if not p.startswith(f"{user}:")]
    passwords.append(entry)
    udp_set_passwords(passwords)
    return jsonify(ok=True)

@app.route("/api/udp/removeuser", methods=["POST"])
@login_required
def api_udp_removeuser():
    data = request.get_json(force=True) or {}
    user = (data.get("username") or "").strip()
    if not user:
        return jsonify(ok=False, error="username ထည့်ပါ"), 400
    passwords = udp_passwords()
    passwords = [p for p in passwords if not p.startswith(f"{user}:")]
    udp_set_passwords(passwords)
    return jsonify(ok=True)

# ============================================================ end UDP Custom ====

app.secret_key = get_secret_key()

# ---------------------------------------------------- auto-kick enforcer ----
# Runs in the background for as long as the panel process is alive (the
# systemd service keeps the panel running 24/7 with Restart=always).
# Every AUTO_KICK_INTERVAL seconds it checks each managed user's online
# session count against their device limit. If a user is OVER their limit,
# it performs the exact same action as clicking "Kick" in the dashboard —
# no manual click needed.
AUTO_KICK_INTERVAL = int(os.environ.get("AUTO_KICK_INTERVAL", "5"))


def auto_kick_enforcer():
    while True:
        try:
            for u in list_users():
                try:
                    limit = int(u["limit"])
                except (TypeError, ValueError):
                    continue
                if u["online"] > limit:
                    kick_user(u["username"])
        except Exception:
            pass
        time.sleep(AUTO_KICK_INTERVAL)


def backfill_traffic_rules():
    """One-time-per-boot pass so users created by an older version of this
    panel (upload-only OUTPUT rule) get the missing INPUT (download) rule
    added, without ever touching or duplicating existing rules."""
    try:
        ensure_dirs()
        for user in os.listdir(LIMIT_DIR):
            if user_exists(user):
                ensure_traffic_rules(user)
    except Exception:
        pass


if __name__ == "__main__":
    ensure_dirs()
    load_auth()
    backfill_traffic_rules()
    threading.Thread(target=auto_kick_enforcer, daemon=True).start()
    port = int(os.environ.get("PANEL_PORT", "2053"))
    app.run(host="0.0.0.0", port=port)
APPEOF


echo -e "${YELLOW}[*] writing templates ...${NC}"
cat <<'LOGINEOF' > /opt/ws-panel/templates/login.html
<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SSH-WS Panel · Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&family=JetBrains+Mono:wght@500&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0d13; --card:#12161f; --card2:#0e121a; --border:#1e2430;
    --text:#e9edf5; --muted:#7d8699; --faint:#4d5566;
    --signal:#2dd4bf; --accent:#5b8def; --danger:#f0525f;
  }
  *{box-sizing:border-box; -webkit-tap-highlight-color:transparent;}
  body{
    margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:var(--bg); color:var(--text); padding:20px;
    font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;
  }
  .card{
    width:100%; max-width:360px; background:var(--card); border:1px solid var(--border);
    border-radius:20px; padding:34px 28px; box-shadow:0 20px 50px rgba(0,0,0,.45);
  }
  .mark{
    width:44px; height:44px; border-radius:13px; margin-bottom:18px;
    background:linear-gradient(150deg,var(--signal),#1a8f82);
    display:flex; align-items:center; justify-content:center;
    font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:20px; color:#04211d;
  }
  h1{font-family:'Space Grotesk',sans-serif; font-size:21px; margin:0 0 4px;}
  p.sub{color:var(--muted); margin:0 0 26px; font-size:13.5px;}
  label{font-size:12.5px; color:var(--muted); display:block; margin:16px 0 7px;}
  input{
    width:100%; padding:12px 14px; border-radius:11px; border:1px solid var(--border);
    background:var(--card2); color:var(--text); font-size:14.5px; font-family:'JetBrains Mono',monospace;
  }
  input:focus{outline:none; border-color:var(--accent);}
  button{
    width:100%; margin-top:24px; padding:13px; border:none; border-radius:12px;
    background:linear-gradient(150deg,var(--accent),#3f6fd6); color:#fff;
    font-family:'Inter',sans-serif; font-size:15px; font-weight:600; cursor:pointer;
  }
  button:active{transform:scale(.98);}
  .err{
    color:var(--danger); font-size:13px; margin-top:16px; text-align:center;
    background:rgba(240,82,95,.1); border:1px solid rgba(240,82,95,.25);
    border-radius:9px; padding:9px;
  }
  .credit{color:var(--faint); font-size:11px; text-align:center; margin-top:22px; letter-spacing:.3px;}
</style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <div class="mark">W</div>
    <h1>SSH-WS Panel</h1>
    <p class="sub">အက်ဒမင် အကောင့်ဝင်ရန်</p>
    <label>အသုံးပြုသူအမည်</label>
    <input name="username" autocomplete="username" required autocapitalize="off">
    <label>စကားဝှက်</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">ဝင်မည်</button>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <div class="credit">Dev Phoe Shan</div>
  </form>
</body>
</html>

LOGINEOF

cat <<'DASHEOF' > /opt/ws-panel/templates/dashboard.html
<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SSH-WS Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0d13; --bg2:#070911;
    --card:#12161f; --card2:#0e121a; --border:#1e2430; --row:#171c26;
    --text:#e9edf5; --muted:#7d8699; --faint:#4d5566;
    --signal:#2dd4bf; --accent:#5b8def; --danger:#f0525f; --warn:#e8b339;
    font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;
  }
  *{box-sizing:border-box; -webkit-tap-highlight-color:transparent;}
  html,body{margin:0; background:var(--bg); color:var(--text);}
  body{min-height:100vh; padding-bottom:calc(84px + env(safe-area-inset-bottom)); -webkit-font-smoothing:antialiased;}
  h1,h2,h3{font-family:'Space Grotesk',sans-serif;}
  .mono{font-family:'JetBrains Mono',ui-monospace,monospace;}

  header{
    position:sticky; top:0; z-index:30; display:flex; align-items:center; justify-content:space-between;
    padding:14px 18px; padding-top:calc(14px + env(safe-area-inset-top));
    background:rgba(10,13,19,.85); backdrop-filter:blur(14px); border-bottom:1px solid var(--border);
  }
  .brand{display:flex; align-items:center; gap:10px;}
  .brand .mark{
    width:30px; height:30px; border-radius:9px; flex:none;
    background:linear-gradient(150deg,var(--signal),#1a8f82);
    display:flex; align-items:center; justify-content:center;
    font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:14px; color:#04211d;
  }
  .brand h1{font-size:16px; font-weight:600; margin:0;}
  .brand .env{font-size:10.5px; color:var(--muted); margin-top:1px;}
  .avatar-btn{
    width:34px; height:34px; border-radius:50%; border:1px solid var(--border);
    background:var(--card2); color:var(--muted); display:flex; align-items:center;
    justify-content:center; font-size:13px; font-weight:600;
  }

  main{padding:16px 16px 8px; max-width:640px; margin:0 auto;}

  .signals{display:flex; gap:8px; overflow-x:auto; padding:2px 2px 14px; margin:0 -2px 4px; scrollbar-width:none;}
  .signals::-webkit-scrollbar{display:none;}
  .sigchip{
    flex:none; display:flex; align-items:center; gap:7px; padding:8px 13px;
    background:var(--card); border:1px solid var(--border); border-radius:999px;
    font-size:12px; font-weight:500; color:var(--muted); white-space:nowrap;
  }
  .sigdot{width:7px; height:7px; border-radius:50%; flex:none; background:var(--faint); position:relative;}
  .sigchip.up{color:var(--text);}
  .sigchip.up .sigdot{background:var(--signal);}
  .sigchip.up .sigdot::after{
    content:''; position:absolute; inset:-4px; border-radius:50%;
    border:1.5px solid var(--signal); animation:ping 2.2s cubic-bezier(.4,0,.3,1) infinite;
  }
  .sigchip.down{color:var(--danger);}
  .sigchip.down .sigdot{background:var(--danger);}
  @keyframes ping{0%{transform:scale(.6); opacity:.9;} 75%,100%{transform:scale(1.9); opacity:0;}}
  @media (prefers-reduced-motion:reduce){ .sigchip.up .sigdot::after{animation:none; display:none;} }

  .stats{display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-bottom:18px;}
  .stat{background:var(--card); border:1px solid var(--border); border-radius:14px; padding:14px 16px;}
  .stat .n{font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; line-height:1;}
  .stat .l{color:var(--muted); font-size:11.5px; margin-top:6px;}
  .stat.online .n{color:var(--signal);}
  .stat.ended .n{color:var(--danger);}

  .sysrow{display:flex; gap:8px; margin-bottom:20px;}
  .sysmini{flex:1; background:var(--card); border:1px solid var(--border); border-radius:12px; padding:10px 12px;}
  .sysmini .top{display:flex; justify-content:space-between; font-size:10.5px; color:var(--muted); margin-bottom:6px;}
  .sysmini .pct{font-weight:600; color:var(--text); font-size:11px;}
  .bar{width:100%; height:4px; border-radius:99px; background:var(--card2); overflow:hidden;}
  .bar>span{display:block; height:100%; border-radius:99px; background:var(--signal); transition:width .4s;}
  .bar.warn>span{background:var(--warn);}
  .bar.danger>span{background:var(--danger);}
  .sysmini.warn .pct{color:var(--warn);} .sysmini.danger .pct{color:var(--danger);}
  .sysmini .sub{font-size:9.5px; color:var(--faint); margin-top:5px;}

  .section-head{display:flex; align-items:center; justify-content:space-between; margin:4px 2px 10px;}
  .section-head h2{font-size:13px; font-weight:600; margin:0; color:var(--muted); letter-spacing:.3px; text-transform:uppercase;}
  .count-pill{font-size:11px; color:var(--faint); font-family:'JetBrains Mono',monospace;}

  .search{
    display:flex; align-items:center; gap:9px; background:var(--card);
    border:1px solid var(--border); border-radius:12px; padding:11px 14px; margin-bottom:12px;
  }
  .search svg{flex:none; color:var(--faint);}
  .search input{border:none; background:none; outline:none; color:var(--text); font-size:14px; width:100%;}
  .search input::placeholder{color:var(--faint);}

  .ulist{display:flex; flex-direction:column; gap:8px; margin-bottom:26px;}
  .ucard{
    background:var(--card); border:1px solid var(--border); border-radius:14px;
    padding:13px 14px; display:flex; flex-direction:column; gap:9px; cursor:pointer;
    transition:border-color .15s;
  }
  .ucard:active{border-color:var(--accent);}
  .ucard.expired{background:linear-gradient(180deg,rgba(240,82,95,.06),var(--card) 60%); border-color:rgba(240,82,95,.28);}
  .urow-top{display:flex; align-items:center; justify-content:space-between; gap:8px;}
  .uid{display:flex; align-items:center; gap:9px; min-width:0;}
  .uid .dot{width:8px; height:8px; border-radius:50%; flex:none; background:var(--faint);}
  .uid .dot.on{background:var(--signal); box-shadow:0 0 0 3px rgba(45,212,191,.15);}
  .uname{font-family:'JetBrains Mono',monospace; font-weight:600; font-size:14px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}
  .expired .uname{color:var(--danger);}
  .chev{color:var(--faint); flex:none;}
  .urow-meta{display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-size:11.5px; color:var(--muted);}
  .pill{padding:3px 9px; border-radius:999px; background:var(--card2); border:1px solid var(--border); font-size:11px;}
  .pill.expired{background:rgba(240,82,95,.14); color:var(--danger); border-color:rgba(240,82,95,.3);}
  .pill.online{background:rgba(45,212,191,.12); color:var(--signal); border-color:rgba(45,212,191,.28);}
  .pill.usage{font-family:'JetBrains Mono',monospace;}
  .ipchips{display:flex; gap:5px; flex-wrap:wrap;}
  .ipchip{
    font-family:'JetBrains Mono',monospace; font-size:10.5px; color:var(--accent);
    background:rgba(91,141,239,.1); border:1px solid rgba(91,141,239,.25); border-radius:6px; padding:2px 6px;
  }
  .empty{padding:50px 20px; text-align:center; color:var(--muted); font-size:13.5px;}
  .empty .big{font-size:30px; margin-bottom:10px;}

  .fab{
    position:fixed; right:18px; bottom:calc(22px + env(safe-area-inset-bottom));
    width:56px; height:56px; border-radius:50%; border:none; z-index:25;
    background:linear-gradient(150deg,var(--accent),#3f6fd6); color:#fff;
    display:flex; align-items:center; justify-content:center;
    box-shadow:0 8px 22px rgba(91,141,239,.4); cursor:pointer;
  }
  .fab:active{transform:scale(.94);}

  .scrim{
    position:fixed; inset:0; background:rgba(4,5,9,.6); backdrop-filter:blur(2px);
    opacity:0; pointer-events:none; transition:opacity .22s; z-index:40;
  }
  .scrim.show{opacity:1; pointer-events:auto;}
  .sheet{
    position:fixed; left:0; right:0; bottom:0; z-index:41;
    background:var(--card); border:1px solid var(--border); border-bottom:none;
    border-radius:20px 20px 0 0; padding:10px 18px calc(22px + env(safe-area-inset-bottom));
    transform:translateY(100%); transition:transform .28s cubic-bezier(.32,.72,0,1);
    max-height:85vh; overflow-y:auto;
  }
  .sheet.show{transform:translateY(0);}
  .sheet .grabber{width:36px; height:4px; border-radius:99px; background:var(--border); margin:2px auto 16px;}
  .sheet h3{font-family:'JetBrains Mono',monospace; font-size:17px; margin:0 0 2px; display:flex; align-items:center; gap:8px;}
  .sheet .subtxt{color:var(--muted); font-size:12.5px; margin-bottom:16px;}
  .sheet-grid{display:grid; grid-template-columns:1fr 1fr; gap:9px; margin-bottom:8px;}
  .sbtn{
    display:flex; flex-direction:column; align-items:center; gap:7px; padding:15px 8px;
    border-radius:14px; border:1px solid var(--border); background:var(--card2); color:var(--text);
    font-size:12.5px; font-weight:500; font-family:'Inter',sans-serif;
  }
  .sbtn svg{color:var(--accent);}
  .sbtn.danger svg{color:var(--danger);}
  .sbtn.danger{border-color:rgba(240,82,95,.25);}
  .sheet .field{margin-top:14px;}
  .sheet .field label{font-size:11.5px; color:var(--muted); display:block; margin-bottom:6px;}
  .sheet .field .valrow{
    display:flex; align-items:center; justify-content:space-between; gap:10px;
    background:var(--card2); border:1px solid var(--border); border-radius:10px; padding:10px 13px;
  }
  .sheet .field .valrow span{font-family:'JetBrains Mono',monospace; font-size:13.5px;}
  .copybtn{background:none; border:none; color:var(--faint); padding:4px;}

  .field-in{margin-bottom:13px;}
  .field-in label{font-size:12px; color:var(--muted); display:block; margin-bottom:6px;}
  .field-in input{
    width:100%; padding:11px 13px; border-radius:10px; border:1px solid var(--border);
    background:var(--card2); color:var(--text); font-size:14px; font-family:'JetBrains Mono',monospace;
  }
  .field-in input:focus{outline:none; border-color:var(--accent);}
  .primary-btn{
    width:100%; padding:13px; border:none; border-radius:12px; margin-top:6px;
    background:var(--accent); color:#fff; font-weight:600; font-size:14.5px; font-family:'Inter',sans-serif;
  }
  .primary-btn.danger{background:var(--danger);}
  .msg{font-size:12.5px; margin-top:10px; min-height:16px;}
  .msg.err{color:var(--danger);}
  .msg.ok{color:var(--signal);}

  .daychips{display:flex; gap:8px; flex-wrap:wrap;}
  .daychip{
    padding:9px 15px; border-radius:999px; border:1px solid var(--border);
    background:var(--card2); color:var(--text); font-size:13.5px; font-weight:600;
    font-family:'JetBrains Mono',monospace;
  }
  .daychip.active{background:rgba(45,212,191,.14); border-color:var(--signal); color:var(--signal);}

  .toast{
    position:fixed; left:50%; bottom:100px; transform:translateX(-50%) translateY(10px);
    background:#1a1f2b; border:1px solid var(--border); color:var(--text); font-size:13px;
    padding:10px 18px; border-radius:999px; opacity:0; pointer-events:none;
    transition:all .25s; z-index:60; white-space:nowrap;
  }
  .toast.show{opacity:1; transform:translateX(-50%) translateY(0);}
  .credit{color:var(--faint); font-size:11px; text-align:center; margin:18px 0 6px;}
</style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="mark">W</div>
      <div>
        <h1>SSH·WS Panel</h1>
        <div class="env">{{ panel_user }}</div>
      </div>
    </div>
    <button class="avatar-btn" onclick="openSheet('accountSheet')">{{ panel_user[0]|upper }}</button>
  </header>

  <main>
    <div class="signals" id="svcRow">
      {% for s in services %}
        <span class="sigchip {{ 'up' if s.up else ('down' if s.known else '') }}">
          <span class="sigdot"></span>{{ s.label }}
        </span>
      {% endfor %}
    </div>

    <div class="stats">
      <div class="stat total"><div class="n">{{ stats.total }}</div><div class="l">အသုံးပြုသူ စုစုပေါင်း</div></div>
      <div class="stat online"><div class="n">{{ stats.online }}</div><div class="l">အွန်လိုင်း အခုလက်ရှိ</div></div>
      <div class="stat active"><div class="n">{{ stats.active }}</div><div class="l">သက်တမ်းရှိ</div></div>
      <div class="stat ended"><div class="n">{{ stats.ended }}</div><div class="l">သက်တမ်းကုန်</div></div>
    </div>

    <div class="sysrow" id="sysrow">
      <div class="sysmini" id="cpuCard">
        <div class="top"><span>CPU</span><span class="pct" id="cpuPct">{{ sys_stats.cpu_percent }}%</span></div>
        <div class="bar" id="cpuBar"><span style="width:{{ sys_stats.cpu_percent }}%"></span></div>
      </div>
      <div class="sysmini" id="ramCard">
        <div class="top"><span>RAM</span><span class="pct" id="ramPct">{{ sys_stats.ram_percent }}%</span></div>
        <div class="bar" id="ramBar"><span style="width:{{ sys_stats.ram_percent }}%"></span></div>
        <div class="sub" id="ramSub">{{ sys_stats.ram_used_gb }}GB/{{ sys_stats.ram_total_gb }}GB</div>
      </div>
      <div class="sysmini" id="diskCard">
        <div class="top"><span>SSD</span><span class="pct" id="diskPct">{{ sys_stats.disk_percent }}%</span></div>
        <div class="bar" id="diskBar"><span style="width:{{ sys_stats.disk_percent }}%"></span></div>
        <div class="sub" id="diskSub">{{ sys_stats.disk_used_gb }}GB/{{ sys_stats.disk_total_gb }}GB</div>
      </div>
    </div>

    <div class="section-head">
      <h2>Accounts</h2>
      <span class="count-pill" id="countPill">{{ users|length }} users</span>
    </div>

    <div class="search">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
      <input id="searchBox" placeholder="အသုံးပြုသူအမည် ရှာရန်..." oninput="filterUsers()">
    </div>

    <div class="ulist" id="ulist">
      {% for u in users %}
      <div class="ucard {{ 'expired' if u.expired else '' }}"
           data-user="{{ u.username|lower }}"
           data-username="{{ u.username }}"
           data-password="{{ u.password }}"
           data-expire="{{ u.expire }}"
           data-expired="{{ 'true' if u.expired else 'false' }}"
           data-limit="{{ u.limit }}"
           data-online="{{ u.online }}"
           data-usage="{{ u.usage_fmt }}"
           data-ips="{{ u.online_ips|join(',') }}"
           onclick="openUserCard(this)">
        <div class="urow-top">
          <div class="uid">
            <span class="dot {{ 'on' if u.online > 0 else '' }}"></span>
            <span class="uname">{{ u.username }}</span>
          </div>
          <svg class="chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
        </div>
        <div class="urow-meta">
          {% if u.expired %}
            <span class="pill expired">EXPIRED · {{ u.expire }}</span>
          {% else %}
            <span class="pill">{{ u.expire }}</span>
          {% endif %}
          <span class="pill">limit {{ u.limit }}</span>
          <span class="pill usage">{{ u.usage_fmt }}</span>
          {% if u.online > 0 %}<span class="pill online">● {{ u.online }} online</span>{% endif %}
        </div>
        {% if u.online_ips %}
        <div class="ipchips">
          {% for ip in u.online_ips %}<span class="ipchip">{{ ip }}</span>{% endfor %}
        </div>
        {% endif %}
      </div>
      {% endfor %}
    </div>
    <div id="emptyMsg" class="empty" style="display:none;"><div class="big">🔍</div>ရှာဖွေမှုနှင့် ကိုက်ညီသော အသုံးပြုသူ မတွေ့ပါ</div>

    <!-- UDP Custom section -->
    <div class="section-head" style="margin-top:8px;">
      <h2>UDP Custom</h2>
      <span class="count-pill" id="udpUserCount">-</span>
    </div>
    <div class="stat" style="margin-bottom:10px; display:flex; align-items:center; justify-content:space-between; padding:14px 16px;">
      <div>
        <div style="font-size:12px; color:var(--muted);">Port</div>
        <div class="mono" id="udpPort" style="font-size:16px; font-weight:600;">-</div>
      </div>
      <div style="display:flex; gap:10px; align-items:center;">
        <button class="sbtn" onclick="openUdpPortSheet()" style="padding:9px 14px; font-size:12px;">Port ပြောင်း</button>
        <button id="udpToggleBtn" onclick="doUdpToggle()" style="padding:9px 18px; border-radius:12px; border:none; font-weight:600; font-size:13px; cursor:pointer; background:var(--signal); color:#04211d;">-</button>
      </div>
    </div>

    <div class="credit">Dev Phoe Shan</div>
  </main>

  <button class="fab" onclick="openCreateSheet()" aria-label="Add user">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
  </button>

  <div class="scrim" id="scrim" onclick="closeSheets()"></div>

  <!-- Account sheet (avatar button) -->
  <div class="sheet" id="accountSheet">
    <div class="grabber"></div>
    <h3 style="font-family:'Space Grotesk',sans-serif;">{{ panel_user }}</h3>
    <div class="subtxt">Panel admin account</div>
    <div class="field-in">
      <label>အသုံးပြုသူအမည်အသစ် (ရွေးချယ်နိုင်)</label>
      <input id="pw_user" placeholder="{{ panel_user }}">
    </div>
    <div class="field-in">
      <label>စကားဝှက်အသစ်</label>
      <input id="pw_pass" type="password">
    </div>
    <div class="msg" id="pw_msg"></div>
    <button class="primary-btn" onclick="doChangePassword()">စကားဝှက်ပြောင်းမည်</button>
    <button class="primary-btn danger" style="margin-top:9px;" onclick="location.href='/logout'">ထွက်မည်</button>
  </div>

  <!-- User action sheet -->
  <div class="sheet" id="userSheet">
    <div class="grabber"></div>
    <h3><span class="mono" id="sh_dot">●</span> <span id="sh_name">username</span></h3>
    <div class="subtxt" id="sh_sub">-</div>

    <div class="field">
      <label>စကားဝှက်</label>
      <div class="valrow">
        <span id="sh_pw">-</span>
        <button class="copybtn" onclick="copyText(document.getElementById('sh_pw').textContent)">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
      </div>
    </div>

    <div class="sheet-grid" style="margin-top:16px;">
      <button class="sbtn" onclick="openRenewSheet()">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>
        သက်တမ်းတိုးမည်
      </button>
      <button class="sbtn" onclick="doKick()">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.4 15A7.5 7.5 0 1 0 6 18.7"/><path d="M12 8v5l3 2"/></svg>
        ထုတ်ပစ်မည်
      </button>
      <button class="sbtn" onclick="openLimitSheet()">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20" rx="2"/><path d="M8 18h8"/></svg>
        Device ကန့်သတ်
      </button>
      <button class="sbtn danger" onclick="doDelete()">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        ဖျက်မည်
      </button>
      <button class="sbtn" onclick="doUdpAddUser()" id="udpAddBtn">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
        UDP ထည့်
      </button>
      <button class="sbtn danger" onclick="doUdpRemoveUser()" id="udpRemoveBtn">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>
        UDP ဖျက်
      </button>
    </div>
    <div class="msg" id="u_msg"></div>
  </div>

  <!-- Renew sheet -->
  <div class="sheet" id="renewSheet">
    <div class="grabber"></div>
    <h3 style="font-family:'Space Grotesk',sans-serif;">သက်တမ်းတိုးမည်</h3>
    <div class="subtxt"><span id="rn_name">username</span> ကို ဘယ်နှရက် ထပ်ထည့်မလဲ</div>
    <div class="daychips" id="daychips">
      <button class="daychip" data-d="7" onclick="pickDays(7)">+7</button>
      <button class="daychip" data-d="15" onclick="pickDays(15)">+15</button>
      <button class="daychip active" data-d="30" onclick="pickDays(30)">+30</button>
      <button class="daychip" data-d="60" onclick="pickDays(60)">+60</button>
      <button class="daychip" data-d="90" onclick="pickDays(90)">+90</button>
    </div>
    <div class="field-in" style="margin-top:14px;">
      <label>ဒါမှမဟုတ် ကိုယ်တိုင်ထည့်မည် (ရက်)</label>
      <input id="rn_days" type="number" value="30" oninput="customDays()">
    </div>
    <div class="subtxt" style="margin:2px 0 4px;">
      သက်တမ်းသစ် — <span class="mono" id="rn_newdate" style="color:var(--signal); font-weight:600;">-</span>
    </div>
    <div class="msg" id="rn_msg"></div>
    <button class="primary-btn" onclick="confirmRenew()">အတည်ပြု၊ သက်တမ်းတိုးမည်</button>
  </div>

  <!-- Limit sheet -->
  <div class="sheet" id="limitSheet">
    <div class="grabber"></div>
    <h3 style="font-family:'Space Grotesk',sans-serif;">Device ကန့်သတ်ချက်</h3>
    <div class="subtxt"><span id="lm_name">username</span> အတွက် တစ်ပြိုင်နက် login ဝင်ခွင့်</div>
    <div class="field-in">
      <label>Device အရေအတွက်</label>
      <input id="l_value" type="number" value="1">
    </div>
    <div class="msg" id="l_msg"></div>
    <button class="primary-btn" onclick="doLimit()">သိမ်းမည်</button>
  </div>

  <!-- Create user sheet -->
  <div class="sheet" id="createSheet">
    <div class="grabber"></div>
    <h3 style="font-family:'Space Grotesk',sans-serif;">အသုံးပြုသူ အသစ်ဖန်တီးမည်</h3>
    <div class="subtxt">Blank ထားရင် auto-generate လုပ်ပေးမည်</div>
    <div class="field-in">
      <label>အသုံးပြုသူအမည်</label>
      <input id="c_user" placeholder="e.g. mgmg01" autocomplete="off">
    </div>
    <div class="field-in">
      <label>စကားဝှက်</label>
      <input id="c_pass" placeholder="auto">
    </div>
    <div class="field-in">
      <label>သက်တမ်း (ရက်)</label>
      <input id="c_days" type="number" value="30">
    </div>
    <div class="field-in">
      <label>Device ကန့်သတ်ချက်</label>
      <input id="c_limit" type="number" value="1">
    </div>
    <div class="msg" id="c_msg"></div>
    <button class="primary-btn" onclick="doCreate()">ဖန်တီးမည်</button>
  </div>

  <!-- UDP Port sheet -->
  <div class="sheet" id="udpPortSheet">
    <div class="grabber"></div>
    <h3 style="font-family:'Space Grotesk',sans-serif;">UDP Custom Port</h3>
    <div class="subtxt">UDP Custom server listen port ပြောင်းရန်</div>
    <div class="field-in">
      <label>Port (1024-65535)</label>
      <input id="udp_port_val" type="number" value="36712">
    </div>
    <div class="msg" id="udp_port_msg"></div>
    <button class="primary-btn" onclick="doUdpSetPort()">သိမ်းမည် + Restart</button>
  </div>

  <div class="toast" id="toast"></div>

<script>
let curUser = null;

// ------------------------------------------------------------ sheets ----
function openSheet(id){
  document.getElementById('scrim').classList.add('show');
  document.getElementById(id).classList.add('show');
}
function closeSheets(){
  document.getElementById('scrim').classList.remove('show');
  document.querySelectorAll('.sheet').forEach(s=>s.classList.remove('show'));
}
function toast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), 1800);
}
function copyText(t){
  navigator.clipboard && navigator.clipboard.writeText(t);
  toast('Copied');
}

function filterUsers(){
  const q = document.getElementById('searchBox').value.trim().toLowerCase();
  const cards = document.querySelectorAll('#ulist .ucard');
  let visible = 0;
  cards.forEach(c => {
    const match = c.dataset.user.includes(q);
    c.style.display = match ? '' : 'none';
    if(match) visible++;
  });
  document.getElementById('countPill').textContent = visible + ' users';
  document.getElementById('emptyMsg').style.display = (visible === 0) ? 'block' : 'none';
}

// -------------------------------------------------------------- API ----
async function api(url, body){
  const res = await fetch(url, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(()=>({ok:false, error:'invalid response'}));
  return {status:res.status, data};
}

// ------------------------------------------------------- user sheet ----
function openUserCard(el){
  curUser = el.dataset.username;
  document.getElementById('sh_name').textContent = el.dataset.username;
  document.getElementById('sh_pw').textContent = el.dataset.password;
  document.getElementById('sh_dot').style.color = el.dataset.online > 0 ? 'var(--signal)' : 'var(--faint)';
  const ips = el.dataset.ips ? el.dataset.ips.split(',').filter(Boolean) : [];
  document.getElementById('sh_sub').textContent =
    `သက်တမ်း ${el.dataset.expire} · usage ${el.dataset.usage} · ${el.dataset.online} device online${ips.length ? ' · ' + ips.join(', ') : ''}`;
  document.getElementById('u_msg').textContent = '';
  openSheet('userSheet');
}

async function doKick(){
  const msg = document.getElementById('u_msg');
  const {data} = await api('/api/kick', {username: curUser});
  if(data.ok){ toast('Kicked'); location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}
async function doDelete(){
  if(!confirm(`'${curUser}' ကို ဖျက်မှာ သေချာပါသလား?`)) return;
  const msg = document.getElementById('u_msg');
  const {data} = await api('/api/delete', {username: curUser});
  if(data.ok){ toast('Deleted'); location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

// ------------------------------------------------------- renew sheet ----
function openRenewSheet(){
  document.getElementById('userSheet').classList.remove('show');
  document.getElementById('rn_name').textContent = curUser;
  document.getElementById('rn_msg').textContent = '';
  document.getElementById('rn_days').value = 30;
  setActiveChip(30);
  updateNewDate(30);
  openSheet('renewSheet');
}
function pickDays(d){ document.getElementById('rn_days').value = d; setActiveChip(d); updateNewDate(d); }
function customDays(){
  const d = parseInt(document.getElementById('rn_days').value || '0', 10);
  setActiveChip(d); updateNewDate(d);
}
function setActiveChip(d){
  document.querySelectorAll('.daychip').forEach(c=>{
    c.classList.toggle('active', parseInt(c.dataset.d,10) === d);
  });
}
function updateNewDate(d){
  const dt = new Date();
  dt.setDate(dt.getDate() + (parseInt(d,10) || 0));
  document.getElementById('rn_newdate').textContent = dt.toISOString().slice(0,10);
}
async function confirmRenew(){
  const msg = document.getElementById('rn_msg');
  const days = document.getElementById('rn_days').value;
  const {data} = await api('/api/renew', {username: curUser, days});
  if(data.ok){ toast(`+${days} ရက် သက်တမ်းတိုးပြီး`); location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

// ------------------------------------------------------- limit sheet ----
function openLimitSheet(){
  document.getElementById('userSheet').classList.remove('show');
  document.getElementById('lm_name').textContent = curUser;
  const card = document.querySelector(`.ucard[data-username="${CSS.escape(curUser)}"]`);
  document.getElementById('l_value').value = card ? card.dataset.limit : 1;
  document.getElementById('l_msg').textContent = '';
  openSheet('limitSheet');
}
async function doLimit(){
  const msg = document.getElementById('l_msg');
  const limit = document.getElementById('l_value').value;
  const {data} = await api('/api/setlimit', {username: curUser, limit});
  if(data.ok){ toast('Limit updated'); location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

// ------------------------------------------------------ create sheet ----
function openCreateSheet(){
  document.getElementById('c_user').value = '';
  document.getElementById('c_pass').value = '';
  document.getElementById('c_days').value = 30;
  document.getElementById('c_limit').value = 1;
  document.getElementById('c_msg').textContent = '';
  openSheet('createSheet');
}
async function doCreate(){
  const msg = document.getElementById('c_msg');
  const payload = {
    username: document.getElementById('c_user').value.trim(),
    password: document.getElementById('c_pass').value,
    days: document.getElementById('c_days').value,
    limit: document.getElementById('c_limit').value,
  };
  const {data} = await api('/api/create', payload);
  if(data.ok){ toast('User created'); location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

// ----------------------------------------------------- account sheet ----
async function doChangePassword(){
  const msg = document.getElementById('pw_msg');
  const payload = {
    username: document.getElementById('pw_user').value.trim(),
    password: document.getElementById('pw_pass').value,
  };
  const {data} = await api('/api/changepassword', payload);
  if(data.ok){ toast('Password changed'); location.href='/logout'; }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

// -------------------------------------------------- UDP Custom control ----
async function loadUdpStatus(){
  try{
    const res = await fetch('/api/udp/status');
    const d = await res.json();
    if(!d.ok) return;
    document.getElementById('udpPort').textContent = d.port;
    document.getElementById('udpUserCount').textContent = d.user_count + ' users';
    const btn = document.getElementById('udpToggleBtn');
    if(d.active){
      btn.textContent = 'ရပ်မည်';
      btn.style.background = 'var(--danger)';
      btn.style.color = '#fff';
    } else {
      btn.textContent = 'စတင်မည်';
      btn.style.background = 'var(--signal)';
      btn.style.color = '#04211d';
    }
  }catch(e){}
}
async function doUdpToggle(){
  const {data} = await api('/api/udp/toggle', {});
  if(data.ok){ toast(data.active ? 'UDP Custom started' : 'UDP Custom stopped'); loadUdpStatus(); }
}
function openUdpPortSheet(){
  const cur = document.getElementById('udpPort').textContent;
  document.getElementById('udp_port_val').value = cur || 36712;
  document.getElementById('udp_port_msg').textContent = '';
  openSheet('udpPortSheet');
}
async function doUdpSetPort(){
  const msg = document.getElementById('udp_port_msg');
  const port = document.getElementById('udp_port_val').value;
  const {data} = await api('/api/udp/setport', {port});
  if(data.ok){ toast('Port updated → ' + data.port); closeSheets(); loadUdpStatus(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}
async function doUdpAddUser(){
  if(!curUser) return;
  const card = document.querySelector(`.ucard[data-username="${CSS.escape(curUser)}"]`);
  const pw = card ? card.dataset.password : '';
  const msg = document.getElementById('u_msg');
  const {data} = await api('/api/udp/adduser', {username: curUser, password: pw});
  if(data.ok){ toast('UDP: ' + curUser + ' ထည့်ပြီး'); loadUdpStatus(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}
async function doUdpRemoveUser(){
  if(!curUser) return;
  const msg = document.getElementById('u_msg');
  const {data} = await api('/api/udp/removeuser', {username: curUser});
  if(data.ok){ toast('UDP: ' + curUser + ' ဖျက်ပြီး'); loadUdpStatus(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}
loadUdpStatus();

// ------------------------------------------------ live system monitor ----
function barClass(pct){ if(pct>=90) return 'danger'; if(pct>=70) return 'warn'; return ''; }
function applyStat(prefix, pct){
  const bar = document.getElementById(prefix+'Bar');
  const card = document.getElementById(prefix+'Card');
  const cls = barClass(pct);
  bar.className = 'bar ' + cls;
  bar.querySelector('span').style.width = pct + '%';
  card.className = 'sysmini ' + cls;
  document.getElementById(prefix+'Pct').textContent = pct + '%';
}
async function refreshSysStats(){
  try{
    const res = await fetch('/api/sysstats');
    const data = await res.json();
    if(!data.ok) return;
    const s = data.stats;
    applyStat('cpu', s.cpu_percent);
    applyStat('ram', s.ram_percent);
    applyStat('disk', s.disk_percent);
    document.getElementById('ramSub').textContent = s.ram_used_gb + 'GB/' + s.ram_total_gb + 'GB';
    document.getElementById('diskSub').textContent = s.disk_used_gb + 'GB/' + s.disk_total_gb + 'GB';

    const row = document.getElementById('svcRow');
    row.innerHTML = data.services.map(svc => {
      const cls = svc.up ? 'up' : (svc.known ? 'down' : '');
      return `<span class="sigchip ${cls}"><span class="sigdot"></span>${svc.label}</span>`;
    }).join('');
  }catch(e){ /* ignore transient errors, keep last known state on screen */ }
}
setInterval(refreshSysStats, 5000);
</script>
</body>
</html>

DASHEOF


# ================================================================
# UDP Custom Server ထည့်သွင်းခြင်း (system.zip မသုံးဘဲ binary ထဲသာ)
# ================================================================
echo -e "${YELLOW}[*] UDP Custom binary ထည့်သွင်းနေသည်...${NC}"
mkdir -p /root/udp

if [ ! -f /root/udp/udp-custom ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "${SCRIPT_DIR}/udp/udp-custom-linux-amd64" ]; then
        cp "${SCRIPT_DIR}/udp/udp-custom-linux-amd64" /root/udp/udp-custom
        echo -e "${GREEN}[+] local binary သုံး${NC}"
    else
        wget -q "https://github.com/Shangyi69/udp-custom-/raw/main/udp-custom-linux-amd64" \
             -O /root/udp/udp-custom
    fi
    chmod +x /root/udp/udp-custom
fi

if [ ! -f /root/udp/config.json ]; then
    cat > /root/udp/config.json <<'UDPCFG'
{
  "listen": ":36712",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords",
    "passwords": []
  }
}
UDPCFG
fi

if [ ! -f /etc/systemd/system/udp-custom.service ]; then
    cat > /etc/systemd/system/udp-custom.service <<'UDPSVC'
[Unit]
Description=UDP Custom Core Server
After=network.target

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
UDPSVC
    systemctl daemon-reload
    systemctl enable udp-custom
fi

echo -e "${GREEN}[+] UDP Custom binary ready${NC}"

echo -e "${YELLOW}[*] detecting WS/SSL ports from existing install...${NC}"
DETECTED_WS_PORT=$(grep -oP '(?<=^Environment=WS_PORT=)\d+' /etc/systemd/system/ws-proxy.service 2>/dev/null || true)
DETECTED_SSL_PORT=$(grep -oP '(?<=^accept = )\d+' /etc/stunnel/ws-ssl.conf 2>/dev/null || true)
DETECTED_WS_PORT="${DETECTED_WS_PORT:-8880}"
DETECTED_SSL_PORT="${DETECTED_SSL_PORT:-443}"

echo -e "${YELLOW}[*] systemd service ...${NC}"
cat <<EOF > /etc/systemd/system/ws-panel.service
[Unit]
Description=SSH-WS web admin panel
After=network.target

[Service]
WorkingDirectory=/opt/ws-panel
Environment=PANEL_PORT=${PANEL_PORT}
Environment=WS_PORT=${DETECTED_WS_PORT}
Environment=SSL_PORT=${DETECTED_SSL_PORT}
Environment=UDP_PORT=36712
ExecStart=/usr/bin/python3 /opt/ws-panel/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ws-panel.service
systemctl restart ws-panel.service

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${PANEL_PORT}"/tcp
fi

IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Panel Install ပြီးပါပြီ!${NC}"
echo -e "${GREEN}  URL      : http://${IP}:${PANEL_PORT}${NC}"
echo -e "${GREEN}  Username : admin${NC}"
echo -e "${GREEN}  Password : admin123${NC}"
echo -e "${YELLOW}  [!] Login ဝင်ပြီးတာနဲ့ \"Change Password\" ကနေ password ချက်ချင်းပြောင်းပါ${NC}"
echo -e "${GREEN}  UDP   : port 36712 (panel ကနေ manage လုပ်နိုင်)${NC}"
echo -e "${GREEN}=========================================${NC}"
