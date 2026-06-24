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
pip3 install -q flask werkzeug --break-system-packages 2>/dev/null || pip3 install -q flask werkzeug

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
import subprocess
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

LIMIT_DIR = "/etc/ws-ssh/limit"
INFO_DIR = "/etc/ws-ssh/info"
PANEL_DIR = "/etc/ws-ssh/panel"
AUTH_FILE = os.path.join(PANEL_DIR, "auth.json")
SECRET_FILE = os.path.join(PANEL_DIR, "secret.key")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

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


def get_usage_gb(user):
    try:
        out = subprocess.run(
            ["iptables", "-L", "OUTPUT", "-v", "-n", "-x"], capture_output=True, text=True, timeout=5
        ).stdout
        total = 0
        for line in out.splitlines():
            if f"wsdata-{user}" in line:
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    total += int(parts[1])
        return round(total / 1024 / 1024 / 1024, 3)
    except Exception:
        return 0.0


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
        rows.append(
            {
                "username": user,
                "password": password,
                "expire": exp,
                "expired": is_expired(exp),
                "limit": limit,
                "online": get_online_count(user),
                "online_ips": get_online_ips(user),
                "usage_gb": get_usage_gb(user),
            }
        )
    return rows


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
        "dashboard.html", users=users, stats=stats, panel_user=load_auth()["username"]
    )


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
        uid = subprocess.run(["id", "-u", user], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", f"wsdata-{user}", "-j", "ACCEPT"]
        )
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
        uid = subprocess.run(["id", "-u", user], capture_output=True, text=True).stdout.strip()
        subprocess.run(["pkill", "-9", "-u", user])
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", f"wsdata-{user}", "-j", "ACCEPT"]
        )
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


if __name__ == "__main__":
    ensure_dirs()
    load_auth()
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH-WS Panel · Login</title>
<style>
  :root{
    --bg:#0f1115; --card:#171a21; --border:#262b35;
    --text:#e7e9ee; --muted:#8b93a3; --accent:#4f8cff; --danger:#ef4f5f;
  }
  *{box-sizing:border-box;}
  body{
    margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:var(--bg); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  .card{
    width:340px; background:var(--card); border:1px solid var(--border);
    border-radius:14px; padding:32px 28px; box-shadow:0 10px 30px rgba(0,0,0,.4);
  }
  h1{font-size:20px; margin:0 0 4px;}
  p.sub{color:var(--muted); margin:0 0 24px; font-size:13px;}
  label{font-size:13px; color:var(--muted); display:block; margin:14px 0 6px;}
  input{
    width:100%; padding:10px 12px; border-radius:8px; border:1px solid var(--border);
    background:#0f1115; color:var(--text); font-size:14px;
  }
  input:focus{outline:none; border-color:var(--accent);}
  button{
    width:100%; margin-top:22px; padding:11px; border:none; border-radius:8px;
    background:var(--accent); color:#fff; font-size:15px; font-weight:600; cursor:pointer;
  }
  button:hover{filter:brightness(1.08);}
  .err{color:var(--danger); font-size:13px; margin-top:14px; text-align:center;}
  .credit{color:var(--muted); font-size:11px; text-align:center; margin-top:18px; letter-spacing:.3px;}
</style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <h1>SSH-WS Panel</h1>
    <p class="sub">အက်ဒမင် အကောင့်ဝင်ရန်</p>
    <label>အသုံးပြုသူအမည်</label>
    <input name="username" autocomplete="username" required>
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH-WS Panel</title>
<style>
  :root{
    --bg:#0c0e13; --card:#151821; --card2:#11141b; --border:#252a36; --row:#1a1e28;
    --text:#e9ebf1; --muted:#8a91a3; --accent:#4f8cff; --green:#2ecf81;
    --red:#ef4f5f; --yellow:#e2b93b;
  }
  *{box-sizing:border-box;}
  body{
    margin:0; background:var(--bg); color:var(--text); min-height:100vh;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  header{
    display:flex; align-items:center; justify-content:space-between;
    padding:14px 22px; border-bottom:1px solid var(--border); position:sticky; top:0;
    background:var(--bg); z-index:5;
  }
  header h1{font-size:17px; margin:0; letter-spacing:.2px;}
  header .right{display:flex; gap:10px; align-items:center;}
  .muted{color:var(--muted); font-size:13px;}
  main{padding:18px 18px 60px; max-width:1280px; margin:0 auto;}

  /* ── stat cards ─────────────────────────────────────────────────── */
  .stats{
    display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px;
  }
  .stat{
    background:var(--card); border:1px solid var(--border); border-radius:10px;
    padding:13px 16px;
  }
  .stat .n{font-size:22px; font-weight:700; display:flex; align-items:center; gap:7px;}
  .stat .l{color:var(--muted); font-size:12px; margin-top:3px;}
  .stat .dot{width:8px; height:8px; border-radius:50%; flex:none;}
  .stat.online .dot{background:var(--green);}
  .stat.ended .n{color:var(--red);}
  .stat.active .n{color:var(--green);}

  .toolbar{display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;}
  .search{
    flex:1; min-width:180px; max-width:340px; display:flex; align-items:center; gap:8px;
    background:var(--card); border:1px solid var(--border); border-radius:8px; padding:0 12px;
  }
  .search svg{flex:none; opacity:.5;}
  .search input{
    border:none; background:none; color:var(--text); font-size:13px; padding:9px 0;
    width:100%; outline:none;
  }

  .btn{
    border:none; border-radius:8px; padding:9px 14px; font-size:13px; font-weight:600;
    cursor:pointer; color:#fff; background:var(--accent);
  }
  .btn.green{background:var(--green);}
  .btn.red{background:var(--red);}
  .btn.ghost{background:transparent; border:1px solid var(--border); color:var(--text);}
  .btn:hover{filter:brightness(1.1);}
  .btn.small{padding:6px 10px; font-size:12px;}

  /* ── table: real table at all sizes, horizontal-scroll on mobile ──── */
  .tablewrap{
    border:1px solid var(--border); border-radius:12px; overflow-x:auto;
    background:var(--card); -webkit-overflow-scrolling:touch;
  }
  table{width:100%; border-collapse:collapse; min-width:760px;}
  thead th{
    text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase;
    letter-spacing:.4px; padding:11px 14px; border-bottom:1px solid var(--border);
    white-space:nowrap; position:sticky; top:0; background:var(--card);
  }
  tbody td{padding:11px 14px; font-size:13.5px; border-bottom:1px solid var(--border); vertical-align:middle; white-space:nowrap;}
  tbody tr:last-child td{border-bottom:none;}
  tbody tr:hover{background:var(--row);}
  .uname{font-weight:600;}
  .pw{font-family:ui-monospace,SFMono-Regular,Menlo,monospace; cursor:pointer; color:var(--muted);}
  .pw:hover{color:var(--text);}
  .status{display:inline-flex; align-items:center; gap:6px; font-size:12.5px; font-weight:600;}
  .status .dot{width:7px; height:7px; border-radius:50%; flex:none;}
  .status.on{color:var(--green);} .status.on .dot{background:var(--green);}
  .status.off{color:var(--muted);} .status.off .dot{background:var(--muted);}
  .badge{padding:3px 9px; border-radius:999px; font-size:11.5px; font-weight:600; white-space:nowrap;}
  .badge.expired{background:rgba(239,79,95,.15); color:var(--red);}
  tr.expired-row{background:rgba(239,79,95,.07);}
  tr.expired-row:hover{background:rgba(239,79,95,.13);}
  tr.expired-row .uname{color:var(--red);}
  .actions{display:flex; gap:6px;}
  .card{background:var(--card); border:1px solid var(--border); border-radius:12px; padding:18px; margin-top:24px;}
  .card h2{font-size:15px; margin:0 0 12px;}
  .ipbadge{
    display:inline-block; background:rgba(79,140,255,.12); color:var(--accent);
    border:1px solid rgba(79,140,255,.25); border-radius:6px;
    padding:2px 7px; font-size:11px; font-family:monospace; margin:1px;
  }
  .empty{padding:40px 14px; text-align:center; color:var(--muted); font-size:13px;}

  /* modal */
  .overlay{
    position:fixed; inset:0; background:rgba(0,0,0,.55); display:none;
    align-items:center; justify-content:center; z-index:20;
  }
  .overlay.show{display:flex;}
  .modal{
    width:340px; background:var(--card); border:1px solid var(--border);
    border-radius:14px; padding:22px; box-shadow:0 10px 30px rgba(0,0,0,.5);
  }
  .modal h3{margin:0 0 16px; font-size:16px;}
  .modal label{font-size:12px; color:var(--muted); display:block; margin:10px 0 5px;}
  .modal input{
    width:100%; padding:9px 11px; border-radius:8px; border:1px solid var(--border);
    background:#0f1115; color:var(--text); font-size:14px;
  }
  .modal .row{display:flex; gap:10px; margin-top:20px;}
  .modal .row .btn{flex:1;}
  .msg{font-size:13px; margin-top:10px; min-height:16px;}
  .msg.err{color:var(--red);}
  .msg.ok{color:var(--green);}
  .credit{color:var(--muted); font-size:11px; text-align:center; margin-top:22px; letter-spacing:.3px;}
  @media (max-width:720px){
    main{padding:14px 12px 50px;}
    .stats{grid-template-columns:repeat(2,1fr);}
    table{min-width:680px;}
  }
</style>
</head>
<body>
  <header>
    <h1>SSH-WS Panel</h1>
    <div class="right">
      <span class="muted">{{ panel_user }}</span>
      <button class="btn ghost small" onclick="openModal('pwModal')">စကားဝှက်ပြောင်းမည်</button>
      <a class="btn ghost small" href="/logout" style="text-decoration:none;">ထွက်မည်</a>
    </div>
  </header>

  <main>
    <div class="stats">
      <div class="stat total">
        <div class="n">{{ stats.total }}</div>
        <div class="l">အသုံးပြုသူ စုစုပေါင်း</div>
      </div>
      <div class="stat online">
        <div class="n"><span class="dot"></span>{{ stats.online }}</div>
        <div class="l">အွန်လိုင်း</div>
      </div>
      <div class="stat active">
        <div class="n">{{ stats.active }}</div>
        <div class="l">သက်တမ်းရှိ</div>
      </div>
      <div class="stat ended">
        <div class="n">{{ stats.ended }}</div>
        <div class="l">သက်တမ်းကုန်</div>
      </div>
    </div>

    <div class="toolbar">
      <div class="search">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input id="searchBox" placeholder="အသုံးပြုသူအမည် ရှာရန်..." oninput="filterRows()">
      </div>
      <button class="btn green" onclick="openModal('createModal')">+ အသုံးပြုသူဖန်တီးမည်</button>
    </div>

    <div class="tablewrap">
    <table>
      <thead>
        <tr>
          <th>အသုံးပြုသူအမည်</th><th>စကားဝှက်</th><th>သက်တမ်းကုန်ဆုံး</th><th>ကန့်သတ်ချက်</th>
          <th>အွန်လိုင်း</th><th>IP စာရင်း</th><th>အသုံးပြုမှု (GB)</th><th>လုပ်ဆောင်ချက်များ</th>
        </tr>
      </thead>
      <tbody id="userRows">
        {% for u in users %}
        <tr data-user="{{ u.username|lower }}"{% if u.expired %} class="expired-row"{% endif %}>
          <td class="uname">{{ u.username }}</td>
          <td><span class="pw" title="click to copy" onclick="copyText('{{ u.password }}')">{{ u.password }}</span></td>
          <td>
            {% if u.expired %}
              <span class="badge expired">{{ u.expire }} · EXPIRED</span>
            {% else %}
              {{ u.expire }}
            {% endif %}
          </td>
          <td>{{ u.limit }}</td>
          <td>
            <span class="status {{ 'on' if u.online > 0 else 'off' }}"><span class="dot"></span>{{ u.online }}</span>
          </td>
          <td>
            {% if u.online_ips %}
              {% for ip in u.online_ips %}
                <span class="ipbadge">{{ ip }}</span>
              {% endfor %}
            {% else %}
              <span class="muted">-</span>
            {% endif %}
          </td>
          <td>{{ u.usage_gb }}</td>
          <td>
            <div class="actions">
              <button class="btn small" onclick="openRenew('{{ u.username }}')">သက်တမ်းတိုးမည်</button>
              <button class="btn ghost small" onclick="openLimit('{{ u.username }}','{{ u.limit }}')">ကန့်သတ်မည်</button>
              <button class="btn small" style="background:var(--yellow);color:#000" onclick="doKick('{{ u.username }}')">ထုတ်ပစ်မည်</button>
              <button class="btn red small" onclick="doDelete('{{ u.username }}')">ဖျက်မည်</button>
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    </div>
    <div id="emptyMsg" class="empty" style="display:none;">ရှာဖွေမှုနှင့် ကိုက်ညီသော အသုံးပြုသူ မတွေ့ပါ</div>

    <div class="credit">Dev Phoe Shan</div>

    </main>

  <!-- Create modal -->
  <div class="overlay" id="createModal">
    <div class="modal">
      <h3>အသုံးပြုသူဖန်တီးမည်</h3>
      <label>အသုံးပြုသူအမည်</label><input id="c_user">
      <label>စကားဝှက်</label><input id="c_pass">
      <label>သက်တမ်း (ရက်ပေါင်း)</label><input id="c_days" type="number" value="30">
      <label>ကန့်သတ်ချက်</label><input id="c_limit" type="number" value="1">
      <div class="msg" id="c_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('createModal')">မလုပ်တော့ပါ</button>
        <button class="btn green" onclick="doCreate()">ဖန်တီးမည်</button>
      </div>
    </div>
  </div>

  <!-- Renew modal -->
  <div class="overlay" id="renewModal">
    <div class="modal">
      <h3>သက်တမ်းတိုးမည် <span id="r_user_label"></span></h3>
      <label>ထပ်ထည့်မည့်ရက်ပေါင်း</label><input id="r_days" type="number" value="30">
      <div class="msg" id="r_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('renewModal')">မလုပ်တော့ပါ</button>
        <button class="btn" onclick="doRenew()">သက်တမ်းတိုးမည်</button>
      </div>
    </div>
  </div>

  <!-- Limit modal -->
  <div class="overlay" id="limitModal">
    <div class="modal">
      <h3>ကန့်သတ်ချက်သတ်မှတ်မည် <span id="l_user_label"></span></h3>
      <label>ကန့်သတ်ချက်</label><input id="l_value" type="number" value="1">
      <div class="msg" id="l_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('limitModal')">မလုပ်တော့ပါ</button>
        <button class="btn" onclick="doLimit()">သိမ်းမည်</button>
      </div>
    </div>
  </div>

  <!-- Change password modal -->
  <div class="overlay" id="pwModal">
    <div class="modal">
      <h3>Panel စကားဝှက်ပြောင်းမည်</h3>
      <label>အသုံးပြုသူအမည်အသစ် (ရွေးချယ်နိုင်)</label><input id="pw_user" placeholder="{{ panel_user }}">
      <label>စကားဝှက်အသစ်</label><input id="pw_pass" type="password">
      <div class="msg" id="pw_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('pwModal')">မလုပ်တော့ပါ</button>
        <button class="btn" onclick="doChangePassword()">သိမ်းမည်</button>
      </div>
    </div>
  </div>

<script>
let curUser = null;

function openModal(id){ document.getElementById(id).classList.add('show'); }
function closeModal(id){ document.getElementById(id).classList.remove('show'); }

function copyText(t){
  navigator.clipboard && navigator.clipboard.writeText(t);
}

function filterRows(){
  const q = document.getElementById('searchBox').value.trim().toLowerCase();
  const rows = document.querySelectorAll('#userRows tr');
  let visible = 0;
  rows.forEach(r => {
    const match = r.dataset.user.includes(q);
    r.style.display = match ? '' : 'none';
    if(match) visible++;
  });
  document.getElementById('emptyMsg').style.display = (visible === 0) ? 'block' : 'none';
}

async function api(url, body){
  const res = await fetch(url, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(()=>({ok:false, error:'invalid response'}));
  return {status:res.status, data};
}

async function doCreate(){
  const msg = document.getElementById('c_msg');
  msg.textContent = ''; msg.className = 'msg';
  const payload = {
    username: document.getElementById('c_user').value.trim(),
    password: document.getElementById('c_pass').value,
    days: document.getElementById('c_days').value,
    limit: document.getElementById('c_limit').value,
  };
  const {data} = await api('/api/create', payload);
  if(data.ok){ location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

function openRenew(user){
  curUser = user;
  document.getElementById('r_user_label').textContent = user;
  document.getElementById('r_msg').textContent = '';
  openModal('renewModal');
}
async function doRenew(){
  const msg = document.getElementById('r_msg');
  const days = document.getElementById('r_days').value;
  const {data} = await api('/api/renew', {username: curUser, days});
  if(data.ok){ location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

function openLimit(user, current){
  curUser = user;
  document.getElementById('l_user_label').textContent = user;
  document.getElementById('l_value').value = current;
  document.getElementById('l_msg').textContent = '';
  openModal('limitModal');
}
async function doLimit(){
  const msg = document.getElementById('l_msg');
  const limit = document.getElementById('l_value').value;
  const {data} = await api('/api/setlimit', {username: curUser, limit});
  if(data.ok){ location.reload(); }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}

async function doKick(user){
  if(!confirm(`'${user}' ရဲ့ session အားလုံး disconnect မှာ သေချာပါသလား?`)) return;
  const {data} = await api('/api/kick', {username:user});
  if(data.ok){ location.reload(); }
  else { alert(data.error || 'Error'); }
}

async function doDelete(user){
  if(!confirm(`'${user}' ကို ဖျက်မှာ သေချာပါသလား?`)) return;
  const {data} = await api('/api/delete', {username:user});
  if(data.ok){ location.reload(); }
  else { alert(data.error || 'Error'); }
}

async function doChangePassword(){
  const msg = document.getElementById('pw_msg');
  const payload = {
    username: document.getElementById('pw_user').value.trim(),
    password: document.getElementById('pw_pass').value,
  };
  const {data} = await api('/api/changepassword', payload);
  if(data.ok){ alert('Password ပြောင်းပြီးပါပြီ - ပြန် login ဝင်ပါ'); location.href='/logout'; }
  else { msg.textContent = data.error || 'Error'; msg.className = 'msg err'; }
}
</script>
</body>
</html>

DASHEOF

echo -e "${YELLOW}[*] systemd service ...${NC}"
cat <<EOF > /etc/systemd/system/ws-panel.service
[Unit]
Description=SSH-WS web admin panel
After=network.target

[Service]
WorkingDirectory=/opt/ws-panel
Environment=PANEL_PORT=${PANEL_PORT}
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
echo -e "${GREEN}=========================================${NC}"
