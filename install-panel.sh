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
touch /etc/ws-ssh/banned_ips.list

echo -e "${YELLOW}[*] writing app.py ...${NC}"
cat <<'APPEOF' > /opt/ws-panel/app.py
#!/usr/bin/env python3
"""ws-panel: lightweight X-ui style web panel for the SSH+WebSocket account
manager. Reuses the same on-disk data the CLI `menu` uses, so both stay in
sync (/etc/ws-ssh/limit, /etc/ws-ssh/info, /etc/ws-ssh/banned_ips.list)."""

import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

LIMIT_DIR = "/etc/ws-ssh/limit"
INFO_DIR = "/etc/ws-ssh/info"
BANLOG = "/etc/ws-ssh/banned_ips.list"
PANEL_DIR = "/etc/ws-ssh/panel"
AUTH_FILE = os.path.join(PANEL_DIR, "auth.json")
SECRET_FILE = os.path.join(PANEL_DIR, "secret.key")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

app = Flask(__name__)


def ensure_dirs():
    for d in (LIMIT_DIR, INFO_DIR, PANEL_DIR):
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(BANLOG):
        open(BANLOG, "a").close()


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


def get_online_count(user):
    try:
        out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5).stdout
        needle = f"sshd: {user}"
        return sum(1 for line in out.splitlines() if needle in line and "grep" not in line)
    except Exception:
        return 0


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
        rows.append(
            {
                "username": user,
                "password": password,
                "expire": get_expire(user),
                "limit": limit,
                "online": get_online_count(user),
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
    return render_template("dashboard.html", users=list_users(), panel_user=load_auth()["username"])


@app.route("/api/banned")
@login_required
def api_banned():
    ensure_dirs()
    with open(BANLOG) as f:
        ips = [l.strip() for l in f if l.strip()]
    return jsonify(ips=ips)


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


@app.route("/api/unban", methods=["POST"])
@login_required
def api_unban():
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify(ok=False, error="ip required"), 400
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    ensure_dirs()
    with open(BANLOG) as f:
        lines = [l.strip() for l in f if l.strip() and l.strip() != ip]
    with open(BANLOG, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
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

if __name__ == "__main__":
    ensure_dirs()
    load_auth()
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
</style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <h1>SSH-WS Panel</h1>
    <p class="sub">Admin login</p>
    <label>Username</label>
    <input name="username" autocomplete="username" required>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Login</button>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
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
    --bg:#0f1115; --card:#171a21; --border:#262b35; --row:#1b1f28;
    --text:#e7e9ee; --muted:#8b93a3; --accent:#4f8cff; --green:#33c481;
    --red:#ef4f5f; --yellow:#e2b93b;
  }
  *{box-sizing:border-box;}
  body{
    margin:0; background:var(--bg); color:var(--text); min-height:100vh;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  header{
    display:flex; align-items:center; justify-content:space-between;
    padding:16px 22px; border-bottom:1px solid var(--border); position:sticky; top:0;
    background:var(--bg); z-index:5;
  }
  header h1{font-size:18px; margin:0;}
  header .right{display:flex; gap:10px; align-items:center;}
  .muted{color:var(--muted); font-size:13px;}
  main{padding:20px 22px 60px;}
  .toolbar{display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;}
  .btn{
    border:none; border-radius:8px; padding:9px 14px; font-size:13px; font-weight:600;
    cursor:pointer; color:#fff; background:var(--accent);
  }
  .btn.green{background:var(--green);}
  .btn.red{background:var(--red);}
  .btn.ghost{background:transparent; border:1px solid var(--border); color:var(--text);}
  .btn:hover{filter:brightness(1.1);}
  .btn.small{padding:6px 10px; font-size:12px;}
  table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:12px; overflow:hidden;}
  thead th{
    text-align:left; font-size:12px; color:var(--muted); text-transform:uppercase;
    padding:12px 14px; border-bottom:1px solid var(--border);
  }
  tbody td{padding:12px 14px; font-size:14px; border-bottom:1px solid var(--border); vertical-align:middle;}
  tbody tr:last-child td{border-bottom:none;}
  tbody tr:hover{background:var(--row);}
  .pw{font-family:monospace; cursor:pointer;}
  .badge{padding:3px 9px; border-radius:999px; font-size:12px; font-weight:600;}
  .badge.on{background:rgba(51,196,129,.15); color:var(--green);}
  .badge.off{background:rgba(139,147,163,.15); color:var(--muted);}
  .badge.expired{background:rgba(239,79,95,.15); color:var(--red);}
  .actions{display:flex; gap:6px; flex-wrap:wrap;}
  .card{background:var(--card); border:1px solid var(--border); border-radius:12px; padding:18px; margin-top:24px;}
  .card h2{font-size:15px; margin:0 0 12px;}
  .iplist{display:flex; gap:8px; flex-wrap:wrap;}
  .ipchip{
    background:#0f1115; border:1px solid var(--border); border-radius:999px;
    padding:6px 10px 6px 14px; font-size:13px; display:flex; gap:8px; align-items:center;
  }
  .ipchip button{background:none; border:none; color:var(--red); cursor:pointer; font-size:13px;}

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
  @media (max-width:720px){
    table{display:block; border:none; background:none;}
    thead{display:none;}
    tbody{display:block;}
    tbody tr{display:block; background:var(--card); border:1px solid var(--border); border-radius:12px; margin-bottom:10px;}
    tbody td{display:flex; justify-content:space-between; border-bottom:none; padding:8px 14px;}
    tbody td::before{content:attr(data-label); color:var(--muted); font-size:12px;}
  }
</style>
</head>
<body>
  <header>
    <h1>SSH-WS Panel</h1>
    <div class="right">
      <span class="muted">{{ panel_user }}</span>
      <button class="btn ghost small" onclick="openModal('pwModal')">Change Password</button>
      <a class="btn ghost small" href="/logout" style="text-decoration:none;">Logout</a>
    </div>
  </header>

  <main>
    <div class="toolbar">
      <div class="muted">Total users: {{ users|length }}</div>
      <button class="btn green" onclick="openModal('createModal')">+ Create User</button>
    </div>

    <table>
      <thead>
        <tr>
          <th>Username</th><th>Password</th><th>Expire</th><th>Limit</th>
          <th>Online</th><th>Usage (GB)</th><th>Actions</th>
        </tr>
      </thead>
      <tbody id="userRows">
        {% for u in users %}
        <tr data-user="{{ u.username }}">
          <td data-label="Username"><b>{{ u.username }}</b></td>
          <td data-label="Password"><span class="pw" title="click to copy" onclick="copyText('{{ u.password }}')">{{ u.password }}</span></td>
          <td data-label="Expire">{{ u.expire }}</td>
          <td data-label="Limit">{{ u.limit }}</td>
          <td data-label="Online">
            <span class="badge {{ 'on' if u.online > 0 else 'off' }}">{{ u.online }}</span>
          </td>
          <td data-label="Usage">{{ u.usage_gb }}</td>
          <td data-label="Actions">
            <div class="actions">
              <button class="btn small" onclick="openRenew('{{ u.username }}')">Renew</button>
              <button class="btn ghost small" onclick="openLimit('{{ u.username }}','{{ u.limit }}')">Limit</button>
              <button class="btn red small" onclick="doDelete('{{ u.username }}')">Delete</button>
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <div class="card">
      <h2>Banned IPs</h2>
      <div class="iplist" id="bannedList"><span class="muted">loading...</span></div>
    </div>
  </main>

  <!-- Create modal -->
  <div class="overlay" id="createModal">
    <div class="modal">
      <h3>Create User</h3>
      <label>Username</label><input id="c_user">
      <label>Password</label><input id="c_pass">
      <label>သက်တမ်း (ရက်ပေါင်း)</label><input id="c_days" type="number" value="30">
      <label>Device limit</label><input id="c_limit" type="number" value="1">
      <div class="msg" id="c_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('createModal')">Cancel</button>
        <button class="btn green" onclick="doCreate()">Create</button>
      </div>
    </div>
  </div>

  <!-- Renew modal -->
  <div class="overlay" id="renewModal">
    <div class="modal">
      <h3>Renew <span id="r_user_label"></span></h3>
      <label>ထပ်ထည့်မည့်ရက်ပေါင်း</label><input id="r_days" type="number" value="30">
      <div class="msg" id="r_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('renewModal')">Cancel</button>
        <button class="btn" onclick="doRenew()">Renew</button>
      </div>
    </div>
  </div>

  <!-- Limit modal -->
  <div class="overlay" id="limitModal">
    <div class="modal">
      <h3>Set limit <span id="l_user_label"></span></h3>
      <label>Device limit</label><input id="l_value" type="number" value="1">
      <div class="msg" id="l_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('limitModal')">Cancel</button>
        <button class="btn" onclick="doLimit()">Save</button>
      </div>
    </div>
  </div>

  <!-- Change password modal -->
  <div class="overlay" id="pwModal">
    <div class="modal">
      <h3>Change Panel Password</h3>
      <label>New username (optional)</label><input id="pw_user" placeholder="{{ panel_user }}">
      <label>New password</label><input id="pw_pass" type="password">
      <div class="msg" id="pw_msg"></div>
      <div class="row">
        <button class="btn ghost" onclick="closeModal('pwModal')">Cancel</button>
        <button class="btn" onclick="doChangePassword()">Save</button>
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

async function loadBanned(){
  const res = await fetch('/api/banned');
  const data = await res.json();
  const el = document.getElementById('bannedList');
  if(!data.ips || data.ips.length === 0){
    el.innerHTML = '<span class="muted">(empty)</span>';
    return;
  }
  el.innerHTML = '';
  data.ips.forEach(ip=>{
    const chip = document.createElement('div');
    chip.className = 'ipchip';
    chip.innerHTML = `<span>${ip}</span><button onclick="unban('${ip}')">unban</button>`;
    el.appendChild(chip);
  });
}
async function unban(ip){
  await api('/api/unban', {ip});
  loadBanned();
}
loadBanned();
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
