# Troubleshooting — SSH-WS + UDP Custom

Real issues hit during deployment on a live VPS, and how each was diagnosed
and fixed. Keeping this here so the next setup goes faster.

---

## 1. `udp-custom.service` stuck on `STOPPED`, no `/root/udp/config.json`

**Symptom:** `menu` → option 10 shows service stopped and config missing.

**Cause:** files were never actually copied into `/root/udp/` — the
install steps were run from the wrong directory, or the upload never
completed.

**Fix:**
```bash
ls -la /root/udp/          # confirm files actually exist first
mkdir -p /root/udp
cp <source>/udp-custom  /root/udp/udp-custom
cp <source>/config.json /root/udp/config.json
```

---

## 2. Service crash-looping — `status=203/EXEC`

**Symptom:**
```
systemd[1]: udp-custom.service: Main process exited, code=exited, status=203/EXEC
systemd[1]: Scheduled restart job, restart counter is at 12.
```

**Cause:** `203/EXEC` = systemd found the file but could not execute it.
`ls -la` showed `-r--r--` — the **execute bit was missing** (`chmod +x`
never ran, or ran before the file was overwritten by a later `cp`/`wget`,
which resets permissions).

**Fix:**
```bash
chmod +x /root/udp/udp-custom
ls -la /root/udp/udp-custom     # must show -rwxr-xr-x
systemctl restart udp-custom.service
systemctl status udp-custom.service   # should show "active (running)"
```

**Lesson:** always run `chmod +x` **after** the final copy/download of the
binary, and verify with `ls -la` before assuming the service will start.

---

## 3. Client stuck on "Connecting attempt 1, 2, 3... (unlimited)"

Debugged in three layers — do them in this order, don't skip ahead:

### 3a. Is the port even reachable from outside?
```bash
ss -uln | grep 36712              # confirm the process is listening
iptables -L INPUT -n --line-numbers   # confirm no DROP/REJECT for the port
ufw status                        # if ufw is installed, confirm ALLOW
```
If `ufw` isn't installed at all, it's not the blocker — check `iptables`
directly instead.

### 3b. Are packets from the client actually arriving?
```bash
apt install -y tcpdump
tcpdump -i any udp port 36712 -n
```
Then attempt to connect from the client app. If **no packets appear at
all**, the block is somewhere in the network path — VPS provider's cloud
firewall/security group (a layer separate from the server's own
iptables/ufw), or the mobile carrier throttling/blocking UDP. Test on
WiFi vs mobile data to isolate ISP-side blocking.

If packets **do** appear (`client_ip.port > server_ip.36712: UDP,
length ...`), the network path is fine — move to 3c.

### 3c. Is the server actually accepting the connection?
```bash
journalctl -u udp-custom -f
```
Watch this while connecting from the client. What you see here tells you
which layer is failing:

- `[user:xxx] Client connected` → **authentication succeeded**. The
  binary's `auth.mode: "passwords"` does re-use real Linux system
  accounts (confirmed: user-creation in this ecosystem uses
  `useradd` + `chpasswd`, same as this project's own `menu` option 1).
- `[error:Application error 0x0 (remote)] Client disconnected` shortly
  after connecting → the **client app** itself closed the connection.
  This is an application-level protocol event, not a network or auth
  failure. Root cause requires the closed-source binary's protocol
  spec, which isn't publicly available — this is a genuine dead end
  without vendor support.

**If you hit exactly this "connects then disconnects" pattern:**
open an issue / ask in the vendor's support channel
(`https://t.me/shaystudiolab`) with the exact `journalctl` output above —
someone who has hit the same client/server version combo may already
know the fix. Also worth checking client app version compatibility
against the server binary's reported version (`udp-custom --version`).

---

## 4. Misleading "port 1-65535" claim in account-info printouts

Some UDP-Custom management scripts print a line like:
```
Badvpn    : 1-65535
<ip>:1-65535@<user>:<pass>
```
**This is static display text, not a real feature.** There is no
iptables/NAT logic anywhere in those scripts that actually redirects a
port range. The only port that really works is whatever is set in
`config.json`'s `"listen"` field. Don't spend time trying to "configure"
the range — there's nothing to configure; just use the single listen
port.

(If you *do* want ISP-port-throttle evasion via a real port-range
redirect, that has to be built separately with iptables `REDIRECT` rules
— see the `badvpn-udpgw` + NAT-redirect setup in this project's
`install.sh`, which implements this properly and was verified working.)

---

## 5. Quick reference — useful diagnostic commands

```bash
# service status + logs
systemctl status udp-custom.service
journalctl -u udp-custom -n 50 --no-pager
journalctl -u udp-custom -f

# is it listening, is it reachable
ss -uln | grep 36712
iptables -L INPUT -n --line-numbers
tcpdump -i any udp port 36712 -n

# binary sanity check
file /root/udp/udp-custom       # should say "ELF 64-bit ... executable"
ls -la /root/udp/udp-custom     # should show the x permission bit
/root/udp/udp-custom --version
```
