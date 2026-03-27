# 🧠 Hack The Box — Writeups
> **Author:** k41r0s3  
> **Platform:** [Hack The Box](https://www.hackthebox.com/)

A collection of my personal writeups for retired Hack The Box machines. Each writeup documents my methodology, tools used, and the full attack chain from initial reconnaissance to root.

---

## ⚠️ Disclaimer
These writeups are for **educational purposes only**. All machines documented here are **retired** HTB machines, meaning they are no longer active challenges. Please respect HTB's rules and do not share writeups for active machines.

---

## 📁 Repository Structure
```
Hack-The-Box/
└── Write-ups/
    └── MachineName/
        └── README.md
```

---

## 📝 Writeups
| # | Machine | Difficulty | OS | Category | Date |
|---|---------|------------|-----|----------|------|
| 1 | [Planning](./Write-ups/Planning/README.md) | Easy | Linux | Web | March 3, 2026 |
| 2 | [Reset](./Write-ups/Reset/README.md) | Easy | Linux | Web / Network | March 4, 2026 |
| 3 | [Data](./Write-ups/Data/README.md) | Easy | Linux | Web / Network | March 7, 2026 |
| 4 | [Browsed](./Write-ups/Browsed/README.md) | Medium | Linux | Web / PrivEsc | March 9, 2026 |
| 5 | [Editor](./Write-ups/Editor/README.md) | Easy | Linux | Web / PrivEsc | March 10, 2026 |
| 6 | [Artificial](./Write-ups/Artificial/README.md) | Easy | Linux | AI / PrivEsc | March 11, 2026 |
| 7 | [Down](./Write-ups/Down/README.md) | Easy | Linux | Web / SSRF | March 12, 2026 |
| 8 | [Nocturnal](./Write-ups/Nocturnal/README.md) | Easy | Linux | Web / Command Injection / CVE | March 13, 2026 |
| 9 | [Code](./Write-ups/Code/README.md) | Easy | Linux | Web | March 14, 2026 |
| 10 | [Dog](./Write-ups/Dog/README.md) | Easy | Linux | Web / Git Disclosure | March 17, 2026 |
| 11 | [Trick](./Write-ups/Trick/README.md) | Easy | Linux | Web / LFI / DNS | March 17, 2026 |
| 12 | [Fluffy](./Write-ups/Fluffy/README.md) | Medium | Windows | Active Directory / ADCS / CVE-2025-24071 / ESC16 | March 18, 2026 |
| 13 | [Postman](./Write-ups/Postman/README.md) | Easy | Linux | Misconfiguration / Redis / CVE-2019-12840 | March 18, 2026 |
| 14 | [Craft](./Write-ups/Craft/README.md) | Medium | Linux | Web / Git Recon / eval() RCE / Vault | March 19, 2026 |
| 15 | [Jeeves](./Write-ups/Jeeves/README.md) | Medium | Windows | Web / Jenkins RCE / JuicyPotato / NTFS ADS | March 19, 2026 |
| 16 | [Snoopy](./Write-ups/Snoopy/README.md) | Hard | Linux | LFI / DNS Injection / Mattermost / CVE-2023-23946 / CVE-2023-20052 | March 20, 2026 |
| 17 | [UnderPass](./Write-ups/UnderPass/README.md) | Easy | Linux | SNMP / daloRADIUS / Mosh | March 26, 2026 |
| 18 | [Titanic](./Write-ups/Titanic/README.md) | Easy | Linux | Web / LFI / Gitea / CVE-2024-41817 | March 26, 2026 |
| 19 | [Support](./Write-ups/Support/README.md) | Easy | Windows | Active Directory / SMB / .NET RE / LDAP / RBCD | March 27, 2026 |

---

## 🛠️ Common Tools

### 🌐 Web & Network
| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Directory and subdomain fuzzing |
| `gobuster` | Directory and vhost enumeration |
| `curl` | Web requests and API interaction |
| `whatweb` | Web technology fingerprinting |
| `BurpSuite` | Web traffic interception and analysis |
| `dig` | DNS zone transfer and record enumeration |
| `nsupdate` | TSIG-authenticated DNS dynamic update injection |
| `aiosmtpd` | Fake SMTP server for email interception |
| `Cowrie` | SSH honeypot for credential capture |
| `snmpwalk` | SNMP enumeration via community string |
| `snmp-check` | Formatted SNMP system info report |
| `onesixtyone` | SNMP community string brute-forcing |
| `sqlite3` | Query SQLite databases (e.g. Gitea user hash extraction) |

### 🪟 Active Directory
| Tool | Purpose |
|------|---------|
| `netexec` | SMB/WinRM credential validation, share enumeration |
| `impacket` | AD attack suite (GetUserSPNs, GetNPUsers, addcomputer, rbcd, getST, secretsdump) |
| `bloodyAD` | ACL enumeration, group membership abuse, shadow credentials |
| `certipy-ad` | ADCS enumeration and exploitation (ESC1–ESC16) |
| `PKINITtools` | PKINIT TGT requests and NT hash recovery |
| `evil-winrm` | WinRM shell via credentials or NT hash |
| `bloodhound-python` | Active Directory data collection for BloodHound |
| `responder` | NTLM hash capture via poisoning |
| `hashcat` | Password hash cracking (NTLMv2, TGS, PBKDF2, etc.) |
| `smbclient` | SMB share interaction and file transfer |
| `ldapsearch` | LDAP enumeration and SID resolution |
| `addcomputer.py` | Create fake machine accounts for RBCD attacks |
| `rbcd.py` | Write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD |
| `getST.py` | Request S4U2Proxy Kerberos service tickets for impersonation |
| `secretsdump.py` | DCSync — extract NT hashes and Kerberos keys from domain |

### 🔬 Reverse Engineering & Binary Analysis
| Tool | Purpose |
|------|---------|
| `python3` | .NET PE metadata parser — extract #US heap string literals |
| `dnfile` | Python library for parsing .NET PE metadata streams |
| `pefile` | Python PE file parsing library |
| `strings` | Basic string extraction from binaries |
| `binwalk` | Binary file analysis and embedded content detection |
| `file` | Identify binary type and architecture |

### 🐧 Linux PrivEsc & General
| Tool | Purpose |
|------|---------|
| `netcat` | Reverse shell listener |
| `LinPEAS` | Linux privilege escalation enumeration |
| `Metasploit` | Exploitation framework |
| `hydra` | Network login brute-forcing |
| `sshpass` | Forced password authentication over SSH |
| `jq` | JSON parsing |
| `git-dumper` | Dump exposed `.git` repositories |
| `rsh-redone-client` | BSD r-services client |
| `pswm-decryptor` | Brute-force pswm password manager vaults |
| `Docker` | Isolated exploit build environments |
| `redis-cli` | Redis interaction and exploitation |
| `ssh2john` | Convert encrypted SSH keys to crackable format |
| `john` | Offline password and passphrase cracking |
| `vault` | HashiCorp Vault CLI — secret engine enumeration and SSH OTP generation |
| `JuicyPotato` | SeImpersonatePrivilege → SYSTEM token impersonation (Windows, pre-1809) |
| `genisoimage` | Build HFS+ disk images for Apple DMG creation |
| `bbe` | Binary stream editor — patch DMG plists for CVE exploitation |
| `mosh-client` | Connect to privileged mosh-server session for root shell access |
| `gcc` | Compile malicious shared libraries for CVE-2024-41817 ImageMagick privesc |

---

## 🔗 Connect
- **HTB Profile:** [k41r0s3](https://app.hackthebox.com/public/users/2406865)
- **GitHub:** [k41r0s3](https://github.com/k41r0s3)

---

*Happy Hacking! 🚀*  
*k41r0s3*
