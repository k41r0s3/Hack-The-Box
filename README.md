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
| 6 | [Artificial](./Write-ups/Artifical/Artificial/README.md) | Easy | Linux | AI / PrivEsc | March 11, 2026 |
| 7 | [Down](./Write-ups/Down/README.md) | Easy | Linux | Web / SSRF | March 12, 2026 |

---

## 🛠️ Common Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Directory and subdomain fuzzing |
| `gobuster` | Directory and vhost enumeration |
| `curl` | Web requests and API interaction |
| `whatweb` | Web technology fingerprinting |
| `netcat` | Reverse shell listener |
| `LinPEAS` | Privilege escalation enumeration |
| `BurpSuite` | Web traffic interception and analysis |
| `Metasploit` | Exploitation framework |
| `rsh-redone-client` | BSD r-services client |
| `jq` | JSON parsing |
| `hashcat` | Password hash cracking |
| `Docker` | Isolated exploit build environments |
| `pswm-decryptor` | Brute-force pswm password manager vaults |

---

## 🔗 Connect

- **HTB Profile:** [k41r0s3](https://app.hackthebox.com/public/users/2406865)
- **GitHub:** [k41r0s3](https://github.com/k41r0s3)

---

*Happy Hacking! 🚀*  
*k41r0s3*
