# SSH Key Authentication — Complete Setup Guide

> **Who this guide is for:** Complete beginners to SSH keys.  
> Every command is shown in full. Nothing is skipped.

---

## Table of Contents

1. [What Is SSH Key Authentication?](#1-what-is-ssh-key-authentication)
2. [How It Works — Plain English](#2-how-it-works)
3. [Windows Setup](#3-windows-setup)
4. [Linux / macOS Setup](#4-linux--macos-setup)
5. [Installing Your Public Key on the Target Machine](#5-installing-your-public-key-on-the-target-machine)
6. [Configuring HUNTER x to Use Your Key](#6-configuring-hunter-x-to-use-your-key)
7. [Testing the Connection](#7-testing-the-connection)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. What Is SSH Key Authentication?

Normal SSH login uses a **username + password** — like logging into a website.  
SSH key authentication uses a **pair of files** instead of a password:

| File | Name | What it does |
|------|------|--------------|
| `id_rsa` | **Private key** | Stays on YOUR computer — never share this |
| `id_rsa.pub` | **Public key** | Goes on the TARGET machine — safe to share |

Think of it like a padlock:
- You give the padlock (public key) to the server.
- Only your matching key (private key) can open it.
- No password ever travels over the network.

---

## 2. How It Works

```
Your Machine                        Target Linux Machine
─────────────────────               ─────────────────────────────────
 private key (id_rsa)   ──────►    checks against
                                    ~/.ssh/authorized_keys
                                    (contains your public key)
                                   ──────────────────────────────────
                                    ✓ Match → Access granted
                                    ✗ No match → Access denied
```

---

## 3. Windows Setup

### Step 1 — Check if OpenSSH Client is Installed

OpenSSH is built into Windows 10 (version 1809+) and Windows 11.

1. Press **Win + X** → click **Terminal** (or PowerShell).
2. Type:
   ```powershell
   ssh -V
   ```
3. You should see something like:
   ```
   OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2
   ```

**If you get "ssh is not recognized":**
1. Open **Settings** → **System** → **Optional Features**.
2. Click **Add a feature**.
3. Search for **OpenSSH Client**.
4. Click **Install**.
5. Restart your terminal and try `ssh -V` again.

---

### Step 2 — Generate Your SSH Key Pair

In **PowerShell** or **Terminal**, run:

```powershell
ssh-keygen -t rsa -b 4096 -C "hunter-x-key"
```

What each part means:
- `-t rsa` → use RSA algorithm (most compatible)
- `-b 4096` → 4096-bit key (strong)
- `-C "hunter-x-key"` → a label/comment (any text is fine)

You will be asked three questions:

```
Enter file in which to save the key (C:\Users\YourName/.ssh/id_rsa):
```
→ Press **Enter** to accept the default location.

```
Enter passphrase (empty for no passphrase):
```
→ Press **Enter** for no passphrase (simplest).  
  OR type a passphrase for extra security (you'll need to add it to vms.json — see Section 6).

```
Enter same passphrase again:
```
→ Press **Enter** again (or retype your passphrase).

You will see output like:
```
Your identification has been saved in C:\Users\YourName/.ssh/id_rsa
Your public key has been saved in C:\Users\YourName/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx hunter-x-key
```

---

### Step 3 — Find Your Keys on Windows

Your keys are in your user profile's `.ssh` folder:

```
C:\Users\YourName\.ssh\
├── id_rsa        ← PRIVATE key (never share this)
└── id_rsa.pub    ← Public key  (copy this to the server)
```

To open this folder in Explorer:
1. Press **Win + R**.
2. Type `%USERPROFILE%\.ssh` and press **Enter**.

---

### Step 4 — View Your Public Key

In PowerShell:
```powershell
cat $env:USERPROFILE\.ssh\id_rsa.pub
```

You will see a long line like:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... hunter-x-key
```

Copy the **entire line** — you need it in Section 5.

---

## 4. Linux / macOS Setup

### Step 1 — Open a Terminal

- **Linux:** Ctrl+Alt+T or search for "Terminal".
- **macOS:** Spotlight (Cmd+Space) → type "Terminal".

---

### Step 2 — Check if the .ssh Directory Exists

```bash
ls -la ~/.ssh
```

If you see `No such file or directory`, create it:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

The `chmod 700` is critical — SSH **refuses to work** if this folder has wrong permissions.

---

### Step 3 — Generate Your SSH Key Pair

```bash
ssh-keygen -t rsa -b 4096 -C "hunter-x-key"
```

Answer the prompts the same way as in the Windows section above.

Your keys will be saved to:
```
~/.ssh/id_rsa        ← PRIVATE key
~/.ssh/id_rsa.pub    ← Public key
```

---

### Step 4 — Set Correct File Permissions

This is **required**. SSH will reject keys with open permissions.

```bash
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

What `chmod 600` means: only YOU can read and write the private key. No one else.

---

### Step 5 — View Your Public Key

```bash
cat ~/.ssh/id_rsa.pub
```

Copy the full output — you need it in the next section.

---

## 5. Installing Your Public Key on the Target Machine

The "target machine" is the Linux server you want HUNTER x to connect to.

You need to put your **public key** (`id_rsa.pub`) into a special file on that server:
```
~/.ssh/authorized_keys
```

---

### Method A — Using ssh-copy-id (Easiest, Linux/macOS only)

If you still have password access to the target machine, run this once:

```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub username@192.168.100.45
```

Replace `username` with your actual username and the IP with your server's IP.  
It will ask for your **password once** — after this, keys are used.

---

### Method B — Manual Method (Works on Windows too)

**On the target Linux machine** (log in with password for the last time):

1. Create the `.ssh` directory if it does not exist:
   ```bash
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   ```

2. Open (or create) the `authorized_keys` file:
   ```bash
   nano ~/.ssh/authorized_keys
   ```

3. Paste your **public key** (the entire `ssh-rsa AAAA...` line) on a new line.

4. Save with **Ctrl+O**, Enter, then **Ctrl+X**.

5. Set correct permissions:
   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

6. Verify it was saved:
   ```bash
   cat ~/.ssh/authorized_keys
   ```
   You should see your key line.

---

### Step — Verify SSH Login Works (No Password)

From your machine, test the connection:

**Linux/macOS:**
```bash
ssh -i ~/.ssh/id_rsa username@192.168.100.45
```

**Windows (PowerShell):**
```powershell
ssh -i $env:USERPROFILE\.ssh\id_rsa username@192.168.100.45
```

If it logs in **without asking for a password**, you are done. ✓

If it still asks for a password, see Section 8 (Troubleshooting).

---

## 6. Configuring HUNTER x to Use Your Key

All VM connection settings are stored in:
```
config/vms.json
```

### Old Format (password — no longer used)
```json
{
  "name": "kali-lab",
  "host": "192.168.100.45",
  "port": 22,
  "username": "kali",
  "password": "kali"
}
```

### New Format (SSH key)
```json
{
  "name": "kali-lab",
  "host": "192.168.100.45",
  "port": 22,
  "username": "kali",
  "key_path": "~/.ssh/id_rsa",
  "key_passphrase": null
}
```

---

### Field Reference

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `name` | Yes | Label shown in the UI | `"web-server-01"` |
| `host` | Yes | IP address or hostname | `"192.168.1.50"` |
| `port` | No | SSH port (default: 22) | `22` |
| `username` | Yes | Linux username on the target | `"kali"` or `"root"` |
| `key_path` | Yes | Path to your **private** key | `"~/.ssh/id_rsa"` |
| `key_passphrase` | No | Passphrase if key is protected | `null` or `"mysecret"` |

---

### key_path Examples

| Where is your key? | What to put in key_path |
|--------------------|-------------------------|
| Default location on Linux/macOS | `"~/.ssh/id_rsa"` |
| Default location on Windows | `"C:/Users/YourName/.ssh/id_rsa"` |
| Key file in the project folder | `"key1.pem"` |
| Key file on Desktop (Windows) | `"C:/Users/YourName/Desktop/mykey.pem"` |
| Absolute path on Linux | `"/home/alice/.ssh/hunter_key"` |

> **Note:** Use forward slashes `/` even on Windows — JSON does not support backslashes.

---

### Using a Passphrase-Protected Key

If you set a passphrase when generating your key, add it like this:

```json
{
  "name": "secure-server",
  "host": "10.0.0.5",
  "port": 22,
  "username": "admin",
  "key_path": "~/.ssh/id_rsa",
  "key_passphrase": "my-secret-passphrase"
}
```

If your key has **no passphrase**, set `key_passphrase` to `null` (no quotes):
```json
"key_passphrase": null
```

---

### Multiple VMs Example

```json
[
  {
    "name": "kali-lab",
    "host": "192.168.100.45",
    "port": 22,
    "username": "kali",
    "key_path": "~/.ssh/id_rsa",
    "key_passphrase": null
  },
  {
    "name": "centos-web01",
    "host": "192.168.100.10",
    "port": 22,
    "username": "root",
    "key_path": "~/.ssh/id_rsa",
    "key_passphrase": null
  },
  {
    "name": "ubuntu-db",
    "host": "10.0.0.20",
    "port": 2222,
    "username": "ubuntu",
    "key_path": "keys/db-server.pem",
    "key_passphrase": null
  }
]
```

---

## 7. Testing the Connection

1. Launch HUNTER x:
   ```bash
   python main.py
   ```

2. In the **VM Fleet** sidebar, find your VM card.

3. Click **⚡ Test** — the status badge should turn **green (Online)** within a few seconds.

4. If it stays grey or turns red — check Section 8.

---

## 8. Troubleshooting

### ❌ "No SSH private key configured"

**Cause:** `key_path` is empty or missing from `config/vms.json`.  
**Fix:** Open `config/vms.json` and add the `key_path` field pointing to your private key.

---

### ❌ "SSH key file not found"

**Cause:** The path in `key_path` does not exist.  
**Fix:**
1. Check the path is spelled correctly.
2. On Windows use forward slashes: `C:/Users/Name/.ssh/id_rsa`
3. Run `ls ~/.ssh/` (Linux) or `dir $env:USERPROFILE\.ssh` (Windows) to confirm the file exists.

---

### ❌ "Key authentication failed"

**Cause:** The public key is not in `authorized_keys` on the server, or the wrong key/username is being used.  
**Fix:**
1. SSH to the target manually: `ssh -i ~/.ssh/id_rsa username@host -v`
   The `-v` flag shows verbose debug output.
2. On the target machine, verify the key is present:
   ```bash
   cat ~/.ssh/authorized_keys
   ```
3. Make sure the `username` in `vms.json` matches the Linux user whose `authorized_keys` you edited.

---

### ❌ "The private key is passphrase-protected"

**Cause:** You set a passphrase during key generation but `key_passphrase` is `null`.  
**Fix:** Add your passphrase to `vms.json`:
```json
"key_passphrase": "the-passphrase-you-set"
```

---

### ❌ Connection times out / "Network error"

**Cause:** The host is unreachable or the firewall blocks port 22.  
**Fix:**
1. Ping the host: `ping 192.168.100.45`
2. Check SSH is running on the target: `sudo systemctl status sshd`
3. Check the firewall: `sudo ufw status` or `sudo iptables -L`
4. Verify the port number in `vms.json` is correct.

---

### ❌ Still asking for password / Permission denied (Linux key permissions)

SSH is very strict about file permissions. If they are wrong, it silently ignores your key.

On the **target machine**, run:
```bash
# The home directory
chmod 755 ~

# The .ssh directory
chmod 700 ~/.ssh

# The authorized_keys file
chmod 600 ~/.ssh/authorized_keys
```

On your **local machine** (where your private key lives):
```bash
chmod 600 ~/.ssh/id_rsa
```

---

### ❌ "WARNING: UNPROTECTED PRIVATE KEY FILE!" on Windows

This is a Windows permissions issue. Fix it in PowerShell:

```powershell
$keyPath = "$env:USERPROFILE\.ssh\id_rsa"
icacls $keyPath /inheritance:r
icacls $keyPath /grant:r "$env:USERNAME:(R)"
```

---

### Quick Diagnostic Checklist

Before opening an issue, go through this list:

- [ ] `key_path` in `vms.json` points to the correct file
- [ ] The private key file exists at that path
- [ ] The public key (`id_rsa.pub`) content is in `~/.ssh/authorized_keys` on the target
- [ ] `username` in `vms.json` matches the Linux user on the target
- [ ] `chmod 600 ~/.ssh/id_rsa` was run (Linux/macOS)
- [ ] `chmod 700 ~/.ssh` and `chmod 600 ~/.ssh/authorized_keys` on target
- [ ] Manual `ssh -i keyfile user@host` works before testing in HUNTER x
- [ ] If key is passphrase-protected, `key_passphrase` is set in `vms.json`

---

*Guide version: 1.0 — HUNTER x SSH Key Migration*
