<<<<<<< HEAD
# 🛡️ Threat Hunting Dashboard

A production-quality Python desktop application for monitoring Linux virtual machines via SSH, collecting security logs, running automated threat-hunting checks, and exporting detailed findings reports.

> Built as a hands-on cybersecurity lab project — developed during NTI cybersecurity training (CyberOps Associate · Endpoint Security · Cyber Threat Management).

---

## 📸 Overview

The dashboard connects to Linux VMs over SSH (key-based auth), pulls critical log files, and runs 8 automated threat-hunting checks aligned with real-world SOC workflows. Results are displayed in a dark-themed GUI and can be exported as TXT or JSON.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🖥️ GUI | Dark-themed CustomTkinter desktop app |
| 🔐 SSH | Key-based authentication via Fabric 3 + Paramiko |
| 🔍 Checks | 8 built-in threat-hunting rules (MITRE-aligned) |
| 📄 Reports | Human-readable TXT + machine-readable JSON export |
| ⚡ Concurrency | Threaded "Hunt All" — GUI stays fully responsive |
| 📋 Logging | Application log in `logs/application.log` |
| 🐧 Distro Support | Works on Debian/Kali/Ubuntu AND RHEL/CentOS |

---

## 📁 Project Structure

```
threat_hunting_dashboard/
├── main.py                   # Entry point
├── requirements.txt          # Python dependencies
├── config/
│   └── vms.json              # VM fleet definitions (IPs, credentials)
├── gui/
│   ├── app.py                # Main application window
│   ├── vm_card.py            # Per-VM card widget
│   └── report_panel.py       # Report viewer + export panel
├── transport/
│   └── ssh.py                # SSH / Fabric wrapper (key-based auth)
├── hunting/
│   ├── models.py             # Dataclasses: VMConfig, Finding, HuntReport
│   ├── checks.py             # 8 threat-hunting check functions
│   └── engine.py             # Hunt orchestrator + VM config loader
├── reports/
│   └── exports.py            # TXT and JSON report export
└── logs/                     # Application logs (auto-created at runtime)
```

---

## 🔧 Requirements

- **Python** 3.12+
- **SSH key-based access** to target Linux VMs
- The SSH user on each VM must be able to read `/var/log/` files (root, or a user in the `adm` group)

### Python Dependencies

```
customtkinter>=5.2.2
fabric>=3.2.2
paramiko>=3.4.0
Pillow>=10.2.0
```

---

## 🚀 Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/threat-hunting-dashboard.git
cd threat-hunting-dashboard
```

### Step 2 — Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

Edit `config/vms.json` to define your VM fleet:

```json
[
  {
    "name": "kali-lab",
    "host": "192.168.56.101",
    "port": 22,
    "username": "analyst",
    "key_path": "~/.ssh/id_rsa",
    "key_passphrase": null
  }
]
```

| Field | Required | Description |
|---|---|---|
| `name` | ✓ | Display label in the dashboard |
| `host` | ✓ | IP address or hostname |
| `port` | optional | SSH port (default: `22`) |
| `username` | optional | SSH login user (default: `root`) |
| `key_path` | optional | Path to SSH private key (default: `~/.ssh/id_rsa`) |
| `key_passphrase` | optional | Passphrase for the private key (`null` = none) |

> ⚠️ **Never commit real IPs or credentials to a public repo.** Use placeholder values in `vms.json` before pushing.

---

## 🔑 SSH Key Setup

The dashboard uses **key-based SSH authentication** (no passwords). Here's how to set it up:

### On the machine running the dashboard:

```bash
# Generate an SSH key pair (skip if you already have one)
ssh-keygen -t rsa -b 4096 -C "threat-hunting-dashboard"

# Copy the public key to the target VM
ssh-copy-id -i ~/.ssh/id_rsa.pub username@VM_IP
```

### Test the connection manually first:

```bash
ssh -i ~/.ssh/id_rsa username@VM_IP
```

For a full SSH key setup guide, see [`SSH_KEY_SETUP_GUIDE.md`](SSH_KEY_SETUP_GUIDE.md).

---

## ▶️ Running the Application

```bash
python main.py
```

---

## 🖱️ Usage

### 1. Test Connectivity

- Click **[Test]** on a VM card to verify SSH access to that VM.
- Click **[Test All]** to test every VM simultaneously.

### 2. Run a Threat Hunt

- Click **[Hunt]** on a VM card to collect logs and run all 8 checks.
- Click **[Hunt All]** to run concurrent hunts across the entire fleet.
- Results appear in the **Report Viewer** panel on the right.

### 3. Export Reports

After a hunt completes:

- **[Export TXT]** → saves `reports/report_<vm>_<timestamp>.txt`
- **[Export JSON]** → saves `reports/report_<vm>_<timestamp>.json`

---

## 🔍 Threat Hunting Checks

| # | Check | Severity | Log Source |
|---|---|---|---|
| 1 | SSH Brute Force Detection | 🔴 HIGH | `/var/log/auth.log` · `/var/log/secure` |
| 2 | Successful Login After Failures | 🚨 CRITICAL | `/var/log/auth.log` · `/var/log/secure` |
| 3 | Sudo Abuse / Failed Escalation | 🟠 MEDIUM | `/var/log/auth.log` · `/var/log/secure` |
| 4 | New User / Group Creation | 🔴 HIGH | `/var/log/auth.log` · `/var/log/secure` |
| 5 | Suspicious Off-Hours Cron Jobs | 🟠 MEDIUM | `/var/log/cron` |
| 6 | Package Installation Activity | 🟡 LOW | `/var/log/dpkg.log` · `/var/log/yum.log` |
| 7 | Privilege Escalation in Audit Log | 🔴 HIGH | `/var/log/audit/audit.log` |
| 8 | Suspicious Bash History Commands | 🔴 HIGH | `~/.bash_history` |

> All checks are **distro-agnostic** — they merge RHEL and Debian log paths automatically.

---

## 📋 Log Files Collected

The engine collects from these paths on each VM (missing files are skipped gracefully):

**Debian / Kali / Ubuntu:**
- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/dpkg.log`
- `/var/log/kern.log`

**RHEL / CentOS / Fedora:**
- `/var/log/secure`
- `/var/log/messages`
- `/var/log/yum.log` · `/var/log/dnf.log`

**Common:**
- `/var/log/cron`
- `/var/log/audit/audit.log`
- `~/.bash_history`

---

## 📄 Example Report Output

```
============================================================
VM:        kali-lab
Host:      192.168.56.101:22
Generated: 2026-06-03 14:00:00
============================================================

  [CRITICAL]
  Successful Login After Multiple Failures
  ----------------------------------------
  Description:
    IP 185.220.101.42 had 17 failed login attempts followed by a
    successful authentication — possible account compromise.
  Evidence:
    IP address: 185.220.101.42 | Failure count: 17
  Source: /var/log/auth.log

  [HIGH]
  SSH Brute Force Detected
  ----------------------------------------
  Description:
    Repeated SSH authentication failures detected from 185.220.101.42.
  Evidence:
    Failed password from 185.220.101.42 (17 times)

============================================================
  SUMMARY
============================================================
  Total Findings : 2
  CRITICAL   : 1
  HIGH       : 1
  MEDIUM     : 0
  LOW        : 0
  Duration   : 4.2s
============================================================
```

---

## 🏗️ Architecture

```
main.py
  └── gui/app.py              ← Main window, spawns threads
        ├── gui/vm_card.py    ← Per-VM widget (Test / Hunt buttons)
        └── gui/report_panel.py ← Results display + export
              └── hunting/engine.py   ← Orchestrates one full hunt
                    ├── transport/ssh.py  ← SSH connection + log collection
                    └── hunting/checks.py ← 8 pure check functions
                          └── hunting/models.py ← Dataclasses
```

**Design principles:**
- **Transport layer** (`transport/ssh.py`) is fully decoupled from the GUI — usable standalone for scripted/automated hunts.
- **Check functions** (`hunting/checks.py`) are pure functions: `dict[str, str] → list[Finding]` — easy to unit-test and extend.
- **Queue-based result passing** ensures the GUI thread is never blocked by network I/O.
- **Dataclasses** throughout provide clean, typed data contracts between all layers.

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---|---|
| `SSHError: SSH key not found` | Check `key_path` in `vms.json`; verify the file exists |
| `Authentication failed` | Verify username and that your public key is in `~/.ssh/authorized_keys` on the VM |
| `Network error connecting` | Confirm the VM is running and reachable; check firewall/iptables rules |
| `No findings returned` | The user may lack read access to log files; try root or a user in the `adm` group |
| `customtkinter not found` | Run `pip install -r requirements.txt` inside your virtual environment |
| `Permission denied on log file` | Run `sudo chmod o+r /var/log/auth.log` on the target VM |

---

## 🗺️ Roadmap

- [ ] Live log streaming (tail -f equivalent over SSH)
- [ ] MITRE ATT&CK technique tagging per finding
- [ ] Email/Slack alert integration
- [ ] Dashboard charts (findings over time, severity breakdown)
- [ ] OpenCTI integration for threat intel enrichment
- [ ] Docker-based lab setup for easy demo deployment

---

## 📜 License

This project is for educational and lab use. Feel free to fork, extend, and build on it.

---

## 👤 Author

**Amr** — Cybersecurity practitioner, NTI Graduate  
*CyberOps Associate · Endpoint Security · Cyber Threat Management*

---

> 💡 **Tip:** Star ⭐ the repo if you find it useful, and feel free to open issues or PRs!
=======
# Threat-hunting-dashboard
Python desktop app for SSH-based threat hunting on Linux VMs
>>>>>>> 9b80409f8ac18bd59a902593a697a2cf8cd16d49
