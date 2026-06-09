"""
hunting/checks.py
-----------------
All eight threat-hunting check functions.

Each function receives a dict mapping log filenames to their raw text content
and returns a list of Finding objects (possibly empty).

Distro compatibility:
    Each check merges content from both the RHEL path and the Debian/Kali
    equivalent before scanning, so the same checks work on either distro
    without any configuration change.

    RHEL / CentOS          Debian / Kali / Ubuntu
    /var/log/secure    ->  /var/log/auth.log
    /var/log/messages  ->  /var/log/syslog
    /var/log/yum.log   ->  /var/log/dpkg.log
"""

import re
import logging
from collections import defaultdict
from datetime import datetime

from hunting.models import Finding, Severity

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now()


def _auth_log(logs: dict[str, str]) -> str:
    """Return merged content of RHEL /var/log/secure + Debian /var/log/auth.log."""
    return logs.get("/var/log/secure", "") + "\n" + logs.get("/var/log/auth.log", "")


def _syslog(logs: dict[str, str]) -> str:
    """Return merged content of /var/log/messages + /var/log/syslog."""
    return logs.get("/var/log/messages", "") + "\n" + logs.get("/var/log/syslog", "")


def _pkg_log(logs: dict[str, str]) -> str:
    """Return merged content of yum.log + dnf.log + dpkg.log."""
    return (
        logs.get("/var/log/yum.log", "") + "\n"
        + logs.get("/var/log/dnf.log", "") + "\n"
        + logs.get("/var/log/dpkg.log", "")
    )


# ────────────────────────────────────────────────────────────────────────────
# CHECK 1 — SSH Brute Force Detection
# ────────────────────────────────────────────────────────────────────────────

def check_ssh_brute_force(logs: dict[str, str]) -> list[Finding]:
    """
    Detect repeated SSH login failures from the same source IP.

    Source: /var/log/secure  OR  /var/log/auth.log (Debian/Kali)
    Threshold: 5+ failures from the same IP.
    Severity: HIGH
    """
    findings: list[Finding] = []
    content = _auth_log(logs)
    if not content.strip():
        return findings

    ip_failures: dict[str, int] = defaultdict(int)
    pattern = re.compile(r"Failed password.*?from\s+([\d.a-fA-F:.]+)")

    for line in content.splitlines():
        match = pattern.search(line)
        if match:
            ip_failures[match.group(1)] += 1

    for ip, count in ip_failures.items():
        if count >= 5:
            source = "/var/log/auth.log" if logs.get("/var/log/auth.log") else "/var/log/secure"
            findings.append(Finding(
                title="SSH Brute Force Detected",
                severity=Severity.HIGH,
                description=(
                    f"Repeated SSH authentication failures detected from {ip}. "
                    "This pattern is consistent with an automated brute-force attack."
                ),
                evidence=f"Failed password from {ip} ({count} times)",
                source_log=source,
                timestamp=_now(),
            ))
            logger.info("CHECK1: Brute force — %s (%d failures)", ip, count)

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 2 — Successful Login After Failures
# ────────────────────────────────────────────────────────────────────────────

def check_login_after_failures(logs: dict[str, str]) -> list[Finding]:
    """
    Detect a successful login from an IP that previously had ≥3 failures.

    Source: /var/log/secure  OR  /var/log/auth.log (Debian/Kali)
    Severity: CRITICAL
    """
    findings: list[Finding] = []
    content = _auth_log(logs)
    if not content.strip():
        return findings

    fail_re = re.compile(r"Failed password.*?from\s+([\d.a-fA-F:.]+)")
    ok_re   = re.compile(r"Accepted (?:password|publickey).*?from\s+([\d.a-fA-F:.]+)")

    ip_failures: dict[str, int] = defaultdict(int)
    successful_ips: set[str] = set()

    for line in content.splitlines():
        fm = fail_re.search(line)
        if fm:
            ip_failures[fm.group(1)] += 1
        sm = ok_re.search(line)
        if sm:
            successful_ips.add(sm.group(1))

    source = "/var/log/auth.log" if logs.get("/var/log/auth.log") else "/var/log/secure"
    for ip in successful_ips:
        count = ip_failures.get(ip, 0)
        if count >= 3:
            findings.append(Finding(
                title="Successful Login After Multiple Failures",
                severity=Severity.CRITICAL,
                description=(
                    f"IP {ip} had {count} failed login attempts followed by a "
                    "successful authentication — possible account compromise."
                ),
                evidence=(
                    f"IP address: {ip}\n"
                    f"Failure count: {count}\n"
                    "Accepted password/publickey (login succeeded)"
                ),
                source_log=source,
                timestamp=_now(),
            ))
            logger.warning("CHECK2: Login after failures — %s (%d fails)", ip, count)

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 3 — Sudo Abuse Detection
# ────────────────────────────────────────────────────────────────────────────

def check_sudo_abuse(logs: dict[str, str]) -> list[Finding]:
    """
    Detect failed sudo authentication attempts.

    Source: auth.log / secure + syslog / messages
    Severity: MEDIUM
    """
    findings: list[Finding] = []
    content = _auth_log(logs) + "\n" + _syslog(logs)
    if not content.strip():
        return findings

    keywords = re.compile(
        r"sudo.*authentication failure"
        r"|sudo.*incorrect password attempt"
        r"|sudo.*3 incorrect password",
        re.IGNORECASE,
    )
    matches = [line for line in content.splitlines() if keywords.search(line)]

    if matches:
        source = "/var/log/auth.log" if logs.get("/var/log/auth.log") else "/var/log/secure"
        findings.append(Finding(
            title="Sudo Abuse / Failed Privilege Escalation",
            severity=Severity.MEDIUM,
            description=(
                f"Detected {len(matches)} sudo authentication failure(s). "
                "Could indicate an insider threat or lateral movement attempt."
            ),
            evidence="\n".join(matches[:20]),
            source_log=source,
            timestamp=_now(),
        ))
        logger.info("CHECK3: %d sudo failure lines found", len(matches))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 4 — New User Creation
# ────────────────────────────────────────────────────────────────────────────

def check_user_creation(logs: dict[str, str]) -> list[Finding]:
    """
    Detect new user or group creation events.

    Source: auth.log / secure + syslog / messages
    Severity: HIGH
    """
    findings: list[Finding] = []
    combined = _auth_log(logs) + "\n" + _syslog(logs)
    if not combined.strip():
        return findings

    pattern = re.compile(r"(useradd|groupadd|usermod)\b.*", re.IGNORECASE)
    matches = [line for line in combined.splitlines() if pattern.search(line)]

    if matches:
        uname_re = re.compile(r"name=(\S+)|user\s+'?(\S+?)'?[,\s]|'(\S+)'")
        usernames: list[str] = []
        for m in matches:
            um = uname_re.search(m)
            if um:
                usernames.append(next((g for g in um.groups() if g), "?"))

        source = "/var/log/auth.log" if logs.get("/var/log/auth.log") else "/var/log/secure"
        findings.append(Finding(
            title="New User / Group Creation Detected",
            severity=Severity.HIGH,
            description=(
                f"User account or group manipulation detected ({len(matches)} event(s)). "
                "Unauthorised account creation is a common persistence technique."
            ),
            evidence=(
                f"Accounts/groups: {', '.join(set(usernames)) or 'unknown'}\n"
                + "\n".join(matches[:20])
            ),
            source_log=source,
            timestamp=_now(),
        ))
        logger.info("CHECK4: %d user-creation lines found", len(matches))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 5 — Suspicious Cron Jobs
# ────────────────────────────────────────────────────────────────────────────

def check_suspicious_cron(logs: dict[str, str]) -> list[Finding]:
    """
    Detect cron job executions between 00:00 and 05:59.

    Source: /var/log/cron  (also appears in /var/log/syslog on Debian/Kali)
    Severity: MEDIUM
    """
    findings: list[Finding] = []
    # On Debian/Kali cron events go to syslog, not a separate cron file
    content = logs.get("/var/log/cron", "") + "\n" + logs.get("/var/log/syslog", "")
    if not content.strip():
        return findings

    time_re = re.compile(r"\w+\s+\d+\s+(\d{2}):\d{2}:\d{2}")
    suspicious: list[str] = []

    for line in content.splitlines():
        if "CMD" not in line and "CRON" not in line:
            continue
        tm = time_re.search(line)
        if tm and 0 <= int(tm.group(1)) < 6:
            suspicious.append(line)

    if suspicious:
        source = "/var/log/cron" if logs.get("/var/log/cron") else "/var/log/syslog"
        findings.append(Finding(
            title="Suspicious Off-Hours Cron Job Execution",
            severity=Severity.MEDIUM,
            description=(
                f"Detected {len(suspicious)} cron job execution(s) between 00:00 and 05:59. "
                "Scheduled tasks during these hours may indicate persistence or data exfiltration."
            ),
            evidence="\n".join(suspicious[:20]),
            source_log=source,
            timestamp=_now(),
        ))
        logger.info("CHECK5: %d suspicious cron entries found", len(suspicious))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 6 — Package Installation Activity
# ────────────────────────────────────────────────────────────────────────────

def check_package_installs(logs: dict[str, str]) -> list[Finding]:
    """
    Detect software installation, update, or removal events.

    Sources:
      RHEL/CentOS: /var/log/yum.log, /var/log/dnf.log
      Debian/Kali: /var/log/dpkg.log
    Severity: LOW
    """
    findings: list[Finding] = []
    content = _pkg_log(logs)
    if not content.strip():
        return findings

    # Match yum/dnf format:  "Installed: pkg" / "Updated: pkg" / "Erased: pkg"
    # AND dpkg format:        "install pkg" / "upgrade pkg" / "remove pkg"
    pattern = re.compile(
        r"(Installed|Updated|Erased):\s+(\S+)"          # yum/dnf
        r"|(install|upgrade|remove)\s+(\S+:\S+|\S+)",   # dpkg
        re.IGNORECASE,
    )
    matches = pattern.findall(content)

    if matches:
        evidence_lines: list[str] = []
        for m in matches[:30]:
            if m[0]:    # yum/dnf match
                evidence_lines.append(f"{m[0]}: {m[1]}")
            else:       # dpkg match
                evidence_lines.append(f"{m[2]}: {m[3]}")

        source = "/var/log/dpkg.log" if logs.get("/var/log/dpkg.log") else "/var/log/yum.log"
        findings.append(Finding(
            title="Package Installation / Removal Activity",
            severity=Severity.LOW,
            description=(
                f"Detected {len(matches)} package management event(s). "
                "Review to confirm all changes are authorised."
            ),
            evidence="\n".join(evidence_lines),
            source_log=source,
            timestamp=_now(),
        ))
        logger.info("CHECK6: %d package events found", len(matches))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 7 — Privilege Escalation Detection
# ────────────────────────────────────────────────────────────────────────────

def check_privilege_escalation(logs: dict[str, str]) -> list[Finding]:
    """
    Detect privilege escalation indicators in the audit log.

    Source: /var/log/audit/audit.log
    Severity: HIGH
    """
    findings: list[Finding] = []
    content = logs.get("/var/log/audit/audit.log", "")
    if not content.strip():
        return findings

    keywords = re.compile(
        r"type=SYSCALL.*\bsetuid\b"
        r"|type=USER_AUTH.*sudo"
        r"|type=USER_CMD.*sudo"
        r"|type=USER_LOGIN.*\bsu\b"
        r"|auid!=4294967295.*euid=0"
        r"|priv_esc",
        re.IGNORECASE,
    )
    matches = [line for line in content.splitlines() if keywords.search(line)]

    if matches:
        findings.append(Finding(
            title="Privilege Escalation Indicators in Audit Log",
            severity=Severity.HIGH,
            description=(
                f"Found {len(matches)} audit event(s) associated with privilege escalation "
                "(sudo/su/setuid). Verify these are from authorised users."
            ),
            evidence="\n".join(matches[:20]),
            source_log="/var/log/audit/audit.log",
            timestamp=_now(),
        ))
        logger.info("CHECK7: %d audit privilege-escalation lines", len(matches))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# CHECK 8 — Suspicious Bash History
# ────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_COMMANDS = [
    r"wget\b", r"curl\b", r"\bnc\b", r"\bncat\b", r"\bnetcat\b",
    r"bash\s+-i", r"python[23]?\s+-c", r"perl\s+-e",
    r"chmod\s+\+x", r"\bbase64\b", r"\bsocat\b",
    r"mkfifo", r"/dev/tcp/", r"openssl.*-connect",
]

def check_suspicious_history(logs: dict[str, str]) -> list[Finding]:
    """
    Scan bash history for commands commonly used in post-exploitation.

    Source: ~/.bash_history
    Severity: HIGH
    """
    findings: list[Finding] = []
    content = logs.get("~/.bash_history", "")
    if not content.strip():
        return findings

    pattern = re.compile("|".join(SUSPICIOUS_COMMANDS), re.IGNORECASE)
    matches = [line.strip() for line in content.splitlines() if pattern.search(line)]

    if matches:
        findings.append(Finding(
            title="Suspicious Commands in Bash History",
            severity=Severity.HIGH,
            description=(
                f"Detected {len(matches)} suspicious command(s) in bash history. "
                "These tools are frequently used for reverse shells, data exfiltration, "
                "and living-off-the-land attacks."
            ),
            evidence="\n".join(matches[:30]),
            source_log="~/.bash_history",
            timestamp=_now(),
        ))
        logger.info("CHECK8: %d suspicious bash history lines", len(matches))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# Master runner
# ────────────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    check_ssh_brute_force,
    check_login_after_failures,
    check_sudo_abuse,
    check_user_creation,
    check_suspicious_cron,
    check_package_installs,
    check_privilege_escalation,
    check_suspicious_history,
]


def run_all_checks(logs: dict[str, str]) -> list[Finding]:
    """
    Execute every check function and return the combined list of findings.

    Args:
        logs: Mapping of log filename -> raw log content.

    Returns:
        Combined list of Finding objects from all checks.
    """
    findings: list[Finding] = []
    for check_fn in ALL_CHECKS:
        try:
            findings.extend(check_fn(logs))
        except Exception as exc:  # noqa: BLE001
            logger.error("Check %s raised an exception: %s", check_fn.__name__, exc)
    return findings
