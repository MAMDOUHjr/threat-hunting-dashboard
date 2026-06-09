"""
transport/ssh.py
----------------
SSH transport layer built on top of Fabric 3.x / Paramiko.

Authentication: SSH key-based (private key file) instead of password.

Provides the SSHManager class which handles:
- Authenticated SSH connections via private key file
- Remote command execution with timeout support
- Connection health checks
- Graceful error handling and logging

Bug fixes retained from original:
  - BUG 1 FIXED: 'timeout' is set ONLY via connect_timeout on Connection(),
    never inside connect_kwargs, to avoid Fabric's ambiguity error.

  - BUG 2 FIXED: LOG_FILES covers both Debian/Kali/Ubuntu and RHEL/CentOS
    paths; missing files are skipped gracefully.
"""

import logging
import os
from pathlib import Path
from typing import Optional

import paramiko
from fabric import Connection  # type: ignore

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT: int = 30

LOG_FILES: list[str] = [
    # Debian / Kali / Ubuntu
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/dpkg.log",
    "/var/log/kern.log",
    # RHEL / CentOS / Fedora
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/yum.log",
    "/var/log/dnf.log",
    # Common
    "/var/log/cron",
    "/var/log/audit/audit.log",
    "~/.bash_history",
]


class SSHError(Exception):
    """Raised when an SSH operation fails unrecoverably."""


class SSHManager:
    """
    Manages SSH connectivity and command execution for a single VM.

    Authentication is performed exclusively via an SSH private key file.
    Password authentication has been removed.

    Args:
        host:            IP address or hostname of the target VM.
        port:            SSH port (default 22).
        username:        Login user on the remote host.
        key_path:        Absolute or relative path to the private key file.
        key_passphrase:  Optional passphrase protecting the private key.
                         Pass None (default) for unencrypted keys.
        timeout:         Connection + per-command execution timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        key_path: str = "",
        key_passphrase: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        self.timeout = timeout
        self._connection: Optional[Connection] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def test_connection(self) -> tuple[bool, str]:
        """
        Verify that the VM is reachable via SSH using the configured key.

        Returns:
            (True, output) on success, (False, error_message) on failure.
        """
        try:
            result = self._run("hostname && uptime")
            return True, result.strip()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Connection test failed for %s: %s", self.host, exc)
            return False, str(exc)

    def collect_logs(self) -> dict[str, str]:
        """
        Collect the content of all target log files from the remote VM.

        Returns:
            dict mapping log file path -> file content (str).
            '_warnings' key contains newline-joined skipped-file messages.
        """
        logs: dict[str, str] = {}
        warnings: list[str] = []

        for log_path in LOG_FILES:
            try:
                content = self._run(f"cat {log_path} 2>/dev/null || true")
                if content.strip():
                    logs[log_path] = content
                    logger.debug("Collected %s (%d bytes)", log_path, len(content))
                else:
                    warnings.append(f"Empty or missing: {log_path}")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Could not read {log_path}: {exc}")
                logger.warning(
                    "Log collection failed for %s on %s: %s",
                    log_path, self.host, exc,
                )

        logs["_warnings"] = "\n".join(warnings)
        return logs

    def close(self) -> None:
        """Close the underlying SSH connection if open."""
        if self._connection:
            try:
                self._connection.close()
            except Exception:  # noqa: BLE001
                pass
            finally:
                self._connection = None

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _resolve_key_path(self) -> Path:
        """
        Resolve the private key path and validate it exists.

        Raises:
            SSHError: If the path is empty, missing, or unreadable.
        """
        if not self.key_path:
            raise SSHError(
                "No SSH private key configured.\n"
                "Set 'key_path' in config/vms.json to point to your private key file.\n"
                "Example: \"key_path\": \"~/.ssh/id_rsa\"  or  \"key_path\": \"key1.pem\""
            )

        path = Path(self.key_path).expanduser()

        # Support paths relative to the project root
        if not path.is_absolute():
            project_root = Path(__file__).parent.parent
            path = (project_root / path).resolve()

        if not path.exists():
            raise SSHError(
                f"SSH key file not found: {path}\n"
                f"Check the 'key_path' value in config/vms.json."
            )

        if not path.is_file():
            raise SSHError(
                f"SSH key path is not a file: {path}"
            )

        # Check file is readable
        if not os.access(path, os.R_OK):
            raise SSHError(
                f"SSH key file is not readable: {path}\n"
                f"On Linux/macOS fix with: chmod 600 {path}"
            )

        # Warn if permissions are too open (Linux/macOS only)
        try:
            mode = oct(path.stat().st_mode)[-3:]
            if mode not in ("600", "400"):
                logger.warning(
                    "Private key %s has permissions %s — should be 600 or 400. "
                    "SSH may refuse to use it. Fix with: chmod 600 %s",
                    path, mode, path,
                )
        except Exception:  # noqa: BLE001
            pass  # Windows — skip permission check

        return path

    def _get_connection(self) -> Connection:
        """
        Return a live Fabric Connection authenticated with the private key.

        Raises:
            SSHError: If the connection cannot be established.
        """
        if self._connection is not None:
            return self._connection

        key_path = self._resolve_key_path()

        # Build connect_kwargs for paramiko — key file auth only
        connect_kwargs: dict = {
            "key_filename": str(key_path),
            "look_for_keys": False,   # don't scan ~/.ssh for other keys
            "allow_agent": False,     # don't use the SSH agent
        }

        # Add passphrase only if provided (avoids paramiko prompting)
        if self.key_passphrase is not None:
            connect_kwargs["passphrase"] = self.key_passphrase

        try:
            conn = Connection(
                host=self.host,
                user=self.username,
                port=self.port,
                connect_kwargs=connect_kwargs,
                connect_timeout=self.timeout,   # timeout lives HERE only
            )
            conn.open()
            self._connection = conn
            logger.info(
                "SSH key-auth connection established to %s@%s:%d (key: %s)",
                self.username, self.host, self.port, key_path.name,
            )
            return conn

        except paramiko.AuthenticationException as exc:
            raise SSHError(
                f"Key authentication failed for {self.username}@{self.host}.\n"
                f"Possible causes:\n"
                f"  1. The public key is not in ~/.ssh/authorized_keys on the target.\n"
                f"  2. Wrong private key file specified.\n"
                f"  3. Wrong username (check 'username' in config/vms.json).\n"
                f"  4. Key passphrase is wrong or missing.\n"
                f"Detail: {exc}"
            ) from exc

        except paramiko.ssh_exception.PasswordRequiredException as exc:
            raise SSHError(
                f"The private key {key_path.name} is passphrase-protected.\n"
                f"Add \"key_passphrase\": \"your-passphrase\" to the VM entry "
                f"in config/vms.json."
            ) from exc

        except paramiko.SSHException as exc:
            raise SSHError(
                f"SSH protocol error connecting to {self.host}: {exc}"
            ) from exc

        except OSError as exc:
            raise SSHError(
                f"Network error connecting to {self.host}:{self.port}: {exc}\n"
                f"Check that the host is reachable and port {self.port} is open."
            ) from exc

    def _run(self, command: str) -> str:
        """
        Execute a shell command on the remote host and return stdout.

        Raises:
            SSHError: On connection or execution failure.
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                command,
                hide=True,
                warn=True,
                timeout=self.timeout,
                encoding="utf-8",
            )
            return result.stdout or ""
        except Exception as exc:  # noqa: BLE001
            self._connection = None
            raise SSHError(f"Command failed on {self.host}: {exc}") from exc

    def __repr__(self) -> str:
        return (
            f"SSHManager(host={self.host!r}, user={self.username!r}, "
            f"port={self.port}, key={self.key_path!r})"
        )
