"""
hunting/engine.py
-----------------
ThreatHuntingEngine: orchestrates log collection and threat-hunting checks
for a single VM, producing a complete HuntReport.

Updated: SSHManager now uses key_path / key_passphrase instead of password.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from hunting.checks import run_all_checks
from hunting.models import Finding, HuntReport, Severity, VMConfig
from transport.ssh import SSHManager, SSHError

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "vms.json"


# ────────────────────────────────────────────────────────────────────────────
# VM loader
# ────────────────────────────────────────────────────────────────────────────

def load_vm_configs(path: Path = CONFIG_PATH) -> list[VMConfig]:
    """
    Parse config/vms.json and return a list of VMConfig instances.

    Now reads key_path and key_passphrase fields instead of password.
    """
    if not path.exists():
        raise FileNotFoundError(f"VM config not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    vms: list[VMConfig] = []
    for entry in raw:
        try:
            vms.append(VMConfig(
                name=entry["name"],
                host=entry["host"],
                port=int(entry.get("port", 22)),
                username=entry.get("username", "root"),
                key_path=entry.get("key_path", ""),
                key_passphrase=entry.get("key_passphrase", None),
            ))
        except KeyError as exc:
            raise ValueError(f"VM config entry missing field: {exc}") from exc

    logger.info("Loaded %d VM configurations from %s", len(vms), path)
    return vms


# ────────────────────────────────────────────────────────────────────────────
# Engine
# ────────────────────────────────────────────────────────────────────────────

class ThreatHuntingEngine:
    """
    Orchestrates the full threat-hunting workflow for a single VM.
    """

    def __init__(self, vm: VMConfig) -> None:
        self.vm = vm

    def run(self) -> HuntReport:
        """Execute the complete threat-hunting run and return a HuntReport."""
        report = HuntReport(vm=self.vm, started=datetime.now())
        ssh = SSHManager(
            host=self.vm.host,
            port=self.vm.port,
            username=self.vm.username,
            key_path=self.vm.key_path,
            key_passphrase=self.vm.key_passphrase,
        )

        try:
            logger.info("Starting hunt on %s", self.vm)

            logs = ssh.collect_logs()

            raw_warnings = logs.pop("_warnings", "")
            if raw_warnings:
                for line in raw_warnings.splitlines():
                    if line.strip():
                        report.warnings.append(line.strip())

            findings = run_all_checks(logs)
            report.findings = findings

            logger.info(
                "Hunt completed on %s — %d finding(s)",
                self.vm.name, len(findings),
            )

        except SSHError as exc:
            report.error = f"SSH Error: {exc}"
            logger.error("SSH error during hunt on %s: %s", self.vm.name, exc)

        except Exception as exc:  # noqa: BLE001
            report.error = f"Unexpected error: {exc}"
            logger.exception("Unexpected error during hunt on %s", self.vm.name)

        finally:
            ssh.close()
            report.completed = datetime.now()

        return report

    def test(self) -> tuple[bool, str]:
        """Perform a quick SSH connectivity test without a full hunt."""
        ssh = SSHManager(
            host=self.vm.host,
            port=self.vm.port,
            username=self.vm.username,
            key_path=self.vm.key_path,
            key_passphrase=self.vm.key_passphrase,
        )
        try:
            return ssh.test_connection()
        finally:
            ssh.close()
