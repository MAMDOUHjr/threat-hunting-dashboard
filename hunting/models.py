"""
hunting/models.py
-----------------
Dataclass definitions for the Threat Hunting Dashboard.

Updated: VMConfig now uses key_path / key_passphrase for SSH key auth.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


class VMStatus(str, Enum):
    UNKNOWN = "Unknown"
    ONLINE  = "Online"
    OFFLINE = "Offline"
    ERROR   = "Error"


@dataclass
class VMConfig:
    """
    Represents a single monitored virtual machine loaded from vms.json.

    Attributes:
        name:            Human-readable label (e.g. "centos-web01")
        host:            IP address or hostname
        port:            SSH port (default 22)
        username:        SSH login user
        key_path:        Path to the SSH private key file
        key_passphrase:  Passphrase for the private key (None = no passphrase)
    """
    name: str
    host: str
    port: int = 22
    username: str = "root"
    key_path: str = ""
    key_passphrase: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.name} ({self.host}:{self.port})"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    source_log: str
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "source_log": self.source_log,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HuntReport:
    vm: VMConfig
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started: datetime = field(default_factory=datetime.now)
    completed: Optional[datetime] = None
    error: Optional[str] = None

    def count_by_severity(self, sev: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == sev)

    @property
    def summary(self) -> dict:
        return {s.value: self.count_by_severity(s) for s in Severity}

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank(), reverse=True)
