"""Data models for ATLAS session state."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Stage(str, Enum):
    INIT        = "init"
    RECON       = "recon"
    ENUMERATION = "enumeration"
    WEB         = "web"
    NETWORK     = "network"
    EXPLOIT     = "exploit"
    PRIVESC     = "privesc"
    REPORT      = "report"
    DONE        = "done"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class WebTarget:
    url: str
    tech: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


@dataclass
class Credential:
    username: str
    password: str = ""
    hash: str = ""
    service: str = ""
    note: str = ""


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    command: str = ""
    agent: str = ""


@dataclass
class AgentResult:
    agent: str
    stage: Stage
    summary: str
    raw_outputs: dict[str, str] = field(default_factory=dict)   # tool → raw output
    findings: list[Finding] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class HackSession:
    target_ip: str
    machine_name: str = ""
    os_guess: str = ""
    current_stage: Stage = Stage.INIT

    ports: list[Port] = field(default_factory=list)
    web_targets: list[WebTarget] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    agent_results: list[AgentResult] = field(default_factory=list)

    user_flag: str = ""
    root_flag: str = ""
    notes: list[str] = field(default_factory=list)

    loot: list[str] = field(default_factory=list)   # paths to downloaded loot files

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def web_ports(self) -> list[Port]:
        return [p for p in self.open_ports if p.service in ("http", "https", "http-alt") or p.number in (80, 443, 8080, 8443, 8000, 8888)]

    @property
    def ssh_port(self) -> Port | None:
        for p in self.open_ports:
            if p.service == "ssh" or p.number == 22:
                return p
        return None

    @property
    def winrm_port(self) -> Port | None:
        for p in self.open_ports:
            if p.number in (5985, 5986) or "winrm" in p.service.lower() or "wsman" in p.service.lower():
                return p
        return None

    @property
    def smb_ports(self) -> list[Port]:
        return [p for p in self.open_ports if p.number in (139, 445) or p.service in ("microsoft-ds", "netbios-ssn", "smb")]

    @property
    def rdp_port(self) -> Port | None:
        for p in self.open_ports:
            if p.number == 3389 or "rdp" in p.service.lower() or "ms-wbt" in p.service.lower():
                return p
        return None

    def context_summary(self) -> str:
        """Compact state summary fed to every LLM call."""
        lines = [
            f"Target: {self.target_ip}  OS: {self.os_guess or 'unknown'}",
            f"Stage: {self.current_stage.value}",
            f"Open ports: {', '.join(str(p.number)+'/'+p.service for p in self.open_ports) or 'none yet'}",
            f"Web targets: {', '.join(w.url for w in self.web_targets) or 'none'}",
            f"Credentials: {len(self.credentials)}",
            f"Findings: {len(self.findings)}",
            f"User flag: {'CAPTURED' if self.user_flag else 'not yet'}",
            f"Root flag: {'CAPTURED' if self.root_flag else 'not yet'}",
        ]
        if self.notes:
            lines.append("Notes: " + " | ".join(self.notes[-3:]))
        return "\n".join(lines)
