"""Shared fixtures for ATLAS test suite."""
from __future__ import annotations
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import (
    HackSession, Port, WebTarget, Credential, Finding,
    AgentResult, Stage, Severity, MachineAttackPlan,
)
from llm import LLMProvider


# ── Minimal LLM stub — returns preconfigured JSON or text ────────────────────

class StubLLM(LLMProvider):
    """Configurable stub. Set .response before calling generate()."""

    def __init__(self, response: str = '{"ok": true}'):
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        self.calls.append((system, user))
        return self.response


# ── Common session factories ─────────────────────────────────────────────────

@pytest.fixture
def bare_session():
    return HackSession(target_ip="10.10.11.1")


@pytest.fixture
def linux_session():
    s = HackSession(target_ip="10.10.11.100", machine_name="TestBox", os_guess="Linux")
    s.ports.append(Port(number=22, service="ssh", version="OpenSSH 8.2p1"))
    s.ports.append(Port(number=80, service="http", version="Apache 2.4.41"))
    s.ports.append(Port(number=445, service="microsoft-ds", version=""))
    s.credentials.append(Credential(username="alice", password="Summer2024!", service="ssh"))
    s.findings.append(Finding(
        title="SMB null session",
        severity=Severity.HIGH,
        description="Anonymous SMB access grants share listing",
        agent="Enumeration",
    ))
    return s


@pytest.fixture
def windows_session():
    s = HackSession(target_ip="10.10.11.200", machine_name="WinBox", os_guess="Windows 10")
    s.ports.append(Port(number=445, service="microsoft-ds", version=""))
    s.ports.append(Port(number=5985, service="winrm", version=""))
    s.ports.append(Port(number=3389, service="rdp", version=""))
    s.credentials.append(Credential(username="Administrator", password="P@ssw0rd!", service="smb"))
    return s


@pytest.fixture
def planned_session(linux_session):
    linux_session.attack_plan = MachineAttackPlan(
        stage_order=["enumeration", "exploit", "privesc", "report"],
        skip_stages=["web"],
        primary_vector="SMB null session → credential in share",
        machine_difficulty="easy",
        machine_type="Linux CTF",
        reasoning="No web ports, SMB exposed, likely cred leak in share",
    )
    return linux_session


@pytest.fixture
def stub_llm():
    return StubLLM()


@pytest.fixture
def tmp_output(tmp_path):
    return str(tmp_path)
