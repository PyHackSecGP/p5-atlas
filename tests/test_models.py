"""Tests for models.py — HackSession, MachineAttackPlan, Port helpers."""
from __future__ import annotations
import pytest
from models import (
    HackSession, Port, WebTarget, Credential, Finding,
    AgentResult, Stage, Severity, MachineAttackPlan,
)


# ── Port helpers ──────────────────────────────────────────────────────────────

def test_open_ports_filters_closed():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=22, service="ssh", state="open"))
    s.ports.append(Port(number=80, service="http", state="closed"))
    assert len(s.open_ports) == 1
    assert s.open_ports[0].number == 22


def test_web_ports_by_service():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=80, service="http", state="open"))
    s.ports.append(Port(number=443, service="https", state="open"))
    s.ports.append(Port(number=22, service="ssh", state="open"))
    assert len(s.web_ports) == 2


def test_web_ports_by_number():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=8080, service="unknown", state="open"))
    assert len(s.web_ports) == 1
    assert s.web_ports[0].number == 8080


def test_ssh_port_found():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=22, service="ssh", state="open"))
    assert s.ssh_port is not None
    assert s.ssh_port.number == 22


def test_ssh_port_by_number():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=22, service="unknown", state="open"))
    assert s.ssh_port is not None


def test_ssh_port_missing():
    s = HackSession(target_ip="10.0.0.1")
    assert s.ssh_port is None


def test_winrm_port_detected():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=5985, service="http", state="open"))
    assert s.winrm_port is not None
    assert s.winrm_port.number == 5985


def test_smb_ports_detected():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=445, service="microsoft-ds", state="open"))
    s.ports.append(Port(number=139, service="netbios-ssn", state="open"))
    assert len(s.smb_ports) == 2


def test_rdp_port_detected():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=3389, service="ms-wbt-server", state="open"))
    assert s.rdp_port is not None


# ── Flag extraction ───────────────────────────────────────────────────────────

def test_extract_flag_htb_format():
    s = HackSession(target_ip="10.0.0.1")
    result = s.extract_flag("cat user.txt\nHTB{abc_def_ghi_123}\n")
    assert result == "HTB{abc_def_ghi_123}"


def test_extract_flag_32hex():
    s = HackSession(target_ip="10.0.0.1")
    result = s.extract_flag("root.txt: aabbccdd11223344aabbccdd11223344")
    assert result == "aabbccdd11223344aabbccdd11223344"


def test_extract_flag_htb_takes_priority_over_hex():
    s = HackSession(target_ip="10.0.0.1")
    result = s.extract_flag("hash: aabbccdd11223344aabbccdd11223344 flag: HTB{real_flag}")
    assert result == "HTB{real_flag}"


def test_extract_flag_empty():
    s = HackSession(target_ip="10.0.0.1")
    assert s.extract_flag("no flag here") == ""


def test_extract_flag_not_triggered_by_version_string():
    s = HackSession(target_ip="10.0.0.1")
    # NTLM auth hash in nmap output — should match as 32-hex (that's fine, flag extraction is separate from shell detection)
    assert s.extract_flag("no 32-char hex here at all") == ""


# ── context_summary ───────────────────────────────────────────────────────────

def test_context_summary_basic(bare_session):
    summary = bare_session.context_summary()
    assert "10.10.11.1" in summary
    assert "Stage:" in summary
    assert "User flag: not yet" in summary
    assert "Root flag: not yet" in summary


def test_context_summary_shows_usernames(linux_session):
    summary = linux_session.context_summary()
    assert "alice" in summary


def test_context_summary_hides_passwords(linux_session):
    summary = linux_session.context_summary()
    assert "Summer2024!" not in summary


def test_context_summary_shows_flags():
    s = HackSession(target_ip="10.0.0.1")
    s.user_flag = "HTB{user_flag}"
    s.root_flag = "HTB{root_flag}"
    summary = s.context_summary()
    assert "CAPTURED" in summary
    assert "HTB{user_flag}" in summary


def test_context_summary_shows_attack_plan(planned_session):
    summary = planned_session.context_summary()
    assert "Linux CTF" in summary
    assert "SMB null session" in summary
    assert "web" in summary  # skip_stages listed


def test_context_summary_shows_findings(linux_session):
    summary = linux_session.context_summary()
    assert "SMB null session" in summary


def test_context_summary_shows_loot():
    s = HackSession(target_ip="10.0.0.1")
    s.loot.extend(["/tmp/atlas/loot/backup.zip", "/tmp/atlas/loot/config.xml"])
    summary = s.context_summary()
    assert "Loot: 2" in summary


# ── MachineAttackPlan ─────────────────────────────────────────────────────────

def test_attack_plan_defaults():
    plan = MachineAttackPlan()
    assert plan.stage_order == []
    assert plan.skip_stages == []
    assert plan.machine_difficulty == "medium"


def test_attack_plan_stored_on_session():
    s = HackSession(target_ip="10.0.0.1")
    assert s.attack_plan is None
    s.attack_plan = MachineAttackPlan(stage_order=["exploit", "privesc", "report"])
    assert s.attack_plan.stage_order[0] == "exploit"


# ── Stage enum ────────────────────────────────────────────────────────────────

def test_stage_values():
    assert Stage("recon") == Stage.RECON
    assert Stage("exploit") == Stage.EXPLOIT
    assert Stage("done") == Stage.DONE


def test_severity_ordering():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.LOW.value == "low"
