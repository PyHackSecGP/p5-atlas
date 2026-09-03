"""Tests for state.py — session serialization round-trip."""
from __future__ import annotations
import json
import pytest
from pathlib import Path
from models import (
    HackSession, Port, WebTarget, Credential, Finding,
    AgentResult, Stage, Severity, MachineAttackPlan,
)
import state


@pytest.fixture
def full_session():
    s = HackSession(
        target_ip="10.10.11.100",
        machine_name="TestBox",
        os_guess="Linux",
        current_stage=Stage.EXPLOIT,
    )
    s.ports.append(Port(number=22, service="ssh", version="OpenSSH 8.2"))
    s.ports.append(Port(number=80, service="http", version="Apache 2.4"))
    s.web_targets.append(WebTarget(url="http://10.10.11.100", tech=["PHP", "nginx"]))
    s.credentials.append(Credential(username="bob", password="hunter2", service="ssh"))
    s.findings.append(Finding(
        title="SUID bash", severity=Severity.CRITICAL,
        description="bash has SUID bit set", evidence="/bin/bash", command="bash -p",
    ))
    s.agent_results.append(AgentResult(
        agent="Recon", stage=Stage.RECON, summary="Found 2 ports",
        next_actions=["check http"], metadata={"os_guess": "Linux"},
    ))
    s.user_flag = "HTB{user_flag_here}"
    s.root_flag = "HTB{root_flag_here}"
    s.notes.append("[recon] interesting FTP banner")
    s.loot.append("/tmp/atlas/loot/backup.zip")
    s.attack_plan = MachineAttackPlan(
        stage_order=["enumeration", "exploit", "privesc", "report"],
        skip_stages=["web"],
        primary_vector="SMB null session",
        machine_difficulty="easy",
        machine_type="Linux CTF",
    )
    return s


def test_save_creates_file(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    assert Path(path).exists()


def test_save_valid_json(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    data = json.loads(Path(path).read_text())
    assert data["target_ip"] == "10.10.11.100"


def test_round_trip_basic_fields(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert loaded.target_ip == "10.10.11.100"
    assert loaded.machine_name == "TestBox"
    assert loaded.os_guess == "Linux"
    assert loaded.current_stage == Stage.EXPLOIT


def test_round_trip_ports(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert len(loaded.ports) == 2
    assert loaded.ports[0].number == 22
    assert loaded.ports[0].service == "ssh"


def test_round_trip_credentials(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert len(loaded.credentials) == 1
    assert loaded.credentials[0].username == "bob"
    assert loaded.credentials[0].password == "hunter2"


def test_round_trip_findings(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert len(loaded.findings) == 1
    assert loaded.findings[0].severity == Severity.CRITICAL
    assert loaded.findings[0].title == "SUID bash"


def test_round_trip_flags(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert loaded.user_flag == "HTB{user_flag_here}"
    assert loaded.root_flag == "HTB{root_flag_here}"


def test_round_trip_attack_plan(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert loaded.attack_plan is not None
    assert loaded.attack_plan.stage_order == ["enumeration", "exploit", "privesc", "report"]
    assert loaded.attack_plan.skip_stages == ["web"]
    assert loaded.attack_plan.primary_vector == "SMB null session"
    assert loaded.attack_plan.machine_difficulty == "easy"


def test_round_trip_no_attack_plan(tmp_path):
    s = HackSession(target_ip="10.0.0.1")
    path = str(tmp_path / "session.json")
    state.save(s, path)
    loaded = state.load(path)
    assert loaded.attack_plan is None


def test_round_trip_loot(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert "/tmp/atlas/loot/backup.zip" in loaded.loot


def test_round_trip_notes(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert "[recon] interesting FTP banner" in loaded.notes


def test_round_trip_agent_results(full_session, tmp_path):
    path = str(tmp_path / "session.json")
    state.save(full_session, path)
    loaded = state.load(path)
    assert len(loaded.agent_results) == 1
    assert loaded.agent_results[0].agent == "Recon"
    assert loaded.agent_results[0].stage == Stage.RECON


def test_load_nonexistent_returns_none(tmp_path):
    result = state.load(str(tmp_path / "missing.json"))
    assert result is None


def test_list_sessions_empty(tmp_path):
    results = state.list_sessions(str(tmp_path))
    assert results == []


def test_list_sessions_returns_saved(full_session, tmp_path):
    session_dir = tmp_path / "10_10_11_100"
    session_dir.mkdir()
    path = str(session_dir / "session.json")
    state.save(full_session, path)
    results = state.list_sessions(str(tmp_path))
    assert len(results) == 1
    assert results[0]["target_ip"] == "10.10.11.100"
    assert results[0]["user_flag"] == "HTB{user_flag_here}"
