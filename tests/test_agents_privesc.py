"""Tests for agents/privesc.py — _is_root, _find_ssh_cred, _extract_flag, helpers."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from models import HackSession, Port, Credential, Stage
from agents.privesc import PrivEscAgent
from conftest import StubLLM


@pytest.fixture
def privesc_agent(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=22, service="ssh", state="open", version="OpenSSH 8.2"))
    s.credentials.append(Credential(username="alice", password="S3cr3t!", service="ssh"))
    llm = StubLLM('{"vectors": [], "current_user": "alice", "current_groups": [], "kernel_version": "5.4", "kernel_exploits": [], "interesting_files": [], "key_finding": "", "linpeas_recommended": false}')
    agent = PrivEscAgent(session=s, llm=llm, output_dir=str(tmp_path))
    return agent


@pytest.fixture
def windows_privesc_agent(tmp_path):
    s = HackSession(target_ip="10.10.11.200", os_guess="Windows 10")
    s.ports.append(Port(number=5985, service="winrm", state="open", version=""))
    s.credentials.append(Credential(username="svc_user", password="Pass1!", service="winrm"))
    llm = StubLLM('{"vectors": [], "current_user": "svc_user", "current_groups": [], "kernel_version": "", "kernel_exploits": [], "interesting_files": [], "key_finding": "", "linpeas_recommended": false}')
    agent = PrivEscAgent(session=s, llm=llm, output_dir=str(tmp_path))
    return agent


# ── _is_root ──────────────────────────────────────────────────────────────────

def test_is_root_uid_zero(privesc_agent):
    assert privesc_agent._is_root("uid=0(root) gid=0(root) groups=0(root)")


def test_is_root_nt_authority_system(privesc_agent):
    assert privesc_agent._is_root("NT AUTHORITY\\SYSTEM")


def test_is_root_builtin_administrators(privesc_agent):
    assert privesc_agent._is_root("BUILTIN\\Administrators")


def test_is_root_false_for_regular_user(privesc_agent):
    assert not privesc_agent._is_root("uid=1001(alice) gid=1001(alice)")


def test_is_root_false_for_empty(privesc_agent):
    assert not privesc_agent._is_root("")


def test_is_root_false_for_root_in_other_context(privesc_agent):
    assert not privesc_agent._is_root("root:x:0:0:root:/root:/bin/bash")


def test_is_root_false_for_shell_prompt_hash(privesc_agent):
    assert not privesc_agent._is_root("alice@victim:~# ")


def test_is_root_false_for_sudo_output(privesc_agent):
    assert not privesc_agent._is_root("User alice may run: /usr/bin/sudo")


# ── _find_ssh_cred ────────────────────────────────────────────────────────────

def test_find_ssh_cred_prefers_ssh_service(privesc_agent):
    cred = privesc_agent._find_ssh_cred()
    assert cred is not None
    assert cred.service == "ssh"
    assert cred.username == "alice"


def test_find_ssh_cred_falls_back_to_any_cred(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.credentials.append(Credential(username="bob", password="pw", service="smb"))
    llm = StubLLM("{}")
    agent = PrivEscAgent(session=s, llm=llm, output_dir=str(tmp_path))
    cred = agent._find_ssh_cred()
    assert cred is not None
    assert cred.username == "bob"


def test_find_ssh_cred_returns_none_when_no_creds(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = PrivEscAgent(session=s, llm=StubLLM(), output_dir=str(tmp_path))
    assert agent._find_ssh_cred() is None


def test_find_ssh_cred_ignores_empty_password(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.credentials.append(Credential(username="alice", password="", service="ssh"))
    agent = PrivEscAgent(session=s, llm=StubLLM(), output_dir=str(tmp_path))
    cred = agent._find_ssh_cred()
    assert cred is None


# ── _extract_flag ─────────────────────────────────────────────────────────────

def test_extract_flag_htb_format(privesc_agent):
    assert privesc_agent._extract_flag("root.txt\nHTB{r00t_fl4g_h3r3}") == "HTB{r00t_fl4g_h3r3}"


def test_extract_flag_32hex(privesc_agent):
    f = privesc_agent._extract_flag("flag: aabbccdd11223344aabbccdd11223344")
    assert f == "aabbccdd11223344aabbccdd11223344"


def test_extract_flag_htb_beats_32hex(privesc_agent):
    out = "hash: aabbccdd11223344aabbccdd11223344  HTB{actual_flag}"
    assert privesc_agent._extract_flag(out) == "HTB{actual_flag}"


def test_extract_flag_empty_on_no_match(privesc_agent):
    assert privesc_agent._extract_flag("no flags here at all") == ""


# ── _build_ssh_cmd ────────────────────────────────────────────────────────────

def test_build_ssh_cmd_standard_port(privesc_agent):
    cred = privesc_agent.session.credentials[0]
    cmd = privesc_agent._build_ssh_cmd("10.10.11.1", cred, "id")
    assert "sshpass" in cmd
    assert "alice" in cmd
    assert "-p S3cr3t!" in cmd or "S3cr3t!" in cmd


def test_build_ssh_cmd_custom_port(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=2222, service="ssh", state="open", version=""))
    s.credentials.append(Credential(username="bob", password="pass", service="ssh"))
    agent = PrivEscAgent(session=s, llm=StubLLM(), output_dir=str(tmp_path))
    cmd = agent._build_ssh_cmd("10.10.11.1", s.credentials[0], "whoami")
    assert "2222" in cmd


# ── Script mode (no SSH creds) ────────────────────────────────────────────────

def test_script_mode_called_when_no_ssh_creds(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"vectors": [], "current_user": "?", "current_groups": [], "kernel_version": "", "kernel_exploits": [], "interesting_files": [], "key_finding": "", "linpeas_recommended": false}')
    agent = PrivEscAgent(session=s, llm=llm, output_dir=str(tmp_path))
    with patch("builtins.input", side_effect=EOFError):
        result = agent.run()
    assert "script" in result.summary.lower() or "no access" in result.summary.lower() or "privesc" in result.summary.lower()


# ── Windows target ────────────────────────────────────────────────────────────

def test_windows_agent_uses_windows_enum_flag(windows_privesc_agent):
    assert "windows" in windows_privesc_agent.session.os_guess.lower()
