"""Tests for agents/loot_analyzer.py — pattern matching, credential extraction."""
from __future__ import annotations
import pytest
from pathlib import Path
from unittest.mock import patch
from models import HackSession, Stage
from agents.loot_analyzer import LootAnalyzerAgent, _QUICK_PATTERNS, _INTERESTING_NAMES
from conftest import StubLLM


@pytest.fixture
def loot_agent(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"credentials": [], "ssh_key_paths": [], "hashes": [], "attack_vectors": [], "interesting_findings": [], "summary": "nothing found"}')
    agent = LootAnalyzerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    return agent, s, tmp_path


# ── _QUICK_PATTERNS ───────────────────────────────────────────────────────────

def test_quick_pattern_password_equals():
    text = "password=SuperSecret123"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "password" in matches


def test_quick_pattern_password_colon():
    text = "pass: hunter2"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "password" in matches


def test_quick_pattern_api_key():
    text = "api_key = sk-abc123xyz"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "api_key" in matches


def test_quick_pattern_ssh_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "ssh_key" in matches


def test_quick_pattern_openssh_key():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "ssh_key" in matches


def test_quick_pattern_db_url():
    text = "mysql://root:password123@localhost/appdb"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "db_url" in matches


def test_quick_pattern_token():
    text = "token = eyJhbGciOiJIUzI1NiJ9.abc.def"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "token" in matches


def test_quick_pattern_secret():
    text = "secret=very_secret_value_here"
    matches = [k for p, k in _QUICK_PATTERNS if p.search(text)]
    assert "secret" in matches


# ── _INTERESTING_NAMES ────────────────────────────────────────────────────────

def test_interesting_names_includes_key():
    assert "key" in _INTERESTING_NAMES


def test_interesting_names_includes_pass():
    assert "pass" in _INTERESTING_NAMES


def test_interesting_names_includes_id_rsa():
    assert "id_rsa" in _INTERESTING_NAMES


def test_interesting_names_includes_env():
    assert ".env" in _INTERESTING_NAMES


# ── run() with no loot ────────────────────────────────────────────────────────

def test_run_no_loot_returns_early(loot_agent):
    agent, session, _ = loot_agent
    result = agent.run()
    assert "no loot" in result.summary.lower()


# ── run() with loot files ─────────────────────────────────────────────────────

def test_run_skips_missing_files(loot_agent):
    agent, session, _ = loot_agent
    session.loot.append("/nonexistent/path/secret.txt")
    result = agent.run()
    assert result is not None


def test_run_skips_large_files(loot_agent, tmp_path):
    agent, session, _ = loot_agent
    big_file = tmp_path / "huge.txt"
    big_file.write_bytes(b"x" * 600_000)
    session.loot.append(str(big_file))
    result = agent.run()
    assert result is not None


def test_run_detects_password_in_file(loot_agent, tmp_path):
    agent, session, _ = loot_agent
    f = tmp_path / "config.php"
    f.write_text("password=SuperSecret123\nother_setting=value")
    session.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = False
        result = agent.run()
    assert result is not None


def test_run_adds_ssh_key_credential_immediately(loot_agent, tmp_path):
    agent, session, _ = loot_agent
    f = tmp_path / "id_rsa"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
    session.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = False
        agent.run()
    ssh_creds = [c for c in session.credentials if c.service == "ssh"]
    assert len(ssh_creds) >= 1
    assert any("id_rsa" in (c.note or "") for c in ssh_creds)


def test_run_extracts_credentials_from_llm(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"credentials": [{"username": "admin", "password": "Pass123", "service": "mysql", "note": "web.config"}], "ssh_key_paths": [], "hashes": [], "attack_vectors": ["SSH as admin:Pass123"], "interesting_findings": [], "summary": "found db creds"}')
    agent = LootAnalyzerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    f = tmp_path / "web.config"
    f.write_text("<add key=\"password\" value=\"Pass123\"/>")
    s.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = True
        result = agent.run()
    mysql_creds = [c for c in s.credentials if c.service == "mysql"]
    assert len(mysql_creds) >= 1
    assert mysql_creds[0].username == "admin"


def test_run_surfaces_hashes_as_findings(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"credentials": [], "ssh_key_paths": [], "hashes": [{"user": "admin", "hash": "aad3b435b51404ee", "type": "NTLM"}], "attack_vectors": [], "interesting_findings": [], "summary": "found hash"}')
    agent = LootAnalyzerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    f = tmp_path / "credentials.txt"
    f.write_text("password=dummy\nadmin:aad3b435b51404ee")
    s.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = True
        result = agent.run()
    assert any("Hash" in fi.title for fi in s.findings)


def test_run_caps_files_sent_to_llm(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"credentials": [], "ssh_key_paths": [], "hashes": [], "attack_vectors": [], "interesting_findings": [], "summary": "done"}')
    agent = LootAnalyzerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    for i in range(12):
        f = tmp_path / f"config_{i}.php"
        f.write_text(f"password=pass{i}")
        s.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = True
        agent.run()
    call_content = llm.calls[-1][1] if llm.calls else ""
    assert call_content.count("===") <= 16  # max 8 files × 2 delimiters each


def test_run_summary_mentions_count(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    llm = StubLLM('{"credentials": [{"username": "u", "password": "p", "service": "ssh", "note": ""}], "ssh_key_paths": [], "hashes": [], "attack_vectors": [], "interesting_findings": [], "summary": "cred found"}')
    agent = LootAnalyzerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    f = tmp_path / "creds.txt"
    f.write_text("password=secret123")
    s.loot.append(str(f))
    with patch("checkpoint.checkpoint") as mock_cp:
        mock_cp.return_value.approved = True
        result = agent.run()
    assert "1" in result.summary
