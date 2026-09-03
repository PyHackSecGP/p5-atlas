"""Tests for tools/mitre_mapper.py — keyword matching, dedup, table format."""
from __future__ import annotations
import pytest
from models import Finding, AgentResult, Stage, Severity
from tools.mitre_mapper import map_findings_to_attack, format_attack_table_markdown, AttackTechnique


def _finding(title: str, desc: str = "") -> Finding:
    return Finding(title=title, severity=Severity.MEDIUM, description=desc)


def _result(summary: str) -> AgentResult:
    return AgentResult(agent="Test", stage=Stage.RECON, summary=summary)


# ── map_findings_to_attack ────────────────────────────────────────────────────

def test_nmap_maps_to_network_service_discovery():
    techniques = map_findings_to_attack(
        [_finding("nmap scan complete")], [], [],
    )
    ids = [t.id for t in techniques]
    assert "T1046" in ids


def test_smb_maps_to_lateral_movement():
    techniques = map_findings_to_attack(
        [], [_result("smb enumeration via enum4linux")], [],
    )
    ids = [t.id for t in techniques]
    assert "T1021.002" in ids or "T1018" in ids


def test_hydra_maps_to_brute_force():
    techniques = map_findings_to_attack(
        [_finding("hydra brute force on SSH")], [], [],
    )
    ids = [t.id for t in techniques]
    assert "T1110.001" in ids


def test_sudo_maps_to_privilege_escalation():
    techniques = map_findings_to_attack(
        [_finding("sudo -l shows NOPASSWD")], [], [],
    )
    ids = [t.id for t in techniques]
    assert "T1548.003" in ids


def test_suid_maps_to_setuid_technique():
    techniques = map_findings_to_attack(
        [_finding("SUID binary found: /usr/bin/find")], [], [],
    )
    ids = [t.id for t in techniques]
    assert "T1548.001" in ids


def test_ssh_maps_to_remote_services():
    techniques = map_findings_to_attack(
        [], [_result("SSH login via sshpass")], [],
    )
    ids = [t.id for t in techniques]
    assert "T1021.004" in ids


def test_reverse_shell_maps_to_execution():
    techniques = map_findings_to_attack(
        [], [], ["obtained reverse shell via bash -i"],
    )
    ids = [t.id for t in techniques]
    assert "T1059.004" in ids


def test_deduplication_same_technique_not_repeated():
    techniques = map_findings_to_attack(
        [_finding("nmap scan"), _finding("nmap port discovery")], [], [],
    )
    ids = [t.id for t in techniques]
    assert ids.count("T1046") == 1


def test_empty_inputs_returns_empty():
    assert map_findings_to_attack([], [], []) == []


def test_techniques_sorted_by_tactic_id():
    techniques = map_findings_to_attack(
        [_finding("nmap"), _finding("suid"), _finding("hydra")], [], [],
    )
    tactic_ids = [t.tactic_id for t in techniques]
    assert tactic_ids == sorted(tactic_ids)


def test_cve_maps_to_exploitation():
    techniques = map_findings_to_attack(
        [_finding("CVE-2021-4034 polkit exploit")], [], [],
    )
    ids = [t.id for t in techniques]
    assert "T1068" in ids or "T1203" in ids


def test_flag_capture_maps_to_collection():
    techniques = map_findings_to_attack(
        [], [], ["user.txt captured HTB{flag}"],
    )
    ids = [t.id for t in techniques]
    assert "T1005" in ids


# ── format_attack_table_markdown ──────────────────────────────────────────────

def test_format_table_empty_returns_empty():
    assert format_attack_table_markdown([]) == ""


def test_format_table_contains_header():
    t = AttackTechnique("T1046", "Network Service Discovery", "Reconnaissance", "TA0043",
                        "https://attack.mitre.org/techniques/T1046/")
    table = format_attack_table_markdown([t])
    assert "## MITRE ATT&CK" in table
    assert "| Technique |" in table


def test_format_table_contains_technique_id():
    t = AttackTechnique("T1046", "Network Service Discovery", "Reconnaissance", "TA0043",
                        "https://attack.mitre.org/techniques/T1046/")
    table = format_attack_table_markdown([t])
    assert "T1046" in table
    assert "Network Service Discovery" in table


def test_format_table_contains_link():
    t = AttackTechnique("T1046", "Network Service Discovery", "Reconnaissance", "TA0043",
                        "https://attack.mitre.org/techniques/T1046/")
    table = format_attack_table_markdown([t])
    assert "https://attack.mitre.org" in table
