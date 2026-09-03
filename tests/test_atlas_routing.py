"""Tests for atlas.py — _derive_stage_order, _should_skip, _flags_captured."""
from __future__ import annotations
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import HackSession, Port, Stage, MachineAttackPlan
from atlas import _derive_stage_order, _should_skip, _flags_captured


# ── _derive_stage_order ───────────────────────────────────────────────────────

def test_derive_uses_attack_plan_order():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(
        stage_order=["enumeration", "exploit", "privesc", "report"],
        skip_stages=[],
    )
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    assert stages[0] == Stage.ENUMERATION
    assert Stage.WEB not in stages


def test_derive_falls_back_to_default_without_plan():
    s = HackSession(target_ip="10.0.0.1")
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    assert Stage.ENUMERATION in stages
    assert Stage.REPORT in stages


def test_derive_starts_from_given_stage():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(
        stage_order=["enumeration", "web", "exploit", "privesc", "report"],
        skip_stages=[],
    )
    stages = _derive_stage_order(s, Stage.EXPLOIT)
    assert stages[0] == Stage.EXPLOIT
    assert Stage.ENUMERATION not in stages


def test_derive_handles_empty_plan_order():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(stage_order=[], skip_stages=[])
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    assert len(stages) > 0


def test_derive_filters_invalid_stage_names():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(
        stage_order=["enumeration", "bogus_stage", "report"],
        skip_stages=[],
    )
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    for st in stages:
        assert isinstance(st, Stage)


def test_derive_excludes_recon_from_plan_order():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(
        stage_order=["recon", "enumeration", "exploit", "report"],
        skip_stages=[],
    )
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    assert Stage.RECON not in stages


def test_derive_report_always_present_in_default():
    s = HackSession(target_ip="10.0.0.1")
    stages = _derive_stage_order(s, Stage.ENUMERATION)
    assert Stage.REPORT in stages


def test_derive_plan_with_only_report():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(stage_order=["report"], skip_stages=[])
    stages = _derive_stage_order(s, Stage.REPORT)
    assert Stage.REPORT in stages


# ── _should_skip ──────────────────────────────────────────────────────────────

def test_should_skip_web_when_no_web_ports():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=22, service="ssh", state="open", version=""))
    assert _should_skip(s, Stage.WEB) is True


def test_should_not_skip_web_when_port_80_open():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=80, service="http", state="open", version=""))
    assert _should_skip(s, Stage.WEB) is False


def test_should_not_skip_web_when_port_443_open():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=443, service="https", state="open", version=""))
    assert _should_skip(s, Stage.WEB) is False


def test_should_skip_stage_in_plan_skip_list():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=80, service="http", state="open", version=""))
    s.attack_plan = MachineAttackPlan(
        stage_order=["exploit", "report"],
        skip_stages=["web", "enumeration"],
    )
    assert _should_skip(s, Stage.WEB) is True
    assert _should_skip(s, Stage.ENUMERATION) is True


def test_should_not_skip_exploit_by_default():
    s = HackSession(target_ip="10.0.0.1")
    assert _should_skip(s, Stage.EXPLOIT) is False


def test_should_not_skip_privesc_by_default():
    s = HackSession(target_ip="10.0.0.1")
    assert _should_skip(s, Stage.PRIVESC) is False


def test_should_skip_respects_plan_skip_for_enumeration():
    s = HackSession(target_ip="10.0.0.1")
    s.attack_plan = MachineAttackPlan(
        stage_order=["exploit", "report"],
        skip_stages=["enumeration"],
    )
    assert _should_skip(s, Stage.ENUMERATION) is True


def test_should_not_skip_when_plan_is_none():
    s = HackSession(target_ip="10.0.0.1")
    s.ports.append(Port(number=80, service="http", state="open", version=""))
    s.attack_plan = None
    assert _should_skip(s, Stage.WEB) is False


# ── _flags_captured ───────────────────────────────────────────────────────────

def test_flags_captured_both_set():
    s = HackSession(target_ip="10.0.0.1")
    s.user_flag = "HTB{user}"
    s.root_flag = "HTB{root}"
    assert _flags_captured(s) is True


def test_flags_not_captured_only_user():
    s = HackSession(target_ip="10.0.0.1")
    s.user_flag = "HTB{user}"
    s.root_flag = ""
    assert _flags_captured(s) is False


def test_flags_not_captured_only_root():
    s = HackSession(target_ip="10.0.0.1")
    s.user_flag = ""
    s.root_flag = "HTB{root}"
    assert _flags_captured(s) is False


def test_flags_not_captured_neither():
    s = HackSession(target_ip="10.0.0.1")
    assert _flags_captured(s) is False


def test_flags_not_captured_when_none():
    s = HackSession(target_ip="10.0.0.1")
    s.user_flag = None
    s.root_flag = None
    assert _flags_captured(s) is False
