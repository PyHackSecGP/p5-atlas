"""Tests for agents/planner.py — stage ordering, skip logic, auto-skip web."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from models import HackSession, Port, Stage, MachineAttackPlan
from agents.planner import PlannerAgent
from conftest import StubLLM


def _make_agent(session: HackSession, llm_response: str, tmp_path) -> PlannerAgent:
    return PlannerAgent(session=session, llm=llm_response if isinstance(llm_response, StubLLM) else StubLLM(llm_response), output_dir=str(tmp_path))


FULL_PLAN = """{
  "stage_order": ["enumeration", "web", "exploit", "privesc", "report"],
  "skip_stages": [],
  "stage_tactics": {"enumeration": ["smb null session"]},
  "primary_vector": "SMB null session",
  "machine_difficulty": "easy",
  "machine_type": "Linux CTF",
  "reasoning": "web exposed, smb visible"
}"""

NO_WEB_PLAN = """{
  "stage_order": ["enumeration", "exploit", "privesc", "report"],
  "skip_stages": [],
  "stage_tactics": {},
  "primary_vector": "SMB null session",
  "machine_difficulty": "easy",
  "machine_type": "Linux CTF",
  "reasoning": "no web ports"
}"""


# ── Stage ordering ────────────────────────────────────────────────────────────

def test_plan_sets_stage_order(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=80, service="http", state="open", version=""))
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan is not None
    assert "enumeration" in s.attack_plan.stage_order


def test_plan_stores_primary_vector(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=445, service="microsoft-ds", state="open", version=""))
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan.primary_vector == "SMB null session"


def test_plan_stores_difficulty(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan.machine_difficulty == "easy"


def test_plan_stores_machine_type(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan.machine_type == "Linux CTF"


def test_plan_stores_reasoning(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan.reasoning != ""


def test_plan_report_always_in_order(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert "report" in s.attack_plan.stage_order


# ── Auto-skip web ─────────────────────────────────────────────────────────────

def test_auto_skip_web_when_no_web_ports(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=22, service="ssh", state="open", version=""))
    s.ports.append(Port(number=445, service="microsoft-ds", state="open", version=""))
    agent = _make_agent(s, NO_WEB_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert "web" in s.attack_plan.skip_stages


def test_web_not_auto_skipped_when_port_80_present(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=80, service="http", state="open", version="Apache"))
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert "web" not in s.attack_plan.skip_stages


def test_web_not_auto_skipped_when_port_443_present(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=443, service="https", state="open", version=""))
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert "web" not in s.attack_plan.skip_stages


# ── Fallback defaults ─────────────────────────────────────────────────────────

def test_invalid_llm_response_falls_back_to_defaults(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.ports.append(Port(number=80, service="http", state="open", version=""))
    agent = _make_agent(s, '{"stage_order": [], "skip_stages": []}', tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert s.attack_plan is not None
    assert len(s.attack_plan.stage_order) > 0


def test_unknown_stages_in_llm_response_filtered(tmp_path):
    bad_plan = """{
      "stage_order": ["unknown_stage", "enumeration", "report"],
      "skip_stages": [],
      "stage_tactics": {},
      "primary_vector": "test",
      "machine_difficulty": "easy",
      "machine_type": "Linux",
      "reasoning": "test"
    }"""
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, bad_plan, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    assert "unknown_stage" not in s.attack_plan.stage_order


# ── Result ────────────────────────────────────────────────────────────────────

def test_result_summary_is_nonempty(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        result = agent.run()
    assert result.summary != ""


def test_result_metadata_stored(tmp_path):
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    agent = _make_agent(s, FULL_PLAN, tmp_path)
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        result = agent.run()
    assert result.metadata is not None
    assert "stage_order" in result.metadata


def test_uses_recon_context_when_available(tmp_path):
    from models import AgentResult
    s = HackSession(target_ip="10.10.11.1", os_guess="Linux")
    s.agent_results.append(AgentResult(
        agent="Recon", stage=Stage.RECON,
        summary="Found SSH and SMB",
        next_actions=["check SMB shares"],
        metadata={"attack_surface": ["ssh", "smb"], "interesting_findings": [], "reasoning": "smb visible"},
    ))
    llm = StubLLM(FULL_PLAN)
    agent = PlannerAgent(session=s, llm=llm, output_dir=str(tmp_path))
    with patch("checkpoint.section"), patch("rich.console.Console.print"):
        agent.run()
    # Check that recon context appeared in the LLM prompt
    assert any("Recon" in call[1] or "smb" in call[1].lower() for call in llm.calls)
