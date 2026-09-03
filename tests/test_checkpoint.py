"""Tests for checkpoint.py — auto mode, risk thresholds, CheckpointResult."""
from __future__ import annotations
import pytest
import checkpoint as cp


@pytest.fixture(autouse=True)
def reset_auto_mode():
    """Restore auto mode state after each test."""
    original_auto = cp.AUTO_MODE
    original_risk = cp.AUTO_MAX_RISK
    yield
    cp.AUTO_MODE = original_auto
    cp.AUTO_MAX_RISK = original_risk


# ── CheckpointResult ──────────────────────────────────────────────────────────

def test_checkpoint_result_approved_is_approved():
    r = cp.CheckpointResult(cp.CheckpointResult.APPROVED)
    assert r.approved is True


def test_checkpoint_result_modified_is_approved():
    r = cp.CheckpointResult(cp.CheckpointResult.MODIFIED, override="new cmd")
    assert r.approved is True
    assert r.override == "new cmd"


def test_checkpoint_result_skipped_not_approved():
    r = cp.CheckpointResult(cp.CheckpointResult.SKIPPED)
    assert r.approved is False


def test_checkpoint_result_aborted_not_approved():
    r = cp.CheckpointResult(cp.CheckpointResult.ABORTED)
    assert r.approved is False


# ── Auto mode ─────────────────────────────────────────────────────────────────

def test_enable_auto_mode_sets_flag():
    cp.enable_auto_mode("medium")
    assert cp.AUTO_MODE is True
    assert cp.AUTO_MAX_RISK == "medium"


def test_auto_mode_approves_low_risk(capsys):
    cp.enable_auto_mode("medium")
    result = cp.checkpoint(
        agent="Test",
        what_found="open port 22",
        plan="run ssh banner grab",
        why="info gathering",
        what_to_look_for="ssh version",
        risk="low",
    )
    assert result.approved is True
    assert result.action == cp.CheckpointResult.APPROVED


def test_auto_mode_approves_at_threshold(capsys):
    cp.enable_auto_mode("medium")
    result = cp.checkpoint(
        agent="Test",
        what_found="SMB open",
        plan="enum4linux",
        why="smb enum",
        what_to_look_for="shares",
        risk="medium",
    )
    assert result.approved is True


def test_risk_level_ordering():
    risk_levels = cp._RISK_LEVEL
    assert risk_levels["low"] < risk_levels["medium"]
    assert risk_levels["medium"] < risk_levels["high"]
    assert risk_levels["high"] < risk_levels["critical"]


# ── Notify / section helpers ──────────────────────────────────────────────────

def test_notify_does_not_raise(capsys):
    cp.notify("Agent", "test message", "info")
    cp.notify("Agent", "warning", "warning")
    cp.notify("Agent", "success", "success")
    cp.notify("Agent", "error", "error")


def test_section_does_not_raise(capsys):
    cp.section("Test Section")


def test_thinking_does_not_raise(capsys):
    cp.thinking("TestAgent", "thinking about next step")


def test_tool_output_does_not_raise(capsys):
    cp.tool_output("nmap", "22/tcp open ssh OpenSSH 8.2")
