"""Tests for metrics.py — flag detection, portfolio I/O, aggregation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import metrics


@dataclass
class _FakeFinding:
    mitre_id: str = ""


@dataclass
class _FakeAgentResult:
    agent: str


@dataclass
class _FakePlan:
    machine_difficulty: str = ""


@dataclass
class _FakeSession:
    target_ip: str = "10.10.11.1"
    machine_name: str = "Lame"
    os_guess: str = "Linux"
    user_flag: str = ""
    root_flag: str = ""
    findings: list = field(default_factory=list)
    agent_results: list = field(default_factory=list)
    attack_plan: _FakePlan | None = None


def test_extract_flags_htb_format():
    out = "root@target:~# cat root.txt\nHTB{p0wn3d_th3_b0x}\n"
    assert "HTB{p0wn3d_th3_b0x}" in metrics.extract_flags(out)


def test_extract_flags_md5_hex():
    out = "user flag: 5f4dcc3b5aa765d61d8327deb882cf99"
    found = metrics.extract_flags(out)
    assert any(f.lower() == "5f4dcc3b5aa765d61d8327deb882cf99" for f in found)


def test_extract_flags_none():
    assert metrics.extract_flags("no flag here") == []


def test_load_portfolio_missing_returns_empty(tmp_path: Path):
    p = tmp_path / "no.json"
    assert metrics.load_portfolio(p) == []


def test_save_and_load_portfolio_roundtrip(tmp_path: Path):
    p = tmp_path / "pf.json"
    recs = [{"target": "10.10.11.1", "root_flag_captured": True}]
    metrics.save_portfolio(recs, p)
    assert metrics.load_portfolio(p) == recs


def test_record_run_appends_and_persists(tmp_path: Path):
    p = tmp_path / "pf.json"
    s = _FakeSession(user_flag="x", root_flag="y", attack_plan=_FakePlan(machine_difficulty="easy"))
    s.agent_results = [_FakeAgentResult("Recon"), _FakeAgentResult("Exploit")]
    s.findings = [_FakeFinding(mitre_id="T1190"), _FakeFinding(mitre_id="T1548")]
    rec = metrics.record_run(s, duration_sec=1234.5, path=p)
    assert rec["user_flag_captured"] is True
    assert rec["root_flag_captured"] is True
    assert rec["difficulty"] == "easy"
    assert rec["agents_used"] == ["Recon", "Exploit"]
    assert sorted(rec["mitre_techniques"]) == ["T1190", "T1548"]
    loaded = metrics.load_portfolio(p)
    assert len(loaded) == 1


def test_aggregate_empty():
    s = metrics.aggregate([])
    assert s["runs"] == 0
    assert s["solve_rate_pct"] == 0.0


def test_aggregate_counts_flags_and_solve_rate():
    recs = [
        {"user_flag_captured": True, "root_flag_captured": True, "difficulty": "easy", "duration_sec": 1000, "mitre_techniques": ["T1190"]},
        {"user_flag_captured": True, "root_flag_captured": False, "difficulty": "medium", "duration_sec": 2000, "mitre_techniques": ["T1190", "T1548"]},
        {"user_flag_captured": False, "root_flag_captured": False, "difficulty": "hard", "duration_sec": 0, "mitre_techniques": []},
    ]
    s = metrics.aggregate(recs)
    assert s["runs"] == 3
    assert s["user_flags"] == 2
    assert s["root_flags"] == 1
    assert s["both_flags"] == 1
    assert s["solve_rate_pct"] == 33.3
    assert s["by_difficulty"]["easy"] == {"runs": 1, "rooted": 1}
    assert s["by_difficulty"]["medium"] == {"runs": 1, "rooted": 0}
    top_ids = [tid for tid, _ in s["top_techniques"]]
    assert "T1190" in top_ids


def test_render_stats_empty():
    out = metrics.render_stats(metrics.aggregate([]))
    assert "no runs recorded" in out


def test_render_stats_formats_summary():
    recs = [
        {"user_flag_captured": True, "root_flag_captured": True, "difficulty": "easy", "duration_sec": 1000, "mitre_techniques": ["T1190"]},
    ]
    out = metrics.render_stats(metrics.aggregate(recs))
    assert "ATLAS Portfolio" in out
    assert "Total runs:" in out
    assert "solve rate" in out
    assert "easy" in out
    assert "T1190" in out
