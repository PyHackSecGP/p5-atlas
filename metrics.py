"""Portfolio metrics — track flag capture rate across HTB runs.

Every session appends one record to ~/.atlas/portfolio.json. The
`atlas-stats` CLI (python -m metrics) prints aggregate solve rate,
average duration, and top MITRE techniques.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

_DEFAULT_PORTFOLIO = Path(os.environ.get("ATLAS_PORTFOLIO", "~/.atlas/portfolio.json")).expanduser()

_FLAG_PATTERNS = (
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE),
)


def _portfolio_path(path: Path | str | None = None) -> Path:
    return Path(path).expanduser() if path else _DEFAULT_PORTFOLIO


def load_portfolio(path: Path | str | None = None) -> list[dict[str, Any]]:
    """Load portfolio.json; return [] if missing."""
    p = _portfolio_path(path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_portfolio(records: list[dict[str, Any]], path: Path | str | None = None) -> None:
    """Overwrite portfolio.json with the given records."""
    p = _portfolio_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(records, indent=2))


def extract_flags(text: str) -> list[str]:
    """Return all HTB{} and 32-hex flag matches in text."""
    found: list[str] = []
    for pat in _FLAG_PATTERNS:
        found.extend(pat.findall(text))
    return found


def record_run(session: Any, *, duration_sec: float | None = None, path: Path | str | None = None) -> dict[str, Any]:
    """Append one run record derived from a HackSession-like object."""
    rec = {
        "target": getattr(session, "target_ip", ""),
        "machine": getattr(session, "machine_name", "") or getattr(session, "target_ip", ""),
        "difficulty": getattr(getattr(session, "attack_plan", None), "machine_difficulty", "") or "",
        "os": getattr(session, "os_guess", ""),
        "user_flag_captured": bool(getattr(session, "user_flag", "")),
        "root_flag_captured": bool(getattr(session, "root_flag", "")),
        "duration_sec": float(duration_sec) if duration_sec is not None else 0.0,
        "timestamp": int(time.time()),
        "agents_used": [ar.agent for ar in getattr(session, "agent_results", []) if hasattr(ar, "agent")],
        "mitre_techniques": sorted({
            tid for f in getattr(session, "findings", [])
            for tid in [getattr(f, "mitre_id", "")] if tid
        }),
    }
    recs = load_portfolio(path)
    recs.append(rec)
    save_portfolio(recs, path)
    return rec


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate stats from portfolio records."""
    n = len(records)
    if n == 0:
        return {
            "runs": 0,
            "user_flags": 0,
            "root_flags": 0,
            "both_flags": 0,
            "solve_rate_pct": 0.0,
            "avg_duration_sec": 0.0,
            "by_difficulty": {},
            "top_techniques": [],
        }
    uf = sum(1 for r in records if r.get("user_flag_captured"))
    rf = sum(1 for r in records if r.get("root_flag_captured"))
    both = sum(1 for r in records if r.get("user_flag_captured") and r.get("root_flag_captured"))
    durations = [r.get("duration_sec", 0.0) for r in records if r.get("duration_sec")]
    avg_dur = sum(durations) / len(durations) if durations else 0.0

    diff_counter: dict[str, dict[str, int]] = {}
    for r in records:
        d = r.get("difficulty", "") or "unknown"
        bucket = diff_counter.setdefault(d, {"runs": 0, "rooted": 0})
        bucket["runs"] += 1
        if r.get("root_flag_captured"):
            bucket["rooted"] += 1

    tech_counter: Counter[str] = Counter()
    for r in records:
        tech_counter.update(r.get("mitre_techniques", []))

    return {
        "runs": n,
        "user_flags": uf,
        "root_flags": rf,
        "both_flags": both,
        "solve_rate_pct": round(100 * both / n, 1),
        "avg_duration_sec": round(avg_dur, 1),
        "by_difficulty": diff_counter,
        "top_techniques": tech_counter.most_common(5),
    }


def render_stats(summary: dict[str, Any]) -> str:
    """Pretty-print aggregate summary."""
    if summary["runs"] == 0:
        return "ATLAS Portfolio\n===============\n(no runs recorded yet)\n"
    lines = [
        "ATLAS Portfolio",
        "===============",
        f"Total runs:        {summary['runs']}",
        f"User flags:        {summary['user_flags']}  ({round(100*summary['user_flags']/summary['runs'],1)}%)",
        f"Root flags:        {summary['root_flags']}  ({round(100*summary['root_flags']/summary['runs'],1)}%)",
        f"Both flags:        {summary['both_flags']}  (solve rate {summary['solve_rate_pct']}%)",
        f"Avg duration:      {summary['avg_duration_sec']}s",
        "",
    ]
    if summary["by_difficulty"]:
        lines.append("By difficulty:")
        for diff, b in sorted(summary["by_difficulty"].items()):
            pct = round(100 * b["rooted"] / b["runs"], 1) if b["runs"] else 0
            lines.append(f"  {diff:<10} {b['rooted']}/{b['runs']}  ({pct}% rooted)")
        lines.append("")
    if summary["top_techniques"]:
        lines.append("Top MITRE techniques:")
        for tid, cnt in summary["top_techniques"]:
            lines.append(f"  {tid:<10} {cnt}")
    return "\n".join(lines)


def main() -> int:
    """CLI: python -m metrics prints aggregate stats."""
    recs = load_portfolio()
    print(render_stats(aggregate(recs)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
