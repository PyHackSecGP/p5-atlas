"""Session persistence — save/resume ATLAS sessions as JSON."""
from __future__ import annotations
import dataclasses
import json
from pathlib import Path
from models import (
    HackSession, Port, WebTarget, Credential, Finding,
    AgentResult, Stage, Severity, MachineAttackPlan,
)


def _to_dict(obj) -> object:
    if obj is None:
        return None
    if dataclasses.is_dataclass(obj):
        return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (Stage, Severity)):
        return obj.value
    return obj


def save(session: HackSession, path: str) -> None:
    Path(path).write_text(json.dumps(_to_dict(session), indent=2))


def _finding_from_dict(f: dict) -> Finding:
    return Finding(
        title=f["title"],
        severity=Severity(f["severity"]),
        description=f["description"],
        evidence=f.get("evidence", ""),
        command=f.get("command", ""),
        agent=f.get("agent", ""),
    )


def _agent_result_from_dict(d: dict) -> AgentResult:
    return AgentResult(
        agent=d["agent"],
        stage=Stage(d["stage"]),
        summary=d.get("summary", ""),
        raw_outputs=d.get("raw_outputs", {}),
        findings=[_finding_from_dict(f) for f in d.get("findings", [])],
        next_actions=d.get("next_actions", []),
        metadata=d.get("metadata", {}),
    )


def load(path: str) -> HackSession | None:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text())

    ap_data = data.get("attack_plan")
    attack_plan = MachineAttackPlan(**ap_data) if ap_data else None

    return HackSession(
        target_ip=data["target_ip"],
        machine_name=data.get("machine_name", ""),
        os_guess=data.get("os_guess", ""),
        current_stage=Stage(data.get("current_stage", "init")),
        ports=[Port(**x) for x in data.get("ports", [])],
        web_targets=[WebTarget(**x) for x in data.get("web_targets", [])],
        credentials=[Credential(**x) for x in data.get("credentials", [])],
        findings=[_finding_from_dict(f) for f in data.get("findings", [])],
        agent_results=[_agent_result_from_dict(a) for a in data.get("agent_results", [])],
        user_flag=data.get("user_flag", ""),
        root_flag=data.get("root_flag", ""),
        notes=data.get("notes", []),
        loot=data.get("loot", []),
        attack_plan=attack_plan,
    )


def list_sessions(base_dir: str = "") -> list[dict]:
    """Return summary of all past sessions."""
    base = Path(base_dir) if base_dir else Path.home() / "atlas-sessions"
    if not base.exists():
        return []

    results: list[dict] = []
    for session_dir in sorted(base.iterdir()):
        session_file = session_dir / "session.json"
        if not session_file.exists():
            continue
        try:
            data = json.loads(session_file.read_text())
            results.append({
                "target_ip":    data.get("target_ip", "?"),
                "machine_name": data.get("machine_name", "?"),
                "os_guess":     data.get("os_guess", "?"),
                "stage":        data.get("current_stage", "?"),
                "user_flag":    data.get("user_flag", ""),
                "root_flag":    data.get("root_flag", ""),
                "ports":        len(data.get("ports", [])),
                "creds":        len(data.get("credentials", [])),
                "loot":         len(data.get("loot", [])),
                "path":         str(session_dir),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return results
