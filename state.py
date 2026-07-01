"""Session persistence — save/resume ATLAS sessions as JSON."""
from __future__ import annotations
import dataclasses
import json
from pathlib import Path
from models import HackSession, Port, WebTarget, Credential, Finding, AgentResult, Stage, Severity


def _to_dict(obj) -> object:
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


def load(path: str) -> HackSession | None:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text())

    ports = [Port(**x) for x in data.get("ports", [])]
    web_targets = [WebTarget(**x) for x in data.get("web_targets", [])]
    credentials = [Credential(**x) for x in data.get("credentials", [])]

    findings = [
        Finding(
            title=f["title"], severity=Severity(f["severity"]),
            description=f["description"], evidence=f.get("evidence", ""),
            command=f.get("command", ""), agent=f.get("agent", ""),
        )
        for f in data.get("findings", [])
    ]

    return HackSession(
        target_ip=data["target_ip"],
        machine_name=data.get("machine_name", ""),
        os_guess=data.get("os_guess", ""),
        current_stage=Stage(data.get("current_stage", "init")),
        ports=ports,
        web_targets=web_targets,
        credentials=credentials,
        findings=findings,
        user_flag=data.get("user_flag", ""),
        root_flag=data.get("root_flag", ""),
        notes=data.get("notes", []),
    )
