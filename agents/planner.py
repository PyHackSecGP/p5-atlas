"""Planner Agent — machine-specific attack strategy built after Recon completes."""
from __future__ import annotations
from models import HackSession, AgentResult, Stage, MachineAttackPlan
from llm import LLMProvider
from agents.base import BaseAgent
import checkpoint as cp


class PlannerAgent(BaseAgent):
    NAME  = "Planner"
    STAGE = Stage.RECON  # conceptually part of recon phase

    SYSTEM_PROMPT = """You are a senior HTB pentester who builds machine-specific attack strategies.
You receive recon data and produce a prioritised, tactical attack plan.
Be decisive. Skip stages that won't yield results for this specific machine.
Focus on highest-probability vectors based solely on what was found.
Never fabricate information."""

    # Ordered fallback when LLM omits stages
    DEFAULT_ORDER = ["enumeration", "web", "exploit", "privesc", "report"]

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")

        recon_result = next(
            (r for r in self.session.agent_results if r.agent == "Recon"), None,
        )
        recon_ctx = ""
        if recon_result:
            meta = recon_result.metadata
            recon_ctx = "\n".join([
                f"Recon summary: {recon_result.summary}",
                f"Attack surface: {', '.join(meta.get('attack_surface', []))}",
                f"Interesting findings: {', '.join(meta.get('interesting_findings', []))}",
                f"Priority targets: {', '.join(recon_result.next_actions[:5])}",
                f"LLM reasoning: {meta.get('reasoning', '')}",
            ])

        has_web = bool(self.session.web_ports)
        has_smb = bool(self.session.smb_ports)
        has_ldap = any(p.number in (389, 636, 3268) for p in self.session.open_ports)
        has_ssh  = self.session.ssh_port is not None
        has_winrm = self.session.winrm_port is not None

        self.log("Building machine-specific attack plan...")
        plan_data = self.ask_json(f"""
Build a tactical attack plan for this HTB machine.

TARGET: {self.session.target_ip}
OS: {self.session.os_guess or 'unknown'}
Open ports: {', '.join(f"{p.number}/{p.service} {p.version}" for p in self.session.open_ports)}
Web targets: {', '.join(w.url for w in self.session.web_targets) or 'none'}
Flags: web={has_web}, smb={has_smb}, ldap={has_ldap}, ssh={has_ssh}, winrm={has_winrm}

{recon_ctx}

Available stages: enumeration, web, exploit, privesc, report
Rules:
- Skip "web" if no HTTP/HTTPS ports exist
- Skip "enumeration" if no SMB/LDAP/FTP/SNMP
- If a direct CVE is visible, put "exploit" before "enumeration"
- Always end with "report"

Respond ONLY with valid JSON:
{{
  "stage_order": ["enumeration", "exploit", "privesc", "report"],
  "skip_stages": ["web"],
  "stage_tactics": {{
    "enumeration": ["try SMB null session", "check FTP anonymous login"],
    "exploit": ["test EternalBlue first on SMB", "try default creds on port 8080"],
    "privesc": ["focus on SUID binaries", "check sudo -l immediately"]
  }},
  "primary_vector": "SMB anonymous share with plaintext credential in config file",
  "machine_difficulty": "easy",
  "machine_type": "Windows AD / Linux web / Linux CTF / etc",
  "reasoning": "2-3 sentence tactical rationale"
}}""")

        # Validate and fill defaults
        raw_order = plan_data.get("stage_order", self.DEFAULT_ORDER)
        stage_order = [s for s in raw_order if s in self.DEFAULT_ORDER]
        if not stage_order:
            stage_order = self.DEFAULT_ORDER[:]

        # Auto-add skip_stages based on hard facts
        skip = list(plan_data.get("skip_stages", []))
        if not has_web and "web" not in skip:
            skip.append("web")

        plan = MachineAttackPlan(
            stage_order=stage_order,
            skip_stages=skip,
            stage_tactics=plan_data.get("stage_tactics", {}),
            primary_vector=plan_data.get("primary_vector", ""),
            machine_difficulty=plan_data.get("machine_difficulty", "medium"),
            machine_type=plan_data.get("machine_type", ""),
            reasoning=plan_data.get("reasoning", ""),
        )
        self.session.attack_plan = plan

        cp.section("Attack Plan")
        from rich.console import Console
        from rich.panel import Panel
        flow = " → ".join(s.upper() for s in plan.stage_order)
        body = (
            f"[bold]Machine type:[/bold] {plan.machine_type or 'unknown'}\n"
            f"[bold]Difficulty:[/bold]   {plan.machine_difficulty}\n"
            f"[bold]Primary vector:[/bold] {plan.primary_vector}\n\n"
            f"[bold cyan]Stage flow:[/bold cyan] {flow}\n"
        )
        if plan.skip_stages:
            body += f"[bold red]Skipping:[/bold red] {', '.join(plan.skip_stages)}\n"
        body += f"\n[bold yellow]Strategy:[/bold yellow] {plan.reasoning}"
        Console().print(Panel(body, title="[cyan]Tactical Plan[/cyan]", border_style="cyan"))

        result.summary = (
            f"{plan.machine_type} [{plan.machine_difficulty}] — "
            f"Primary: {plan.primary_vector} — "
            f"Flow: {' → '.join(plan.stage_order)}"
        )
        result.metadata = plan_data
        return result
