#!/usr/bin/env python3
"""
ATLAS — Autonomous Team for LLM-Assisted Security

Autonomous HTB/CTF pentest pipeline with dynamic stage routing:
  Recon → Plan → [Enumeration] → [Web] → Exploit → PrivEsc → Report

Stage order is determined by PlannerAgent after Recon, not hardcoded.
Stages with no relevant targets are auto-skipped.
Both flags captured → immediate jump to Report.

Usage:
  atlas.py <IP> [--provider claude|ollama] [--model MODEL]
                [--resume] [--stage STAGE] [--auto] [--auto-risk RISK]
  atlas.py --list-sessions
"""
from __future__ import annotations
import argparse
import os
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import HackSession, Stage
from llm import get_provider, ClaudeProvider
import state as session_state
import checkpoint as cp
from agents.recon import ReconAgent
from agents.enumeration import EnumerationAgent
from agents.web import WebAgent
from agents.exploit import ExploitAgent
from agents.privesc import PrivEscAgent
from agents.reporter import ReporterAgent
from agents.planner import PlannerAgent
from agents.loot_analyzer import LootAnalyzerAgent

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# Ordered agent registry — Planner and LootAnalyzer are injected dynamically
PIPELINE_AGENTS: dict[Stage, type] = {
    Stage.RECON:       ReconAgent,
    Stage.ENUMERATION: EnumerationAgent,
    Stage.WEB:         WebAgent,
    Stage.EXPLOIT:     ExploitAgent,
    Stage.PRIVESC:     PrivEscAgent,
    Stage.REPORT:      ReporterAgent,
}

# Default stage order when no attack plan is available
DEFAULT_STAGE_ORDER = [
    Stage.ENUMERATION,
    Stage.WEB,
    Stage.EXPLOIT,
    Stage.PRIVESC,
    Stage.REPORT,
]

BANNER = r"""
 █████╗ ████████╗██╗      █████╗ ███████╗
██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝
███████║   ██║   ██║     ███████║███████╗
██╔══██║   ██║   ██║     ██╔══██║╚════██║
██║  ██║   ██║   ███████╗██║  ██║███████║
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
Autonomous Team for LLM-Assisted Security
"""


# ── Stage routing helpers ─────────────────────────────────────────────────────

def _derive_stage_order(session: HackSession, start_stage: Stage) -> list[Stage]:
    """Derive ordered stage list from attack plan or fall back to default."""
    plan = session.attack_plan
    if plan and plan.stage_order:
        ordered: list[Stage] = []
        for s in plan.stage_order:
            try:
                stage = Stage(s)
                if stage not in (Stage.INIT, Stage.DONE, Stage.RECON):
                    ordered.append(stage)
            except ValueError:
                pass
        if ordered:
            if start_stage in ordered:
                return ordered[ordered.index(start_stage):]
            return ordered

    start_idx = DEFAULT_STAGE_ORDER.index(start_stage) if start_stage in DEFAULT_STAGE_ORDER else 0
    return DEFAULT_STAGE_ORDER[start_idx:]


def _should_skip(session: HackSession, stage: Stage) -> bool:
    """Return True if this stage has no relevant targets or is explicitly skipped."""
    plan = session.attack_plan
    if plan and stage.value in plan.skip_stages:
        return True
    if stage == Stage.WEB and not session.web_ports:
        return True
    return False


def _flags_captured(session: HackSession) -> bool:
    return bool(session.user_flag and session.root_flag)


# ── Agent runners ─────────────────────────────────────────────────────────────

def _run_agent(
    AgentClass: type,
    session: HackSession,
    llm,
    output_dir: str,
    stage_label: str,
) -> bool:
    """Run one agent. Returns False if pipeline should abort."""
    agent = AgentClass(session=session, llm=llm, output_dir=output_dir)
    try:
        result = agent.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚡ Interrupted. Saving session...[/yellow]")
        return False
    except Exception as e:
        console.print(f"\n[red]Agent {agent.NAME} crashed: {e}[/red]")
        import traceback
        traceback.print_exc()
        resume = cp.checkpoint(
            agent="Orchestrator",
            what_found=f"{agent.NAME} crashed: {e}",
            plan="Skip to next stage",
            why="Agent failed — tool may not be installed or network issue",
            what_to_look_for="Check required tools are installed",
            risk="low",
        )
        return resume.approved

    session.agent_results.append(result)
    session_state.save(session, f"{output_dir}/session.json")
    return True


def _run_planner(session: HackSession, llm, output_dir: str) -> None:
    if isinstance(llm, ClaudeProvider):
        llm.set_stage("planning")
    agent = PlannerAgent(session=session, llm=llm, output_dir=output_dir)
    try:
        result = agent.run()
        session.agent_results.append(result)
        session_state.save(session, f"{output_dir}/session.json")
    except Exception as e:
        cp.notify("Orchestrator", f"Planner failed ({e}) — using default stage order", "warning")


def _run_loot_analyzer(session: HackSession, llm, output_dir: str) -> None:
    if not session.loot:
        return
    cp.section("Stage: LOOT ANALYSIS")
    if isinstance(llm, ClaudeProvider):
        llm.set_stage("enumeration")
    agent = LootAnalyzerAgent(session=session, llm=llm, output_dir=output_dir)
    try:
        result = agent.run()
        session.agent_results.append(result)
        session_state.save(session, f"{output_dir}/session.json")
    except Exception as e:
        cp.notify("Orchestrator", f"LootAnalyzer error: {e}", "warning")


def _run_reporter_now(session: HackSession, llm, output_dir: str) -> None:
    """Jump straight to report (e.g. after both flags captured)."""
    cp.section("Stage: REPORT (early — both flags captured)")
    session.current_stage = Stage.REPORT
    if isinstance(llm, ClaudeProvider):
        llm.set_stage("report")
    _run_agent(ReporterAgent, session, llm, output_dir, "report")


def _announce_flags(session: HackSession) -> None:
    if session.user_flag:
        console.print(f"\n  [bold green]🚩 USER FLAG: {session.user_flag}[/bold green]")
    if session.root_flag:
        console.print(f"  [bold green]🏆 ROOT FLAG: {session.root_flag}[/bold green]")


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    session: HackSession,
    llm,
    output_dir: str,
    start_stage: Stage,
) -> None:
    """Run the ATLAS pipeline with dynamic routing."""

    # ── Recon (always first unless resuming past it) ──────────────
    if start_stage == Stage.RECON:
        cp.section("Stage: RECON")
        session.current_stage = Stage.RECON
        if isinstance(llm, ClaudeProvider):
            llm.set_stage("recon")
        if not _run_agent(ReconAgent, session, llm, output_dir, "recon"):
            return
        _announce_flags(session)

        # ── Planner runs immediately after Recon ──────────────────
        _run_planner(session, llm, output_dir)

    # ── Derive stage order from plan (or default) ─────────────────
    post_recon_start = Stage.ENUMERATION if start_stage == Stage.RECON else start_stage
    stage_order = _derive_stage_order(session, post_recon_start)
    cp.notify(
        "Orchestrator",
        f"Stage order: {' → '.join(s.value for s in stage_order)}",
        "info",
    )

    # ── Execute planned stages ────────────────────────────────────
    for stage in stage_order:
        if _flags_captured(session) and stage != Stage.REPORT:
            console.print("\n  [bold green]🎉 Both flags captured! Jumping to Report.[/bold green]")
            _run_reporter_now(session, llm, output_dir)
            return

        if _should_skip(session, stage):
            cp.notify("Orchestrator", f"Skipping {stage.value} — no relevant targets", "info")
            continue

        cp.section(f"Stage: {stage.value.upper()}")
        session.current_stage = stage

        if isinstance(llm, ClaudeProvider):
            llm.set_stage(stage.value)

        # Inject stage-specific tactics into session notes if planner provided them
        plan = session.attack_plan
        if plan and stage.value in plan.stage_tactics:
            tactics = plan.stage_tactics[stage.value]
            if tactics:
                tactic_note = f"[{stage.value}] tactics: " + " | ".join(tactics[:3])
                if tactic_note not in session.notes:
                    session.notes.append(tactic_note)

        AgentClass = PIPELINE_AGENTS[stage]
        if not _run_agent(AgentClass, session, llm, output_dir, stage.value):
            return

        _announce_flags(session)

        # Post-enumeration: analyze loot files before moving on
        if stage == Stage.ENUMERATION and session.loot:
            _run_loot_analyzer(session, llm, output_dir)

        # Between-stage pause in interactive mode
        if stage != Stage.REPORT and not cp.AUTO_MODE:
            console.print()
            console.print(
                f"  [dim]Stage {stage.value} done. Enter to continue, "
                f"type a note, or 'q' to quit.[/dim]"
            )
            note = input("  > ").strip()
            if note.lower() in ("q", "quit", "exit"):
                console.print("[yellow]Stopping pipeline. Session saved.[/yellow]")
                return
            if note:
                session.notes.append(f"[{stage.value}] {note}")

    session.current_stage = Stage.DONE
    session_state.save(session, f"{output_dir}/session.json")


# ── Session listing ───────────────────────────────────────────────────────────

def print_session_list() -> None:
    sessions = session_state.list_sessions()
    if not sessions:
        console.print("[yellow]No past sessions in ~/atlas-sessions/[/yellow]")
        return

    t = Table(box=box.SIMPLE, title="ATLAS Sessions")
    t.add_column("IP", style="cyan")
    t.add_column("Machine", style="white")
    t.add_column("OS", style="dim")
    t.add_column("Stage")
    t.add_column("Ports", justify="right")
    t.add_column("Creds", justify="right")
    t.add_column("Loot", justify="right")
    t.add_column("User", justify="center")
    t.add_column("Root", justify="center")

    for s in sessions:
        user_mark = "[green]✓[/green]" if s["user_flag"] else "[red]✗[/red]"
        root_mark = "[green]✓[/green]" if s["root_flag"] else "[red]✗[/red]"
        t.add_row(
            s["target_ip"], s["machine_name"], s["os_guess"],
            s["stage"], str(s["ports"]), str(s["creds"]),
            str(s.get("loot", 0)), user_mark, root_mark,
        )
    console.print(t)

    rooted = sum(1 for s in sessions if s["root_flag"])
    console.print(
        f"\n  [bold]Total:[/bold] {len(sessions)}   "
        f"[bold green]Rooted:[/bold green] {rooted}   "
        f"[bold yellow]In progress:[/bold yellow] {len(sessions) - rooted}"
    )


# ── Pre-flight ────────────────────────────────────────────────────────────────

def preflight(target: str) -> bool:
    vpn = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    tun_found = "tun" in vpn.stdout
    if not tun_found:
        console.print("  [yellow]⚠  No tun interface — is HTB VPN connected?[/yellow]")
    else:
        tuns = [l.split(":")[1].strip() for l in vpn.stdout.splitlines() if "tun" in l]
        console.print(f"  [green]✓  VPN interface: {', '.join(tuns)}[/green]")

    ping = subprocess.run(
        ["ping", "-c", "2", "-W", "2", target], capture_output=True, text=True,
    )
    if ping.returncode != 0:
        console.print(f"  [red]✗  {target} not responding to ping[/red]")
        console.print("  [dim]Target may block ICMP — continue anyway? (y/n)[/dim]")
        if input("  > ").strip().lower() != "y":
            return False
    else:
        rtt = ""
        for line in ping.stdout.splitlines():
            if "avg" in line:
                rtt = line.split("/")[4] + "ms" if "/" in line else ""
        console.print(f"  [green]✓  {target} alive{' RTT: ' + rtt if rtt else ''}[/green]")
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ATLAS — Autonomous Hacking Team",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  atlas.py 10.10.11.100                          # Interactive, Claude auto-tier
  atlas.py 10.10.11.100 --auto                   # Autonomous below high risk
  atlas.py 10.10.11.100 --provider ollama        # Local claw-core
  atlas.py 10.10.11.100 --resume --stage privesc # Resume from privesc
  atlas.py --list-sessions                       # Show all past runs
        """,
    )
    parser.add_argument("target", nargs="?", help="Target IP address")
    parser.add_argument("--provider", default="claude", choices=["claude", "ollama"])
    parser.add_argument("--model", default="", help="Model override (disables auto-tier)")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--output", default="", help="Output directory override")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--stage", default="recon",
        choices=["recon", "enumeration", "web", "exploit", "privesc", "report"],
    )
    parser.add_argument("--auto", action="store_true",
                        help="Autonomous mode — skip checkpoints up to auto-risk")
    parser.add_argument("--auto-risk", default="medium",
                        choices=["low", "medium", "high", "critical"])
    parser.add_argument("--list-sessions", action="store_true")
    args = parser.parse_args()

    if args.list_sessions:
        print_session_list()
        return

    if not args.target:
        parser.error("target IP required (or use --list-sessions)")

    console.print(f"[green]{BANNER}[/green]")

    if args.auto:
        cp.enable_auto_mode(max_risk=args.auto_risk)
        console.print(f"  [yellow]⚡ AUTO mode (approve up to {args.auto_risk} risk)[/yellow]")

    ip_safe = args.target.replace(".", "_")
    output_dir = args.output or str(Path.home() / "atlas-sessions" / ip_safe)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    console.print(f"  [dim]Session: {output_dir}[/dim]")

    session_file = f"{output_dir}/session.json"
    session: HackSession | None = None

    if args.resume:
        session = session_state.load(session_file)
        if session:
            console.print(f"  [cyan]Resuming: {session.machine_name or session.target_ip}[/cyan]")
            console.print(
                f"  [dim]Stage: {session.current_stage.value} | "
                f"Ports: {len(session.open_ports)} | "
                f"Creds: {len(session.credentials)} | "
                f"Findings: {len(session.findings)}[/dim]"
            )
        else:
            console.print("  [yellow]No saved session found. Starting fresh.[/yellow]")

    if not session:
        session = HackSession(target_ip=args.target)
        console.print(f"  [cyan]New session: {args.target}[/cyan]")

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    try:
        llm = get_provider(args.provider, model=args.model, api_key=api_key)
        console.print(f"  [dim]LLM: {llm}[/dim]\n")
    except Exception as e:
        console.print(f"  [red]LLM setup failed: {e}[/red]")
        sys.exit(1)

    start_stage = Stage(args.stage)

    console.print(Panel(
        f"[bold]Target:[/bold]   {args.target}\n"
        f"[bold]LLM:[/bold]      {llm}\n"
        f"[bold]Output:[/bold]   {output_dir}\n"
        f"[bold]Stage:[/bold]    {start_stage.value}\n"
        f"[bold]Mode:[/bold]     {'AUTO (' + args.auto_risk + ')' if args.auto else 'interactive'}\n\n"
        "[dim]Checkpoint: [bold]a[/bold]=approve  [bold]s[/bold]=skip  "
        "[bold]m[/bold]=modify  [bold]q[/bold]=quit[/dim]",
        title="[bold cyan]ATLAS — Operation Start[/bold cyan]",
        border_style="cyan",
    ))

    console.print("\n[bold dim]Pre-flight checks...[/bold dim]")
    if not preflight(args.target):
        sys.exit(1)

    if not cp.AUTO_MODE:
        input("\n  Press Enter to begin...\n")

    run_pipeline(session, llm, output_dir, start_stage)

    console.print("\n[bold green]ATLAS session complete.[/bold green]")
    if isinstance(llm, ClaudeProvider):
        console.print(f"[dim]{llm.cost_summary()}[/dim]")
    console.print(f"[dim]Session: {session_file}[/dim]")


if __name__ == "__main__":
    main()
