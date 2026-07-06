#!/usr/bin/env python3
"""
ATLAS — Autonomous Team for LLM-Assisted Security

Autonomous HTB/CTF pentest pipeline:
  Recon → Enumeration → Web → Exploit → PrivEsc → Report

Usage:
  atlas.py <IP> [--provider claude|ollama] [--model MODEL]
                [--resume] [--stage STAGE] [--auto] [--auto-risk RISK]
  atlas.py --list-sessions
"""
from __future__ import annotations
import argparse
import os
import sys
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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


BANNER = r"""
 █████╗ ████████╗██╗      █████╗ ███████╗
██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝
███████║   ██║   ██║     ███████║███████╗
██╔══██║   ██║   ██║     ██╔══██║╚════██║
██║  ██║   ██║   ███████╗██║  ██║███████║
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
Autonomous Team for LLM-Assisted Security
"""


PIPELINE = [
    (Stage.RECON,       ReconAgent),
    (Stage.ENUMERATION, EnumerationAgent),
    (Stage.WEB,         WebAgent),
    (Stage.EXPLOIT,     ExploitAgent),
    (Stage.PRIVESC,     PrivEscAgent),
    (Stage.REPORT,      ReporterAgent),
]


def run_pipeline(session: HackSession, llm, output_dir: str, start_stage: Stage) -> None:
    """Run the ATLAS pipeline from start_stage."""
    stage_order = [s for s, _ in PIPELINE]
    start_idx = stage_order.index(start_stage) if start_stage in stage_order else 0

    for stage, AgentClass in PIPELINE[start_idx:]:
        cp.section(f"Stage: {stage.value.upper()}")
        session.current_stage = stage

        # Switch model tier per stage (Claude only, no-op for Ollama)
        if isinstance(llm, ClaudeProvider):
            llm.set_stage(stage.value)

        agent = AgentClass(session=session, llm=llm, output_dir=output_dir)
        try:
            result = agent.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]⚡ Interrupted. Saving session...[/yellow]")
            break
        except Exception as e:
            console.print(f"\n[red]Agent {agent.NAME} crashed: {e}[/red]")
            import traceback
            traceback.print_exc()
            resume = cp.checkpoint(
                agent="Orchestrator",
                what_found=f"{agent.NAME} crashed with: {e}",
                plan="Skip to next stage",
                why="Agent failed — tool may not be installed or network issue",
                what_to_look_for="Check required tools are installed (nmap, gobuster, sshpass, hydra)",
                risk="low",
            )
            if not resume.approved:
                break
            continue

        session.agent_results.append(result)
        session_state.save(session, f"{output_dir}/session.json")

        # Between-stage note prompt (skip in auto mode)
        if stage != Stage.REPORT and not cp.AUTO_MODE:
            console.print()
            console.print(f"  [dim]Stage complete: {stage.value}. Enter to continue, "
                          f"type a note, or 'q' to quit.[/dim]")
            note = input("  > ").strip()
            if note.lower() in ("q", "quit", "exit"):
                console.print("[yellow]Stopping pipeline. Session saved.[/yellow]")
                break
            if note:
                session.notes.append(f"[{stage.value}] {note}")

        if session.user_flag:
            console.print(f"\n  [bold green]🚩 USER FLAG: {session.user_flag}[/bold green]")
        if session.root_flag:
            console.print(f"  [bold green]🏆 ROOT FLAG: {session.root_flag}[/bold green]")

    session.current_stage = Stage.DONE
    session_state.save(session, f"{output_dir}/session.json")


def print_session_list() -> None:
    """Show all past ATLAS sessions."""
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
    t.add_column("User", justify="center")
    t.add_column("Root", justify="center")

    for s in sessions:
        user_mark = "[green]✓[/green]" if s["user_flag"] else "[red]✗[/red]"
        root_mark = "[green]✓[/green]" if s["root_flag"] else "[red]✗[/red]"
        t.add_row(
            s["target_ip"], s["machine_name"], s["os_guess"],
            s["stage"], str(s["ports"]), str(s["creds"]),
            user_mark, root_mark,
        )
    console.print(t)

    rooted = sum(1 for s in sessions if s["root_flag"])
    console.print(f"\n  [bold]Total:[/bold] {len(sessions)}   "
                  f"[bold green]Rooted:[/bold green] {rooted}   "
                  f"[bold yellow]In progress:[/bold yellow] {len(sessions) - rooted}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ATLAS — Autonomous Hacking Team",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  atlas.py 10.10.11.100                          # Interactive Claude
  atlas.py 10.10.11.100 --auto                   # Autonomous below high risk
  atlas.py 10.10.11.100 --provider ollama        # Local claw-core
  atlas.py 10.10.11.100 --resume --stage privesc # Continue from privesc
  atlas.py --list-sessions                       # Show all past runs
        """
    )
    parser.add_argument("target", nargs="?", help="Target IP address")
    parser.add_argument("--provider", default="claude", choices=["claude", "ollama"],
                        help="LLM provider (default: claude)")
    parser.add_argument("--model", default="",
                        help="Model override (disables auto-tier)")
    parser.add_argument("--api-key", default="", help="API key (or set ANTHROPIC_API_KEY)")
    parser.add_argument("--output", default="", help="Output directory (default: ~/atlas-sessions/<ip>)")
    parser.add_argument("--resume", action="store_true", help="Resume previous session")
    parser.add_argument("--stage", default="recon",
                        choices=["recon", "enumeration", "web", "exploit", "privesc", "report"],
                        help="Start from this stage (default: recon)")
    parser.add_argument("--auto", action="store_true",
                        help="Autonomous mode — skip checkpoints up to auto-risk level")
    parser.add_argument("--auto-risk", default="medium",
                        choices=["low", "medium", "high", "critical"],
                        help="Max risk level for auto-approval (default: medium)")
    parser.add_argument("--list-sessions", action="store_true", help="List all past sessions and exit")
    args = parser.parse_args()

    if args.list_sessions:
        print_session_list()
        return

    if not args.target:
        parser.error("target IP required (or use --list-sessions)")

    console.print(f"[green]{BANNER}[/green]")

    # ── Auto mode ─────────────────────────────────────────────────
    if args.auto:
        cp.enable_auto_mode(max_risk=args.auto_risk)
        console.print(f"  [yellow]⚡ AUTO mode (auto-approve up to {args.auto_risk} risk)[/yellow]")

    # ── Output directory ──────────────────────────────────────────
    ip_safe = args.target.replace(".", "_")
    output_dir = args.output or str(Path.home() / "atlas-sessions" / ip_safe)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    console.print(f"  [dim]Session directory: {output_dir}[/dim]")

    # ── Session: resume or new ────────────────────────────────────
    session_file = f"{output_dir}/session.json"
    session = None

    if args.resume:
        session = session_state.load(session_file)
        if session:
            console.print(f"  [cyan]Resuming: {session.machine_name or session.target_ip}[/cyan]")
            console.print(f"  [dim]Stage: {session.current_stage.value} | "
                          f"Ports: {len(session.open_ports)} | "
                          f"Creds: {len(session.credentials)} | "
                          f"Findings: {len(session.findings)}[/dim]")
        else:
            console.print("  [yellow]No saved session found. Starting fresh.[/yellow]")

    if not session:
        session = HackSession(target_ip=args.target)
        console.print(f"  [cyan]New session: {args.target}[/cyan]")

    # ── LLM provider ──────────────────────────────────────────────
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    try:
        llm = get_provider(args.provider, model=args.model, api_key=api_key)
        console.print(f"  [dim]LLM: {llm}[/dim]\n")
    except Exception as e:
        console.print(f"  [red]LLM setup failed: {e}[/red]")
        sys.exit(1)

    # ── Start stage ───────────────────────────────────────────────
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

    if not cp.AUTO_MODE:
        input("\n  Press Enter to begin...\n")

    run_pipeline(session, llm, output_dir, start_stage)

    # ── Final summary ────────────────────────────────────────────
    console.print("\n[bold green]ATLAS session complete.[/bold green]")
    if isinstance(llm, ClaudeProvider):
        console.print(f"[dim]LLM stats: {llm.cost_summary()}[/dim]")
    console.print(f"[dim]Session saved: {session_file}[/dim]")


if __name__ == "__main__":
    main()
