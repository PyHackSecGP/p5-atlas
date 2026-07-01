#!/usr/bin/env python3
"""
ATLAS — Autonomous Team for LLM-Assisted Security
Usage: python atlas.py <TARGET_IP> [--provider claude|ollama] [--model MODEL]
"""
from __future__ import annotations
import argparse
import os
import sys
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import HackSession, Stage
from llm import get_provider
import state as session_state
import checkpoint as cp
from agents.recon import ReconAgent
from agents.enumeration import EnumerationAgent
from agents.web import WebAgent
from agents.exploit import ExploitAgent
from agents.reporter import ReporterAgent

from rich.console import Console
from rich.panel import Panel

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


def run_pipeline(session: HackSession, llm, output_dir: str, start_stage: Stage) -> None:
    """Run the ATLAS pipeline from start_stage."""

    stages = [
        (Stage.RECON,       ReconAgent),
        (Stage.ENUMERATION, EnumerationAgent),
        (Stage.WEB,         WebAgent),
        (Stage.EXPLOIT,     ExploitAgent),
        (Stage.REPORT,      ReporterAgent),
    ]

    stage_order = [s for s, _ in stages]
    start_idx = stage_order.index(start_stage) if start_stage in stage_order else 0

    for stage, AgentClass in stages[start_idx:]:
        cp.section(f"Stage: {stage.value.upper()}")
        session.current_stage = stage

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
                why="Agent failed — may be tool not installed or network issue",
                what_to_look_for="Check if required tool is installed (nmap, gobuster, etc.)",
                risk="low",
            )
            if not resume.approved:
                break
            continue

        session.agent_results.append(result)
        session_state.save(session, f"{output_dir}/session.json")

        # Ask between stages if user wants to continue, add notes, or jump
        if stage != Stage.REPORT:
            console.print()
            console.print(f"  [dim]Stage complete: {stage.value}. Press Enter to continue, or type a note to add.[/dim]")
            note = input("  > ").strip()
            if note.lower() in ("q", "quit", "exit"):
                console.print("[yellow]Stopping pipeline. Session saved.[/yellow]")
                break
            if note:
                session.notes.append(f"[{stage.value}] {note}")

        # Check for flags
        if session.user_flag:
            console.print(f"\n  [bold green]🚩 USER FLAG: {session.user_flag}[/bold green]")
        if session.root_flag:
            console.print(f"  [bold green]🏆 ROOT FLAG: {session.root_flag}[/bold green]")

    session.current_stage = Stage.DONE
    session_state.save(session, f"{output_dir}/session.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ATLAS — Autonomous Hacking Team",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python atlas.py 10.10.11.100
  python atlas.py 10.10.11.100 --provider ollama --model hermes3:70b
  python atlas.py 10.10.11.100 --resume
  python atlas.py 10.10.11.100 --stage web
        """
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--provider", default="claude", choices=["claude", "ollama"],
                        help="LLM provider (default: claude)")
    parser.add_argument("--model", default="", help="Model override")
    parser.add_argument("--api-key", default="", help="API key (or set ANTHROPIC_API_KEY)")
    parser.add_argument("--output", default="", help="Output directory (default: ~/atlas-sessions/<ip>)")
    parser.add_argument("--resume", action="store_true", help="Resume previous session")
    parser.add_argument("--stage", default="recon",
                        choices=["recon", "enumeration", "web", "exploit", "report"],
                        help="Start from this stage (default: recon)")
    args = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────────
    console.print(f"[green]{BANNER}[/green]")

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
            console.print(f"  [cyan]Resuming session: {session.machine_name or session.target_ip}[/cyan]")
            console.print(f"  [dim]Stage: {session.current_stage.value} | Ports: {len(session.open_ports)} | Creds: {len(session.credentials)}[/dim]")
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
        f"[bold]Stage:[/bold]    {start_stage.value}\n\n"
        "[dim]At each checkpoint: [bold]a[/bold]=approve  [bold]s[/bold]=skip  [bold]m[/bold]=modify  [bold]q[/bold]=quit[/dim]",
        title="[bold cyan]ATLAS — Operation Start[/bold cyan]",
        border_style="cyan",
    ))

    input("\n  Press Enter to begin...\n")

    run_pipeline(session, llm, output_dir, start_stage)

    console.print("\n[bold green]ATLAS session complete.[/bold green]")
    console.print(f"[dim]Session saved: {session_file}[/dim]")


if __name__ == "__main__":
    main()
