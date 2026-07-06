"""Human-in-the-loop checkpoint system.

Every checkpoint shows: what found, what plan, why, what to look for.
Then pauses for approval — unless AUTO_MODE is enabled.
"""
from __future__ import annotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

# Module-level flag — set by atlas.py based on --auto
AUTO_MODE = False
# Auto mode skips low+medium risk automatically; still prompts on high/critical
AUTO_MAX_RISK = "medium"

_RISK_LEVEL = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class CheckpointResult:
    APPROVED = "approved"
    MODIFIED = "modified"
    SKIPPED  = "skipped"
    ABORTED  = "aborted"

    def __init__(self, action: str, note: str = "", override: str = ""):
        self.action   = action
        self.note     = note
        self.override = override

    @property
    def approved(self) -> bool:
        return self.action in (self.APPROVED, self.MODIFIED)


def _render_checkpoint(agent: str, what_found: str, plan: str, why: str,
                       what_to_look_for: str, command: str, risk: str) -> None:
    risk_color = {"low": "green", "medium": "yellow", "high": "red",
                  "critical": "bright_red"}.get(risk, "yellow")
    console.print()
    console.print(Panel(
        f"[bold cyan]{agent}[/bold cyan]",
        title=f"[{risk_color}]⚡ CHECKPOINT — {risk.upper()} RISK[/{risk_color}]",
        border_style=risk_color,
        width=90,
    ))
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("", style="bold dim", width=18)
    t.add_column("", style="white")
    t.add_row("📡 FOUND",     what_found)
    t.add_row("🎯 PLAN",      plan)
    t.add_row("🧠 WHY",       why)
    t.add_row("👁  LOOK FOR", what_to_look_for)
    if command:
        t.add_row("💻 COMMAND", f"[green]{command}[/green]")
    console.print(t)


def checkpoint(agent: str, what_found: str, plan: str, why: str,
               what_to_look_for: str, command: str = "",
               risk: str = "medium") -> CheckpointResult:
    """Show checkpoint panel. Auto-approve in auto mode below risk threshold."""
    _render_checkpoint(agent, what_found, plan, why, what_to_look_for, command, risk)

    # Autonomous mode — approve automatically for low/medium risk
    if AUTO_MODE and _RISK_LEVEL.get(risk, 1) <= _RISK_LEVEL.get(AUTO_MAX_RISK, 1):
        console.print("  [dim green]▶ auto-approved (--auto below threshold)[/dim green]")
        return CheckpointResult(CheckpointResult.APPROVED, note="auto")

    if AUTO_MODE:
        console.print(f"  [yellow]⚠ {risk.upper()} risk exceeds auto threshold — pausing[/yellow]")

    console.print()
    choice = Prompt.ask(
        "[bold]Decision[/bold]",
        choices=["a", "s", "m", "q"],
        default="a",
        show_choices=False,
        console=console,
    )
    console.print("  [dim]a=approve  s=skip  m=modify command  q=quit[/dim]")

    if choice == "q":
        return CheckpointResult(CheckpointResult.ABORTED, "User quit")
    if choice == "s":
        note = Prompt.ask("  Skip reason (optional)", default="", console=console)
        return CheckpointResult(CheckpointResult.SKIPPED, note)
    if choice == "m":
        override = Prompt.ask("  Enter your command", default=command, console=console)
        return CheckpointResult(CheckpointResult.MODIFIED, override=override)
    return CheckpointResult(CheckpointResult.APPROVED)


def enable_auto_mode(max_risk: str = "medium") -> None:
    global AUTO_MODE, AUTO_MAX_RISK
    AUTO_MODE = True
    AUTO_MAX_RISK = max_risk


def notify(agent: str, message: str, level: str = "info") -> None:
    colors = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}
    icon   = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗"}
    console.print(f"  [{colors.get(level,'cyan')}]{icon.get(level,'ℹ')}[/{colors.get(level,'cyan')}] "
                  f"[bold dim]{agent}[/bold dim] {message}")


def section(title: str) -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]")


def thinking(agent: str, thought: str) -> None:
    console.print(f"  [dim]🧠 {agent}: {thought}[/dim]")


def tool_output(tool: str, line: str) -> None:
    console.print(f"  [dim green]┃[/dim green] [dim]{tool}:[/dim] {line}")
