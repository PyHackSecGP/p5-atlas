"""Reporter Agent — generates writeup.md, commits to ctf-lab, prints summary."""
from __future__ import annotations
import datetime
import subprocess
from pathlib import Path
from models import HackSession, AgentResult, Stage
from llm import LLMProvider
from agents.base import BaseAgent
import checkpoint as cp


class ReporterAgent(BaseAgent):
    NAME  = "Reporter"
    STAGE = Stage.REPORT

    CTF_LAB_PATH = "/home/tony/projects/ctf-lab"

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")
        session = self.session

        cp.section("Report Generation")
        self.log("Generating writeup...")

        # ── Collect all agent outputs for LLM ────────────────────
        context_parts = [session.context_summary(), ""]
        for ar in session.agent_results:
            context_parts.append(f"=== {ar.agent.upper()} ({ar.stage.value}) ===")
            context_parts.append(ar.summary)
            if ar.next_actions:
                context_parts.append("Actions taken: " + ", ".join(ar.next_actions[:3]))
        full_context = "\n".join(context_parts)

        # ── LLM writes the writeup ────────────────────────────────
        writeup_text = self.llm.generate(
            system="""You are a security researcher writing an HTB writeup.
Write clear, educational writeups that explain WHY each step was taken, not just WHAT.
Use markdown. Include code blocks for all commands. Explain techniques for learning.""",
            user=f"""Write a complete HTB writeup for machine: {session.machine_name or session.target_ip}

SESSION DATA:
{full_context}

FINDINGS:
{chr(10).join(f.title + ': ' + f.description[:200] for f in session.findings[:10])}

USER FLAG: {session.user_flag or 'not captured'}
ROOT FLAG: {session.root_flag or 'not captured'}

NOTES:
{chr(10).join(session.notes)}

Write a professional writeup with sections: Overview, Recon, Enumeration, Exploitation, Privilege Escalation, Flags, Key Takeaways.
For each step explain WHY you did it, WHAT you expected, and WHAT you found.""",
        )

        # ── Save writeup ──────────────────────────────────────────
        machine = (session.machine_name or session.target_ip).replace(" ", "_").lower()
        date_str = datetime.date.today().strftime("%Y-%m-%d")

        # Try ctf-lab repo, fall back to output dir
        ctf_path = Path(self.CTF_LAB_PATH)
        if ctf_path.exists():
            writeup_dir = ctf_path / "htb" / machine
        else:
            writeup_dir = Path(self.output_dir) / "writeup"

        writeup_dir.mkdir(parents=True, exist_ok=True)
        writeup_path = writeup_dir / f"{date_str}-{machine}.md"
        writeup_path.write_text(writeup_text)
        self.log(f"Writeup saved: {writeup_path}", "success")

        # ── Print final summary ───────────────────────────────────
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        console = Console()
        cp.section("ATLAS Session Complete")

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("", style="bold dim", width=16)
        t.add_column("")

        t.add_row("Machine",     session.machine_name or session.target_ip)
        t.add_row("IP",          session.target_ip)
        t.add_row("OS",          session.os_guess or "Unknown")
        t.add_row("Ports",       str(len(session.open_ports)))
        t.add_row("Credentials", str(len(session.credentials)))
        t.add_row("Findings",    str(len(session.findings)))
        t.add_row("User flag",   f"[green]{session.user_flag}[/green]" if session.user_flag else "[red]Not captured[/red]")
        t.add_row("Root flag",   f"[green]{session.root_flag}[/green]" if session.root_flag else "[red]Not captured[/red]")
        t.add_row("Writeup",     str(writeup_path))

        console.print(Panel(t, title="[green]Session Summary[/green]", border_style="green"))

        # ── Commit to ctf-lab if available ────────────────────────
        if ctf_path.exists():
            cr = self.checkpoint(
                what_found=f"Writeup written to {writeup_path}",
                plan=f"git add + commit to ctf-lab: '{machine} — HTB writeup'",
                why="Commit discipline: every rooted/attempted machine gets documented. Builds portfolio and searchable knowledge base.",
                what_to_look_for="Clean commit, no sensitive data in writeup",
                command=f"git -C {ctf_path} add . && git -C {ctf_path} commit -m 'htb: {machine} writeup {date_str}'",
                risk="low",
            )
            if cr.approved:
                subprocess.run(["git", "-C", str(ctf_path), "add", "."], check=False)
                subprocess.run(
                    ["git", "-C", str(ctf_path), "commit", "-m", f"htb: {machine} writeup {date_str}"],
                    check=False,
                )
                self.log("Committed to ctf-lab", "success")

        result.summary = f"Writeup generated at {writeup_path}"
        return result
