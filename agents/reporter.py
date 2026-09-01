"""Reporter Agent — generates writeup.md, commits to ctf-lab, prints summary."""
from __future__ import annotations
import datetime
import subprocess
from pathlib import Path
from models import HackSession, AgentResult, Stage
from llm import LLMProvider
from agents.base import BaseAgent
from tools.mitre_mapper import map_findings_to_attack, format_attack_table_markdown
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

        # Append MITRE ATT&CK table
        techniques = map_findings_to_attack(
            session.findings, session.agent_results, session.notes
        )
        attack_section = format_attack_table_markdown(techniques)
        if attack_section:
            writeup_text = writeup_text.rstrip() + "\n\n" + attack_section + "\n"

        writeup_path.write_text(writeup_text)
        self.log(f"Writeup saved: {writeup_path}", "success")

        if techniques:
            self.log(f"MITRE ATT&CK: {len(techniques)} techniques mapped", "info")

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
        if techniques:
            tactic_names = list(dict.fromkeys(tech.tactic for tech in techniques))
            t.add_row("ATT&CK",      f"{len(techniques)} techniques — {', '.join(tactic_names[:4])}")

        console.print(Panel(t, title="[green]Session Summary[/green]", border_style="green"))

        # Print ATT&CK table inline
        if techniques:
            from rich.table import Table as RichTable
            atk = RichTable(title="MITRE ATT&CK", box=box.MINIMAL_DOUBLE_HEAD, show_lines=False)
            atk.add_column("ID", style="cyan", width=14)
            atk.add_column("Technique", style="white")
            atk.add_column("Tactic", style="yellow")
            for tech in techniques:
                atk.add_row(tech.id, tech.name, tech.tactic)
            console.print(atk)

        # ── Commit + push to ctf-lab if available ─────────────────
        if ctf_path.exists():
            cr = self.checkpoint(
                what_found=f"Writeup written to {writeup_path}",
                plan=f"git commit + push to GitHub + Forgejo: '{machine} writeup {date_str}'",
                why="Commit discipline: every rooted/attempted machine gets documented. Push to both remotes so GitHub portfolio and Forgejo self-hosted stay in sync.",
                what_to_look_for="Clean commit, no internal IPs or API keys in writeup",
                command=f"git -C {ctf_path} add . && git -C {ctf_path} commit + push",
                risk="low",
            )
            if cr.approved:
                subprocess.run(["git", "-C", str(ctf_path), "add", "."], check=False)
                commit_result = subprocess.run(
                    ["git", "-C", str(ctf_path), "commit", "-m", f"htb: {machine} writeup {date_str}"],
                    capture_output=True, text=True,
                )
                if commit_result.returncode == 0:
                    self.log("Committed to ctf-lab", "success")
                    self._push_to_remotes(ctf_path)
                elif "nothing to commit" in (commit_result.stdout + commit_result.stderr):
                    self.log("Nothing new to commit", "info")
                    self._push_to_remotes(ctf_path)
                else:
                    self.log(f"Commit failed: {commit_result.stderr[:200]}", "error")

        result.summary = f"Writeup generated at {writeup_path}"
        return result

    def _push_to_remotes(self, repo_path) -> None:
        """Push to all configured remotes."""
        # Get list of remotes
        remotes_result = subprocess.run(
            ["git", "-C", str(repo_path), "remote"],
            capture_output=True, text=True,
        )
        remotes = [r.strip() for r in remotes_result.stdout.splitlines() if r.strip()]
        if not remotes:
            self.log("No remotes configured", "warning")
            return

        for remote in remotes:
            self.log(f"Pushing to {remote}...")
            push = subprocess.run(
                ["git", "-C", str(repo_path), "push", remote, "--all"],
                capture_output=True, text=True, timeout=60,
            )
            if push.returncode == 0:
                self.log(f"Pushed to {remote}", "success")
            else:
                err = (push.stderr or push.stdout)[:150]
                self.log(f"Push to {remote} failed: {err}", "warning")
