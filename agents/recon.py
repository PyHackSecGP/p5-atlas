"""Recon Agent — nmap, whatweb, wafw00f. Builds the port/service map."""
from __future__ import annotations
import re
from models import HackSession, AgentResult, Stage, Port, WebTarget, Finding, Severity
from llm import LLMProvider
from tools.runner import run, run_parallel
from agents.base import BaseAgent
import checkpoint as cp


class ReconAgent(BaseAgent):
    NAME  = "Recon"
    STAGE = Stage.RECON

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")
        ip = self.session.target_ip

        # ── 1. Fast port discovery ────────────────────────────────
        self.log("Running fast port scan (top 1000)...")
        fast = run(
            f"nmap -T4 --open -n {ip}",
            timeout=120,
            log_dir=self.output_dir,
            on_output=lambda l: cp.tool_output("nmap-fast", l),
        )
        result.raw_outputs["nmap_fast"] = fast.output

        open_ports = re.findall(r"(\d+)/tcp\s+open", fast.output)
        self.log(f"Fast scan: {len(open_ports)} open ports found", "success" if open_ports else "warning")

        if not open_ports:
            self.log("No ports found — trying all ports...", "warning")
            allports = run(
                f"nmap -T4 --open -p- -n {ip}",
                timeout=300,
                log_dir=self.output_dir,
                on_output=lambda l: cp.tool_output("nmap-all", l),
            )
            result.raw_outputs["nmap_all"] = allports.output
            open_ports = re.findall(r"(\d+)/tcp\s+open", allports.output)

        if not open_ports:
            result.summary = "No open ports found. Check if target is alive."
            return result

        ports_str = ",".join(open_ports)

        # ── CHECKPOINT 1: Show what was found, ask before deep scan ─
        cr = self.checkpoint(
            what_found=f"Open ports: {ports_str}",
            plan=f"Deep service scan: nmap -sCV -p{ports_str}",
            why="Service version detection + default scripts reveal CVEs, misconfigs, banners. Essential before any further work.",
            what_to_look_for="SSH version (old = CVE), HTTP title, SMB signing, FTP anonymous, SMTP, unusual ports (8080, 9200, etc.)",
            command=f"nmap -sCV -p{ports_str} {ip}",
            risk="low",
        )
        if not cr.approved:
            result.summary = f"Recon paused at user request. Found ports: {ports_str}"
            return result

        # ── 2. Deep service scan ──────────────────────────────────
        self.log(f"Deep scan on {len(open_ports)} ports...")
        deep_cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else f"nmap -sCV -p{ports_str} {ip}"
        deep = run(deep_cmd, timeout=300, log_dir=self.output_dir,
                   on_output=lambda l: cp.tool_output("nmap-deep", l))
        result.raw_outputs["nmap_deep"] = deep.output

        # ── 3. Parse ports into session ───────────────────────────
        self._parse_nmap_into_session(deep.output)

        # ── 3b. NSE vulnerability scripts (free wins) ─────────────
        cr = self.checkpoint(
            what_found=f"{len(open_ports)} services identified",
            plan=f"nmap --script=vuln,default -p{ports_str}",
            why="NSE vuln scripts detect EternalBlue (ms17-010), Shellshock, Heartbleed, ms08-067, smb-vuln-* — free CVE hits without extra tooling.",
            what_to_look_for="VULNERABLE: entries in output, especially SMB/HTTP/SSL vulns",
            command=f"nmap --script vuln -p{ports_str} {ip}",
            risk="low",
        )
        if cr.approved:
            self.log("Running NSE vuln scripts (may take 2-3 min)...")
            vuln_cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else f"nmap --script vuln -p{ports_str} {ip}"
            vuln = run(vuln_cmd, timeout=400, log_dir=self.output_dir,
                       on_output=lambda l: cp.tool_output("nmap-vuln", l) if "VULNERABLE" in l else None)
            result.raw_outputs["nmap_vuln"] = vuln.output

            # Surface any VULNERABLE hits
            vuln_hits = re.findall(r"(\S+):\s*\n\s+VULNERABLE", vuln.output)
            if vuln_hits:
                self.log(f"NSE flagged vulnerable: {', '.join(set(vuln_hits))}", "success")

        # ── 4. Web fingerprinting — all ports in parallel ─────────
        if self.session.web_ports:
            self.log(f"Web fingerprinting {len(self.session.web_ports)} port(s) in parallel...")
            ww_tasks = []
            port_url_map: dict[int, str] = {}
            for p in self.session.web_ports:
                scheme = "https" if p.number in (443, 8443) else "http"
                url = f"{scheme}://{ip}:{p.number}"
                port_url_map[p.number] = url
                ww_tasks.append({
                    "name": f"whatweb_{p.number}",
                    "command": f"whatweb -a 3 {url}",
                    "timeout": 60,
                    "log_dir": self.output_dir,
                })

            ww_results = run_parallel(ww_tasks, max_workers=len(ww_tasks))

            for p in self.session.web_ports:
                url = port_url_map[p.number]
                ww = ww_results.get(f"whatweb_{p.number}")
                if ww:
                    result.raw_outputs[f"whatweb_{p.number}"] = ww.output
                wt = WebTarget(url=url)
                wt.tech = re.findall(r'\[([^\]]+)\]', ww.output if ww else "")[:10]
                self.session.web_targets.append(wt)

        # ── 5. LLM analysis ──────────────────────────────────────
        self.log("LLM analysing recon output...")
        vuln_out = result.raw_outputs.get("nmap_vuln", "")
        analysis = self.ask_json(f"""
Analyse this nmap output for an HTB machine at {ip}.

NMAP OUTPUT:
{deep.output[:4000]}

NSE VULN SCRIPTS:
{vuln_out[:2000] if vuln_out else '(not run)'}

Respond with JSON:
{{
  "machine_name_guess": "...",
  "os_guess": "Linux/Windows/...",
  "attack_surface": ["list of interesting services"],
  "priority_targets": ["ordered list: what to attack first and why"],
  "interesting_findings": ["specific version numbers, banners, anything notable"],
  "next_stage": "web|network|exploit|privesc",
  "reasoning": "2-3 sentences on best first attack vector"
}}""")

        self.session.os_guess = analysis.get("os_guess", "")
        if not self.session.machine_name:
            self.session.machine_name = analysis.get("machine_name_guess", "unknown")

        result.next_actions = analysis.get("priority_targets", [])
        result.metadata = {
            "attack_surface": analysis.get("attack_surface", []),
            "interesting_findings": analysis.get("interesting_findings", []),
            "next_stage": analysis.get("next_stage", "enumeration"),
            "reasoning": analysis.get("reasoning", ""),
        }

        # Print LLM reasoning for the user
        cp.section("Recon Analysis")
        from rich.console import Console
        from rich.panel import Panel
        Console().print(Panel(
            f"[bold]OS:[/bold] {self.session.os_guess}\n"
            f"[bold]Attack surface:[/bold] {', '.join(analysis.get('attack_surface', []))}\n\n"
            f"[bold]Interesting:[/bold]\n" + "\n".join(f"  • {f}" for f in analysis.get("interesting_findings", [])) + "\n\n"
            f"[bold cyan]Priority targets:[/bold cyan]\n" + "\n".join(f"  {i+1}. {t}" for i, t in enumerate(analysis.get("priority_targets", []))) + "\n\n"
            f"[bold yellow]LLM reasoning:[/bold yellow] {analysis.get('reasoning', '')}",
            title=f"[cyan]Recon Complete — {len(self.session.open_ports)} ports[/cyan]",
            border_style="cyan",
        ))

        result.summary = (
            f"Found {len(self.session.open_ports)} open ports. "
            f"OS: {self.session.os_guess}. "
            f"Recommended next: {analysis.get('next_stage', 'enumeration')}. "
            f"{analysis.get('reasoning', '')}"
        )
        return result

    def _parse_nmap_into_session(self, output: str) -> None:
        """Parse nmap -sCV output into Port objects."""
        for m in re.finditer(
            r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)",
            output,
        ):
            port_num = int(m.group(1))
            service  = m.group(2).strip()
            version  = m.group(3).strip()
            # Avoid duplicates
            if not any(p.number == port_num for p in self.session.ports):
                self.session.ports.append(Port(
                    number=port_num, service=service, version=version,
                ))

        # OS detection
        os_m = re.search(r"OS details?:\s*(.+)", output, re.I)
        if os_m and not self.session.os_guess:
            self.session.os_guess = os_m.group(1).strip()

        # Aggressive OS guess from CPE/service strings
        if not self.session.os_guess:
            if "Windows" in output:
                self.session.os_guess = "Windows"
            elif "Linux" in output or "Ubuntu" in output or "Debian" in output:
                self.session.os_guess = "Linux"
