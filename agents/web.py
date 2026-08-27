"""Web Agent — directory brute, nuclei vuln scan, nikto, vhost enum, LFI/SQLi probing."""
from __future__ import annotations
import os
import re
import shutil
from models import HackSession, AgentResult, Stage, Finding, Severity
from llm import LLMProvider
from tools.runner import run, run_parallel
from agents.base import BaseAgent
import checkpoint as cp

WORDLISTS = [
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

NUCLEI_TEMPLATES = os.path.expanduser("~/nuclei-templates")
NUCLEI_BIN = shutil.which("nuclei") or os.path.expanduser("~/bin/nuclei")


def _find_wordlist() -> str:
    for w in WORDLISTS:
        if os.path.exists(w):
            return w
    return "/usr/share/wordlists/dirb/common.txt"


def _nuclei_available() -> bool:
    return bool(NUCLEI_BIN and os.path.exists(NUCLEI_BIN))


class WebAgent(BaseAgent):
    NAME  = "Web"
    STAGE = Stage.WEB

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")
        ip = self.session.target_ip
        all_findings: list[str] = []

        if not self.session.web_targets:
            result.summary = "No web targets found."
            return result

        for wt in self.session.web_targets:
            url = wt.url
            self.log(f"Attacking web target: {url}")
            cp.section(f"Web: {url}")

            # ── Nikto + Gobuster — single checkpoint, parallel run ─
            wordlist = _find_wordlist()
            gobuster_cmd = f"gobuster dir -u {url} -w {wordlist} -t 50 -x php,txt,html,bak,zip --no-error -q"
            nikto_cmd    = f"nikto -h {url} -timeout 10"

            cr = self.checkpoint(
                what_found=f"{url} — Tech: {', '.join(wt.tech[:5]) or 'unknown'}",
                plan=f"nikto + gobuster in parallel (wordlist: {wordlist.split('/')[-1]})",
                why="Nikto finds server misconfigs; gobuster finds hidden paths. Running both simultaneously cuts stage time in half.",
                what_to_look_for="nikto: old software, dangerous methods, admin panels. gobuster: /admin, /upload, /.git, /backup, /api",
                command=f"[parallel] {nikto_cmd}  &&  {gobuster_cmd}",
                risk="medium",
            )
            if cr.approved:
                self.log("Running nikto + gobuster in parallel...")
                parallel_results = run_parallel([
                    {"name": "nikto",    "command": nikto_cmd,    "timeout": 120, "log_dir": self.output_dir},
                    {"name": "gobuster", "command": gobuster_cmd, "timeout": 300, "log_dir": self.output_dir},
                ], max_workers=2)

                nikto_r    = parallel_results.get("nikto")
                gobuster_r = parallel_results.get("gobuster")

                if nikto_r:
                    result.raw_outputs[f"nikto_{url}"] = nikto_r.output
                    all_findings.append(f"Nikto ({url}):\n{nikto_r.output[:1000]}")

                if gobuster_r:
                    result.raw_outputs[f"gobuster_{url}"] = gobuster_r.output
                    wt.directories = re.findall(r"(/\S+)\s+\(Status: (\d+)\)", gobuster_r.output)
                    all_findings.append(f"Gobuster ({url}):\n{gobuster_r.output[:1500]}")

            # ── Nuclei vuln scan ──────────────────────────────────
            if _nuclei_available():
                cr = self.checkpoint(
                    what_found=f"{url} — {len(wt.directories)} paths found",
                    plan=f"nuclei -u {url} (critical/high/medium templates)",
                    why="Nuclei has 4000+ templates covering CVEs, misconfigs, default creds, exposed panels, API issues. Fastest way to find known vulns on web services.",
                    what_to_look_for="[critical] [high] severity hits — CVEs, exposed admin panels, default creds, path traversal, SSRF",
                    command=f"{NUCLEI_BIN} -u {url} -t {NUCLEI_TEMPLATES} -severity critical,high,medium -silent",
                    risk="medium",
                )
                if cr.approved:
                    nuclei_cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else (
                        f"{NUCLEI_BIN} -u {url} -t {NUCLEI_TEMPLATES} "
                        f"-severity critical,high,medium -silent -timeout 10 -rl 50"
                    )
                    self.log("Running nuclei (this may take 2-3 min)...")
                    nuclei_r = run(nuclei_cmd, timeout=300, log_dir=self.output_dir,
                                  on_output=lambda l: cp.tool_output("nuclei", l) if l.strip() else None)
                    if nuclei_r.output.strip():
                        result.raw_outputs[f"nuclei_{url}"] = nuclei_r.output
                        all_findings.append(f"Nuclei ({url}):\n{nuclei_r.output[:3000]}")
                        hit_count = nuclei_r.output.count("[critical]") + nuclei_r.output.count("[high]")
                        if hit_count:
                            self.log(f"NUCLEI: {hit_count} critical/high hit(s) — check output!", "success")
                    else:
                        self.log("Nuclei: no findings at medium+ severity")

            # ── ffuf vhost enumeration if applicable ──────────────
            # (only run if we suspect vhost routing, i.e. non-IP hostname)
            domain_m = re.search(r'\.htb|\.local', " ".join(wt.tech), re.I)
            if domain_m:
                domain = domain_m.group(0).lstrip(".")
                cr = self.checkpoint(
                    what_found=f"Domain pattern detected: *.{domain}",
                    plan=f"ffuf vhost bruteforce on {domain}",
                    why="HTB machines often use virtual hosting. Subdomains like dev.htb, admin.htb, api.htb expose additional attack surface not visible on the main IP.",
                    what_to_look_for="Non-404 responses with different size than baseline, especially admin/dev/api/internal subdomains",
                    command=f"ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u {url} -H 'Host: FUZZ.{domain}' -fs 0",
                    risk="medium",
                )
                if cr.approved:
                    cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else f"ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u {url} -H 'Host: FUZZ.{domain}' -fs 0 -mc 200,301,302,403"
                    self.log("Running vhost bruteforce...")
                    ffuf = run(cmd, timeout=180, log_dir=self.output_dir,
                               on_output=lambda l: cp.tool_output("ffuf", l))
                    result.raw_outputs[f"ffuf_vhost"] = ffuf.output
                    all_findings.append(f"vhost ffuf:\n{ffuf.output[:500]}")

        # ── LLM analysis ─────────────────────────────────────────
        if all_findings:
            self.log("LLM analysing web findings...")
            combined = "\n\n---\n\n".join(all_findings)
            nuclei_hits = [f for f in all_findings if f.startswith("Nuclei")]
            analysis = self.ask_json(f"""
You are analysing web recon output for an HTB machine.
Tech stack detected: {[wt.tech for wt in self.session.web_targets]}
Nuclei found {len(nuclei_hits)} result set(s).

WEB FINDINGS:
{combined[:6000]}

Respond with JSON:
{{
  "vulnerabilities": [
    {{"type": "SQLi|LFI|RCE|IDOR|etc", "url": "...", "parameter": "...", "confidence": "high|medium|low", "exploit_command": "..."}}
  ],
  "interesting_endpoints": ["list of URLs worth manually visiting"],
  "login_pages": ["any login forms found"],
  "file_upload": ["any file upload endpoints"],
  "tech_cves": ["known CVEs for detected tech versions"],
  "priority_attack": "best attack vector with exact command",
  "reasoning": "why this is the best vector",
  "what_to_look_for": "what the user should manually check"
}}""")

            result.next_actions = [v.get("exploit_command", "") for v in analysis.get("vulnerabilities", []) if v.get("exploit_command")]
            result.metadata = analysis

            cp.section("Web Analysis")
            from rich.console import Console
            from rich.panel import Panel

            vulns = analysis.get("vulnerabilities", [])
            vuln_text = "\n".join(
                f"  [{v.get('confidence','?').upper()}] {v.get('type','?')} @ {v.get('url','')}" +
                (f"\n    → {v.get('exploit_command','')}" if v.get("exploit_command") else "")
                for v in vulns
            ) or "  None identified yet"

            Console().print(Panel(
                f"[bold red]Vulnerabilities:[/bold red]\n{vuln_text}\n\n"
                f"[bold]Interesting endpoints:[/bold] {', '.join(analysis.get('interesting_endpoints', []))}\n"
                f"[bold]Login pages:[/bold] {', '.join(analysis.get('login_pages', []))}\n"
                f"[bold]File uploads:[/bold] {', '.join(analysis.get('file_upload', []))}\n\n"
                f"[bold cyan]Best attack:[/bold cyan] {analysis.get('priority_attack', '')}\n"
                f"[bold yellow]Reasoning:[/bold yellow] {analysis.get('reasoning', '')}\n\n"
                f"[bold green]Manually check:[/bold green] {analysis.get('what_to_look_for', '')}",
                title="[cyan]Web Analysis Complete[/cyan]",
                border_style="cyan",
            ))

        result.summary = f"Web analysis of {len(self.session.web_targets)} target(s) complete."
        return result
