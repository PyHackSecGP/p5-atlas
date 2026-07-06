"""Enumeration Agent — deep per-service enumeration based on recon findings."""
from __future__ import annotations
from models import HackSession, AgentResult, Stage, Finding, Severity
from llm import LLMProvider
from tools.runner import run, run_parallel
from agents.base import BaseAgent
import checkpoint as cp


class EnumerationAgent(BaseAgent):
    NAME  = "Enumeration"
    STAGE = Stage.ENUMERATION

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")
        ip = self.session.target_ip
        findings: list[str] = []

        # Collect approved tasks first — then run all in parallel
        approved_tasks: list[dict] = []

        # ── SMB / NetBIOS ─────────────────────────────────────────
        smb_ports = [p for p in self.session.open_ports if p.service in ("microsoft-ds", "netbios-ssn", "smb") or p.number in (139, 445)]
        if smb_ports:
            cr = self.checkpoint(
                what_found=f"SMB open on port(s): {', '.join(str(p.number) for p in smb_ports)}",
                plan="enum4linux-ng + smbclient anonymous share listing",
                why="SMB often has anonymous access, null sessions, or world-readable shares with creds/configs. Common HTB foothold.",
                what_to_look_for="Shares named 'backup', 'files', 'Users', anonymous login, readable files, .txt/.conf/.xml files",
                command=f"enum4linux-ng -A {ip}",
                risk="low",
            )
            if cr.approved:
                cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else f"enum4linux-ng -A {ip}"
                approved_tasks.append({"name": "enum4linux", "command": cmd, "timeout": 120, "log_dir": self.output_dir})
                approved_tasks.append({"name": "smbclient",  "command": f"smbclient -L //{ip} -N", "timeout": 30, "log_dir": self.output_dir})

        # ── FTP ───────────────────────────────────────────────────
        ftp_ports = [p for p in self.session.open_ports if p.service == "ftp" or p.number == 21]
        if ftp_ports:
            cr = self.checkpoint(
                what_found=f"FTP on port {ftp_ports[0].number}: {ftp_ports[0].version}",
                plan="Test anonymous login, list files",
                why="Anonymous FTP is common on HTB. Files in FTP root often contain creds or configs.",
                what_to_look_for="Anonymous login success, files like passwords.txt, config.xml, .key files, upload directory",
                command=f"ftp -n {ip} <<< $'user anonymous\\npass\\nls -la\\nbye'",
                risk="low",
            )
            if cr.approved:
                approved_tasks.append({
                    "name": "ftp_anon",
                    "command": ["bash", "-c", f"echo -e 'open {ip}\\nuser anonymous\\npass\\nls -la\\nbye' | ftp -n"],
                    "timeout": 30, "log_dir": self.output_dir,
                })

        # ── SSH version check (no tool needed — already in session) ─
        ssh_port = self.session.ssh_port
        if ssh_port:
            self.log(f"SSH on port {ssh_port.number}: {ssh_port.version}")
            findings.append(f"SSH: {ssh_port.version} (check for CVEs, username enumeration)")

        # ── LDAP ─────────────────────────────────────────────────
        ldap_ports = [p for p in self.session.open_ports if "ldap" in p.service.lower() or p.number in (389, 636, 3268)]
        if ldap_ports:
            cr = self.checkpoint(
                what_found=f"LDAP on port(s): {', '.join(str(p.number) for p in ldap_ports)}",
                plan="ldapsearch anonymous base query",
                why="Anonymous LDAP often leaks usernames, groups, descriptions with passwords, and AD structure.",
                what_to_look_for="User accounts, description fields with passwords, service accounts, domain name",
                command=f"ldapsearch -x -H ldap://{ip} -b '' -s base namingContexts",
                risk="low",
            )
            if cr.approved:
                approved_tasks.append({"name": "ldap_base", "command": f"ldapsearch -x -H ldap://{ip} -b '' -s base namingContexts", "timeout": 30, "log_dir": self.output_dir})

        # ── SNMP ─────────────────────────────────────────────────
        snmp_ports = [p for p in self.session.open_ports if "snmp" in p.service.lower() or p.number == 161]
        if snmp_ports:
            cr = self.checkpoint(
                what_found="SNMP port 161 open",
                plan="snmpwalk with community string 'public'",
                why="SNMP with default community 'public' leaks system info, running processes, network interfaces, user accounts.",
                what_to_look_for="Running processes (may show credentials in command lines), installed software, network config",
                command=f"snmpwalk -v2c -c public {ip}",
                risk="low",
            )
            if cr.approved:
                approved_tasks.append({"name": "snmp", "command": f"snmpwalk -v2c -c public {ip}", "timeout": 60, "log_dir": self.output_dir})

        # ── Hydra brute-force if usernames enumerated + login service ─
        # Collect usernames already found from earlier stages
        known_users = list({c.username for c in self.session.credentials if c.username})
        # Also extract usernames from enum4linux output later — done in analysis phase

        # ── Run all approved tasks in parallel ────────────────────
        if approved_tasks:
            self.log(f"Running {len(approved_tasks)} enumeration task(s) in parallel...")
            parallel_results = run_parallel(approved_tasks, max_workers=len(approved_tasks))

            if "enum4linux" in parallel_results:
                result.raw_outputs["enum4linux"] = parallel_results["enum4linux"].output
                findings.append(f"SMB enumeration:\n{parallel_results['enum4linux'].output[:500]}")
            if "smbclient" in parallel_results:
                result.raw_outputs["smbclient_list"] = parallel_results["smbclient"].output
                findings.append(f"SMB shares:\n{parallel_results['smbclient'].output[:300]}")
            if "ftp_anon" in parallel_results:
                result.raw_outputs["ftp_anon"] = parallel_results["ftp_anon"].output
                findings.append(f"FTP anonymous:\n{parallel_results['ftp_anon'].output[:300]}")
            if "ldap_base" in parallel_results:
                result.raw_outputs["ldap_base"] = parallel_results["ldap_base"].output
                findings.append(f"LDAP base:\n{parallel_results['ldap_base'].output[:300]}")
            if "snmp" in parallel_results:
                result.raw_outputs["snmp"] = parallel_results["snmp"].output
                findings.append(f"SNMP:\n{parallel_results['snmp'].output[:500]}")

        # ── LLM analysis of all enumeration ─────────────────────
        if findings:
            self.log("LLM analysing enumeration results...")
            combined = "\n\n---\n\n".join(findings)
            analysis = self.ask_json(f"""
Analyse this enumeration data from an HTB machine at {ip}.

FINDINGS:
{combined[:5000]}

Respond with JSON:
{{
  "credentials_found": [{{"username": "", "password": "", "service": "", "note": ""}}],
  "interesting_files": ["list of files worth downloading"],
  "attack_vectors": ["ordered list of attack paths to try"],
  "usernames": ["any usernames found"],
  "key_finding": "most important single finding in one sentence",
  "what_to_do_next": "specific next command to run"
}}""")

            # Surface credentials
            for cred in analysis.get("credentials_found", []):
                from models import Credential
                if cred.get("username"):
                    self.session.credentials.append(Credential(**{k: v for k, v in cred.items() if k in ("username", "password", "hash", "service", "note")}))

            result.next_actions = analysis.get("attack_vectors", [])
            result.metadata = analysis

            # ── Hydra brute-force if usernames + login-service found ─
            llm_users = [u.strip() for u in analysis.get("usernames", []) if u and u.strip()]
            all_users = list(dict.fromkeys(known_users + llm_users))
            if all_users:
                self._try_hydra_bruteforce(ip, all_users, result)

            cp.section("Enumeration Analysis")
            from rich.console import Console
            from rich.panel import Panel
            Console().print(Panel(
                f"[bold green]Key finding:[/bold green] {analysis.get('key_finding', 'No key findings')}\n\n"
                f"[bold]Attack vectors:[/bold]\n" + "\n".join(f"  {i+1}. {v}" for i, v in enumerate(analysis.get("attack_vectors", []))) + "\n\n"
                f"[bold cyan]Next action:[/bold cyan] {analysis.get('what_to_do_next', '')}",
                title="[cyan]Enumeration Complete[/cyan]",
                border_style="cyan",
            ))

        result.summary = f"Enumerated {len(self.session.open_ports)} services. Found {len(self.session.credentials)} credentials."
        return result

    # ── Hydra brute-force helper ─────────────────────────────────

    HYDRA_WORDLISTS = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "/usr/share/wordlists/fasttrack.txt",
    ]

    def _find_wordlist(self) -> str:
        import os
        for w in self.HYDRA_WORDLISTS:
            if os.path.exists(w):
                return w
        return ""

    def _try_hydra_bruteforce(self, ip: str, usernames: list[str], result) -> None:
        """Run hydra against SSH/FTP with enumerated usernames + top password list."""
        from pathlib import Path
        wordlist = self._find_wordlist()
        if not wordlist:
            self.log("No password wordlist found (rockyou/seclists)", "warning")
            return

        # Determine attackable services
        targets: list[tuple[str, int]] = []
        for p in self.session.open_ports:
            if p.service == "ssh" or p.number == 22:
                targets.append(("ssh", p.number))
            elif p.service == "ftp" or p.number == 21:
                targets.append(("ftp", p.number))

        if not targets:
            return

        # Write usernames to a file
        users_file = Path(self.output_dir) / "hydra_users.txt"
        users_file.write_text("\n".join(usernames[:20]))  # cap at 20

        for svc, port in targets:
            cr = self.checkpoint(
                what_found=f"{svc.upper()} on port {port} + {len(usernames)} enumerated users",
                plan=f"hydra brute-force with rockyou top passwords (capped)",
                why=f"Enumerated usernames + weak-password wordlist = common HTB foothold. "
                    f"Hydra will stop on first hit.",
                what_to_look_for="[svc] host: X login: Y password: Z — indicates successful auth",
                command=f"hydra -L {users_file} -P {wordlist} -f -t 4 -e nsr {svc}://{ip}:{port}",
                risk="medium",
            )
            if not cr.approved:
                continue

            cmd = cr.override if cr.action == cp.CheckpointResult.MODIFIED else (
                # -f: stop on first hit, -t 4: threads (be nice), -e nsr: try empty/reverse/same
                # Small wordlist cap via head to keep it under 5 min
                f"bash -c 'hydra -L {users_file} -P <(head -500 {wordlist}) "
                f"-f -t 4 -e nsr -w 3 {svc}://{ip}:{port} 2>&1'"
            )
            self.log(f"Hydra brute-force on {svc}:{port} (limited to top 500 passwords)...")
            r = run(cmd, timeout=300, log_dir=self.output_dir)
            result.raw_outputs[f"hydra_{svc}_{port}"] = r.output

            # Parse hit
            import re
            hit = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", r.output)
            if hit:
                from models import Credential
                user, pwd = hit.group(1), hit.group(2)
                cred = Credential(username=user, password=pwd, service=svc,
                                  note=f"hydra brute on port {port}")
                self.session.credentials.append(cred)
                self.log(f"HYDRA HIT: {user}:{pwd} on {svc}:{port}", "success")
