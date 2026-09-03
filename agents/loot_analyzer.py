"""Loot Analyzer Agent — extract credentials and secrets from downloaded files."""
from __future__ import annotations
import re
from pathlib import Path
from models import HackSession, AgentResult, Stage, Credential, Finding, Severity
from llm import LLMProvider
from agents.base import BaseAgent
import checkpoint as cp

# Patterns to detect interesting content without LLM (fast pre-filter)
_QUICK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'password\s*[=:]\s*["\']?(\S+)', re.I),      "password"),
    (re.compile(r'passwd\s*[=:]\s*["\']?(\S+)', re.I),        "password"),
    (re.compile(r'\bpass\s*[=:]\s*["\']?(\S+)', re.I),        "password"),
    (re.compile(r'secret\s*[=:]\s*["\']?(\S+)', re.I),        "secret"),
    (re.compile(r'api.?key\s*[=:]\s*["\']?(\S+)', re.I),      "api_key"),
    (re.compile(r'\btoken\s*[=:]\s*["\']?(\S+)', re.I),        "token"),
    (re.compile(r'username\s*[=:]\s*["\']?(\S+)', re.I),       "username"),
    (re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY', re.I), "ssh_key"),
    (re.compile(r'(?:mysql|postgresql|mongodb|redis)://([^:]+):([^@]+)@', re.I), "db_url"),
    (re.compile(r'jdbc:mysql://[^:]+/[^?]+\?user=([^&]+)&password=([^&]+)', re.I), "jdbc"),
]

_INTERESTING_NAMES = frozenset((
    "pass", "cred", "key", "secret", "config", "backup", "db",
    ".env", "id_rsa", "web.config", "settings", "database",
))

MAX_FILE_SIZE = 500_000   # 500 KB
MAX_FILES_TO_LLM = 8      # avoid massive prompts


class LootAnalyzerAgent(BaseAgent):
    NAME  = "LootAnalyzer"
    STAGE = Stage.ENUMERATION

    SYSTEM_PROMPT = """You are a forensic analyst extracting credentials and attack vectors from files.
Look for: passwords, API keys, SSH keys, connection strings, tokens, hardcoded credentials.
Report only what is actually present in the content — never fabricate."""

    def run(self) -> AgentResult:
        result = AgentResult(agent=self.NAME, stage=self.STAGE, summary="")

        if not self.session.loot:
            result.summary = "No loot files to analyze."
            return result

        self.log(f"Scanning {len(self.session.loot)} loot file(s) for credentials...")
        interesting: list[tuple[str, str]] = []   # (path_str, excerpt)
        quick_creds_added = 0

        for file_path in self.session.loot:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_SIZE:
                self.log(f"Skipping {path.name} — too large ({path.stat().st_size // 1024}KB)", "warning")
                continue

            try:
                content = path.read_text(errors="replace")
            except Exception:
                continue

            hits: list[str] = []
            has_ssh_key = bool(re.search(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY", content, re.I))

            for pattern, kind in _QUICK_PATTERNS:
                for m in pattern.finditer(content):
                    hits.append(f"[{kind}] {m.group(0)[:80]}")

            name_interesting = any(kw in path.name.lower() for kw in _INTERESTING_NAMES)

            if hits or has_ssh_key or name_interesting:
                interesting.append((str(path), content[:2500]))
                level = "success" if hits else "info"
                self.log(f"{'[SSH KEY] ' if has_ssh_key else ''}{path.name}: {len(hits)} pattern hit(s)", level)

                if has_ssh_key:
                    self.session.credentials.append(Credential(
                        username="",
                        password="",
                        service="ssh",
                        note=f"SSH private key: {str(path)}",
                    ))
                    quick_creds_added += 1

        if not interesting:
            result.summary = f"Scanned {len(self.session.loot)} file(s). No credentials found."
            return result

        self.log(f"{len(interesting)} interesting file(s) — running LLM deep extraction...")

        cr = cp.checkpoint(
            agent=self.NAME,
            what_found=f"{len(interesting)} file(s) with potential secrets/credentials",
            plan="LLM extracts all credentials, keys, and attack vectors from file contents",
            why="Regex misses context-dependent credentials (encoded, split across lines, config formats). LLM understands structure.",
            what_to_look_for="Username/password pairs, API keys, SSH keys, DB connection strings, hardcoded tokens",
            risk="low",
        )
        if not cr.approved:
            result.summary = f"LLM analysis skipped — {len(interesting)} interesting files found, {quick_creds_added} quick creds added."
            return result

        # Build LLM content block — cap total size
        content_block = ""
        for path_str, excerpt in interesting[:MAX_FILES_TO_LLM]:
            fname = Path(path_str).name
            content_block += f"\n=== {fname} ===\n{excerpt[:1200]}\n"

        try:
            analysis = self.ask_json(f"""
Analyze these files from an HTB machine. Extract ALL credentials, secrets, and attack vectors.

{content_block[:6000]}

Respond ONLY with valid JSON:
{{
  "credentials": [
    {{"username": "alice", "password": "Summer2024!", "service": "ssh", "note": "found in config.xml"}}
  ],
  "ssh_key_paths": ["/path/to/id_rsa"],
  "hashes": [
    {{"user": "admin", "hash": "aad3b435...", "type": "NTLM"}}
  ],
  "attack_vectors": ["SSH as alice:Summer2024!", "crack NTLM hash for admin"],
  "interesting_findings": ["DB backup contains schema", "web.config has plaintext SA password"],
  "summary": "one sentence summary of what was found"
}}""")
        except RuntimeError as e:
            self.log(f"LLM analysis failed: {e}", "warning")
            result.summary = f"Loot scanned. LLM extraction failed. {quick_creds_added} quick creds added."
            return result

        # Store extracted credentials
        new_creds = 0
        for cred in analysis.get("credentials", []):
            if cred.get("username") or cred.get("password"):
                self.session.credentials.append(Credential(
                    username=cred.get("username", ""),
                    password=cred.get("password", ""),
                    service=cred.get("service", ""),
                    note=f"loot: {cred.get('note', '')}",
                ))
                new_creds += 1
                self.log(
                    f"CRED: {cred.get('username')}:{cred.get('password')} [{cred.get('service')}]",
                    "success",
                )

        # Surface hash findings as findings
        for h in analysis.get("hashes", []):
            self.session.findings.append(Finding(
                title=f"Hash: {h.get('user', '?')} [{h.get('type', '?')}]",
                severity=Severity.HIGH,
                description=f"Crackable {h.get('type')} hash for user {h.get('user', '?')}",
                evidence=h.get("hash", ""),
                agent=self.NAME,
            ))

        result.next_actions = analysis.get("attack_vectors", [])
        result.metadata = analysis

        cp.section("Loot Analysis")
        from rich.console import Console
        from rich.panel import Panel
        total_creds = new_creds + quick_creds_added
        body = (
            f"[bold green]Credentials extracted:[/bold green] {total_creds}\n"
            f"[bold]Hashes:[/bold] {len(analysis.get('hashes', []))}\n\n"
        )
        if analysis.get("attack_vectors"):
            body += "[bold]Attack vectors:[/bold]\n"
            body += "\n".join(f"  • {v}" for v in analysis["attack_vectors"]) + "\n\n"
        if analysis.get("interesting_findings"):
            body += "[bold dim]Other findings:[/bold dim]\n"
            body += "\n".join(f"  - {f}" for f in analysis["interesting_findings"]) + "\n\n"
        body += f"[bold yellow]Summary:[/bold yellow] {analysis.get('summary', '')}"
        Console().print(Panel(
            body,
            title=f"[cyan]Loot Analysis — {len(interesting)}/{len(self.session.loot)} files[/cyan]",
            border_style="cyan",
        ))

        result.summary = (
            f"Analyzed {len(self.session.loot)} files. "
            f"Extracted {total_creds} credential(s), {len(analysis.get('hashes', []))} hash(es). "
            f"{analysis.get('summary', '')}"
        )
        return result
