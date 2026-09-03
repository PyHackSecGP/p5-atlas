"""Base agent class — all agents inherit this."""
from __future__ import annotations
import re
import subprocess
from models import HackSession, AgentResult, Stage
from llm import LLMProvider
from checkpoint import notify, thinking
import checkpoint as cp


class BaseAgent:
    NAME  = "Agent"
    STAGE = Stage.INIT

    SYSTEM_PROMPT = """You are a senior penetration tester working on an HTB machine.
You are part of ATLAS — an autonomous security research team.
Be precise, technical, and focus only on what the evidence shows.
Never fabricate vulnerabilities. If unsure, say so."""

    def __init__(self, session: HackSession, llm: LLMProvider, output_dir: str):
        self.session    = session
        self.llm        = llm
        self.output_dir = output_dir

    def run(self) -> AgentResult:
        raise NotImplementedError

    def ask(self, prompt: str, system_extra: str = "") -> str:
        system = self.SYSTEM_PROMPT
        if system_extra:
            system += f"\n\n{system_extra}"
        thinking(self.NAME, prompt[:80] + "...")
        return self.llm.generate(system, f"{self.session.context_summary()}\n\n{prompt}")

    def ask_json(self, prompt: str) -> dict:
        system = self.SYSTEM_PROMPT + "\nAlways respond with valid JSON."
        return self.llm.generate_json(system, f"{self.session.context_summary()}\n\n{prompt}")

    def log(self, message: str, level: str = "info") -> None:
        notify(self.NAME, message, level)

    def checkpoint(self, what_found: str, plan: str, why: str,
                   what_to_look_for: str, command: str = "",
                   risk: str = "medium") -> cp.CheckpointResult:
        return cp.checkpoint(
            agent=self.NAME,
            what_found=what_found,
            plan=plan,
            why=why,
            what_to_look_for=what_to_look_for,
            command=command,
            risk=risk,
        )

    def run_tool_adaptive(self, cmd: str, timeout: int = 60,
                          fallback_context: str = "") -> str:
        """Run tool; if it fails/empty, ask LLM for an alternative command."""
        from tools.runner import run
        r = run(cmd, timeout=timeout, log_dir=self.output_dir)
        if r.returncode == 0 and r.output.strip():
            return r.output

        if not fallback_context:
            return r.output

        alt_raw = self.ask(
            f"Command failed or returned empty:\n"
            f"Command: {cmd}\nOutput: {r.output[:400]}\n\n"
            f"Context: {fallback_context}\n\n"
            f"Provide ONE alternative shell command that achieves the same goal. "
            f"Reply with the command only — no explanation, no markdown."
        )
        alt_cmd = alt_raw.strip().splitlines()[0].strip().strip("`")
        if alt_cmd and alt_cmd != cmd:
            self.log(f"Adaptive retry: {alt_cmd[:80]}", "info")
            r2 = run(alt_cmd, timeout=timeout, log_dir=self.output_dir)
            return r2.output
        return r.output

    @staticmethod
    def get_tun_ip() -> str:
        """Return IP of the first tun interface (HTB VPN). Empty if none found."""
        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
        m = re.search(
            r"tun\d[^\n]*\n(?:[^\n]+\n)*?\s+inet (\d+\.\d+\.\d+\.\d+)", result.stdout,
        )
        return m.group(1) if m else ""
