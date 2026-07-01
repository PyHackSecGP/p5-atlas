"""LLM provider — Claude now, Ollama-ready for future."""
from __future__ import annotations
import os
import json
import re
import requests


class LLMProvider:
    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        raise NotImplementedError

    def generate_json(self, system: str, user: str, timeout: int = 120) -> dict:
        raw = self.generate(system, user + "\n\nRespond with valid JSON only.", timeout)
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return {"raw": raw}


class ClaudeProvider(LLMProvider):
    def __init__(self, model: str = "claude-haiku-4-5-20251001", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        msg = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    def __str__(self) -> str:
        return f"Claude({self.model})"


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = "hermes3:70b", endpoint: str = "http://100.126.22.55:11434"):
        self.model = model
        self.endpoint = endpoint.rstrip("/")

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        payload = {
            "model": self.model,
            "prompt": f"<|system|>\n{system}\n<|user|>\n{user}\n<|assistant|>",
            "stream": False,
        }
        r = requests.post(f"{self.endpoint}/api/generate", json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("response", "")

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def __str__(self) -> str:
        return f"Ollama({self.model})"


def get_provider(provider: str = "claude", model: str = "", api_key: str = "",
                 endpoint: str = "") -> LLMProvider:
    if provider == "claude":
        return ClaudeProvider(model=model or "claude-haiku-4-5-20251001", api_key=api_key)
    if provider == "ollama":
        ep = endpoint or "http://100.126.22.55:11434"
        return OllamaProvider(model=model or "hermes3:70b", endpoint=ep)
    raise ValueError(f"Unknown provider: {provider}")
