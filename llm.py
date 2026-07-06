"""LLM provider — Claude with prompt caching + retry, Ollama for local claw-core."""
from __future__ import annotations
import os
import json
import re
import time
import random
import requests


# Model tiers — pick the right tool for the job
TIER_CHEAP  = "claude-haiku-4-5-20251001"   # recon, enumeration analysis
TIER_SMART  = "claude-sonnet-4-6"           # web, exploit, privesc planning
TIER_ELITE  = "claude-opus-4-7"             # optional override for hard boxes

STAGE_MODEL_MAP: dict[str, str] = {
    "recon":       TIER_CHEAP,
    "enumeration": TIER_CHEAP,
    "web":         TIER_SMART,
    "exploit":     TIER_SMART,
    "privesc":     TIER_SMART,
    "report":      TIER_SMART,
}


class LLMProvider:
    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        raise NotImplementedError

    def generate_json(self, system: str, user: str, timeout: int = 120) -> dict:
        raw = self.generate(system, user + "\n\nRespond with valid JSON only.", timeout)
        # Try full-string parse first, then greedy braces match
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            pass
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return {"raw": raw}

    def model_for_stage(self, stage: str) -> str:
        """Override in subclass to switch models per stage."""
        return ""


class ClaudeProvider(LLMProvider):
    """Claude API with prompt caching + exponential-backoff retry."""

    MAX_RETRIES = 4
    BASE_BACKOFF = 2.0

    def __init__(self, model: str = TIER_SMART, api_key: str = "",
                 auto_tier: bool = True):
        self.model = model
        self.auto_tier = auto_tier
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        self._current_stage = ""
        # Rough cost tracking
        self.cache_hits = 0
        self.cache_misses = 0

    def set_stage(self, stage: str) -> None:
        self._current_stage = stage

    def _select_model(self) -> str:
        if self.auto_tier and self._current_stage:
            return STAGE_MODEL_MAP.get(self._current_stage, self.model)
        return self.model

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)

        # Prompt caching: mark system prompt as cacheable
        # System prompts are ~500 tokens, cached across all agents
        system_blocks = [{
            "type": "text",
            "text": system,
            "cache_control": {"type": "ephemeral"},
        }]

        model = self._select_model()
        last_err: Exception | None = None

        for attempt in range(self.MAX_RETRIES):
            try:
                msg = client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=system_blocks,
                    messages=[{"role": "user", "content": user}],
                )

                # Track cache stats
                usage = getattr(msg, "usage", None)
                if usage:
                    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
                    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
                    if cache_read > 0:
                        self.cache_hits += 1
                    elif cache_write > 0:
                        self.cache_misses += 1

                return msg.content[0].text

            except anthropic.RateLimitError as e:
                last_err = e
                backoff = self.BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                time.sleep(backoff)
            except anthropic.APIStatusError as e:
                # 5xx = retryable, 4xx = fatal
                if e.status_code and 500 <= e.status_code < 600:
                    last_err = e
                    backoff = self.BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(backoff)
                else:
                    raise
            except (anthropic.APIConnectionError, anthropic.APITimeoutError) as e:
                last_err = e
                time.sleep(self.BASE_BACKOFF * (attempt + 1))

        raise RuntimeError(f"Claude API exhausted retries: {last_err}")

    def cost_summary(self) -> str:
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return "no LLM calls yet"
        hit_rate = 100 * self.cache_hits / total if total else 0
        return f"cache: {self.cache_hits}/{total} hits ({hit_rate:.0f}%)"

    def __str__(self) -> str:
        tier = "auto-tier" if self.auto_tier else self.model
        return f"Claude({tier})"


class OllamaProvider(LLMProvider):
    """Ollama at claw-core — no caching, no retry needed (local)."""

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

    def cost_summary(self) -> str:
        return "local (free)"

    def __str__(self) -> str:
        return f"Ollama({self.model})"


def get_provider(provider: str = "claude", model: str = "", api_key: str = "",
                 endpoint: str = "", auto_tier: bool = True) -> LLMProvider:
    if provider == "claude":
        return ClaudeProvider(
            model=model or TIER_SMART,
            api_key=api_key,
            auto_tier=auto_tier and not model,  # honor explicit model choice
        )
    if provider == "ollama":
        ep = endpoint or "http://100.126.22.55:11434"
        return OllamaProvider(model=model or "hermes3:70b", endpoint=ep)
    raise ValueError(f"Unknown provider: {provider}")
