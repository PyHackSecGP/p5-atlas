"""LLM provider — Claude with prompt caching + retry, Ollama for local claw-core."""
from __future__ import annotations
import logging
import os
import json
import re
import time
import random
import requests

log = logging.getLogger(__name__)

TIER_CHEAP = "claude-haiku-4-5-20251001"
TIER_SMART = "claude-sonnet-4-6"
TIER_ELITE = "claude-opus-4-7"

STAGE_MODEL_MAP: dict[str, str] = {
    "recon":       TIER_CHEAP,
    "enumeration": TIER_CHEAP,
    "planning":    TIER_CHEAP,
    "web":         TIER_SMART,
    "exploit":     TIER_SMART,
    "privesc":     TIER_SMART,
    "report":      TIER_SMART,
}

_JSON_RETRY_SUFFIX = (
    "\n\nCRITICAL: Respond with ONLY valid JSON. "
    "No markdown fences, no explanation, no prose. "
    "Start with { and end with }."
)


class LLMProvider:
    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        raise NotImplementedError

    def generate_json(self, system: str, user: str, timeout: int = 120, retries: int = 3) -> dict:
        """Generate JSON with retry on parse failure. Raises on exhaustion."""
        last_raw = ""
        for attempt in range(retries):
            prompt = user if attempt == 0 else user + _JSON_RETRY_SUFFIX
            try:
                raw = self.generate(system, prompt, timeout)
            except Exception as e:
                log.warning("generate() error on attempt %d: %s", attempt + 1, e)
                if attempt == retries - 1:
                    raise
                continue

            last_raw = raw

            # 1. Direct parse
            try:
                return json.loads(raw.strip())
            except json.JSONDecodeError:
                pass

            # 2. Strip markdown fences then parse
            stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE)
            try:
                return json.loads(stripped.strip())
            except json.JSONDecodeError:
                pass

            # 3. Greedy brace extraction
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass

            log.warning("JSON parse failed (attempt %d/%d)", attempt + 1, retries)

        raise RuntimeError(
            f"LLM returned invalid JSON after {retries} attempts. "
            f"Last response (first 400 chars): {last_raw[:400]}"
        )

    def model_for_stage(self, stage: str) -> str:
        return ""


class ClaudeProvider(LLMProvider):
    """Claude API — prompt caching + exponential-backoff retry."""

    MAX_RETRIES = 4
    BASE_BACKOFF = 2.0

    def __init__(self, model: str = TIER_SMART, api_key: str = "", auto_tier: bool = True):
        import anthropic as _a
        self.model = model
        self.auto_tier = auto_tier
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        # Single client — reused across all calls (avoids per-call connection overhead)
        self._client = _a.Anthropic(api_key=self.api_key)
        self._current_stage = ""
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_calls = 0

    def set_stage(self, stage: str) -> None:
        self._current_stage = stage

    def _select_model(self) -> str:
        if self.auto_tier and self._current_stage:
            return STAGE_MODEL_MAP.get(self._current_stage, self.model)
        return self.model

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        import anthropic

        system_blocks = [{
            "type": "text",
            "text": system,
            "cache_control": {"type": "ephemeral"},
        }]

        model = self._select_model()
        last_err: Exception | None = None

        for attempt in range(self.MAX_RETRIES):
            try:
                msg = self._client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=system_blocks,
                    messages=[{"role": "user", "content": user}],
                )
                self.total_calls += 1

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
                log.warning("Rate limited, backing off %.1fs", backoff)
                time.sleep(backoff)
            except anthropic.APIStatusError as e:
                if e.status_code and 500 <= e.status_code < 600:
                    last_err = e
                    backoff = self.BASE_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(backoff)
                else:
                    raise
            except (anthropic.APIConnectionError, anthropic.APITimeoutError) as e:
                last_err = e
                time.sleep(self.BASE_BACKOFF * (attempt + 1))

        raise RuntimeError(f"Claude API exhausted {self.MAX_RETRIES} retries: {last_err}")

    def cost_summary(self) -> str:
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return f"no LLM calls ({self.total_calls} total)"
        hit_rate = 100 * self.cache_hits / total
        return (
            f"cache: {self.cache_hits}/{total} hits ({hit_rate:.0f}%), "
            f"{self.total_calls} total API calls"
        )

    def __str__(self) -> str:
        tier = "auto-tier" if self.auto_tier else self.model
        return f"Claude({tier})"


DEFAULT_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


class OllamaProvider(LLMProvider):
    """Ollama — local inference, no caching, retry on connection errors."""

    MAX_RETRIES = 3

    def __init__(self, model: str = "hermes3:70b", endpoint: str = ""):
        self.model = model
        self.endpoint = (endpoint or DEFAULT_OLLAMA_HOST).rstrip("/")
        self._session = requests.Session()

    def generate(self, system: str, user: str, timeout: int = 120) -> str:
        payload = {
            "model": self.model,
            "prompt": f"<|system|>\n{system}\n<|user|>\n{user}\n<|assistant|>",
            "stream": False,
        }
        last_err: Exception | None = None
        for attempt in range(self.MAX_RETRIES):
            try:
                r = self._session.post(
                    f"{self.endpoint}/api/generate", json=payload, timeout=timeout,
                )
                r.raise_for_status()
                return r.json().get("response", "")
            except (requests.ConnectionError, requests.Timeout) as e:
                last_err = e
                time.sleep(2 * (attempt + 1))
            except requests.HTTPError as e:
                raise RuntimeError(f"Ollama HTTP error: {e}") from e
        raise RuntimeError(
            f"Ollama connection failed after {self.MAX_RETRIES} retries: {last_err}"
        )

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


def get_provider(
    provider: str = "claude",
    model: str = "",
    api_key: str = "",
    endpoint: str = "",
    auto_tier: bool = True,
) -> LLMProvider:
    if provider == "claude":
        return ClaudeProvider(
            model=model or TIER_SMART,
            api_key=api_key,
            auto_tier=auto_tier and not model,
        )
    if provider == "ollama":
        return OllamaProvider(
            model=model or "hermes3:70b",
            endpoint=endpoint or DEFAULT_OLLAMA_HOST,
        )
    raise ValueError(f"Unknown provider: {provider!r}")
