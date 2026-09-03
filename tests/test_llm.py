"""Tests for llm.py — providers, JSON retry, caching stats."""
from __future__ import annotations
import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from llm import (
    LLMProvider, OllamaProvider, ClaudeProvider,
    get_provider, TIER_CHEAP, TIER_SMART, STAGE_MODEL_MAP,
)


# ── generate_json retry logic ─────────────────────────────────────────────────

class SequenceLLM(LLMProvider):
    """Returns responses from a sequence, then repeats the last one."""
    def __init__(self, responses: list[str]):
        self._responses = responses
        self._idx = 0

    def generate(self, system, user, timeout=120):
        r = self._responses[min(self._idx, len(self._responses) - 1)]
        self._idx += 1
        return r


def test_generate_json_direct_parse():
    llm = SequenceLLM(['{"key": "value"}'])
    assert llm.generate_json("sys", "user") == {"key": "value"}


def test_generate_json_strips_markdown_fences():
    llm = SequenceLLM(['```json\n{"key": "value"}\n```'])
    assert llm.generate_json("sys", "user") == {"key": "value"}


def test_generate_json_greedy_brace_extraction():
    llm = SequenceLLM(['Here is the result: {"a": 1, "b": 2} and that is it.'])
    assert llm.generate_json("sys", "user") == {"a": 1, "b": 2}


def test_generate_json_retries_on_bad_response():
    llm = SequenceLLM(["not json at all", "still bad", '{"ok": true}'])
    result = llm.generate_json("sys", "user", retries=3)
    assert result == {"ok": True}
    assert llm._idx == 3  # tried all three


def test_generate_json_raises_after_exhaustion():
    llm = SequenceLLM(["bad", "also bad"])
    with pytest.raises(RuntimeError, match="invalid JSON"):
        llm.generate_json("sys", "user", retries=2)


def test_generate_json_nested_object():
    llm = SequenceLLM(['{"vectors": [{"rank": 1, "type": "SUID"}]}'])
    result = llm.generate_json("sys", "user")
    assert result["vectors"][0]["type"] == "SUID"


def test_generate_json_empty_object():
    llm = SequenceLLM(['{}'])
    assert llm.generate_json("sys", "user") == {}


# ── OllamaProvider ────────────────────────────────────────────────────────────

def test_ollama_provider_init():
    p = OllamaProvider(model="hermes3:70b", endpoint="http://localhost:11434")
    assert p.model == "hermes3:70b"
    assert p.endpoint == "http://localhost:11434"


def test_ollama_endpoint_trailing_slash_stripped():
    p = OllamaProvider(endpoint="http://localhost:11434/")
    assert not p.endpoint.endswith("/")


def test_ollama_generate_success():
    p = OllamaProvider(endpoint="http://localhost:11434")
    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "test output"}
    mock_response.raise_for_status = MagicMock()

    with patch.object(p._session, "post", return_value=mock_response):
        result = p.generate("system prompt", "user message")

    assert result == "test output"


def test_ollama_generate_retries_on_connection_error():
    import requests
    p = OllamaProvider(endpoint="http://localhost:11434")
    p.MAX_RETRIES = 3

    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "success on third try"}
    mock_response.raise_for_status = MagicMock()

    call_count = 0
    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise requests.ConnectionError("refused")
        return mock_response

    with patch.object(p._session, "post", side_effect=side_effect), \
         patch("time.sleep"):  # don't actually sleep in tests
        result = p.generate("sys", "user")

    assert result == "success on third try"
    assert call_count == 3


def test_ollama_generate_raises_after_max_retries():
    import requests
    p = OllamaProvider(endpoint="http://localhost:11434")
    p.MAX_RETRIES = 2

    with patch.object(p._session, "post", side_effect=requests.ConnectionError("refused")), \
         patch("time.sleep"):
        with pytest.raises(RuntimeError, match="connection failed"):
            p.generate("sys", "user")


def test_ollama_is_available_true():
    p = OllamaProvider(endpoint="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.get", return_value=mock_resp):
        assert p.is_available() is True


def test_ollama_is_available_false_on_exception():
    import requests
    p = OllamaProvider(endpoint="http://localhost:11434")
    with patch("requests.get", side_effect=requests.ConnectionError()):
        assert p.is_available() is False


def test_ollama_cost_summary():
    p = OllamaProvider()
    assert "free" in p.cost_summary()


def test_ollama_str():
    p = OllamaProvider(model="qwen3.5:latest")
    assert "qwen3.5:latest" in str(p)


# ── Stage model mapping ───────────────────────────────────────────────────────

def test_stage_model_map_haiku_for_recon():
    assert STAGE_MODEL_MAP["recon"] == TIER_CHEAP


def test_stage_model_map_sonnet_for_exploit():
    assert STAGE_MODEL_MAP["exploit"] == TIER_SMART


def test_stage_model_map_sonnet_for_privesc():
    assert STAGE_MODEL_MAP["privesc"] == TIER_SMART


# ── get_provider factory ──────────────────────────────────────────────────────

def test_get_provider_ollama():
    p = get_provider("ollama", model="hermes3:70b", endpoint="http://localhost:11434")
    assert isinstance(p, OllamaProvider)
    assert p.model == "hermes3:70b"


def test_get_provider_unknown_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("openai")


def test_get_provider_claude_requires_api_key():
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        get_provider("claude", api_key="")
