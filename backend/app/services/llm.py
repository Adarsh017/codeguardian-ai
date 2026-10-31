"""Provider-agnostic LLM client used by the AI Reviewer and AI Remediation agents.

Supported providers (set LLM_PROVIDER):
  * openai    - any OpenAI-compatible Chat Completions API: OpenAI, Groq, Google Gemini
                (https://generativelanguage.googleapis.com/v1beta/openai), Ollama
                (http://localhost:11434/v1), LM Studio, OpenRouter, Together ...
  * anthropic - Anthropic Messages API
  * none      - disabled; agents fall back to the rule knowledge base
"""
import hashlib
import json
import re

import httpx

from ..config import settings
from .cache import cache


class LLMError(Exception):
    pass


def enabled() -> bool:
    if settings.LLM_PROVIDER == "none":
        return False
    # local OpenAI-compatible servers (Ollama) don't need a key
    return bool(settings.LLM_API_KEY) or "localhost" in settings.LLM_BASE_URL or "127.0.0.1" in settings.LLM_BASE_URL


def describe() -> dict:
    return {"provider": settings.LLM_PROVIDER, "model": settings.LLM_MODEL if enabled() else None, "enabled": enabled()}


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise LLMError("No JSON object in model response")
    return json.loads(text[start:end + 1])


def chat_json(system: str, user: str, max_tokens: int = 4000) -> dict:
    """Send a prompt and return the parsed JSON object from the reply (cached)."""
    if not enabled():
        raise LLMError("LLM is not configured")
    key = "llm:" + hashlib.sha256(f"{settings.LLM_PROVIDER}|{settings.LLM_MODEL}|{system}|{user}".encode()).hexdigest()
    cached = cache.get_json(key)
    if cached is not None:
        return cached
    try:
        if settings.LLM_PROVIDER == "anthropic":
            text = _anthropic(system, user, max_tokens)
        else:
            text = _openai(system, user, max_tokens)
        data = _extract_json(text)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError, IndexError) as exc:
        raise LLMError(str(exc)) from exc
    cache.set_json(key, data, ttl=7 * 86400)
    return data


def _openai(system: str, user: str, max_tokens: int) -> str:
    headers = {"Content-Type": "application/json"}
    if settings.LLM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"
    body = {
        "model": settings.LLM_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    url = settings.LLM_BASE_URL.rstrip("/") + "/chat/completions"
    with httpx.Client(timeout=settings.LLM_TIMEOUT) as client:
        r = client.post(url, headers=headers, json=body)
        if r.status_code == 400 and "response_format" in r.text:
            body.pop("response_format")
            r = client.post(url, headers=headers, json=body)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def _anthropic(system: str, user: str, max_tokens: int) -> str:
    base = settings.LLM_BASE_URL if "anthropic" in settings.LLM_BASE_URL else "https://api.anthropic.com/v1"
    with httpx.Client(timeout=settings.LLM_TIMEOUT) as client:
        r = client.post(base.rstrip("/") + "/messages",
                        headers={"x-api-key": settings.LLM_API_KEY, "anthropic-version": "2023-06-01",
                                 "content-type": "application/json"},
                        json={"model": settings.LLM_MODEL, "max_tokens": max_tokens, "temperature": 0.1,
                              "system": system, "messages": [{"role": "user", "content": user}]})
        r.raise_for_status()
        return "".join(block.get("text", "") for block in r.json()["content"])
