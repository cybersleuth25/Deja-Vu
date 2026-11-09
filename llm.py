"""Groq chat completion with a model fallback. Callers must handle LLMUnavailable."""
from __future__ import annotations

import os
import re

DEFAULT_MODEL = "openai/gpt-oss-120b"
FALLBACK_MODEL = "qwen/qwen3-32b"
THINK_RE = re.compile(r"<think>.*?</think>", re.S)


class LLMUnavailable(Exception):
    pass


class GroqLLM:
    def __init__(self, api_key: str | None = None, model: str | None = None, timeout: float = 20.0):
        from groq import Groq

        key = api_key or os.environ.get("GROQ_API_KEY")
        if not key:
            raise LLMUnavailable("GROQ_API_KEY is not set")
        self.models = [model or os.environ.get("GROQ_MODEL") or DEFAULT_MODEL]
        if FALLBACK_MODEL not in self.models:
            self.models.append(FALLBACK_MODEL)
        self.client = Groq(api_key=key, timeout=timeout, max_retries=1)

    def complete(self, system: str, user: str, max_tokens: int = 700) -> str:
        errors = []
        for model in self.models:
            try:
                resp = self.client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.2,
                    max_completion_tokens=max_tokens,
                )
                text = THINK_RE.sub("", resp.choices[0].message.content or "").strip()
                if text:
                    return text
                errors.append(f"{model}: empty response")
            except Exception as exc:  # rate limit, network, unknown model
                errors.append(f"{model}: {exc}")
        raise LLMUnavailable("; ".join(errors))


def get_llm() -> GroqLLM | None:
    try:
        return GroqLLM()
    except Exception:
        return None
