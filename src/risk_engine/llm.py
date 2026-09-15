"""Minimal provider-agnostic LLM client.

Any OpenAI-compatible endpoint works (OpenAI, Groq, Together, ...):
  LLM_API_KEY  (or OPENAI_API_KEY)
  LLM_BASE_URL (default https://api.openai.com/v1;
                Groq free tier: https://api.groq.com/openai/v1)
  LLM_MODEL    (default gpt-4o-mini; Groq: llama-3.3-70b-versatile)

temperature=0 everywhere — the agent's outputs must be reproducible.
No SDK dependency for the request itself: a chat completion is one POST.

Tracing (optional, off by default): set LANGSMITH_TRACING=true +
LANGSMITH_API_KEY to see every agent.py graph node (build_query, retrieve,
grade, generate, verify) plus this raw chat() call as nested spans in the
LangSmith UI — the graph is a LangGraph CompiledStateGraph, which is a
LangChain Runnable, so nodes trace automatically with zero code changes;
only this non-LangChain HTTP call needs the explicit @traceable below.
Absent those env vars, `traceable` is a no-op and nothing leaves the machine.
"""
from __future__ import annotations

import os

import requests
from dotenv import load_dotenv

from .observability import metrics

load_dotenv()

try:
    from langsmith import get_current_run_tree, traceable
except ImportError:  # tracing is optional; the app must still run without it
    def traceable(*targs, **tkwargs):
        if targs and callable(targs[0]) and not tkwargs:
            return targs[0]

        def _decorator(fn):
            return fn

        return _decorator

    def get_current_run_tree():
        return None


class LLMUnavailable(Exception):
    """Raised when no key is configured or the endpoint cannot be reached."""


class LLMClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int = 60,
    ):
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = (base_url or os.getenv("LLM_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.getenv("LLM_MODEL") or "gpt-4o-mini"
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @traceable(run_type="llm", name="llm_chat")
    def chat(self, system: str, user: str, max_tokens: int = 900) -> str:
        # LangSmith already omits `self` from a bound method's traced inputs
        # (verified empirically, not assumed) — api_key is never at risk here.
        # model/base_url are attached explicitly since they'd otherwise be
        # invisible in the trace.
        run = get_current_run_tree()
        if run is not None:
            run.add_metadata({"model": self.model, "base_url": self.base_url})
        if not self.configured:
            metrics.increment("llm_request", status="unconfigured")
            raise LLMUnavailable("no API key configured (LLM_API_KEY / OPENAI_API_KEY)")
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": 0,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            metrics.increment("llm_request", status="success")
            return resp.json()["choices"][0]["message"]["content"]
        except LLMUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            metrics.increment("llm_request", status="error")
            raise LLMUnavailable(str(exc)) from exc
