"""Centralized logging, in-process metrics, and alerting.

This project has no external metrics/logging infrastructure (no Prometheus,
no Datadog, no log aggregator) wired up, and adding a hard dependency on one
would fail the same "must run on a laptop with no network" requirement the
rest of the pipeline is built around. So this module follows the codebase's
own resilience convention (kev.py: live feed -> cached snapshot; retriever.py:
dense -> BM25; agent.py: LLM -> template): structured stdlib logging + a
thread-safe in-memory counter registry + a best-effort webhook alert that is
a total no-op when unconfigured. Every function here degrades to "just a log
line" rather than raising -- instrumentation must never be the reason the
app breaks.

Env vars:
  LOG_LEVEL           default INFO
  LOG_FORMAT          "json" or "text" (default text)
  ALERT_WEBHOOK_URL   optional Slack-compatible incoming webhook. When unset,
                      alert() still logs at WARNING/ERROR -- just doesn't ship
                      anywhere -- so alerting degrades to "check the logs",
                      never to silence.

What gets instrumented (see call sites): CISA KEV live-vs-cached fetch,
dense-retrieval availability, every LLM call (grade/generate) success vs
failure, citation-verification failures, and the per-run narrative
generation_mode mix (llm_grounded vs template_fallback). Read the current
counts with metrics.snapshot(); App.py's "About This System" tab renders
them so a degraded run is visible in the UI, not just in logs.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger("risk_engine")

_configured = False
_configure_lock = threading.Lock()


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extra = getattr(record, "context", None)
        if extra:
            payload["context"] = extra
        return json.dumps(payload, default=str)


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    """Idempotent: safe to call from App.py, every script's main(), and
    tests without producing duplicate handlers on repeated Streamlit reruns
    or repeated test-session imports."""
    global _configured
    with _configure_lock:
        if _configured:
            return
        level_name = (level or os.getenv("LOG_LEVEL") or "INFO").upper()
        format_kind = (fmt or os.getenv("LOG_FORMAT") or "text").lower()

        handler = logging.StreamHandler()
        if format_kind == "json":
            handler.setFormatter(_JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            ))

        root = logging.getLogger()
        root.setLevel(getattr(logging, level_name, logging.INFO))
        root.handlers = [handler]
        _configured = True
        log.info("logging configured (level=%s, format=%s)", level_name, format_kind)


class Metrics:
    """Thread-safe in-memory counters, labeled like a minimal Prometheus
    counter. Process-lifetime only -- there is no persistence or aggregation
    across restarts/instances by design; that's what a real metrics backend
    is for. Good enough to answer "is this run degraded" from inside the app
    or the logs, which is the actual gap being closed here."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> tuple[str, tuple[tuple[str, str], ...]]:
        return name, tuple(sorted(labels.items()))

    def increment(self, name: str, value: int = 1, **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def get(self, name: str, **labels: str) -> int:
        with self._lock:
            return self._counters.get(self._key(name, labels), 0)

    def snapshot(self) -> dict[str, Any]:
        """{"metric_name": {"label=val,...": count, "total": N}, ...}"""
        out: dict[str, Any] = {}
        with self._lock:
            items = dict(self._counters)
        for (name, labels), count in items.items():
            bucket = out.setdefault(name, {"total": 0})
            bucket["total"] += count
            if labels:
                label_key = ",".join(f"{k}={v}" for k, v in labels)
                bucket[label_key] = count
        return out

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


metrics = Metrics()


def alert(event: str, message: str, severity: str = "warning", **context: Any) -> None:
    """Best-effort operational alert. Always logs; also posts to
    ALERT_WEBHOOK_URL (a Slack-compatible incoming webhook) if configured.
    Never raises -- a broken alert channel must not break the request that
    triggered the alert."""
    level = logging.ERROR if severity == "error" else logging.WARNING
    log.log(level, "[ALERT:%s] %s", event, message, extra={"context": context})

    webhook = os.getenv("ALERT_WEBHOOK_URL")
    if not webhook:
        return
    try:
        import requests
        text = f":rotating_light: *{event}* ({severity}) — {message}"
        if context:
            text += "\n" + "\n".join(f"• {k}: {v}" for k, v in context.items())
        requests.post(webhook, json={"text": text}, timeout=5)
    except Exception as exc:  # noqa: BLE001 - alerting must never raise
        log.warning("alert webhook delivery failed (%s): %s", event, exc)


def check_fallback_rate(mode_counts: dict[str, int], threshold: float = 0.5) -> None:
    """Call once per batch of generated cards (App.py, run_stage5.py) with
    e.g. {"llm_grounded": 2, "template_fallback": 3}. Fires an alert when the
    template-fallback share crosses `threshold` -- the signal that the LLM
    path is effectively down for this run, not just that one card happened
    to fall back."""
    total = sum(mode_counts.values())
    if not total:
        return
    fallback = mode_counts.get("template_fallback", 0)
    rate = fallback / total
    metrics.increment("narration_batch", mode="mixed" if 0 < fallback < total else
                       ("all_fallback" if fallback == total else "all_llm_grounded"))
    if rate >= threshold:
        alert(
            "narration_fallback_rate_high",
            f"{fallback}/{total} risk cards fell back to the deterministic template "
            f"({rate:.0%} >= {threshold:.0%} threshold) -- LLM path is likely unavailable.",
            severity="error" if rate == 1.0 else "warning",
            fallback=fallback, total=total, rate=round(rate, 3),
        )


def timed(metric_name: str, **labels: str):
    """Decorator: records call duration (ms) and success/failure count under
    `metric_name`. Duration isn't exposed as a proper histogram (no metrics
    backend to bucket it) -- logged at DEBUG for now, which is enough to spot
    a slow endpoint in the logs without pulling in a metrics library."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                result = fn(*args, **kwargs)
            except Exception:
                metrics.increment(metric_name, status="error", **labels)
                raise
            else:
                metrics.increment(metric_name, status="success", **labels)
                return result
            finally:
                elapsed_ms = (time.monotonic() - start) * 1000
                log.debug("%s took %.1fms", metric_name, elapsed_ms)
        return wrapper
    return decorator
