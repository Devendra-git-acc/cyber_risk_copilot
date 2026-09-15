"""Unit tests for the logging/metrics/alerting module added for production
observability: counters, the fallback-rate alert threshold, and that
configure_logging() is safe to call repeatedly (App.py calls it at import
time; every script's main() calls it too)."""
from __future__ import annotations

import json
import logging

from risk_engine import observability
from risk_engine.observability import (
    Metrics,
    _JsonFormatter,
    check_fallback_rate,
    configure_logging,
)


def test_metrics_increment_and_get():
    m = Metrics()
    m.increment("kev_fetch", source="live")
    m.increment("kev_fetch", source="live")
    m.increment("kev_fetch", source="cached")
    assert m.get("kev_fetch", source="live") == 2
    assert m.get("kev_fetch", source="cached") == 1
    assert m.get("kev_fetch", source="never_seen") == 0


def test_metrics_snapshot_totals_and_labels():
    m = Metrics()
    m.increment("card_generated", mode="llm_grounded")
    m.increment("card_generated", mode="llm_grounded")
    m.increment("card_generated", mode="template_fallback")
    snap = m.snapshot()
    assert snap["card_generated"]["total"] == 3
    assert snap["card_generated"]["mode=llm_grounded"] == 2
    assert snap["card_generated"]["mode=template_fallback"] == 1


def test_metrics_reset_clears_counters():
    m = Metrics()
    m.increment("x")
    m.reset()
    assert m.snapshot() == {}


def test_check_fallback_rate_alerts_above_threshold(monkeypatch):
    calls = []
    monkeypatch.setattr(observability, "alert",
                        lambda event, message, **kw: calls.append((event, message, kw)))
    check_fallback_rate({"llm_grounded": 1, "template_fallback": 4}, threshold=0.5)
    assert len(calls) == 1
    assert calls[0][0] == "narration_fallback_rate_high"


def test_check_fallback_rate_silent_below_threshold(monkeypatch):
    calls = []
    monkeypatch.setattr(observability, "alert",
                        lambda event, message, **kw: calls.append((event, message, kw)))
    check_fallback_rate({"llm_grounded": 4, "template_fallback": 1}, threshold=0.5)
    assert calls == []


def test_check_fallback_rate_handles_empty_batch(monkeypatch):
    calls = []
    monkeypatch.setattr(observability, "alert",
                        lambda event, message, **kw: calls.append((event, message, kw)))
    check_fallback_rate({}, threshold=0.5)
    assert calls == []


def test_configure_logging_is_idempotent():
    configure_logging()
    handlers_after_first = list(logging.getLogger().handlers)
    configure_logging()
    handlers_after_second = list(logging.getLogger().handlers)
    assert len(handlers_after_first) == len(handlers_after_second) == 1


def test_json_formatter_produces_valid_json():
    record = logging.LogRecord(
        name="risk_engine.test", level=logging.WARNING, pathname=__file__,
        lineno=1, msg="something degraded", args=(), exc_info=None,
    )
    record.context = {"reason": "test"}
    formatted = _JsonFormatter().format(record)
    payload = json.loads(formatted)
    assert payload["level"] == "WARNING"
    assert payload["message"] == "something degraded"
    assert payload["context"] == {"reason": "test"}


def test_alert_never_raises_without_webhook_configured(monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    observability.alert("test_event", "just checking it doesn't raise", foo="bar")
