"""Shared fixtures for the risk_engine test suite.

Session-scoped because the underlying data is read-only for the duration of
a test run and rebuilding it per-test (pandas joins + NIST chunk loading)
would make the suite noticeably slower for no benefit. Nothing here talks to
an LLM and the retriever is built WITHOUT a persist_dir (see `retriever`
below) specifically so the suite never needs chromadb/sentence-transformers
model downloads or an embedding model load -- BM25-only mode is sufficient
to test retrieval behaviour and keeps CI fast and offline-safe.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.llm import LLMClient
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.retriever import NISTRetriever
from risk_engine.score import load_config, rank_top_risks, score_findings


@pytest.fixture(scope="session")
def datasets():
    return load_datasets(ROOT / "data" / "raw")


@pytest.fixture(scope="session")
def kev_catalog():
    catalog, _source = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    return catalog


@pytest.fixture(scope="session")
def cfg():
    return load_config(ROOT / "config" / "weights.yaml")


@pytest.fixture(scope="session")
def master(datasets, kev_catalog):
    return build_master_table(datasets, kev_index(kev_catalog))


@pytest.fixture(scope="session")
def scored(master, cfg):
    return score_findings(master, cfg)


@pytest.fixture(scope="session")
def top5(scored, cfg, datasets):
    return rank_top_risks(scored, cfg, report_md=datasets.threat_report_md)


@pytest.fixture(scope="session")
def nist_chunks():
    return load_or_build_chunks(
        ROOT / "data" / "external" / "nist_oscal_snapshot.json",
        ROOT / "data" / "external" / "nist_chunks.json",
    )


@pytest.fixture(scope="session")
def retriever(nist_chunks):
    # No persist_dir -> BM25-only; see module docstring.
    return NISTRetriever(nist_chunks)


@pytest.fixture(scope="session")
def known_actors(datasets):
    return set(datasets.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}


class MockLLM(LLMClient):
    """Deterministic stand-in for LLMClient — no network, no API key.
    Dispatches on a fragment of the system prompt so one mock can serve all
    three call sites (grade / generate / vocab-expansion) in agent.py."""

    def __init__(self, grade_reply=None, generate_reply=None, vocab_reply=None):
        super().__init__(api_key="mock")
        self.grade_reply = grade_reply
        self.generate_reply = generate_reply
        self.vocab_reply = vocab_reply or (lambda user: "")
        self.calls: list[str] = []

    def chat(self, system, user, max_tokens=900):
        if "Respond ONLY with JSON" in system:
            kind = "grade"
        elif "vocabulary lookup" in system:
            kind = "vocab"
        else:
            kind = "generate"
        self.calls.append(kind)
        if kind == "grade":
            return self.grade_reply(user)
        if kind == "vocab":
            return self.vocab_reply(user)
        return self.generate_reply(user)


@pytest.fixture
def mock_llm_factory():
    return MockLLM


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Every test starts with a clean metrics registry so assertions about
    counts are never order-dependent on which other tests ran first."""
    from risk_engine.observability import metrics
    metrics.reset()
    yield
    metrics.reset()
