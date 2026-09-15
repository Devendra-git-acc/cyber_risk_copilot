"""Unit tests for hybrid retrieval: tokenization, RRF fusion math, and
vulnerability-class query construction. Uses the session `retriever` fixture
(BM25-only, no network/model download — see conftest.py)."""
from __future__ import annotations

from risk_engine.retriever import VULN_CLASS_VOCAB, NISTRetriever, _tokenize


def test_tokenize_drops_stopwords_but_keeps_content_words():
    tokens = _tokenize("the system shall enforce approved authorizations for logical access")
    assert "the" not in tokens
    assert "for" not in tokens
    assert "system" not in tokens  # "system" is in the embedded stopword list
    assert "shall" in tokens  # content word, not filtered


def test_tokenize_stems_common_suffixes():
    tokens = _tokenize("authorizations enforcement")
    # "authorizations" -stems-> "authorization"/"authoriz"; "enforcement" -> "enforc"/"enforce"
    assert any(t.startswith("authoriz") for t in tokens)
    assert any(t.startswith("enforc") for t in tokens)


def test_tokenize_drops_very_short_tokens():
    tokens = _tokenize("an id is ok")
    assert "id" not in tokens  # len<=2 filtered
    assert "ok" not in tokens


def test_rrf_favors_items_ranked_highly_across_multiple_lists():
    # idx 0 is #1 in both lists; idx 1 is #1 in one list only -> 0 must outrank 1.
    fused = NISTRetriever._rrf([[0, 1, 2], [0, 2, 1]])
    order = [idx for idx, _score in fused]
    assert order[0] == 0


def test_search_returns_no_duplicate_controls_and_respects_k(retriever):
    hits = retriever.search("flaw remediation security patches", k=5)
    ids = [h["control_id"] for h in hits]
    assert len(ids) == len(set(ids))
    assert len(hits) <= 5


def test_search_multi_matches_search_with_single_query(retriever):
    single = retriever.search("account management", k=4)
    multi = retriever.search_multi(["account management"], k=4)
    assert [h["control_id"] for h in single] == [h["control_id"] for h in multi]


def test_vuln_class_vocab_matches_known_idor_phrasing():
    pattern, vocab = VULN_CLASS_VOCAB[0]
    assert pattern.search("Insecure Direct Object Reference in Payment API")
    assert "authoriz" in vocab


def test_retriever_reports_a_mode_string(retriever):
    assert retriever.mode in (
        "BM25-only (lexical)",
        "hybrid (BM25 + dense, RRF-fused)",
    )
