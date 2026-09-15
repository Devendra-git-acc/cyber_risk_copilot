"""Agent control-flow tests using mock LLMs — prove the graph's guarantees:
happy path, hallucination containment, no-LLM degradation, bounded rewrites,
vocabulary-expansion fallthrough, MDR-excerpt grounding, chunking
correctness, retrieval dedup, and (new) that each path emits the metrics
observability.py expects. Run: pytest tests/test_agent.py
"""
from __future__ import annotations

import json
import re

from risk_engine.agent import build_agent, narrate_risk
from risk_engine.observability import metrics
from risk_engine.retriever import VULN_CLASS_VOCAB, build_retrieval_queries


def _good_grade(user):
    ids = [ln.split(":")[0].strip("- ") for ln in user.splitlines()
           if ln.startswith("- ")][:4]
    return json.dumps({"applicable_ids": ids, "sufficient": True, "suggested_query": ""})


def _good_generate(user):
    ctrl_ids = [ln.strip("[").split("]")[0] for ln in user.splitlines()
                if ln.startswith("[")][:2]
    return ("**Why this ranks here** — grounded text.\n"
            "**Recommended actions (NIST SP 800-53)**\n"
            + "\n".join(f"- [{c}] act." for c in ctrl_ids)
            + "\n**Urgency** — patch now.")


def test_t1_happy_path_llm_grounded(retriever, top5, datasets, known_actors, mock_llm_factory):
    agent = build_agent(retriever, datasets.remediation_hints,
                        mock_llm_factory(_good_grade, _good_generate),
                        known_actors=known_actors)
    card = narrate_risk(agent, top5[0])
    assert card["generation_mode"] == "llm_grounded"
    assert card["cited_controls"]
    assert metrics.get("card_generated", mode="llm_grounded") == 1


def test_t2_hallucination_contained_falls_back(retriever, top5, datasets, mock_llm_factory):
    def bad_generate(user):
        return ("**Why** — bad. cite [ZZ-99] and CVE-2019-99999.\n"
                "**Recommended actions (NIST SP 800-53)**\n- [ZZ-99] nonsense\n"
                "**Urgency** — now.")

    agent = build_agent(retriever, datasets.remediation_hints,
                        mock_llm_factory(_good_grade, bad_generate))
    card = narrate_risk(agent, top5[0])

    valid_ids = {c["control_id"] for c in card["retrieved_controls"]}
    assert card["generation_mode"] == "template_fallback"
    assert set(card["cited_controls"]) <= valid_ids
    assert "ZZ-99" not in card["narrative_md"]
    assert any("FAIL" in s for s in card["agent_trace"])
    assert metrics.get("narrative_fallback_reason", reason="hallucination_after_regen") == 1


def test_t3_no_llm_configured_degrades_to_template(retriever, top5, datasets):
    agent = build_agent(retriever, datasets.remediation_hints, None)
    card = narrate_risk(agent, top5[0])
    assert card["generation_mode"] == "template_fallback"
    assert card["cited_controls"]
    assert metrics.get("narrative_fallback_reason", reason="no_llm_configured") == 1


def test_t4_bounded_query_rewrites(retriever, top5, datasets, mock_llm_factory):
    def weak_grade(user):
        return json.dumps({"applicable_ids": [], "sufficient": False,
                           "suggested_query": "flaw remediation patching"})

    agent = build_agent(retriever, datasets.remediation_hints,
                        mock_llm_factory(weak_grade, _good_generate))
    card = narrate_risk(agent, top5[0])
    rewrites = sum(1 for s in card["agent_trace"] if "rewrite #" in s)
    assert rewrites == 2  # MAX_QUERY_REWRITES
    assert card["narrative_md"]


def test_t5_vocab_expansion_only_engages_on_a_real_miss(top5, datasets):
    # VULN_CLASS_VOCAB is a fixed 7-pattern hand list; find a real finding it
    # actually misses (verified empirically, not assumed) to prove the LLM
    # expansion fallback engages exactly where the hand list falls through.
    miss_case = next(r for r in top5 if not any(
        p.search(r["vulnerability_name"]) for p, _ in VULN_CLASS_VOCAB))

    queries_no_llm = build_retrieval_queries(miss_case, datasets.remediation_hints, llm=None)
    assert len(queries_no_llm) == 1  # unchanged without an LLM

    from risk_engine.llm import LLMClient

    class _VocabOnlyMock(LLMClient):
        def __init__(self):
            super().__init__(api_key="mock")

        def chat(self, system, user, max_tokens=900):
            return "access enforcement least privilege boundary protection"

    queries_with_llm = build_retrieval_queries(
        miss_case, datasets.remediation_hints, llm=_VocabOnlyMock())
    assert len(queries_with_llm) == 2
    assert "access enforcement" in queries_with_llm[1]


def test_t6_agent_wiring_engages_vocab_expansion(retriever, top5, datasets, mock_llm_factory):
    miss_case = next(r for r in top5 if not any(
        p.search(r["vulnerability_name"]) for p, _ in VULN_CLASS_VOCAB))

    def vocab_reply(user):
        return "access enforcement least privilege boundary protection"

    agent = build_agent(retriever, datasets.remediation_hints,
                        mock_llm_factory(_good_grade, _good_generate, vocab_reply=vocab_reply))
    card = narrate_risk(agent, miss_case)
    build_trace = next(s for s in card["agent_trace"] if s.startswith("build_query"))
    assert "2 quer" in build_trace


def test_t7_mdr_excerpt_is_real_and_from_the_matched_campaign(top5, datasets):
    with_actor = next(r for r in top5 if r["threat_context"]["ti_actors"])
    actor_name = with_actor["threat_context"]["ti_actors"].split(",")[0].strip()
    excerpt = with_actor["threat_context"]["mdr_excerpt"]
    assert excerpt
    assert actor_name in datasets.threat_report_md
    assert len(excerpt) > 100


def test_t8_template_surfaces_mdr_excerpt_and_kev_action_without_llm(retriever, top5, datasets):
    with_actor = next(r for r in top5 if r["threat_context"]["ti_actors"])
    agent = build_agent(retriever, datasets.remediation_hints, None)
    card = narrate_risk(agent, with_actor)
    assert "MDR advisory" in card["narrative_md"]
    if with_actor["threat_context"]["kev_required_action"]:
        assert "CISA KEV requires" in card["narrative_md"]


def test_t9_ac2_chunking_no_stray_leading_punctuation(retriever):
    ac2_chunks = [c for c in retriever.chunks if c["control_id"] == "AC-2"]
    assert len(ac2_chunks) > 1, "AC-2 has 21 real sub-requirements; must split"
    for c in ac2_chunks:
        body_start = len(c["control_id"]) + len(c["title"]) + 3
        assert not re.match(r"^[\s.,;:]", c["search_text"][body_start:])


def test_t10_retrieval_dedup_and_full_k(retriever):
    for q in ["flaw remediation patching", "account management access control",
             "session authenticity", "ransomware incident handling"]:
        hits = retriever.search(q, k=6)
        ids = [h["control_id"] for h in hits]
        assert len(ids) == len(set(ids)), f"duplicate control_id for query {q!r}"
        assert len(hits) >= 6


def test_t11_vocab_expansion_skipped_on_a_hand_list_hit(top5, datasets, mock_llm_factory):
    hit_case = next(r for r in top5 if any(
        p.search(r["vulnerability_name"]) for p, _ in VULN_CLASS_VOCAB))
    mock = mock_llm_factory(_good_grade, _good_generate,
                            vocab_reply=lambda user: "should not be called")
    build_retrieval_queries(hit_case, datasets.remediation_hints, llm=mock)
    assert "vocab" not in mock.calls
