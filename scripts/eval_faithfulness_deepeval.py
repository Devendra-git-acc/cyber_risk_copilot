"""Tier 2 evaluation: DeepEval faithfulness scoring, LLM-as-judge.

Genuinely deeper than Tier 1 (scripts/eval_output_quality.py) -- an LLM judge
checks whether every claim in the narrative is actually supported by the
context the model was given, rather than the pattern-matching Tier 1 does.
Costs real money: one extra LLM call per card to do the judging, on top of
what generating the card already costs. Deliberately separate from the main
pipeline and from Tier 1 -- run this on purpose, not on every invocation.

Uses DeepEval, not RAGAS. RAGAS was tried first and is the more commonly
cited "standard" framework -- but installing it in this project's actual
environment produces a real, reproducible conflict: ragas's own import chain
pulls in a langchain_community submodule (chat_models.vertexai) that no
longer exists in current langchain_community releases, and forcing an older
langchain_community back in to work around it breaks langchain-core's
version far enough to conflict with langgraph itself. This isn't a
hypothetical -- it was actually installed and reproduced. DeepEval installs
cleanly alongside this project's real dependencies (verified: this
project's own test suite still passes with it installed) and its
FaithfulnessMetric covers the same ground.

Requires a configured LLM key (used both to generate the cards AND to judge
them) plus: pip install -r requirements-eval.txt

Run: python3 scripts/eval_faithfulness_deepeval.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.agent import build_agent, narrate_risk
from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.llm import LLMClient
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.retriever import NISTRetriever
from risk_engine.score import load_config, rank_top_risks, score_findings

FAITHFULNESS_THRESHOLD = 0.8  # below this, print the judge's reasoning


def _evidence_context(risk: dict) -> str:
    """The evidence bundle is ALSO ground truth the model was given -- not
    just the retrieved NIST text. The judge must see both, or it will
    wrongly flag legitimately-grounded claims (the CVSS figure, the business
    service name) as unsupported, since they don't appear in the NIST
    control text itself."""
    t, s, a, f = (risk["threat_context"], risk["business_service"],
                  risk["asset"], risk["finding"])
    return (
        f"Risk evidence for {risk['cve']} ({risk['vulnerability_name']}): "
        f"CVSS {risk['cvss']}, computed risk score {risk['risk_score']}. "
        f"Asset: {a['asset_name']} ({a['asset_type']}), internet-exposed: "
        f"{a['internet_exposed']}, EDR missing: {a['edr_missing']}. "
        f"Business service: {s['name']} (revenue impact {s['revenue_impact']}, "
        f"compliance {s['compliance_scope']}, {s['dependents']} dependent "
        f"service(s)). Threat: actor(s) {t['ti_actors'] or 'none'}, "
        f"maturity {t['ti_maturity']}, ransomware-linked {t['ransomware_linked']}, "
        f"in CISA KEV: {t['in_kev']}. Patch available: {f['patch_available']}, "
        f"days open: {f['days_open']}."
    )


def main() -> None:
    llm = LLMClient()
    if not llm.configured:
        sys.exit("No LLM key configured -- this needs one both to generate "
                 "the narratives and to judge them. Set OPENAI_API_KEY or "
                 "LLM_API_KEY first.")

    try:
        from deepeval.metrics import FaithfulnessMetric
        from deepeval.models import OpenAIModel
        from deepeval.test_case import LLMTestCase
    except ImportError as exc:
        sys.exit(f"missing dependency ({exc}). "
                 f"Run: pip install -r requirements.txt")

    ds = load_datasets(ROOT / "data" / "raw")
    kev_catalog, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev_catalog))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    top5 = rank_top_risks(score_findings(master, cfg), cfg,
                          report_md=ds.threat_report_md)
    chunks = load_or_build_chunks(ROOT / "data" / "external" / "nist_oscal_snapshot.json",
                                  ROOT / "data" / "external" / "nist_chunks.json")
    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    known_actors = set(ds.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}
    agent = build_agent(retriever, ds.remediation_hints, llm, known_actors=known_actors)

    # Judge model deliberately independent of the generator: a model grading
    # its own output is weak evidence (it's biased toward finding its own
    # claims acceptable). DEEPEVAL_JUDGE_MODEL lets you point the judge at a
    # different/stronger model on the same OpenAI-compatible endpoint (same
    # api_key/base_url as LLMClient -- just a different model string), e.g.
    # generate with gpt-4o-mini, judge with gpt-4o. Falls back to the
    # generator's own model only if you haven't set one, with a loud warning
    # since that's the weaker, self-judging setup.
    judge_model = os.getenv("DEEPEVAL_JUDGE_MODEL") or llm.model
    if judge_model == llm.model:
        print(f"WARNING: DEEPEVAL_JUDGE_MODEL not set -- judging with the same "
              f"model that generated the cards ({llm.model}). This is weaker "
              f"evidence (self-judging bias). Set DEEPEVAL_JUDGE_MODEL to a "
              f"different/stronger model for a real independent check.\n")
    judge = OpenAIModel(model=judge_model, api_key=llm.api_key, base_url=llm.base_url)
    metric = FaithfulnessMetric(threshold=FAITHFULNESS_THRESHOLD, model=judge)

    print(f"DeepEval faithfulness evaluation (generator={llm.model}, judge={judge_model})\n")
    scores: list[float] = []
    for risk in top5:
        card = narrate_risk(agent, risk)
        if card["generation_mode"] != "llm_grounded":
            print(f"#{risk['rank']} {risk['cve']}: skipped (template_fallback -- "
                 f"nothing generative to judge)")
            continue

        contexts = [_evidence_context(risk)] + [
            f"[{c['control_id']}] {c['title']}: {c['statement']} {c['guidance']}"
            for c in card["retrieved_controls"]
        ]
        test_case = LLMTestCase(
            input=f"Why does {risk['vulnerability_name']} rank as a top risk, "
                 f"and what should be done about it?",
            actual_output=card["narrative_md"],
            retrieval_context=contexts,
        )
        score = metric.measure(test_case)
        scores.append(score)
        flag = "" if score >= FAITHFULNESS_THRESHOLD else "  <-- below threshold"
        print(f"#{risk['rank']} {risk['cve']}: faithfulness = {score:.2f}{flag}")
        if score < FAITHFULNESS_THRESHOLD:
            print(f"    judge's reasoning: {metric.reason}")

    if scores:
        avg = sum(scores) / len(scores)
        print(f"\naverage faithfulness across {len(scores)} llm_grounded card(s): "
             f"{avg:.2f}")
    else:
        print("\nno llm_grounded cards to judge -- nothing scored")


if __name__ == "__main__":
    main()