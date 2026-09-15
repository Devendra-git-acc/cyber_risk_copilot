"""Tier 1 evaluation: cheap, deterministic checks on generated risk cards.

No extra LLM calls -- pure checks against the actual generated text, so this
can run on every pipeline execution for free. Every check here targets an
issue we ACTUALLY found by manually reading real traces this project, not a
hypothetical one:

- Uncited bullets: found twice in real live-LLM runs (the model adding a
  generic closing bullet with no [control-id]).
- CVSS-led opening: found in 2 of 5 real traces ("poses a critical risk due
  to its high CVSS score...") despite the prompt explicitly forbidding it --
  tracked as a rate here, not hard-failed, since it's a documented, accepted
  soft limitation, not a blocking defect.
- Invented numbers/entities: not yet observed in this project, but a known
  LLM failure mode worth guarding against regardless.

Run: python3 scripts/eval_output_quality.py
"""
from __future__ import annotations

import json
import re
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

WORD_BUDGET = 230
WORD_BUDGET_TOLERANCE = 30  # the prompt asks for <=230; LLMs don't hit it exactly
_CITATION = re.compile(r"\[([A-Z]{2}-\d+(?:\.\d+)?)\]")
_NUMBER = re.compile(r"\b\d+\.\d\b")  # X.X pattern: could be CVSS or risk_score
_DAYS = re.compile(r"\b(\d+)\s+days?\b")


def _known_actors(ds) -> set[str]:
    return set(ds.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}


def check_card(card: dict, risk: dict, all_actors: set[str]) -> dict:
    text = card["narrative_md"]
    issues: list[str] = []

    # ---- format compliance ------------------------------------------------
    has_why = "**Why this ranks here**" in text
    has_actions = "**Recommended actions" in text
    has_urgency = "**Urgency**" in text
    if not (has_why and has_actions and has_urgency):
        missing = [n for n, ok in [("Why", has_why), ("Actions", has_actions),
                                   ("Urgency", has_urgency)] if not ok]
        issues.append(f"missing section(s): {missing}")

    # ---- every bullet cites a control --------------------------------------
    # Independent of whether Urgency is present -- if it's missing, fall back
    # to "everything after Recommended actions" so a missing-section issue
    # never silently hides an uncited-bullet issue in the same card (a real
    # bug caught in testing: a card missing BOTH only reported the missing
    # section, since bullet extraction required Urgency to bound the block).
    actions_block = text.split("**Recommended actions")[-1] if has_actions else ""
    if has_urgency:
        actions_block = actions_block.split("**Urgency**")[0]
    bullets = [ln for ln in actions_block.splitlines() if ln.strip().startswith("-")]
    uncited = [b.strip() for b in bullets if not _CITATION.search(b)]
    if uncited:
        issues.append(f"{len(uncited)}/{len(bullets)} bullet(s) have no [control-id] "
                      f"citation: {uncited[0][:70]}...")

    # ---- word budget -------------------------------------------------------
    word_count = len(text.split())
    over_budget = word_count > WORD_BUDGET + WORD_BUDGET_TOLERANCE
    if over_budget:
        issues.append(f"{word_count} words, over the {WORD_BUDGET}-word target "
                      f"by more than the {WORD_BUDGET_TOLERANCE}-word tolerance")

    # ---- numeric grounding: every X.X figure must be CVSS or risk_score ----
    # Scoped to the Why/Urgency sections only -- the model actually reasons
    # about this risk's own metrics there. The threat-actor-background
    # section is sourced MDR text about the actor's broader history and can
    # legitimately contain an X.X-shaped figure that isn't a risk metric at
    # all (caught in testing: "LockBit 3.0" is a real ransomware variant
    # name, not a hallucinated score -- checking it would be a false
    # positive, not a real finding). Citation brackets are stripped too,
    # since a control ID like [AC-3.3] also isn't a claimed figure.
    why_section = text.split("**Why this ranks here**")[-1].split(
        "**Threat actor background")[0].split("**Recommended actions")[0] if has_why else ""
    urgency_section = text.split("**Urgency**")[-1] if has_urgency else ""
    scored_text = _CITATION.sub("", why_section + " " + urgency_section)
    valid_numbers = {round(float(risk["cvss"]), 1), round(float(risk["risk_score"]), 1)}
    found_numbers = {float(n) for n in _NUMBER.findall(scored_text)}
    unexplained_numbers = found_numbers - valid_numbers
    if unexplained_numbers:
        issues.append(f"number(s) not matching CVSS ({risk['cvss']}) or risk "
                      f"score ({risk['risk_score']}): {unexplained_numbers}")

    # ---- days_open grounding ------------------------------------------------
    # Anchored to "open" appearing near the day-count, not just any "N days"
    # mention -- our own template and GENERATE_SYSTEM prompt both phrase
    # this concept as "open N days" specifically. Without this anchor,
    # legitimate content the prompt explicitly asks the model to include
    # (threat-actor dwell time, e.g. "average dwell time of 4-6 days") reads
    # as a false claim about this finding's own timeline -- confirmed as a
    # real false positive from an actual run, not a hypothetical.
    text_no_citations = _CITATION.sub("", text)
    bad_days: set[int] = set()
    snippets = []
    for m in _DAYS.finditer(text_no_citations):
        window = text_no_citations[max(0, m.start() - 25):m.end() + 25]
        if not re.search(r"\bopen\b", window, re.IGNORECASE):
            continue  # not shaped like a days_open claim at all
        n = int(m.group(1))
        if n != risk["finding"]["days_open"]:
            bad_days.add(n)
            start = max(0, m.start() - 40)
            snippets.append(f"...{text_no_citations[start:m.end() + 15].strip()}...")
    if bad_days:
        issues.append(f"'N days' figure(s) near 'open' not matching days_open="
                      f"{risk['finding']['days_open']}: {bad_days} "
                      f"(context: {' | '.join(snippets)})")

    # ---- entity grounding: no OTHER threat actor mentioned -------------------
    this_risk_actors = {a.strip() for a in risk["threat_context"]["ti_actors"].split(",")
                        if a.strip()}
    other_actors_mentioned = {a for a in all_actors - this_risk_actors if a in text}
    if other_actors_mentioned:
        issues.append(f"mentions threat actor(s) not linked to this risk: "
                      f"{other_actors_mentioned}")

    # ---- CVSS-led opening: tracked as a rate, not a hard failure -------------
    why_block = text.split("**Why this ranks here**")[-1][:150] if has_why else ""
    cvss_led = bool(re.search(r"cvss", why_block, re.IGNORECASE))

    return {
        "rank": risk["rank"], "cve": risk["cve"], "mode": card["generation_mode"],
        "word_count": word_count, "cvss_led_opening": cvss_led,
        "issues": issues, "passed": not issues,
        # Saved specifically so a FAIL can be read and judged afterward --
        # without this, diagnosing a flagged card meant re-running the whole
        # pipeline (and paying for new LLM calls) just to see what it said.
        "narrative_md": text,
    }


def main() -> None:
    ds = load_datasets(ROOT / "data" / "raw")
    kev, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    top5 = rank_top_risks(score_findings(master, cfg), cfg, report_md=ds.threat_report_md)
    chunks = load_or_build_chunks(ROOT / "data" / "external" / "nist_oscal_snapshot.json",
                                  ROOT / "data" / "external" / "nist_chunks.json")
    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    llm = LLMClient()
    all_actors = _known_actors(ds)
    agent = build_agent(retriever, ds.remediation_hints, llm, known_actors=all_actors)

    print(f"TIER 1 OUTPUT-QUALITY EVAL ({'llm_grounded expected' if llm.configured else 'template_fallback expected, no key configured'})\n")

    results = [check_card(narrate_risk(agent, r), r, all_actors) for r in top5]

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"[{status}] #{r['rank']} {r['cve']} ({r['mode']}, {r['word_count']} words"
             f"{', CVSS-led opening' if r['cvss_led_opening'] else ''})")
        for issue in r["issues"]:
            print(f"    - {issue}")

    n = len(results)
    passed = sum(1 for r in results if r["passed"])
    cvss_led_rate = sum(1 for r in results if r["cvss_led_opening"]) / n
    avg_words = sum(r["word_count"] for r in results) / n
    print(f"\n{passed}/{n} cards passed all hard checks")
    print(f"CVSS-led-opening rate: {cvss_led_rate:.0%} (tracked, not blocking -- "
         f"documented known limitation)")
    print(f"average word count: {avg_words:.0f} (target <= {WORD_BUDGET})")

    (ROOT / "outputs").mkdir(exist_ok=True)
    (ROOT / "outputs" / "eval_tier1.json").write_text(json.dumps({
        "results": results, "passed": passed, "total": n,
        "cvss_led_rate": cvss_led_rate, "avg_word_count": avg_words,
    }, indent=2, default=str))

    if passed < n:
        sys.exit(1)


if __name__ == "__main__":
    main()