"""Best-case / worst-case scenario matrix for the agent — exercises every
guarantee in agent.py's docstring and gives each run a distinct, labelled
trace in LangSmith (if LANGSMITH_TRACING=true) so you can see what a happy
path, a caught hallucination, a no-LLM fallback, and a bounded rewrite loop
actually look like in the run tree, side by side.

Run: python scripts/run_eval_scenarios.py
Then open smith.langchain.com -> project (see .env) -> filter by tag
"eval" to see just these six runs, or by "best-case"/"worst-case".

This does not replace tests/test_agent.py (which asserts pass/fail in CI
without needing network access or a LangSmith account) — it's the same
scenarios, run for real against the live agent, for visual trace inspection
and ad-hoc evaluation.
"""
from __future__ import annotations

import copy
import json
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


class MockLLM(LLMClient):
    """Same shape as tests/test_agent.py's MockLLM: scripted replies instead
    of a real API call. Overriding chat() means these calls are NOT traced by
    llm.py's @traceable (there is no real HTTP call to trace) — only the
    graph nodes (build_query/retrieve/grade/generate/verify) show up for
    these scenarios, which is enough to see the control-flow shape."""

    def __init__(self, grade_reply=None, generate_reply=None):
        super().__init__(api_key="mock")
        self.grade_reply = grade_reply
        self.generate_reply = generate_reply

    def chat(self, system, user, max_tokens=900):
        kind = "grade" if "Respond ONLY with JSON" in system else "generate"
        return self.grade_reply(user) if kind == "grade" else self.generate_reply(user)


def good_grade(user: str) -> str:
    ids = [ln.split(":")[0].strip("- ") for ln in user.splitlines()
           if ln.startswith("- ")][:4]
    return json.dumps({"applicable_ids": ids, "sufficient": True, "suggested_query": ""})


def good_generate(user: str) -> str:
    ctrl_ids = [ln.strip("[").split("]")[0] for ln in user.splitlines()
                if ln.startswith("[")][:2]
    return ("**Why this ranks here** — grounded text.\n"
            "**Recommended actions (NIST SP 800-53)**\n"
            + "\n".join(f"- [{c}] act." for c in ctrl_ids)
            + "\n**Urgency** — patch now.")


def bad_generate(user: str) -> str:
    """A hallucinating LLM: invents a control ID and a foreign CVE."""
    return ("**Why** — bad. cite [ZZ-99] and CVE-2019-99999.\n"
            "**Recommended actions (NIST SP 800-53)**\n- [ZZ-99] nonsense\n"
            "**Urgency** — now.")


def weak_grade(user: str) -> str:
    """Never satisfied -> forces the query-rewrite loop to its bound."""
    return json.dumps({"applicable_ids": [], "sufficient": False,
                       "suggested_query": "flaw remediation patching"})


def weaken_evidence(risk: dict) -> dict:
    """Strip every aggravating signal from a real risk so the scorer/agent
    see a low-likelihood, low-impact story instead — the 'quiet' worst case
    that isn't a bug, just a genuinely boring finding."""
    r = copy.deepcopy(risk)
    r["asset"]["internet_exposed"] = False
    r["asset"]["edr_missing"] = False
    r["threat_context"]["in_kev"] = False
    r["threat_context"]["kev_ransomware"] = False
    r["threat_context"]["ti_actors"] = ""
    r["threat_context"]["ransomware_linked"] = False
    r["finding"]["patch_available"] = True
    r["finding"]["auth_required"] = True
    r["business_service"]["dependents"] = 0
    return r


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return condition


def main() -> None:
    ds = load_datasets(ROOT / "data" / "raw")
    kev, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    top5 = rank_top_risks(score_findings(master, cfg), cfg)
    chunks = load_or_build_chunks(ROOT / "data" / "external" / "nist_oscal_snapshot.json",
                                  ROOT / "data" / "external" / "nist_chunks.json")
    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    print(f"retriever: {retriever.mode}\n")

    ok = True

    # ---- BEST CASE 1: real top risk, real LLM, single-pass grounded ------
    print("BEST CASE 1 — strongest real risk, live LLM (expect: 1-pass llm_grounded)")
    llm = LLMClient()
    if llm.configured:
        agent = build_agent(retriever, ds.remediation_hints, llm)
        card = narrate_risk(agent, top5[0], run_config={
            "run_name": "BEST CASE 1: strong evidence, live LLM",
            "tags": ["eval", "best-case", "live-llm"],
        })
        ok &= check("llm_grounded on first pass", card["generation_mode"] == "llm_grounded")
        ok &= check(">=2 controls cited", len(card["cited_controls"]) >= 2,
                    str(card["cited_controls"]))
        rewrites = sum(1 for s in card["agent_trace"] if "rewrite #" in s)
        ok &= check("no rewrites needed", rewrites == 0, f"{rewrites} rewrites")
    else:
        print("  SKIPPED (no API key configured — see .env)")

    # ---- BEST CASE 2: real risk with evidence stripped out ----------------
    # Note: risk_score itself is a value already baked in by score_findings()
    # before ranking — mutating this copy's evidence fields does NOT re-run
    # the scorer, so risk_score stays whatever it was. What this scenario
    # actually exercises is the narrator: same rank/score label, but the
    # evidence handed to generate() is now thin, so "Why this ranks here"
    # has much less to weave together.
    print("\nBEST CASE 2 — same risk, evidence stripped, live LLM "
          "(expect: still llm_grounded, but a much thinner 'why it ranks here')")
    if llm.configured:
        weak_risk = weaken_evidence(top5[0])
        card = narrate_risk(agent, weak_risk, run_config={
            "run_name": "BEST CASE 2: weak evidence, live LLM",
            "tags": ["eval", "best-case", "live-llm", "weak-evidence"],
        })
        ok &= check("still produced a grounded card", card["generation_mode"] == "llm_grounded")
    else:
        print("  SKIPPED (no API key configured)")

    # ---- WORST CASE 1: hallucinating LLM -> contained ---------------------
    print("\nWORST CASE 1 — LLM invents a control + foreign CVE "
          "(expect: verify FAILs, regenerates once, falls back to template)")
    mock_agent = build_agent(retriever, ds.remediation_hints, MockLLM(good_grade, bad_generate))
    card = narrate_risk(mock_agent, top5[0], run_config={
        "run_name": "WORST CASE 1: hallucination -> contained",
        "tags": ["eval", "worst-case", "hallucination"],
    })
    valid_ids = {c["control_id"] for c in card["retrieved_controls"]}
    ok &= check("fell back to deterministic template", card["generation_mode"] == "template_fallback")
    ok &= check("no invented control leaked into final card",
                set(card["cited_controls"]) <= valid_ids)
    ok &= check("no foreign CVE leaked into final card",
                "CVE-2019-99999" not in card["narrative_md"])

    # ---- WORST CASE 2: no LLM configured at all ----------------------------
    print("\nWORST CASE 2 — no LLM configured "
          "(expect: heuristic grading, deterministic template, still cited)")
    noLLM_agent = build_agent(retriever, ds.remediation_hints, None)
    card = narrate_risk(noLLM_agent, top5[0], run_config={
        "run_name": "WORST CASE 2: no LLM configured",
        "tags": ["eval", "worst-case", "no-llm"],
    })
    ok &= check("template_fallback", card["generation_mode"] == "template_fallback")
    ok &= check("still cites real controls", bool(card["cited_controls"]))

    # ---- WORST CASE 3: retrieval never satisfies the grader ---------------
    print("\nWORST CASE 3 — grader never satisfied "
          "(expect: exactly 2 rewrites, then proceeds anyway — never hangs)")
    weak_agent = build_agent(retriever, ds.remediation_hints, MockLLM(weak_grade, good_generate))
    card = narrate_risk(weak_agent, top5[0], run_config={
        "run_name": "WORST CASE 3: bounded rewrite loop",
        "tags": ["eval", "worst-case", "bounded-rewrites"],
    })
    rewrites = sum(1 for s in card["agent_trace"] if "rewrite #" in s)
    ok &= check("exactly 2 rewrites (MAX_QUERY_REWRITES)", rewrites == 2, f"got {rewrites}")
    ok &= check("still terminated with a card", bool(card["narrative_md"]))

    print(f"\n{'ALL SCENARIOS PASSED' if ok else 'SOME SCENARIOS FAILED'}")
    if llm.configured:
        print("Open smith.langchain.com and filter tag=eval to see all traces "
              "(best-case vs worst-case, live-llm vs mocked).")
    else:
        print("Note: BEST CASE scenarios were skipped (no API key) — only the "
              "3 WORST CASE (mocked) scenarios ran and traced.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
