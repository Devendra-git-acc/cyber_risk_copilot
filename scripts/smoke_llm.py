"""One-command live-LLM smoke test (run on your machine with your API key):

    export OPENAI_API_KEY=sk-...        # or LLM_API_KEY
    python scripts/smoke_llm.py

Verifies: (1) the endpoint answers, (2) one real risk flows through the full
agent with LLM-grounded generation, (3) verify passes on the live output.
"""
import sys
from pathlib import Path

# Some models (e.g. Groq's openai/gpt-oss-*) favor Unicode punctuation
# (non-breaking hyphens, smart quotes) that Windows' default terminal
# encoding (cp1252) can't print -- crashes this script's own output, not
# the app itself (a browser renders UTF-8 fine). Harmless everywhere else.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.agent import build_agent, narrate_risk
from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.llm import LLMClient
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.observability import configure_logging
from risk_engine.retriever import NISTRetriever
from risk_engine.score import load_config, rank_top_risks, score_findings


def main() -> None:
    configure_logging()
    llm = LLMClient()
    if not llm.configured:
        sys.exit("No API key found. Set OPENAI_API_KEY or LLM_API_KEY.")
    print(f"endpoint: {llm.base_url}  model: {llm.model}")
    # max_tokens=60, not 5: reasoning-style models (e.g. Groq's openai/gpt-oss-*)
    # spend a variable, prompt-dependent amount of the budget on hidden
    # reasoning before any visible output, so a small budget can come back
    # empty on a model that's actually working fine -- confirmed empirically
    # (5 and even 30 both came back blank on this exact model/prompt shape).
    pong = llm.chat("Reply with exactly: OK", "ping", max_tokens=60)
    print(f"connectivity: {pong.strip()[:20]}")

    ds = load_datasets(ROOT / "data" / "raw")
    kev, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    top5 = rank_top_risks(score_findings(master, cfg), cfg, report_md=ds.threat_report_md)
    chunks = load_or_build_chunks(ROOT / "data" / "external" / "nist_oscal_snapshot.json",
                                  ROOT / "data" / "external" / "nist_chunks.json")
    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    print(f"retriever: {retriever.mode}")

    known_actors = set(ds.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}
    agent = build_agent(retriever, ds.remediation_hints, llm, known_actors=known_actors)
    card = narrate_risk(agent, top5[0])

    print(f"\ngeneration_mode: {card['generation_mode']} "
          f"(expect llm_grounded)\ncited: {card['cited_controls']}\n")
    print(card["narrative_md"])
    print("\ntrace:")
    for s in card["agent_trace"]:
        print(f"  - {s}")
    if card["generation_mode"] != "llm_grounded":
        sys.exit("WARN: fell back to template — check key/quota above.")
    print("\nSMOKE TEST PASSED")


if __name__ == "__main__":
    main()