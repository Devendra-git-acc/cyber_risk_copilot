"""Run the full pipeline end-to-end: validate -> enrich -> score -> agent
narration -> human-readable risk report (outputs/risk_report.md + .json)."""
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.agent import build_agent, narrate_risk
from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.llm import LLMClient
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.observability import check_fallback_rate, configure_logging
from risk_engine.retriever import NISTRetriever
from risk_engine.score import load_config, rank_top_risks, score_findings
from risk_engine.validate import validate


def main() -> None:
    configure_logging()
    ds = load_datasets(ROOT / "data" / "raw")
    validation = validate(ds)
    kev_catalog, kev_src = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev_catalog))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    scored = score_findings(master, cfg)
    top5 = rank_top_risks(scored, cfg, report_md=ds.threat_report_md)

    chunks = load_or_build_chunks(ROOT / "data" / "external" / "nist_oscal_snapshot.json",
                                  ROOT / "data" / "external" / "nist_chunks.json")
    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    llm = LLMClient()
    known_actors = set(ds.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}
    agent = build_agent(retriever, ds.remediation_hints, llm, known_actors=known_actors)

    print(f"LLM: {'configured (' + llm.model + ')' if llm.configured else 'NOT configured -> template fallback'}")
    print(f"Retriever: {retriever.mode}\n")

    cards = [narrate_risk(agent, e) for e in top5]
    mode_counts: dict[str, int] = {}
    for c in cards:
        mode_counts[c["generation_mode"]] = mode_counts.get(c["generation_mode"], 0) + 1
    check_fallback_rate(mode_counts)

    # ---- outputs ---------------------------------------------------------
    out = ROOT / "outputs"
    out.mkdir(exist_ok=True)
    (out / "risk_report.json").write_text(json.dumps({
        "generated": str(date.today()),
        "kev_source": kev_src,
        "retriever_mode": retriever.mode,
        "validation_summary": validation["summary"],
        "cards": cards,
    }, indent=2, default=str))

    md = [f"# TawasolPay — Top 5 Cyber Risks ({date.today()})",
          "_Scoring: deterministic likelihood x impact. Remediation: retrieved "
          "from NIST SP 800-53 Rev 5. Narration mode varies per card (see tag)._\n"]
    for c in cards:
        md.append(f"---\n## #{c['rank']} — {c['title']} ({c['cve']})  "
                  f"`score {c['risk_score']}`")
        md.append(f"**Assets:** {', '.join(c['assets'])} | "
                  f"**Service:** {c['business_service']} | "
                  f"**Mode:** `{c['generation_mode']}`\n")
        md.append(c["narrative_md"])
        md.append(f"\n_Retrieved controls: "
                  f"{', '.join(x['control_id'] for x in c['retrieved_controls'])}_\n")
    (out / "risk_report.md").write_text("\n".join(md), encoding="utf-8")

    # Agent graph diagram for the README
    try:
        mermaid = agent.get_graph().draw_mermaid()
        (out / "agent_graph.mmd").write_text(mermaid)
        print("agent graph exported -> outputs/agent_graph.mmd")
    except Exception as exc:  # noqa: BLE001
        print(f"(mermaid export skipped: {exc})")

    print("report written -> outputs/risk_report.md / .json\n")
    print("=" * 70)
    print(cards[4]["narrative_md"])  # show the VPN chain card as the sample
    print("=" * 70)
    print("agent trace for that card:")
    for step in cards[4]["agent_trace"]:
        print(f"  - {step}")


if __name__ == "__main__":
    main()