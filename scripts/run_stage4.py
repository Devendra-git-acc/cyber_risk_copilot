"""Run Stage 4: build the NIST index, evaluate retrieval quality, and
retrieve controls for the actual top-5 risks."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.retriever import NISTRetriever, build_retrieval_queries
from risk_engine.score import load_config, rank_top_risks, score_findings

# Retrieval eval: expected control (or its family prefix) must appear in top-5
# for queries phrased the way our query builder phrases them. Expected IDs come
# from the assignment's own hint list (SI-2, RA-5, IR-4, AC-2, SA-22).
EVAL_CASES = [
    ("apply vendor security patches flaw remediation software updates", "SI-2"),
    ("vulnerability scanning monitoring identify report vulnerabilities", "RA-5"),
    ("ransomware incident handling response containment recovery", "IR-4"),
    ("account management disable inactive accounts review privileges", "AC-2"),
    ("unsupported end-of-life software no vendor security updates", "SA-22"),
]


def main() -> None:
    chunks = load_or_build_chunks(
        ROOT / "data" / "external" / "nist_oscal_snapshot.json",
        ROOT / "data" / "external" / "nist_chunks.json",
    )
    fams = len({c["family"] for c in chunks})
    n_controls = len({c["control_id"] for c in chunks})
    print(f"NIST 800-53 Rev 5 parsed: {n_controls} active controls/enhancements "
          f"({len(chunks)} retrieval chunks) across {fams} families")

    retriever = NISTRetriever(chunks, persist_dir=str(ROOT / "data" / "chroma"))
    print(f"Retriever mode: {retriever.mode}\n")

    # ---- Retrieval quality eval -----------------------------------------
    print("RETRIEVAL EVAL (expected control in top-5)")
    passed = 0
    for query, expected in EVAL_CASES:
        hits = retriever.search(query, k=5)
        ids = [h["control_id"] for h in hits]
        ok = any(i == expected or i.startswith(expected + ".") for i in ids)
        passed += ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {expected:<6} <- \"{query[:48]}...\" got {ids}")
    print(f"  {passed}/{len(EVAL_CASES)} eval cases passed")

    # ---- Retrieval for the real top-5 risks ------------------------------
    ds = load_datasets(ROOT / "data" / "raw")
    kev_catalog, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev_catalog))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    top5 = rank_top_risks(score_findings(master, cfg), cfg)

    print("\nCONTROLS RETRIEVED FOR TOP-5 RISKS")
    retrievals = []
    for e in top5:
        query = " || ".join(build_retrieval_queries(e, ds.remediation_hints))
        queries = build_retrieval_queries(e, ds.remediation_hints)
        hits = retriever.search_multi(queries, k=4)
        retrievals.append({"rank": e["rank"], "cve": e["cve"], "query": query,
                           "controls": hits})
        print(f"  #{e['rank']} {e['cve']} ({e['asset']['asset_name']})")
        print(f"     query: {query[:110]}...")
        for h in hits:
            print(f"     -> {h['control_id']:<8} {h['title']}")

    (ROOT / "outputs").mkdir(exist_ok=True)
    (ROOT / "outputs" / "top5_retrievals.json").write_text(
        json.dumps(retrievals, indent=2))
    if passed < len(EVAL_CASES):
        sys.exit(1)


if __name__ == "__main__":
    main()