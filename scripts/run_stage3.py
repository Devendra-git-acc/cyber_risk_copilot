"""Run Stage 3: score, rank, and sanity-test the results."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.loader import load_datasets
from risk_engine.score import load_config, rank_top_risks, score_findings


def main() -> None:
    ds = load_datasets(ROOT / "data" / "raw")
    kev_catalog, _ = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev_catalog))
    cfg = load_config(ROOT / "config" / "weights.yaml")

    scored = score_findings(master, cfg)
    top5 = rank_top_risks(scored, cfg)

    out = ROOT / "outputs"
    out.mkdir(exist_ok=True)
    scored_out = scored.copy()
    scored_out["likelihood_breakdown"] = scored_out["likelihood_breakdown"].apply(json.dumps)
    scored_out["impact_breakdown"] = scored_out["impact_breakdown"].apply(json.dumps)
    scored_out.to_csv(out / "scored_findings.csv", index=False)
    (out / "top5_risks.json").write_text(json.dumps(top5, indent=2, default=str))

    # ---- Calibration view: top 15 findings (pre-grouping) ----------------
    print("TOP 15 FINDINGS (pre-grouping calibration view)")
    cols = ["vuln_id", "cve", "cvss", "risk_score", "likelihood", "impact",
            "asset_name", "business_service"]
    view = scored[cols].head(15).copy()
    view["likelihood"] = view["likelihood"].round(2)
    view["impact"] = view["impact"].round(2)
    print(view.to_string(index=False))

    # ---- Grouped top 5 ---------------------------------------------------
    print("\nTOP 5 RISKS (one per asset, chains folded)")
    for e in top5:
        chain = [r for r in e["related_findings_same_asset"] if r["same_campaign_chain"]]
        chain_txt = f" + chained {', '.join(c['cve'] for c in chain)}" if chain else ""
        assets_txt = ", ".join(a["asset_name"] for a in e["affected_assets"])
        print(f"  #{e['rank']} [{e['risk_score']:5.1f}] {e['cve']}{chain_txt}")
        print(f"      L={e['likelihood']:.2f} x I={e['impact']:.2f} | assets: {assets_txt}"
              f" -> {e['business_service']['name']}")
        tc = e["threat_context"]
        evidence = []
        if tc["in_kev"]:
            evidence.append(f"KEV{'+ransomware' if tc['kev_ransomware'] else ''}")
        if tc["ti_actors"]:
            evidence.append(f"TI: {tc['ti_actors']} ({tc['ti_maturity']})")
        if e["asset"]["edr_missing"]:
            evidence.append("no EDR")
        print(f"      evidence: {'; '.join(evidence) if evidence else 'severity only'}")

    # ---- Sanity assertions ----------------------------------------------
    print("\nSANITY TESTS")
    def get(vuln_id):
        return scored.loc[scored.vuln_id == vuln_id].iloc[0]

    # T1 — the assignment's own test: CVSS 9.8 Jenkins on internal dev build
    # server must rank below CVSS 9.4 NetScaler on exposed payment LB.
    jenkins_dev = scored[(scored.asset_name.str.startswith("dev-build")) &
                         (scored.cve == "CVE-2024-23897")]["risk_score"].max()
    netscaler_pay = get("V-2066")["risk_score"]
    t1 = jenkins_dev < netscaler_pay
    print(f"  [{'PASS' if t1 else 'FAIL'}] T1 assignment test: internal-dev Jenkins 9.8 "
          f"({jenkins_dev}) < exposed payment NetScaler 9.4 ({netscaler_pay})")

    # T2 — impact separation: marketing CMS 9.8 must rank below payment LB 9.4
    cms = get("V-2083")["risk_score"]
    t2 = cms < netscaler_pay
    print(f"  [{'PASS' if t2 else 'FAIL'}] T2 impact test: marketing CMS 9.8 ({cms}) < "
          f"payment NetScaler 9.4 ({netscaler_pay})")

    # T3 — every top-5 entry is exposed + actively exploited
    t3 = all(e["asset"]["internet_exposed"] and
             (e["threat_context"]["in_kev"] or e["threat_context"]["ti_actors"])
             for e in top5)
    print(f"  [{'PASS' if t3 else 'FAIL'}] T3 top-5 all internet-exposed with exploitation evidence")

    # T4 — determinism: rescoring yields identical ranking
    rescored = score_findings(master, cfg)
    t4 = list(rescored.vuln_id.head(20)) == list(scored.vuln_id.head(20))
    print(f"  [{'PASS' if t4 else 'FAIL'}] T4 deterministic: identical top-20 across runs")

    # T5 — staging VPN ranks below both production VPN edges
    vpn_stage = get("V-2092")["risk_score"]
    vpn_prod = min(get("V-2015")["risk_score"], get("V-2019")["risk_score"])
    t5 = vpn_stage < vpn_prod
    print(f"  [{'PASS' if t5 else 'FAIL'}] T5 environment test: staging VPN ({vpn_stage}) < "
          f"production VPN ({vpn_prod})")

    # T6 — the report's lead campaign (CrimsonJackal VPN chain) makes top 5,
    # with the chained CVE folded into the same entry.
    vpn_entries = [e for e in top5 if "vpn" in e["asset"]["asset_name"]]
    t6 = bool(vpn_entries) and any(
        r["same_campaign_chain"] for e in vpn_entries
        for r in e["related_findings_same_asset"]
    )
    print(f"  [{'PASS' if t6 else 'FAIL'}] T6 VPN chain present in top 5 with chained CVE folded")

    # T7 — five distinct stories: no CVE repeats across entries.
    cves = [e["cve"] for e in top5]
    t7 = len(cves) == len(set(cves))
    print(f"  [{'PASS' if t7 else 'FAIL'}] T7 no duplicate CVE across top-5 entries")

    if not all([t1, t2, t3, t4, t5, t6, t7]):
        sys.exit(1)


if __name__ == "__main__":
    main()