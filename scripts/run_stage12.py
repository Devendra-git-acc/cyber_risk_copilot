"""Run Stage 1 (validate) + Stage 2 (enrich) and inspect the results."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.loader import load_datasets
from risk_engine.validate import validate


def main() -> None:
    ds = load_datasets(ROOT / "data" / "raw")

    # ---- Stage 1 ----
    report = validate(ds)
    out = ROOT / "outputs"
    out.mkdir(exist_ok=True)
    (out / "validation_report.json").write_text(json.dumps(report, indent=2, default=str))

    s = report["summary"]
    print(f"STAGE 1 — VALIDATION: {s['checks_passed']}/{s['checks_total']} checks passed, "
          f"{s['issues_found']} issues surfaced")
    for c in report["checks"]:
        print(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['check']}  {c['detail']}")
    print("  Issues:")
    for i in report["issues"]:
        print(f"  - ({i['severity']}) {i['kind']}: {i['detail'][:110]}")
        for item in i["items"][:3]:
            print(f"      {item}")

    # ---- Stage 2 ----
    kev_catalog, kev_source = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    idx = kev_index(kev_catalog)
    print(f"\nSTAGE 2 — ENRICHMENT (KEV source: {kev_source}, "
          f"version {kev_catalog.get('catalogVersion')}, {len(idx)} entries)")

    master = build_master_table(ds, idx)
    master.to_csv(out / "master_table.csv", index=False)
    print(f"  master table: {master.shape[0]} rows x {master.shape[1]} cols "
          f"-> outputs/master_table.csv")

    print("\n  Evidence profile across 114 findings:")
    print(f"    internet-exposed (effective): {int(master.effective_internet_exposed.sum())}")
    print(f"    exposure conflicts flagged:   {int(master.exposure_conflict.sum())}")
    print(f"    in CISA KEV:                  {int(master.in_kev.sum())}")
    print(f"    KEV ransomware-linked:        {int(master.kev_ransomware.sum())}")
    print(f"    matched to threat intel:      {int((master.ti_match_count > 0).sum())}")
    print(f"    TI ransomware-linked:         {int(master.ti_ransomware.sum())}")
    print(f"    actively_exploited (layered): {int(master.actively_exploited.sum())}")
    print(f"    ransomware_linked (layered):  {int(master.ransomware_linked.sum())}")
    print(f"    on EDR-less assets:           {int(master.edr_missing.sum())}")
    print(f"    profile-targeted campaigns:   {int(master.ti_profile_targeted.sum())}")

    # The layered-evidence payoff: exploited findings invisible to KEV alone
    layered_win = master[master.actively_exploited & ~master.in_kev]
    print(f"\n  Layered-evidence payoff: {len(layered_win)} actively-exploited findings "
          f"that a KEV-only check would have MISSED (synthetic CVEs):")
    for _, r in layered_win.sort_values("cvss", ascending=False).head(6).iterrows():
        print(f"    {r.vuln_id} {r.cve} cvss={r.cvss} on {r.asset_name} "
              f"[{r.ti_actors or 'no actor'} / {r.ti_best_maturity}]")

    # Preview of the natural top candidates (no scoring yet — raw evidence view)
    hot = master[master.effective_internet_exposed & master.ransomware_linked]
    print(f"\n  Raw preview — internet-exposed AND ransomware-linked ({len(hot)} findings):")
    cols = ["vuln_id", "cve", "cvss", "asset_name", "business_service",
            "edr_missing", "ti_actors"]
    print(hot[cols].sort_values("cvss", ascending=False).to_string(index=False))


if __name__ == "__main__":
    main()
