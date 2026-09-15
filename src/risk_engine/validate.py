"""Stage 1: validate the datasets before any scoring happens.

The assignment plants deliberate imperfections (synthetic CVEs, one exposure
contradiction, threat-intel noise, control gaps). We surface every one of them
explicitly instead of silently 'fixing' the data. The output doubles as
evidence for README supporting question 2 (failure modes).
"""
from __future__ import annotations

import re
from typing import Any

from .loader import Datasets

SYNTHETIC_CVE_PATTERN = re.compile(r"SYN", re.IGNORECASE)
STALE_DAYS_THRESHOLD = 30


def validate(ds: Datasets) -> dict[str, Any]:
    a, v, t, b = ds.assets, ds.vulnerabilities, ds.threat_intel, ds.business_services
    report: dict[str, Any] = {"checks": [], "issues": []}

    def check(name: str, passed: bool, detail: str = "") -> None:
        report["checks"].append({"check": name, "passed": bool(passed), "detail": detail})

    def issue(kind: str, severity: str, detail: str, items: list | None = None) -> None:
        report["issues"].append(
            {"kind": kind, "severity": severity, "detail": detail, "items": items or []}
        )

    # --- Row counts ------------------------------------------------------
    report["row_counts"] = {
        "assets": len(a),
        "vulnerabilities": len(v),
        "threat_intel": len(t),
        "business_services": len(b),
        "remediation_hints": len(ds.remediation_hints),
    }

    # --- Referential integrity ------------------------------------------
    orphan_vulns = v[~v["asset_id"].isin(a["asset_id"])]
    check(
        "every vulnerability maps to a real asset",
        orphan_vulns.empty,
        f"{len(orphan_vulns)} orphan rows" if not orphan_vulns.empty else "all asset_ids resolve",
    )

    unknown_services = a[~a["business_service"].isin(b["business_service"])]
    check(
        "every asset's business_service exists",
        unknown_services.empty,
        f"{len(unknown_services)} unknown" if not unknown_services.empty else "all services resolve",
    )

    check("vuln_id unique", v["vuln_id"].is_unique)
    check("asset_id unique", a["asset_id"].is_unique)

    # --- Value sanity ----------------------------------------------------
    bad_cvss = v[(v["cvss"] < 0) | (v["cvss"] > 10)]
    check("CVSS within [0, 10]", bad_cvss.empty)
    bad_days = v[v["days_open"] < 0]
    check("days_open non-negative", bad_days.empty)

    # --- Planted imperfection 1: exposure contradiction ------------------
    merged = v.merge(
        a[["asset_id", "asset_name", "internet_exposed"]], on="asset_id", how="left"
    )
    conflicts = merged[
        (merged["asset_exposure"].eq("Internet")) != (merged["internet_exposed"].eq("Yes"))
    ]
    if not conflicts.empty:
        issue(
            "exposure_conflict",
            "high",
            "vuln-level asset_exposure disagrees with asset-level internet_exposed; "
            "policy: treat as internet-exposed (worst case) and flag",
            conflicts[["vuln_id", "asset_id", "asset_name", "asset_exposure", "internet_exposed"]]
            .to_dict("records"),
        )

    # --- Planted imperfection 2: synthetic CVE identifiers ---------------
    is_syn = v["cve"].str.contains(SYNTHETIC_CVE_PATTERN)
    report["cve_profile"] = {
        "synthetic": int(is_syn.sum()),
        "real": int((~is_syn).sum()),
        "unique_real": int(v.loc[~is_syn, "cve"].nunique()),
    }
    issue(
        "synthetic_cves",
        "info",
        f"{int(is_syn.sum())}/{len(v)} findings use synthetic CVE ids that can never "
        "match external feeds (CISA KEV); exploitation evidence must be layered "
        "(KEV for real CVEs, internal threat intel + exploit_available for synthetic).",
    )

    # --- Planted imperfection 3: threat-intel noise -----------------------
    env_cves = set(v["cve"])
    t_matched = t["matched_cve_or_control"].isin(env_cves)
    report["threat_intel_profile"] = {
        "matched_to_environment": int(t_matched.sum()),
        "noise": int((~t_matched).sum()),
        "noise_intel_ids": t.loc[~t_matched, "intel_id"].tolist(),
    }
    issue(
        "threat_intel_noise",
        "info",
        f"{int((~t_matched).sum())}/{len(t)} intel records reference CVEs/controls not present "
        "in the environment; they are excluded from scoring as industry noise.",
    )

    # --- Planted imperfection 4: asset hygiene gaps -----------------------
    no_edr = a[a["edr_installed"].eq("No")]
    stale = a[a["last_seen_days"] > STALE_DAYS_THRESHOLD]
    ownerless = a[a["owner_team"].isna() | a["owner_team"].eq("")]
    report["asset_hygiene"] = {
        "edr_missing": len(no_edr),
        "stale_over_30d": stale[["asset_id", "asset_name", "last_seen_days"]].to_dict("records"),
        "ownerless": ownerless[["asset_id", "asset_name"]].to_dict("records"),
    }
    if len(no_edr):
        issue(
            "edr_gaps", "medium",
            f"{len(no_edr)}/{len(a)} assets lack EDR — scored as missing compensating control.",
        )
    if len(stale):
        issue("stale_assets", "medium", "assets unseen >30 days (possibly unmanaged)",
              report["asset_hygiene"]["stale_over_30d"])
    if len(ownerless):
        issue("ownerless_assets", "low", "assets with no owning team (remediation has no owner)",
              report["asset_hygiene"]["ownerless"])

    report["summary"] = {
        "checks_passed": sum(1 for c in report["checks"] if c["passed"]),
        "checks_total": len(report["checks"]),
        "issues_found": len(report["issues"]),
    }
    return report
