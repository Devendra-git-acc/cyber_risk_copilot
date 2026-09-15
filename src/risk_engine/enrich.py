"""Stage 2: build the enriched master table.

One row per open vulnerability, with everything the scorer needs attached:
asset context, business-service context (including dependency fan-in),
matched threat-intel campaigns (noise discarded), and KEV status.

After this stage every scoring question is a column lookup — no more joins.
"""
from __future__ import annotations

import re

import pandas as pd

from .loader import Datasets

SYNTHETIC_CVE_PATTERN = re.compile(r"SYN", re.IGNORECASE)

# Ordered worst-first; used to pick the most mature exploitation among matches.
MATURITY_ORDER = [
    "Weaponized",
    "Active Exploitation",
    "Commodity Exploit",
    "Proof of Concept",
    "Social Engineering",
    "Not Applicable",
]

# TawasolPay's profile: Dubai fintech. Campaigns aimed at this profile are
# treated as more relevant than generic global activity.
PROFILE_REGIONS = {"Middle East"}
PROFILE_SECTOR_PATTERN = re.compile(r"fin", re.IGNORECASE)


def _best_maturity(values: pd.Series) -> str:
    for level in MATURITY_ORDER:
        if (values == level).any():
            return level
    return "Not Applicable"


def _aggregate_threat_intel(ti: pd.DataFrame, env_cves: set[str]) -> pd.DataFrame:
    """Collapse matched intel records to one row per CVE. Noise is dropped."""
    matched = ti[ti["matched_cve_or_control"].isin(env_cves)].copy()
    matched["profile_hit"] = matched["target_region"].isin(PROFILE_REGIONS) | matched[
        "target_sector"
    ].str.contains(PROFILE_SECTOR_PATTERN)

    grouped = matched.groupby("matched_cve_or_control").agg(
        ti_match_count=("intel_id", "count"),
        ti_intel_ids=("intel_id", lambda s: ", ".join(s)),
        ti_actors=("threat_actor", lambda s: ", ".join(sorted(set(s)))),
        ti_campaigns=("campaign_name", lambda s: ", ".join(sorted(set(s)))),
        ti_ransomware=("ransomware_association", lambda s: bool((s == "Yes").any())),
        ti_best_maturity=("exploit_maturity", _best_maturity),
        ti_profile_targeted=("profile_hit", "any"),
        ti_last_seen=("active_last_seen", "max"),
        ti_summaries=("summary", lambda s: " | ".join(s)),
    )
    return grouped.reset_index().rename(columns={"matched_cve_or_control": "cve"})


def _service_fan_in(services: pd.DataFrame) -> pd.Series:
    """How many other services depend on each service (cascade weight)."""
    counts: dict[str, int] = {s: 0 for s in services["business_service"]}
    for deps in services["depends_on"].dropna():
        for dep in [d.strip() for d in str(deps).split(",") if d.strip()]:
            if dep in counts:
                counts[dep] += 1
    return services["business_service"].map(counts)


def build_master_table(ds: Datasets, kev_idx: dict[str, dict]) -> pd.DataFrame:
    a, v, b = ds.assets.copy(), ds.vulnerabilities.copy(), ds.business_services.copy()

    # Only open findings are rankable risk (all 114 are Open in this dataset,
    # but the filter is a correctness guard, not an assumption).
    v = v[v["status"].str.lower().isin({"open", "in progress"})].copy()

    # --- asset context ---------------------------------------------------
    asset_cols = [
        "asset_id", "asset_name", "asset_type", "environment", "owner_team",
        "business_service", "internet_exposed", "criticality",
        "data_classification", "edr_installed", "last_seen_days", "vendor_product",
    ]
    m = v.merge(a[asset_cols], on="asset_id", how="left")

    # --- business-service context ---------------------------------------
    b = b.copy()
    b["service_dependents"] = _service_fan_in(b)
    svc_cols = [
        "business_service", "business_impact", "customer_facing", "compliance_scope",
        "revenue_impact", "rto_hours", "depends_on", "risk_appetite", "service_dependents",
    ]
    m = m.merge(b[svc_cols], on="business_service", how="left")

    # --- derived exposure (worst-case policy + conflict flag) ------------
    vuln_internet = m["asset_exposure"].eq("Internet")
    asset_internet = m["internet_exposed"].eq("Yes")
    m["effective_internet_exposed"] = vuln_internet | asset_internet
    m["exposure_conflict"] = vuln_internet != asset_internet

    # --- derived flags ----------------------------------------------------
    m["is_synthetic_cve"] = m["cve"].str.contains(SYNTHETIC_CVE_PATTERN)
    m["edr_missing"] = m["edr_installed"].eq("No")
    m["asset_stale"] = m["last_seen_days"] > 30
    m["exploit_available_flag"] = m["exploit_available"].eq("Yes")
    m["patch_available_flag"] = m["patch_available"].eq("Yes")
    m["auth_required_flag"] = m["auth_required"].eq("Yes")

    # --- threat intel (matched only; noise discarded) ---------------------
    ti_agg = _aggregate_threat_intel(ds.threat_intel, set(m["cve"]))
    m = m.merge(ti_agg, on="cve", how="left")
    m["ti_match_count"] = m["ti_match_count"].fillna(0).astype(int)

    # Boolean columns need the nullable "boolean" dtype BEFORE fillna: once the
    # merge introduces NaN, these columns become plain object dtype, and
    # object.fillna(bool) is exactly the pattern pandas now warns about — the
    # warning fires *during* fillna itself, so chaining .infer_objects() or
    # .astype() afterward does not help (verified empirically, not assumed).
    # Casting to "boolean" first means fillna operates on a proper nullable
    # boolean array, which never triggers the warning; plain fillna is fine
    # for the string columns below, since there is no narrower dtype for
    # pandas to attempt downcasting into.
    for col in ("ti_ransomware", "ti_profile_targeted"):
        m[col] = m[col].astype("boolean").fillna(False).astype(bool)
    for col, default in [
        ("ti_best_maturity", "Not Applicable"), ("ti_actors", ""),
        ("ti_campaigns", ""), ("ti_intel_ids", ""), ("ti_last_seen", ""),
        ("ti_summaries", ""),
    ]:
        m[col] = m[col].fillna(default)

    # --- KEV --------------------------------------------------------------
    m["in_kev"] = m["cve"].map(lambda c: kev_idx.get(c, {}).get("in_kev", False))
    m["kev_ransomware"] = m["cve"].map(lambda c: kev_idx.get(c, {}).get("kev_ransomware", False))
    m["kev_date_added"] = m["cve"].map(lambda c: kev_idx.get(c, {}).get("kev_date_added", ""))
    m["kev_required_action"] = m["cve"].map(
        lambda c: kev_idx.get(c, {}).get("kev_required_action", ""))

    # --- consolidated evidence flags used by the scorer -------------------
    m["actively_exploited"] = m["in_kev"] | m["ti_best_maturity"].isin(
        ["Weaponized", "Active Exploitation", "Commodity Exploit"]
    )
    m["ransomware_linked"] = m["kev_ransomware"] | m["ti_ransomware"]

    return m