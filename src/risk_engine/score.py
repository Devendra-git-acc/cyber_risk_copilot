"""Stage 3: deterministic risk scoring — Likelihood x Impact.

Design decisions (see README for alternatives considered):
- Multiplicative structure: an internal-only finding is capped by its low
  reachability and can never 'buy back' rank with CVSS alone. The assignment's
  own test case (CVSS 10 on an internal dev server vs CVSS 8 on an exposed
  payment gateway under ransomware campaign) passes by architecture.
- Every score ships with a factor-by-factor breakdown: it drives the UI,
  the audit trail, and the grounded context handed to the LLM narrator.
  The LLM never ranks anything.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from .threat_report import get_campaign_excerpt


def load_config(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Likelihood
# --------------------------------------------------------------------------
def _evidence_tier(row: pd.Series, tiers: dict) -> tuple[str, float]:
    if row["actively_exploited"] and row["ransomware_linked"]:
        return "active_and_ransomware", tiers["active_and_ransomware"]
    if row["actively_exploited"]:
        return "actively_exploited", tiers["actively_exploited"]
    if row["exploit_available_flag"]:
        return "poc_exploit_only", tiers["poc_exploit_only"]
    return "no_known_exploit", tiers["no_known_exploit"]


def _max_likelihood_raw(cfg: dict) -> float:
    """The true ceiling raw likelihood is normalized against: every
    multiplier at ITS OWN maximum, simultaneously. Computed from the config
    (not a hand-picked constant) so it self-corrects if weights.yaml changes.

    Why this matters: raw = exposure * tier * cvss_mult * auth * profile * edr
    chains six independently-designed multipliers, several of which sit
    above 1.0 (no_auth_required, profile_targeted, edr_missing are >1.0
    bonuses). A merely-severe finding can push raw past 1.0 long before it
    reaches the true worst case -- capping each row at a flat 1.0 there
    throws away exactly how far past that point it was, which silently
    collapses the ranking between two findings that both cross 1.0 by
    different margins (verified empirically: CVE-2023-4966's raw 1.353 vs
    CVE-SYN-2026-0010's raw 1.113 both read as 1.0 under the old flat cap,
    inverting their true relative order). Normalizing by the real ceiling
    instead of an arbitrary one preserves that information."""
    c = cfg["likelihood"]
    return (
        max(c["base_exposure"].values())
        * max(c["evidence_tiers"].values())
        * (c["cvss_floor"] + c["cvss_span"])  # cvss_mult's own max, at cvss=10
        * c["no_auth_required"]
        * c["profile_targeted"]
        * c["edr_missing"]
    )


def _likelihood(row: pd.Series, cfg: dict) -> tuple[float, dict[str, Any]]:
    c = cfg["likelihood"]
    exposure = c["base_exposure"]["internet" if row["effective_internet_exposed"] else "internal"]
    tier_name, tier_val = _evidence_tier(row, c["evidence_tiers"])
    cvss_mult = c["cvss_floor"] + c["cvss_span"] * (float(row["cvss"]) / 10.0)
    auth_mult = c["no_auth_required"] if not row["auth_required_flag"] else 1.0
    profile_mult = c["profile_targeted"] if row["ti_profile_targeted"] else 1.0
    edr_mult = c["edr_missing"] if row["edr_missing"] else 1.0

    raw = exposure * tier_val * cvss_mult * auth_mult * profile_mult * edr_mult
    # Normalize against the true theoretical ceiling, not a flat 1.0 -- see
    # _max_likelihood_raw's docstring. The outer min() is a defensive
    # safety net only (raw can't structurally exceed the ceiling); it should
    # never actually engage.
    likelihood = min(raw / _max_likelihood_raw(cfg), 1.0)
    breakdown = {
        "exposure": {"internet_exposed": bool(row["effective_internet_exposed"]), "value": exposure},
        "evidence_tier": {"tier": tier_name, "value": tier_val,
                          "in_kev": bool(row["in_kev"]),
                          "kev_ransomware": bool(row["kev_ransomware"]),
                          "ti_actors": row["ti_actors"],
                          "ti_maturity": row["ti_best_maturity"]},
        "cvss_multiplier": {"cvss": float(row["cvss"]), "value": round(cvss_mult, 3)},
        "no_auth_required": {"applied": not row["auth_required_flag"], "value": auth_mult},
        "profile_targeted": {"applied": bool(row["ti_profile_targeted"]), "value": profile_mult},
        "edr_missing": {"applied": bool(row["edr_missing"]), "value": edr_mult},
    }
    return likelihood, breakdown


# --------------------------------------------------------------------------
# Impact
# --------------------------------------------------------------------------
def _compliance_score(scope: Any, cfg: dict) -> float:
    if not isinstance(scope, str) or not scope.strip():
        return cfg["compliance_default"]
    vals = [cfg["compliance_map"].get(tok.strip(), cfg["compliance_default"])
            for tok in scope.split(",")]
    return max(vals)


def _rto_score(hours: Any, bands: list) -> float:
    try:
        h = float(hours)
    except (TypeError, ValueError):
        return 0.4
    for limit, score in bands:
        if h <= limit:
            return score
    return 0.2


def _max_impact_raw(cfg: dict) -> float:
    """Mirrors _max_likelihood_raw: the true ceiling raw impact is normalized
    against, not a flat 1.0. Every blend component maxes at 1.0 (by the
    level/compliance/customer_facing/rto/data-classification maps' own
    design), so the blend's max is just its weights summed -- computed, not
    assumed to be exactly 1.0, so this self-corrects if weights.yaml's blend
    stops summing to 1.0. Plus both bonuses at once, at the most favorable
    environment multiplier."""
    c = cfg["impact"]
    return (
        sum(c["blend"].values())
        + c["dependency_bonus_cap"]
        + c.get("gateway_asset_bonus", 0.0)
    ) * max(c["environment_modifier"].values())


def _impact(row: pd.Series, cfg: dict) -> tuple[float, dict[str, Any]]:
    c = cfg["impact"]
    lv = c["level_map"]
    parts = {
        "asset_criticality": lv.get(row["criticality"], 0.5),
        "service_revenue": lv.get(row["revenue_impact"], 0.5),
        "compliance": _compliance_score(row["compliance_scope"], c),
        "customer_facing": c["customer_facing"].get(row["customer_facing"], 0.4),
        "rto_urgency": _rto_score(row["rto_hours"], c["rto_bands"]),
        "data_classification": c["data_classification_map"].get(
            row["data_classification"], c["data_classification_default"]),
    }
    blended = sum(parts[k] * c["blend"][k] for k in parts)

    dep_bonus = min(
        c["dependency_bonus_per_dependent"] * int(row["service_dependents"] or 0),
        c["dependency_bonus_cap"],
    )
    gateway = row["asset_type"] in c.get("gateway_asset_types", [])
    gateway_bonus = c.get("gateway_asset_bonus", 0.0) if gateway else 0.0
    env_mod = c["environment_modifier"].get(row["environment"], 1.0)
    raw = (blended + dep_bonus + gateway_bonus) * env_mod
    # Normalize against the true theoretical ceiling, not a flat 1.0 -- see
    # _max_impact_raw's docstring and _likelihood's identical reasoning.
    impact = min(raw / _max_impact_raw(cfg), 1.0)

    breakdown = {
        "components": {k: {"input": str(row[_IMPACT_INPUT_COL[k]]), "score": v,
                           "weight": c["blend"][k]} for k, v in parts.items()},
        "dependency_bonus": {"dependents": int(row["service_dependents"] or 0),
                             "value": round(dep_bonus, 3)},
        "gateway_asset_bonus": {"applied": gateway, "asset_type": row["asset_type"],
                                "value": gateway_bonus},
        "environment_modifier": {"environment": row["environment"], "value": env_mod},
    }
    return impact, breakdown


_IMPACT_INPUT_COL = {
    "asset_criticality": "criticality",
    "service_revenue": "revenue_impact",
    "compliance": "compliance_scope",
    "customer_facing": "customer_facing",
    "rto_urgency": "rto_hours",
    "data_classification": "data_classification",
}


# --------------------------------------------------------------------------
# Scoring + ranking
# --------------------------------------------------------------------------
def score_findings(master: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    scored = master.copy()
    results = scored.apply(
        lambda r: (*_likelihood(r, cfg), *_impact(r, cfg)), axis=1, result_type="expand"
    )
    results.columns = ["likelihood", "likelihood_breakdown", "impact", "impact_breakdown"]
    scored = pd.concat([scored, results], axis=1)
    scored["risk_score"] = (scored["likelihood"] * scored["impact"] * 100).round(1)
    return scored.sort_values("risk_score", ascending=False).reset_index(drop=True)


def _related_findings(asset_rows: pd.DataFrame, primary: pd.Series) -> list[dict]:
    """Other open findings on the same asset; mark same-campaign chains."""
    primary_actors = set(a.strip() for a in str(primary["ti_actors"]).split(",") if a.strip())
    related = []
    for _, r in asset_rows.iterrows():
        if r["vuln_id"] == primary["vuln_id"]:
            continue
        actors = set(a.strip() for a in str(r["ti_actors"]).split(",") if a.strip())
        related.append({
            "vuln_id": r["vuln_id"], "cve": r["cve"], "cvss": float(r["cvss"]),
            "risk_score": float(r["risk_score"]),
            "same_campaign_chain": bool(primary_actors & actors),
        })
    return sorted(related, key=lambda d: -d["risk_score"])


def rank_top_risks(scored: pd.DataFrame, cfg: dict, report_md: str = "") -> list[dict]:
    """Top-N with two diversity rules so the briefing reads as N distinct fires:

    1. One entry per asset — chained CVEs on the same asset (shared campaign)
       fold into the entry as one story (e.g. the Fortinet 21762+55591 chain).
    2. One entry per CVE — the same flaw on twin/parallel infrastructure
       (e.g. NetScaler on both load balancers) folds into one entry listing
       all affected assets: it is one remediation act, not two risks.
    """
    top_n = cfg["ranking"]["top_n"]
    entries: list[dict] = []
    seen_assets: set[str] = set()
    seen_cves: set[str] = set()

    for _, row in scored.iterrows():
        if cfg["ranking"]["one_risk_per_asset"] and row["asset_id"] in seen_assets:
            continue
        if row["cve"] in seen_cves:
            continue
        seen_cves.add(row["cve"])

        # Fold: all not-yet-covered assets sharing this CVE join this entry.
        cve_group = scored[(scored["cve"] == row["cve"]) &
                           (~scored["asset_id"].isin(seen_assets))]
        affected_assets = [
            {
                "asset_id": r["asset_id"], "asset_name": r["asset_name"],
                "environment": r["environment"],
                "business_service": r["business_service"],
                "risk_score": float(r["risk_score"]),
                "edr_missing": bool(r["edr_missing"]),
            }
            for _, r in cve_group.sort_values("risk_score", ascending=False).iterrows()
        ]
        seen_assets.update(cve_group["asset_id"])
        asset_rows = scored[scored["asset_id"] == row["asset_id"]]
        entries.append({
            "affected_assets": affected_assets,
            "rank": len(entries) + 1,
            "risk_score": float(row["risk_score"]),
            "likelihood": round(float(row["likelihood"]), 3),
            "impact": round(float(row["impact"]), 3),
            "vuln_id": row["vuln_id"],
            "cve": row["cve"],
            "vulnerability_name": row["vulnerability_name"],
            "cvss": float(row["cvss"]),
            "asset": {
                "asset_id": row["asset_id"], "asset_name": row["asset_name"],
                "asset_type": row["asset_type"], "environment": row["environment"],
                "vendor_product": row["vendor_product"], "owner_team": row["owner_team"],
                "internet_exposed": bool(row["effective_internet_exposed"]),
                "exposure_conflict": bool(row["exposure_conflict"]),
                "edr_missing": bool(row["edr_missing"]),
            },
            "business_service": {
                "name": row["business_service"], "revenue_impact": row["revenue_impact"],
                "customer_facing": row["customer_facing"],
                "compliance_scope": row["compliance_scope"],
                "rto_hours": row["rto_hours"],
                "dependents": int(row["service_dependents"] or 0),
                "business_impact": row["business_impact"],
            },
            "threat_context": {
                "in_kev": bool(row["in_kev"]), "kev_ransomware": bool(row["kev_ransomware"]),
                "kev_date_added": row["kev_date_added"],
                "kev_required_action": row["kev_required_action"],
                "ti_actors": row["ti_actors"], "ti_campaigns": row["ti_campaigns"],
                "ti_maturity": row["ti_best_maturity"], "ti_last_seen": row["ti_last_seen"],
                "ransomware_linked": bool(row["ransomware_linked"]),
                "ti_summaries": row["ti_summaries"],
                "mdr_excerpt": get_campaign_excerpt(report_md, row["ti_actors"]),
            },
            "finding": {
                "exploit_available": bool(row["exploit_available_flag"]),
                "patch_available": bool(row["patch_available_flag"]),
                "days_open": int(row["days_open"]),
                "auth_required": bool(row["auth_required_flag"]),
                "affected_component": row["affected_component"],
            },
            "likelihood_breakdown": row["likelihood_breakdown"],
            "impact_breakdown": row["impact_breakdown"],
            "related_findings_same_asset": _related_findings(asset_rows, row),
        })
        if len(entries) >= top_n:
            break
    return entries