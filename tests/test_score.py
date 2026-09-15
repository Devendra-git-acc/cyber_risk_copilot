"""Unit tests for the deterministic scorer (Stage 3).

_likelihood/_impact are tested directly against hand-built pd.Series (not
the full master table) so these stay fast, isolated white-box tests of the
scoring math itself; rank_top_risks' diversity rules are checked against the
real `top5` fixture since that logic is inherently about interactions across
rows that aren't worth hand-faking.
"""
from __future__ import annotations

import pandas as pd
import pytest

from risk_engine.score import _compliance_score, _evidence_tier, _impact, _likelihood, _rto_score


def test_multiplicative_dominance_exposed_beats_internal(cfg):
    """The assignment's own headline test case: a severe internal finding
    can never outrank a modest finding on an exposed, actively-exploited
    asset under a ransomware campaign -- likelihood x impact is multiplicative,
    not additive, so raw CVSS alone can't buy back rank."""
    internal_critical = pd.Series({
        "effective_internet_exposed": False, "actively_exploited": False,
        "ransomware_linked": False, "exploit_available_flag": False,
        "cvss": 10.0, "auth_required_flag": True, "ti_profile_targeted": False,
        "edr_missing": False, "in_kev": False, "kev_ransomware": False,
        "ti_actors": "", "ti_best_maturity": "Not Applicable",
    })
    exposed_exploited = pd.Series({
        "effective_internet_exposed": True, "actively_exploited": True,
        "ransomware_linked": True, "exploit_available_flag": True,
        "cvss": 8.0, "auth_required_flag": False, "ti_profile_targeted": True,
        "edr_missing": True, "in_kev": True, "kev_ransomware": True,
        "ti_actors": "IronVeil", "ti_best_maturity": "Weaponized",
    })
    l_internal, _ = _likelihood(internal_critical, cfg)
    l_exposed, _ = _likelihood(exposed_exploited, cfg)
    assert l_exposed > l_internal


def test_likelihood_is_bounded(cfg):
    row = pd.Series({
        "effective_internet_exposed": True, "actively_exploited": True,
        "ransomware_linked": True, "exploit_available_flag": True,
        "cvss": 10.0, "auth_required_flag": False, "ti_profile_targeted": True,
        "edr_missing": True, "in_kev": True, "kev_ransomware": True,
        "ti_actors": "X", "ti_best_maturity": "Weaponized",
    })
    likelihood, _ = _likelihood(row, cfg)
    assert 0.0 <= likelihood <= 1.0


@pytest.mark.parametrize(("actively_exploited", "ransomware_linked", "exploit_available", "expected_tier"), [
    (True, True, True, "active_and_ransomware"),
    (True, False, True, "actively_exploited"),
    (False, False, True, "poc_exploit_only"),
    (False, False, False, "no_known_exploit"),
])
def test_evidence_tier_precedence(cfg, actively_exploited, ransomware_linked,
                                  exploit_available, expected_tier):
    row = pd.Series({"actively_exploited": actively_exploited,
                     "ransomware_linked": ransomware_linked,
                     "exploit_available_flag": exploit_available})
    tier_name, _value = _evidence_tier(row, cfg["likelihood"]["evidence_tiers"])
    assert tier_name == expected_tier


def test_impact_is_bounded(cfg):
    row = pd.Series({
        "criticality": "Critical", "revenue_impact": "Critical",
        "compliance_scope": "PCI DSS, GDPR", "customer_facing": "Yes",
        "rto_hours": 1, "data_classification": "Payment Card Data",
        "service_dependents": 10, "asset_type": "VPN Gateway",
        "environment": "Production",
    })
    impact, _ = _impact(row, cfg)
    assert 0.0 <= impact <= 1.0


def test_compliance_score_takes_max_across_scopes(cfg):
    c = cfg["impact"]
    assert _compliance_score("SOC 2, PCI DSS", c) == c["compliance_map"]["PCI DSS"]


def test_compliance_score_defaults_on_blank(cfg):
    c = cfg["impact"]
    assert _compliance_score("", c) == c["compliance_default"]
    assert _compliance_score(None, c) == c["compliance_default"]


def test_rto_score_handles_non_numeric_hours(cfg):
    bands = cfg["impact"]["rto_bands"]
    assert _rto_score("not-a-number", bands) == 0.4
    assert _rto_score(None, bands) == 0.4


def test_rto_score_picks_tightest_matching_band(cfg):
    bands = cfg["impact"]["rto_bands"]
    assert _rto_score(1, bands) == bands[0][1]


# --------------------------------------------------------------------------
# rank_top_risks diversity rules, against real scored data
# --------------------------------------------------------------------------
def test_top5_respects_one_cve_per_entry(top5):
    cves = [r["cve"] for r in top5]
    assert len(cves) == len(set(cves))


def test_top5_is_sorted_by_risk_score_descending(top5):
    scores = [r["risk_score"] for r in top5]
    assert scores == sorted(scores, reverse=True)


def test_top5_affected_assets_all_share_the_entrys_cve(scored, top5):
    for entry in top5:
        cve = entry["cve"]
        for a in entry["affected_assets"]:
            matching = scored[(scored["cve"] == cve) & (scored["asset_id"] == a["asset_id"])]
            assert not matching.empty, f"{a['asset_id']} claimed for {cve} but not in scored data"


def test_risk_score_matches_likelihood_times_impact(scored):
    recomputed = (scored["likelihood"] * scored["impact"] * 100).round(1)
    assert (scored["risk_score"] == recomputed).all()
