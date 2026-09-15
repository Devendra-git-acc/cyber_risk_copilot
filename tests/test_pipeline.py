"""Stage 1/2 tests: loading, whitespace normalization, enrichment joins, and
validation's planted-imperfection detection.

test_load_datasets_strips_whitespace builds tiny synthetic CSVs in tmp_path
so it doesn't depend on the real dataset's contents; everything else uses
the session fixtures against the real data, since the "planted imperfections"
being checked for (exposure conflicts, synthetic CVEs, TI noise, asset
hygiene gaps) are properties of that specific dataset by design (see
validate.py's module docstring).
"""
from __future__ import annotations

from risk_engine.loader import load_datasets
from risk_engine.validate import validate


def test_load_datasets_strips_whitespace_from_cells_and_headers(tmp_path):
    raw = tmp_path
    (raw / "assets.csv").write_text(
        "asset_id , asset_name\n a-1 , Web Server \n", encoding="utf-8")
    (raw / "vulnerabilities.csv").write_text(
        "vuln_id,asset_id\nv-1,a-1\n", encoding="utf-8")
    (raw / "threat_intelligence.csv").write_text(
        "intel_id,matched_cve_or_control\ni-1,CVE-2024-0001\n", encoding="utf-8")
    (raw / "business_services.csv").write_text(
        "business_service\nPayments\n", encoding="utf-8")
    (raw / "remediation_guidance.csv").write_text(
        "finding_type,recommended_action\nRCE,Patch\n", encoding="utf-8")

    ds = load_datasets(raw)
    assert ds.assets.columns.tolist() == ["asset_id", "asset_name"]
    assert ds.assets.loc[0, "asset_id"] == "a-1"
    assert ds.assets.loc[0, "asset_name"] == "Web Server"
    assert ds.threat_report_md == ""  # no synthetic_threat_report.md in tmp_path


def test_validate_detects_exposure_conflict(datasets):
    report = validate(datasets)
    kinds = {i["kind"] for i in report["issues"]}
    assert "exposure_conflict" in kinds


def test_validate_detects_synthetic_cves(datasets):
    report = validate(datasets)
    assert report["cve_profile"]["synthetic"] > 0
    assert report["cve_profile"]["synthetic"] + report["cve_profile"]["real"] \
        == len(datasets.vulnerabilities)


def test_validate_summary_counts_are_consistent(datasets):
    report = validate(datasets)
    s = report["summary"]
    assert s["checks_total"] == len(report["checks"])
    assert s["checks_passed"] == sum(1 for c in report["checks"] if c["passed"])
    assert s["issues_found"] == len(report["issues"])


def test_master_table_effective_exposure_is_worst_case(master):
    """enrich.py's stated policy: on a conflict, treat as internet-exposed
    (worst case). Any row flagged exposure_conflict must therefore also be
    effective_internet_exposed."""
    conflicted = master[master["exposure_conflict"]]
    if not conflicted.empty:
        assert conflicted["effective_internet_exposed"].all()


def test_master_table_has_one_row_per_open_finding(datasets, master):
    open_vulns = datasets.vulnerabilities[
        datasets.vulnerabilities["status"].str.lower().isin({"open", "in progress"})
    ]
    assert len(master) == len(open_vulns)


def test_master_table_actively_exploited_implies_kev_or_mature_ti(master):
    flagged = master[master["actively_exploited"]]
    assert (
        flagged["in_kev"]
        | flagged["ti_best_maturity"].isin(
            ["Weaponized", "Active Exploitation", "Commodity Exploit"])
    ).all()
