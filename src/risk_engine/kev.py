"""Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog.

Fetch order (production instinct: external feeds fail, demos must not):
  1. official cisa.gov feed
  2. CISA's own official GitHub mirror (cisagov/kev-data, synced within minutes)
  3. local cached snapshot committed to the repo

A successful live fetch refreshes the local snapshot.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import requests

from .observability import alert, metrics

log = logging.getLogger(__name__)

KEV_SOURCES = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]


def fetch_kev(snapshot_path: str | Path, timeout: int = 20) -> tuple[dict, str]:
    """Return (kev_catalog, source_used)."""
    snapshot_path = Path(snapshot_path)
    failures: list[str] = []
    for url in KEV_SOURCES:
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            catalog = resp.json()
            if "vulnerabilities" not in catalog:
                raise ValueError("unexpected KEV payload shape")
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot_path.write_text(json.dumps(catalog), encoding="utf-8")
            log.info("KEV fetched live from %s (version %s)", url, catalog.get("catalogVersion"))
            metrics.increment("kev_fetch", source="live")
            return catalog, url
        except Exception as exc:  # noqa: BLE001 - any failure falls through
            log.warning("KEV fetch failed from %s: %s", url, exc)
            failures.append(f"{url}: {exc}")

    catalog = json.loads(snapshot_path.read_text(encoding="utf-8"))
    log.warning("Using cached KEV snapshot (version %s)", catalog.get("catalogVersion"))
    metrics.increment("kev_fetch", source="cached")
    alert(
        "kev_feed_down",
        "All live CISA KEV sources failed; serving cached snapshot -- "
        "exploitation evidence for real CVEs may be stale.",
        catalog_version=catalog.get("catalogVersion"),
        snapshot=str(snapshot_path),
        failures="; ".join(failures),
    )
    return catalog, f"cached snapshot ({snapshot_path.name})"


def kev_index(catalog: dict) -> dict[str, dict]:
    """Index the catalog by cveID for O(1) lookups during enrichment."""
    return {
        entry["cveID"]: {
            "in_kev": True,
            "kev_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "kev_date_added": entry.get("dateAdded", ""),
            "kev_required_action": entry.get("requiredAction", ""),
        }
        for entry in catalog.get("vulnerabilities", [])
    }