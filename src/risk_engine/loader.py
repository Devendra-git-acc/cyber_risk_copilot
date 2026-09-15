"""Load the raw TawasolPay datasets into DataFrames.

Structured data is loaded and queried with pandas — deliberately NOT embedded.
See README: 'What did you embed vs. what did you query directly?'
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

RAW_FILES = {
    "assets": "assets.csv",
    "vulnerabilities": "vulnerabilities.csv",
    "threat_intel": "threat_intelligence.csv",
    "business_services": "business_services.csv",
    "remediation_hints": "remediation_guidance.csv",
}


@dataclass
class Datasets:
    assets: pd.DataFrame
    vulnerabilities: pd.DataFrame
    threat_intel: pd.DataFrame
    business_services: pd.DataFrame
    remediation_hints: pd.DataFrame
    threat_report_md: str


def load_datasets(raw_dir: str | Path) -> Datasets:
    raw_dir = Path(raw_dir)
    frames = {}
    for key, fname in RAW_FILES.items():
        df = pd.read_csv(raw_dir / fname)
        # Normalise: strip stray whitespace from string cells and headers.
        df.columns = [c.strip() for c in df.columns]
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].str.strip()
        frames[key] = df

    report_path = raw_dir / "synthetic_threat_report.md"
    threat_report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""

    return Datasets(
        assets=frames["assets"],
        vulnerabilities=frames["vulnerabilities"],
        threat_intel=frames["threat_intel"],
        business_services=frames["business_services"],
        remediation_hints=frames["remediation_hints"],
        threat_report_md=threat_report,
    )
