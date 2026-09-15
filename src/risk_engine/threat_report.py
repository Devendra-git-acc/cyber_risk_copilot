"""Parse the MDR threat report (synthetic_threat_report.md).

Previously loaded into Datasets.threat_report_md and never read again --
ingested but not used, which is exactly the kind of gap a careful reviewer
would catch. This module makes it load-bearing: each campaign section
becomes a lookup keyed by threat actor name, so a risk whose threat_intel
match names that actor can be grounded in the MDR's own narrative prose
(richer, more specific detail than threat_intelligence.csv's one-line
summary), not just structured fields.
"""
from __future__ import annotations

import re

# Matches "### 1. IronVeil — "CitrixBleed Exploitation"" style headers and
# captures the actor name and everything up to the next "###" heading or the
# "## Threat Intelligence Analyst Notes" section that follows the campaigns.
_CAMPAIGN_PATTERN = re.compile(
    r'^### *\d+\.\s*([A-Za-z][\w]*)\s*[—-]\s*"([^"]*)"\s*\n(.*?)(?=^#{1,6} |\Z)',
    re.MULTILINE | re.DOTALL,
)


def parse_campaigns(report_md: str) -> dict[str, dict]:
    """Return {actor_name: {"campaign_name": str, "excerpt": str}}.

    excerpt is the section body, lightly cleaned (markdown bold markers and
    the IOC block stripped) so it reads as plain prose suitable for an LLM
    prompt or direct display -- not raw markdown.
    """
    campaigns: dict[str, dict] = {}
    for match in _CAMPAIGN_PATTERN.finditer(report_md):
        actor, campaign_name, body = match.group(1), match.group(2), match.group(3)
        body = re.split(r'\n\*\*IOCs:\*\*', body)[0]  # drop the IOC block
        body = re.sub(r'\*\*([^*]+)\*\*', r'\1', body)  # strip bold markers
        body = re.sub(r'\n{2,}', ' ', body).strip()
        body = re.sub(r'\s+', ' ', body)
        body = re.sub(r'\s*-{3,}\s*$', '', body)  # trailing markdown rule, if any
        campaigns[actor] = {"campaign_name": campaign_name, "excerpt": body}
    return campaigns


def get_campaign_excerpt(report_md: str, actor_names: str) -> str:
    """actor_names may be a comma-joined list (as ti_actors stores it, since
    a CVE can have multiple matching intel records). Returns the first
    matching campaign's excerpt, or "" if none of the named actors appear
    in the report."""
    if not actor_names:
        return ""
    campaigns = parse_campaigns(report_md)
    for name in [a.strip() for a in actor_names.split(",")]:
        if name in campaigns:
            return campaigns[name]["excerpt"]
    return ""


def parse_analyst_notes(report_md: str) -> list[str]:
    """The report's own prioritisation guidance -- five numbered factors.
    This is the literal source the scoring config's factor ordering was
    modeled on; parsing it out lets the UI cite the source directly instead
    of only paraphrasing it in a YAML comment."""
    section = re.search(
        r'\*\*Prioritisation guidance:\*\*\s*\n(.*?)(?=\n\*\*Intelligence gaps|\Z)',
        report_md, re.DOTALL,
    )
    if not section:
        return []
    items = re.findall(r'^\d+\.\s*\*\*([^*]+)\*\*\s*[—-]\s*(.+)$',
                       section.group(1), re.MULTILINE)
    return [f"{label.strip()} — {detail.strip()}" for label, detail in items]