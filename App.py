"""TawasolPay Cyber Risk Copilot — Streamlit UI.

Entry point for `streamlit run app.py` locally and for Hugging Face Spaces
deployment. This file contains NO scoring, retrieval, or agent logic of its
own — it imports risk_engine exactly like scripts/run_stage5.py and only
orchestrates + renders what that engine already computes. See src/risk_engine/
for the actual pipeline.
"""
from __future__ import annotations

import os
import sys
from html import escape as esc
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from risk_engine.agent import build_agent, narrate_risk
from risk_engine.enrich import build_master_table
from risk_engine.kev import fetch_kev, kev_index
from risk_engine.llm import LLMClient
from risk_engine.loader import load_datasets
from risk_engine.nist_catalog import load_or_build_chunks
from risk_engine.observability import check_fallback_rate, configure_logging, metrics
from risk_engine.retriever import NISTRetriever
from risk_engine.score import load_config, rank_top_risks, score_findings
from risk_engine.validate import validate

configure_logging()

st.set_page_config(
    page_title="TawasolPay — Cyber Risk Copilot",
    page_icon="\u25C8",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================================
# DESIGN — a SOC severity-triage instrument, not a generic dashboard.
# Dark slate (not flat near-black) because this genuinely is the vernacular
# of monitoring/SOC tooling, not a default. Severity is a functional 3-stop
# amber->red scale, not decoration — it IS the content. IBM Plex Mono for
# real identifiers (CVE/control IDs/scores), IBM Plex Sans for prose: one
# family, two roles, not an arbitrary pairing. No eyebrow labels, no ALL-CAPS
# chrome, no uniform rounded SaaS-cards — each risk card carries a left edge
# colored by its own severity, doing double duty as structure and signal.
# ============================================================================
STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #0F1720;
    --surface: #161F2C;
    --surface-alt: #1B2532;
    --border: #263142;
    --text: #E7ECF2;
    --text-muted: #93A1B5;
    --text-faint: #5C6B7F;
    --system: #4BB4C0;
    --sev-critical: #E13A4B;
    --sev-high: #E37B2C;
    --sev-medium: #E3B92C;
    --sev-low: #4BB4C0;
}

html, body, [class*="css"] { font-family: 'IBM Plex Sans', -apple-system, sans-serif; }
.stApp { background: var(--bg); color: var(--text); }
[data-testid="stSidebar"] { background: var(--surface); border-right: 1px solid var(--border); }
[data-testid="stHeader"] { background: transparent; }
h1, h2, h3 { font-family: 'IBM Plex Sans', sans-serif; font-weight: 600; color: var(--text); }
p, li, div { color: var(--text); }
code, .mono { font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace; }

/* ---- hero ---- */
.hero { padding: 4px 0 20px 0; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
.hero .org { font-size: 15px; color: var(--text-muted); margin-bottom: 2px; }
.hero .headline { font-size: 30px; font-weight: 600; letter-spacing: -0.02em; line-height: 1.25; }
.hero .sub { font-size: 15px; color: var(--text-muted); margin-top: 6px; max-width: 640px; line-height: 1.5; }

/* ---- status strip ---- */
.status-row { display: flex; gap: 28px; margin: 18px 0 8px 0; flex-wrap: wrap; }
.status-item .num { font-family: 'IBM Plex Mono', monospace; font-size: 26px; font-weight: 600; color: var(--text); line-height: 1; }
.status-item .lbl { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

/* ---- risk card ---- */
.risk-card { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--sev); border-radius: 3px; padding: 20px 22px; margin-bottom: 18px; }
.risk-card .top-row { display: flex; align-items: baseline; gap: 14px; }
.risk-card .rank { font-family: 'IBM Plex Mono', monospace; font-size: 22px; color: var(--text-faint); font-weight: 600; min-width: 28px; }
.risk-card .title { font-size: 18px; font-weight: 600; color: var(--text); flex: 1; }
.risk-card .score { font-family: 'IBM Plex Mono', monospace; font-size: 24px; font-weight: 600; color: var(--sev); }
.risk-card .meta { font-size: 13.5px; color: var(--text-muted); margin: 6px 0 14px 42px; }
.risk-card .meta .cve { font-family: 'IBM Plex Mono', monospace; color: var(--text); }
.chip-row { display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 16px 42px; }
.chip { font-size: 12px; padding: 3px 9px; border-radius: 3px; border: 1px solid var(--border); color: var(--text-muted); background: var(--surface-alt); }
.chip.warn { color: var(--sev-high); border-color: var(--sev-high); }
.chip.danger { color: var(--sev-critical); border-color: var(--sev-critical); }
.chip.ok { color: var(--system); border-color: var(--system); }

/* ---- factor bars ---- */
.bar-block { margin: 0 0 4px 42px; }
.bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; }
.bar-row .blabel { font-size: 12.5px; color: var(--text-muted); width: 168px; flex-shrink: 0; }
.bar-track { flex: 1; height: 7px; background: var(--surface-alt); border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; }
.bar-row .bval { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--text-faint); width: 34px; text-align: right; }

/* ---- narrative ---- narrative content is rendered via plain st.markdown()
   inside a keyed container, not mixed into a hand-built HTML string, so
   Streamlit's own markdown pipeline (bold/bullets) is never in question. */
[class*="st-key-narrative-"] { margin: 4px 0 6px 42px !important; max-width: 760px; }
[class*="st-key-narrative-"] p, [class*="st-key-narrative-"] li { font-size: 14.5px !important; line-height: 1.65; color: var(--text); }
[class*="st-key-narrative-"] strong { color: var(--text); }

.mode-badge { font-family: 'IBM Plex Mono', monospace; font-size: 11px; padding: 2px 8px; border-radius: 3px; margin-left: 42px; display: inline-block; }
.mode-badge.llm { background: rgba(75,180,192,0.12); color: var(--system); border: 1px solid var(--system); }
.mode-badge.template { background: rgba(147,161,181,0.1); color: var(--text-muted); border: 1px solid var(--border); }

.control-block { margin-bottom: 14px; padding-left: 12px; border-left: 2px solid var(--border); }
.control-block .cid { font-family: 'IBM Plex Mono', monospace; color: var(--system); font-weight: 600; font-size: 13.5px; }
.control-block .ctitle { color: var(--text); font-size: 13.5px; margin-left: 6px; }
.control-block .ctext { color: var(--text-muted); font-size: 13px; margin-top: 4px; line-height: 1.5; }

.trace-line { font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; color: var(--text-muted); padding: 3px 0; border-bottom: 1px solid var(--surface-alt); }

.issue-row { padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--sev); border-radius: 3px; margin-bottom: 10px; }
.issue-row .kind { font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; color: var(--text); font-weight: 600; }
.issue-row .detail { font-size: 13.5px; color: var(--text-muted); margin-top: 3px; line-height: 1.5; }
</style>
"""
st.markdown(STYLE, unsafe_allow_html=True)


# ============================================================================
# SEVERITY SCALE
# ============================================================================
def severity_color(score: float) -> str:
    if score >= 80:
        return "var(--sev-critical)"
    if score >= 60:
        return "var(--sev-high)"
    if score >= 35:
        return "var(--sev-medium)"
    return "var(--sev-low)"


def bar(label: str, value: float, color: str = "var(--system)") -> str:
    pct = max(0, min(100, round(value * 100)))
    return (f'<div class="bar-row"><div class="blabel">{label}</div>'
            f'<div class="bar-track"><div class="bar-fill" '
            f'style="width:{pct}%;background:{color}"></div></div>'
            f'<div class="bval">{value:.2f}</div></div>')


# ============================================================================
# CACHED PIPELINE STAGES — deterministic stages (1-3) cache as data and never
# touch an LLM; the retriever + agent cache as resources; only card
# generation is keyed on the API credentials, so changing a key in the
# sidebar correctly invalidates and re-runs narration, nothing else.
# ============================================================================
@st.cache_data(show_spinner=False)
def stage_load_and_score():
    ds = load_datasets(ROOT / "data" / "raw")
    validation = validate(ds)
    kev_catalog, kev_source = fetch_kev(ROOT / "data" / "external" / "kev_snapshot.json")
    master = build_master_table(ds, kev_index(kev_catalog))
    cfg = load_config(ROOT / "config" / "weights.yaml")
    scored = score_findings(master, cfg)
    top5 = rank_top_risks(scored, cfg, report_md=ds.threat_report_md)
    known_actors = set(ds.threat_intel["threat_actor"].dropna().unique()) - {"Unknown"}
    return validation, kev_source, top5, ds.remediation_hints, len(master), known_actors


@st.cache_resource(show_spinner=False)
def stage_retriever():
    persist_dir = ROOT / "data" / "chroma"
    persist_dir.mkdir(parents=True, exist_ok=True)
    chunks = load_or_build_chunks(
        ROOT / "data" / "external" / "nist_oscal_snapshot.json",
        ROOT / "data" / "external" / "nist_chunks.json",
    )
    retriever = NISTRetriever(chunks, persist_dir=str(persist_dir))
    n_controls = len({c["control_id"] for c in chunks})
    return retriever, n_controls, len(chunks)


@st.cache_resource(show_spinner=False)
def stage_agent(api_key: str, base_url: str, model: str, _retriever, _hints, _known_actors):
    llm = LLMClient(api_key=api_key or None, base_url=base_url or None, model=model or None)
    return build_agent(_retriever, _hints, llm, known_actors=_known_actors), llm


@st.cache_data(show_spinner=False)
def stage_cards(_agent, top5: list, cache_key: str):
    progress = st.progress(0.0, text="Starting risk analysis\u2026")
    cards = []
    for i, risk in enumerate(top5):
        progress.progress(
            i / len(top5),
            text=f"Analyzing risk {i + 1} of {len(top5)}: {risk['vulnerability_name'][:48]}\u2026",
        )
        cards.append(narrate_risk(_agent, risk))
    progress.empty()
    return cards


# ============================================================================
# RENDER — risk card
# ============================================================================
def render_risk_card(risk: dict, card: dict) -> None:
    sev = severity_color(risk["risk_score"])
    a, s, t, f = risk["asset"], risk["business_service"], risk["threat_context"], risk["finding"]

    html = [f'<div class="risk-card" style="--sev:{sev}">']
    html.append(
        f'<div class="top-row"><div class="rank">{risk["rank"]:02d}</div>'
        f'<div class="title">{esc(risk["vulnerability_name"])}</div>'
        f'<div class="score">{risk["risk_score"]:.1f}</div></div>'
    )
    assets_txt = esc(", ".join(x["asset_name"] for x in risk["affected_assets"]))
    html.append(
        f'<div class="meta"><span class="cve">{esc(risk["cve"])}</span> \u00b7 '
        f'{assets_txt} \u00b7 {esc(s["name"])}</div>'
    )

    chips = []
    if a["internet_exposed"]:
        chips.append('<span class="chip warn">Internet-exposed</span>')
    if a["exposure_conflict"]:
        chips.append('<span class="chip">Exposure conflict flagged</span>')
    if t["kev_ransomware"] or t["ransomware_linked"]:
        chips.append('<span class="chip danger">Ransomware-linked</span>')
    elif t["in_kev"]:
        chips.append('<span class="chip warn">CISA KEV</span>')
    if t["ti_actors"]:
        chips.append(f'<span class="chip warn">{esc(t["ti_actors"])}</span>')
    if a["edr_missing"]:
        chips.append('<span class="chip warn">No EDR</span>')
    chips.append(
        '<span class="chip ok">Patch available</span>' if f["patch_available"]
        else '<span class="chip">No patch yet</span>'
    )
    html.append(f'<div class="chip-row">{"".join(chips)}</div>')

    html.append('<div class="bar-block">')
    html.append(bar("Likelihood", risk["likelihood"], sev))
    html.append(bar("Impact", risk["impact"], sev))
    html.append("</div>")

    st.markdown("".join(html), unsafe_allow_html=True)

    with st.expander("Show scoring factors"):
        lb, ib = risk["likelihood_breakdown"], risk["impact_breakdown"]
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Likelihood factors**")
            st.markdown(
                bar("Exposure", lb["exposure"]["value"])
                + bar("Exploitation evidence", lb["evidence_tier"]["value"])
                + bar("CVSS multiplier", lb["cvss_multiplier"]["value"])
                + bar("No-auth-required", lb["no_auth_required"]["value"])
                + bar("Profile-targeted", lb["profile_targeted"]["value"])
                + bar("EDR-missing", lb["edr_missing"]["value"]),
                unsafe_allow_html=True,
            )
            st.caption(f"Evidence tier: {lb['evidence_tier']['tier']}")
        with c2:
            st.markdown("**Impact factors**")
            comp = ib["components"]
            st.markdown(
                "".join(bar(k.replace("_", " ").title(), v["score"]) for k, v in comp.items())
                + bar("Dependency cascade", min(ib["dependency_bonus"]["value"] * 4, 1.0))
                + bar("Gateway asset", 1.0 if ib["gateway_asset_bonus"]["applied"] else 0.0),
                unsafe_allow_html=True,
            )
            st.caption(f"Environment modifier: {ib['environment_modifier']['environment']} "
                      f"(\u00d7{ib['environment_modifier']['value']})")

    mode = card["generation_mode"]
    badge_cls, badge_txt = (
        ("llm", "LLM-grounded narration") if mode == "llm_grounded"
        else ("template", "Deterministic template (no LLM configured or grounding failed)")
    )
    st.markdown(f'<div class="mode-badge {badge_cls}">{badge_txt}</div>', unsafe_allow_html=True)
    with st.container(key=f"narrative-{risk['rank']}"):
        st.markdown(card["narrative_md"])

    with st.expander(f"Retrieved NIST SP 800-53 controls ({len(card['retrieved_controls'])})"):
        for c in card["retrieved_controls"]:
            cited = " \u2713 cited" if c["control_id"] in card["cited_controls"] else ""
            st.markdown(
                f'<div class="control-block"><span class="cid">{esc(c["control_id"])}</span>'
                f'<span class="ctitle">{esc(c["title"])}{cited}</span>'
                f'<div class="ctext">{esc(c["statement"][:400])}</div></div>',
                unsafe_allow_html=True,
            )

    with st.expander("How this was retrieved (agent trace)"):
        st.markdown(f'<div class="trace-line">query: {esc(card["retrieval_query"][:200])}</div>',
                    unsafe_allow_html=True)
        for step in card["agent_trace"]:
            st.markdown(f'<div class="trace-line">{esc(step)}</div>', unsafe_allow_html=True)

    excerpt = t.get("mdr_excerpt")
    if excerpt:
        with st.expander("Source: threat actor background (MDR advisory, raw excerpt)"):
            st.caption(f"Background on {t['ti_actors']} from this morning's advisory — "
                      f"describes the actor's general profile; the specific exploit "
                      f"chain named below may target a different CVE than this finding's.")
            st.markdown(esc(excerpt))


# ============================================================================
# RENDER — data quality tab
# ============================================================================
def render_validation_tab(validation: dict, n_findings: int) -> None:
    rc = validation["row_counts"]
    cols = st.columns(5)
    for col, (label, key) in zip(cols, [
        ("Assets", "assets"), ("Vulnerabilities", "vulnerabilities"),
        ("Threat intel", "threat_intel"), ("Business services", "business_services"),
        ("Remediation hints", "remediation_hints"),
    ], strict=True):
        with col:
            st.markdown(f'<div class="status-item"><div class="num">{rc[key]}</div>'
                        f'<div class="lbl">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    s = validation["summary"]
    st.markdown(f"**{s['checks_passed']}/{s['checks_total']}** integrity checks passed \u00b7 "
               f"**{s['issues_found']}** data-quality issues surfaced below (by design \u2014 "
               f"these are planted imperfections the pipeline is meant to catch, not silently fix)")

    sev_color = {"high": "var(--sev-critical)", "medium": "var(--sev-high)",
                "low": "var(--sev-medium)", "info": "var(--system)"}
    for issue in validation["issues"]:
        st.markdown(
            f'<div class="issue-row" style="--sev:{sev_color.get(issue["severity"], "var(--system)")}">'
            f'<div class="kind">{esc(issue["kind"])} \u00b7 {esc(issue["severity"])}</div>'
            f'<div class="detail">{esc(issue["detail"])}</div></div>',
            unsafe_allow_html=True,
        )

    cve = validation["cve_profile"]
    st.caption(f"CVE profile: {cve['real']} real CVEs ({cve['unique_real']} unique), "
              f"{cve['synthetic']} synthetic \u2014 exploitation evidence is layered across both.")


# ============================================================================
# RENDER — about tab
# ============================================================================
def render_about_tab(n_controls: int, n_chunks: int, retriever_mode: str,
                     kev_source: str) -> None:
    st.markdown("""
Five open vulnerabilities become five risk cards through a pipeline that
keeps two kinds of work strictly separate.

**Stages 1-3 are deterministic** \u2014 loading, validating, enriching, and
scoring the structured CSVs (assets, vulnerabilities, threat intel, business
services) is plain pandas joins and arithmetic. No model touches a ranking
decision. Risk is scored as **likelihood \u00d7 impact**, not a flat weighted
sum, so a severe finding on an unreachable internal server can never
outrank a modest finding on an exposed, actively-exploited production
system \u2014 that property holds by construction, not by tuning.

**Stage 4 is retrieval** \u2014 NIST SP 800-53's ~1,000 controls are embedded
once; each risk's evidence (exposure, exploitation signal, missing controls)
builds a query against that index, hybrid BM25 + dense, fused with
reciprocal rank fusion.

**Stage 5 is a bounded, self-correcting agent** \u2014 a LangGraph loop
retrieves, grades its own retrieval, generates a grounded narrative, and
verifies every cited control ID actually came from what was retrieved. A
weak retrieval triggers a rewritten query (capped at 2 attempts); an
ungrounded draft triggers one regeneration; persistent failure falls back to
a deterministic template built from the same evidence \u2014 so a narrative
always ships, and it can never cite a control, or reference a CVE, that
isn't real.

The LLM never decides *what* ranks where. It only explains, with citations,
a ranking it was handed.
""")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("NIST controls indexed", n_controls,
                 help=f"Split into {n_chunks} retrieval chunks — long controls "
                      "are divided so nothing gets silently truncated.")
    with c2:
        st.metric("Retriever mode", retriever_mode.split(" (")[0])
    with c3:
        st.metric("KEV source", "live" if kev_source.startswith("http") else "cached")


# ============================================================================
# MAIN
# ============================================================================
with st.sidebar:
    st.markdown("### Configuration")
    key_input = st.text_input(
        "API key (optional)", type="password",
        placeholder="sk-\u2026 or gsk_\u2026",
        help="Leave blank to use the server's configured key, if any. "
             "Nothing typed here is stored \u2014 it only lives for this session.",
    )
    api_key = key_input or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")

    st.markdown("---")
    st.caption(f"Model: `{model}`")
    st.caption("LLM configured" if api_key else "No LLM key \u2014 narration will use the "
              "deterministic template fallback")
    if st.button("Clear cache & re-run"):
        st.cache_data.clear()
        st.rerun()

    with st.expander("System health (this process)"):
        snap = metrics.snapshot()
        if not snap:
            st.caption("No pipeline events recorded yet this session.")
        else:
            for name, buckets in snap.items():
                labels = ", ".join(f"{k}={v}" for k, v in buckets.items() if k != "total")
                st.caption(f"**{name}**: {buckets['total']}" + (f" ({labels})" if labels else ""))
        st.caption("Counters are per-process and reset on restart — for real "
                  "alerting this feeds ALERT_WEBHOOK_URL, not just this panel.")

validation, kev_source, top5, hints, n_findings, known_actors = stage_load_and_score()
retriever, n_controls, n_chunks = stage_retriever()

st.markdown(
    '<div class="hero"><div class="org">TawasolPay \u00b7 Security Operations</div>'
    '<div class="headline">Top 5 Cyber Risks</div>'
    '<div class="sub">Ranked by likelihood \u00d7 business impact, not raw severity \u2014 '
    'each risk grounded in retrieved NIST SP 800-53 guidance, not a static template.</div>'
    '</div>',
    unsafe_allow_html=True,
)

exposed = sum(1 for r in top5 if r["asset"]["internet_exposed"])
exploited = sum(1 for r in top5 if r["threat_context"]["in_kev"] or r["threat_context"]["ti_actors"])
no_edr = sum(1 for r in top5 if r["asset"]["edr_missing"])
status_items = [
    (str(n_findings), "open findings assessed"),
    (f"{exposed}/5", "top risks internet-exposed"),
    (f"{exploited}/5", "under active exploitation"),
    (f"{no_edr}/5", "missing EDR coverage"),
]
st.markdown(
    '<div class="status-row">' + "".join(
        f'<div class="status-item"><div class="num">{num}</div><div class="lbl">{lbl}</div></div>'
        for num, lbl in status_items
    ) + "</div>",
    unsafe_allow_html=True,
)

tab1, tab2, tab3 = st.tabs(["Top 5 Risks", "Data Quality", "About This System"])

with tab1:
    agent, llm = stage_agent(api_key, base_url, model, retriever, hints, known_actors)
    cards = stage_cards(agent, top5, f"{api_key}:{model}:{base_url}")
    mode_counts: dict[str, int] = {}
    for card in cards:
        mode_counts[card["generation_mode"]] = mode_counts.get(card["generation_mode"], 0) + 1
    check_fallback_rate(mode_counts)
    for risk, card in zip(top5, cards, strict=True):
        render_risk_card(risk, card)

with tab2:
    render_validation_tab(validation, n_findings)

with tab3:
    retriever_mode = getattr(retriever, "mode", "unknown")
    render_about_tab(n_controls, n_chunks, retriever_mode, kev_source)