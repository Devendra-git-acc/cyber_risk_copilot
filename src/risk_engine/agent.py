"""The LangGraph corrective-RAG agent: retrieval + narration for one risk.

Design principle: deterministic core, agentic edges. The agent operates only
where genuine uncertainty lives — semantic retrieval and text generation —
with bounded self-correction (CRAG/Self-RAG style) and deterministic exits:

    build_query -> retrieve -> grade --(weak, <=2 rewrites)--> build_query
                                  \\--> generate -> verify --(bad citation,
                                       <=1 regenerate)--> generate
                                                      \\--> finalize

Hard guarantees, regardless of LLM behaviour:
- The LLM NEVER ranks risks and NEVER chooses facts — it narrates an evidence
  bundle produced by the deterministic scorer.
- verify is a regex ground-truth check, not an LLM opinion: cited control IDs
  must be a subset of retrieved+graded controls; CVE strings must come from
  the risk itself; any CVSS/risk-score figure mentioned must match this
  finding's actual numbers; any known threat-actor name mentioned must be one
  actually associated with THIS finding (catches the specific misattribution
  risk the GENERATE_SYSTEM prompt warns about: an MDR excerpt naming an actor
  linked to more than one campaign/CVE).
- Every path terminates: on persistent failure or no API key the card is built
  by a deterministic template from the same evidence. The demo cannot hang and
  cannot ship a hallucinated control ID, CVE, threat actor, or figure.
"""
from __future__ import annotations

import json
import re
from typing import TypedDict

from langgraph.graph import END, StateGraph

from .llm import LLMClient, LLMUnavailable
from .observability import alert, metrics

MAX_QUERY_REWRITES = 2
MAX_REGENERATIONS = 1
RETRIEVE_K = 6
_NUMBER_TOLERANCE = 0.05  # rounding/formatting slack, not a real discrepancy

_CITATION = re.compile(r"\[([A-Z]{2}-\d+(?:\.\d+)?)\]")
_CVE_TOKEN = re.compile(r"CVE-[A-Z0-9]+-\d{4}-\d{4,}|CVE-\d{4}-\d{4,}")
_CVSS_MENTION = re.compile(r"CVSS(?:\s+score)?(?:\s+of)?\s*[:\-]?\s*(\d+(?:\.\d+)?)", re.IGNORECASE)
_RISKSCORE_MENTION = re.compile(r"risk\s*score(?:\s+of)?\s*[:\-]?\s*(\d+(?:\.\d+)?)", re.IGNORECASE)


class AgentState(TypedDict, total=False):
    risk: dict
    query: str
    queries: list[str]
    retrieved: list[dict]
    applicable: list[dict]
    grade_sufficient: bool
    suggested_query: str
    rewrites: int
    draft: str
    regenerations: int
    citation_issues: list[str]
    final_card: dict
    used_fallback: bool
    trace: list[str]


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
GRADE_SYSTEM = """You are a security compliance analyst. You will see one \
security risk and candidate NIST SP 800-53 controls retrieved for it. Judge \
which controls are genuinely applicable as remediation/mitigation guidance \
for THIS risk. Respond ONLY with JSON, no prose:
{"applicable_ids": ["SI-2", ...], "sufficient": true|false, "suggested_query": "..."}
sufficient=true when at least two applicable controls cover remediation of the \
finding. If insufficient, propose a better retrieval query in suggested_query."""

GENERATE_SYSTEM = """You are a senior security analyst writing one risk card \
for a technical manager at TawasolPay (Dubai fintech). STRICT RULES:
- Use ONLY the facts provided in the evidence JSON and the NIST controls given.
- Cite NIST controls inline in square brackets, e.g. [SI-2], only from the \
provided list. Cite at least two.
- Never invent numbers, dates, threat actors, CVEs, or controls.
- No CVSS-alone reasoning: explain rank through exposure, exploitation \
evidence, and business impact.
- If evidence.threat_context.mdr_excerpt is non-empty, it is this morning's \
MDR advisory's own background on the matched threat actor (motive, \
objective, dwell time, general behaviour) -- use it for that. The specific \
exploit chain named in the excerpt may describe a DIFFERENT CVE than this \
finding's own CVE if the same actor is linked to more than one; do not \
claim the excerpt's specific technical mechanism (e.g. a named CVE or \
exploit method) applies to this finding unless it matches evidence.cve.
- If evidence.threat_context.kev_required_action is non-empty, treat it as \
CISA's own mandated remediation instruction and reflect it in the actions.
Format (markdown, <=230 words total):
**Why this ranks here** — 2-4 sentences weaving exposure, exploitation \
evidence (KEV/campaigns/ransomware), and business impact (service, revenue, \
compliance, dependencies).
**Recommended actions (NIST SP 800-53)** — 3-5 bullets; each bullet is a \
concrete action grounded in a cited control [ID].
**Urgency** — one sentence using patch availability and days open."""


# ---------------------------------------------------------------------------
# Deterministic template fallback (also the no-API-key path)
# ---------------------------------------------------------------------------
def _trim(text: str, limit: int = 170) -> str:
    """Cut at a word boundary with an ellipsis — no mid-word amputations."""
    text = text.strip()
    if len(text) <= limit:
        return text.rstrip(".") + "."
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(".,;")
    return cut + " …"


def template_card(risk: dict, controls: list[dict]) -> str:
    a, s, t, f = (risk["asset"], risk["business_service"],
                  risk["threat_context"], risk["finding"])
    evidence = []
    if a["internet_exposed"]:
        evidence.append("internet-exposed")
    if t["in_kev"]:
        evidence.append("listed in CISA KEV" + (" with known ransomware use"
                        if t["kev_ransomware"] else ""))
    if t["ti_actors"]:
        evidence.append(f"actively targeted by {t['ti_actors']} "
                        f"({t['ti_maturity']})")
    if a["edr_missing"]:
        evidence.append("no EDR on the asset")
    dep_txt = (f"; {s['dependents']} dependent service(s)" if s["dependents"] else "")
    impact_sentence = str(s["business_impact"]).rstrip(".") + "."
    lines = [
        f"**Why this ranks here** — {risk['vulnerability_name']} ({risk['cve']}) on "
        f"{a['asset_name']} is {', '.join(evidence) or 'a severity-driven finding'}. "
        f"It underpins {s['name']} (revenue impact: {s['revenue_impact']}; "
        f"compliance: {s['compliance_scope']}{dep_txt}). {impact_sentence}",
    ]
    if t.get("mdr_excerpt"):
        lines += ["", f"**Threat actor background ({t['ti_actors']}, MDR advisory)** — "
                     f"{_trim(t['mdr_excerpt'], 280)}"]
    lines += ["", "**Recommended actions (NIST SP 800-53)**"]
    for c in controls[:4]:
        lines.append(f"- [{c['control_id']}] {c['title']}: "
                     f"{_trim(c['statement'] or c['title'])}")
    urgency_bits = [
        "A vendor patch is available" if f["patch_available"]
        else "No vendor patch is available; apply compensating controls"
    ]
    if t.get("kev_required_action"):
        urgency_bits.append(f"CISA KEV requires: {t['kev_required_action'].rstrip('.')}")
    lines += ["", f"**Urgency** — {'; '.join(urgency_bits)}; finding open {f['days_open']} days."]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------
def build_agent(retriever, hints_df, llm: LLMClient | None,
                known_actors: set[str] | None = None):
    """known_actors (optional): every threat-actor name that appears ANYWHERE
    in threat_intelligence.csv, not just this risk's own. Lets verify() catch
    a real actor name that's genuine (not a hallucination in the CVE/control
    sense) but belongs to a DIFFERENT finding — e.g. leaking in from another
    risk's MDR excerpt. Omit it (default None) to skip that specific check;
    every other guarantee is unaffected."""
    from .retriever import build_retrieval_queries

    def _trace(state: AgentState, msg: str) -> list[str]:
        return state.get("trace", []) + [msg]

    # ---- nodes -----------------------------------------------------------
    def node_build_query(state: AgentState) -> AgentState:
        if state.get("suggested_query"):
            queries = [state["suggested_query"]]
            note = f"build_query: rewrite #{state.get('rewrites', 0)}"
        else:
            queries = build_retrieval_queries(state["risk"], hints_df, llm=llm)
            note = (f"build_query: {len(queries)} quer"
                    f"{'y' if len(queries) == 1 else 'ies'} "
                    "(evidence + hint vocabulary, class list and/or LLM expansion)")
        return {"query": " || ".join(queries), "queries": queries,
                "trace": _trace(state, note)}

    def node_retrieve(state: AgentState) -> AgentState:
        hits = retriever.search_multi(state["queries"], k=RETRIEVE_K)
        return {"retrieved": hits,
                "trace": _trace(state, f"retrieve: {len(hits)} controls "
                                       f"[{', '.join(h['control_id'] for h in hits)}]")}

    def node_grade(state: AgentState) -> AgentState:
        retrieved = state["retrieved"]
        if llm and llm.configured:
            try:
                controls_txt = "\n".join(
                    f"- {c['control_id']}: {c['title']} — {c['statement'][:200]}"
                    for c in retrieved)
                risk = state["risk"]
                user = (f"RISK: {risk['vulnerability_name']} ({risk['cve']}) on "
                        f"{risk['asset']['asset_type']} "
                        f"'{risk['asset']['asset_name']}'; threat: "
                        f"{risk['threat_context']['ti_actors'] or 'KEV-listed'}; "
                        f"ransomware={risk['threat_context']['ransomware_linked']}\n"
                        f"CANDIDATE CONTROLS:\n{controls_txt}")
                raw = llm.chat(GRADE_SYSTEM, user, max_tokens=300)
                parsed = json.loads(re.sub(r"```(json)?", "", raw).strip())
                ids = set(parsed.get("applicable_ids", []))
                applicable = [c for c in retrieved if c["control_id"] in ids]
                sufficient = bool(parsed.get("sufficient")) and len(applicable) >= 2
                metrics.increment("agent_node", node="grade", outcome="llm")
                return {"applicable": applicable or retrieved[:4],
                        "grade_sufficient": sufficient,
                        "suggested_query": parsed.get("suggested_query", ""),
                        "trace": _trace(state,
                                        f"grade(LLM): {len(applicable)} applicable, "
                                        f"sufficient={sufficient}")}
            except (LLMUnavailable, json.JSONDecodeError, KeyError) as exc:
                note = f"grade: LLM unavailable/unparseable ({type(exc).__name__}), heuristic"
                metrics.increment("agent_node", node="grade", outcome="degraded")
        else:
            note = "grade: heuristic (no LLM configured)"
            metrics.increment("agent_node", node="grade", outcome="no_llm")
        # Heuristic: retrieval eval showed BM25 top-k is reliable; accept top 4.
        return {"applicable": retrieved[:4], "grade_sufficient": True,
                "trace": _trace(state, note)}

    def route_after_grade(state: AgentState) -> str:
        if (not state["grade_sufficient"]
                and state.get("suggested_query")
                and state.get("rewrites", 0) < MAX_QUERY_REWRITES):
            return "rewrite"
        return "generate"

    def node_count_rewrite(state: AgentState) -> AgentState:
        return {"rewrites": state.get("rewrites", 0) + 1}

    def node_generate(state: AgentState) -> AgentState:
        risk, applicable = state["risk"], state["applicable"]
        if llm and llm.configured:
            try:
                evidence = {k: risk[k] for k in
                            ("rank", "risk_score", "likelihood", "impact", "cve",
                             "vulnerability_name", "cvss", "asset",
                             "business_service", "threat_context", "finding",
                             "affected_assets")}
                controls_txt = "\n".join(
                    f"[{c['control_id']}] {c['title']}\nStatement: "
                    f"{c['statement'][:400]}\nGuidance: {c['guidance'][:300]}"
                    for c in applicable)
                feedback = ""
                if state.get("citation_issues"):
                    feedback = ("\nPREVIOUS DRAFT REJECTED: "
                                + "; ".join(state["citation_issues"])
                                + ". Fix these issues.")
                user = (f"EVIDENCE:\n{json.dumps(evidence, default=str)}\n\n"
                        f"NIST CONTROLS (the ONLY citable controls):\n"
                        f"{controls_txt}{feedback}")
                draft = llm.chat(GENERATE_SYSTEM, user)
                metrics.increment("agent_node", node="generate", outcome="llm")
                return {"draft": draft,
                        "trace": _trace(state, "generate(LLM): draft produced")}
            except LLMUnavailable as exc:
                note = f"generate: LLM unavailable ({exc}), template fallback"
                metrics.increment("agent_node", node="generate", outcome="degraded")
                metrics.increment("narrative_fallback_reason", reason="llm_unavailable")
        else:
            note = "generate: template fallback (no LLM configured)"
            metrics.increment("agent_node", node="generate", outcome="no_llm")
            metrics.increment("narrative_fallback_reason", reason="no_llm_configured")
        return {"draft": template_card(risk, applicable), "used_fallback": True,
                "trace": _trace(state, note)}

    def node_verify(state: AgentState) -> AgentState:
        draft, risk = state["draft"], state["risk"]
        allowed_controls = {c["control_id"] for c in state["applicable"]}
        cited = set(_CITATION.findall(draft))
        allowed_cves = {risk["cve"]} | {
            r["cve"] for r in risk.get("related_findings_same_asset", [])}
        cves_in_draft = set(_CVE_TOKEN.findall(draft))

        issues = []
        if not cited:
            issues.append("no NIST control cited")
        if cited - allowed_controls:
            issues.append(f"cites controls not retrieved: {sorted(cited - allowed_controls)}")
        if cves_in_draft - allowed_cves:
            issues.append(f"mentions CVEs outside this risk: {sorted(cves_in_draft - allowed_cves)}")

        # Numeric ground truth: a cited CVSS/risk-score figure must match this
        # finding's actual numbers, not just "some number the LLM felt like."
        bad_cvss = {float(x) for x in _CVSS_MENTION.findall(draft)
                   if abs(float(x) - float(risk["cvss"])) > _NUMBER_TOLERANCE}
        if bad_cvss:
            issues.append(f"cites a CVSS value ({sorted(bad_cvss)}) that doesn't "
                          f"match this finding's actual CVSS ({risk['cvss']})")
        bad_score = {float(x) for x in _RISKSCORE_MENTION.findall(draft)
                    if abs(float(x) - float(risk["risk_score"])) > _NUMBER_TOLERANCE}
        if bad_score:
            issues.append(f"cites a risk score ({sorted(bad_score)}) that doesn't "
                          f"match this finding's actual score ({risk['risk_score']})")

        # Threat-actor ground truth: mirrors the CVE check above, but for
        # actor names -- catches a real actor name (not a hallucinated one)
        # that belongs to a DIFFERENT finding, e.g. leaking in from an MDR
        # excerpt shared across campaigns.
        if known_actors:
            this_risk_actors = {a.strip() for a in
                                str(risk["threat_context"].get("ti_actors", "")).split(",")
                                if a.strip()}
            mentioned = {a for a in known_actors if a and a in draft}
            foreign_actors = mentioned - this_risk_actors
            if foreign_actors:
                issues.append(f"mentions threat actor(s) not associated with this "
                              f"finding: {sorted(foreign_actors)}")

        # NOTE (observed empirically, not a regression from this change): the
        # deterministic template path can also fail this check, since
        # template_card() echoes threat_context.mdr_excerpt verbatim and that
        # excerpt may legitimately name a CVE belonging to a DIFFERENT
        # finding sharing the same actor (App.py already discloses this to
        # the viewer via a caption). route_after_verify treats the template
        # as ground truth regardless, so this never blocks a card -- but it
        # means agent_verify's fail-rate metric has a nonzero expected
        # baseline from template cards, not just from LLM misbehaviour.
        metrics.increment("agent_verify", outcome="pass" if not issues else "fail")
        return {"citation_issues": issues,
                "trace": _trace(state,
                                "verify: PASS" if not issues
                                else f"verify: FAIL ({'; '.join(issues)})")}

    def route_after_verify(state: AgentState) -> str:
        if not state["citation_issues"]:
            return "finalize"
        if state.get("used_fallback"):
            return "finalize"  # template is ground truth by construction
        if state.get("regenerations", 0) < MAX_REGENERATIONS:
            return "regenerate"
        return "fallback"

    def node_count_regen(state: AgentState) -> AgentState:
        return {"regenerations": state.get("regenerations", 0) + 1}

    def node_fallback(state: AgentState) -> AgentState:
        # Reaching here means the LLM was configured and answered, but kept
        # producing ungrounded drafts through the regeneration budget -- a
        # meaningfully different (worse) signal than "no LLM configured" or
        # "LLM endpoint unreachable", so it gets its own metric label.
        metrics.increment("narrative_fallback_reason", reason="hallucination_after_regen")
        alert(
            "citation_verification_exhausted",
            f"Risk #{state['risk'].get('rank')} ({state['risk'].get('cve')}): LLM draft "
            f"kept failing citation verification through the regeneration budget; "
            f"served the deterministic template instead.",
            issues="; ".join(state.get("citation_issues", [])),
        )
        return {"draft": template_card(state["risk"], state["applicable"]),
                "used_fallback": True, "citation_issues": [],
                "trace": _trace(state, "fallback: deterministic template card")}

    def node_finalize(state: AgentState) -> AgentState:
        risk = state["risk"]
        card = {
            "rank": risk["rank"], "risk_score": risk["risk_score"],
            "cve": risk["cve"], "title": risk["vulnerability_name"],
            "assets": [a["asset_name"] for a in risk["affected_assets"]],
            "business_service": risk["business_service"]["name"],
            "narrative_md": state["draft"],
            "cited_controls": sorted(set(_CITATION.findall(state["draft"]))),
            "retrieved_controls": [
                {"control_id": c["control_id"], "title": c["title"],
                 "family": c["family"], "statement": c["statement"],
                 "guidance": c["guidance"]}
                for c in state["applicable"]],
            "retrieval_query": state["query"],
            "generation_mode": ("template_fallback" if state.get("used_fallback")
                                else "llm_grounded"),
            "agent_trace": state.get("trace", []),
        }
        metrics.increment("card_generated", mode=card["generation_mode"])
        return {"final_card": card}

    # ---- graph -----------------------------------------------------------
    g = StateGraph(AgentState)
    g.add_node("build_query", node_build_query)
    g.add_node("retrieve", node_retrieve)
    g.add_node("grade", node_grade)
    g.add_node("count_rewrite", node_count_rewrite)
    g.add_node("generate", node_generate)
    g.add_node("verify", node_verify)
    g.add_node("count_regen", node_count_regen)
    g.add_node("fallback", node_fallback)
    g.add_node("finalize", node_finalize)

    g.set_entry_point("build_query")
    g.add_edge("build_query", "retrieve")
    g.add_edge("retrieve", "grade")
    g.add_conditional_edges("grade", route_after_grade,
                            {"rewrite": "count_rewrite", "generate": "generate"})
    g.add_edge("count_rewrite", "build_query")
    g.add_edge("generate", "verify")
    g.add_conditional_edges("verify", route_after_verify,
                            {"finalize": "finalize", "regenerate": "count_regen",
                             "fallback": "fallback"})
    g.add_edge("count_regen", "generate")
    g.add_edge("fallback", "finalize")
    g.add_edge("finalize", END)
    return g.compile()


def narrate_risk(agent, risk: dict) -> dict:
    """Run one risk through the compiled agent; returns the final card."""
    result = agent.invoke({"risk": risk, "rewrites": 0, "regenerations": 0,
                           "trace": []})
    return result["final_card"]