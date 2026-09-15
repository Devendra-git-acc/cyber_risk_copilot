"""Hybrid retrieval over the NIST 800-53 control catalog.

Two complementary backends, fused with Reciprocal Rank Fusion (RRF):
- BM25 (lexical): NIST control language is exact-terminology-heavy
  ("flaw remediation", "least functionality"); keyword match is strong here.
- Dense embeddings (semantic, sentence-transformers + ChromaDB): bridges
  vocabulary gaps ("patch the VPN" -> SI-2 Flaw Remediation).

The dense backend is optional at runtime: if the embedding model cannot be
loaded (offline environment), the retriever degrades gracefully to BM25-only
and reports its mode — never crashes, never silently changes behaviour.

Query construction is deterministic and evidence-driven. The provided
remediation_guidance.csv is used exactly as the assignment intends — 'a hint,
not the answer': its action vocabulary enriches the retrieval query; it is
never surfaced as remediation output.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from rank_bm25 import BM25Okapi

from .observability import alert, metrics

log = logging.getLogger(__name__)

_TOKEN = re.compile(r"[a-z0-9][a-z0-9\-\.]+")
# Standard English stopword list (the widely-used scikit-learn /
# "Glasgow Information Retrieval Group" list), embedded directly so this file
# has no runtime dependency on scikit-learn or NLTK just for a static list of
# function words, and keeps working fully offline like the rest of this
# retriever. Replaces an earlier hand-typed 28-word version that was missing
# 258 common words ("about", "after", "already", "also", "although", "can"...)
# which were leaking through as real BM25 search terms.
_STOP = frozenset({
    "a", "about", "above", "across", "after", "afterwards", "again", "against",
    "all", "almost", "alone", "along", "already", "also", "although", "always",
    "am", "among", "amongst", "amoungst", "amount", "an", "and", "another",
    "any", "anyhow", "anyone", "anything", "anyway", "anywhere", "are", "around",
    "as", "at", "back", "be", "became", "because", "become", "becomes",
    "becoming", "been", "before", "beforehand", "behind", "being", "below", "beside",
    "besides", "between", "beyond", "bill", "both", "bottom", "but", "by",
    "call", "can", "cannot", "cant", "co", "con", "could", "couldnt",
    "cry", "de", "describe", "detail", "do", "done", "down", "due",
    "during", "each", "eg", "eight", "either", "eleven", "else", "elsewhere",
    "empty", "enough", "etc", "even", "ever", "every", "everyone", "everything",
    "everywhere", "except", "few", "fifteen", "fifty", "fill", "find", "fire",
    "first", "five", "for", "former", "formerly", "forty", "found", "four",
    "from", "front", "full", "further", "get", "give", "go", "had",
    "has", "hasnt", "have", "he", "hence", "her", "here", "hereafter",
    "hereby", "herein", "hereupon", "hers", "herself", "him", "himself", "his",
    "how", "however", "hundred", "i", "ie", "if", "in", "inc",
    "indeed", "interest", "into", "is", "it", "its", "itself", "keep",
    "last", "latter", "latterly", "least", "less", "ltd", "made", "many",
    "may", "me", "meanwhile", "might", "mill", "mine", "more", "moreover",
    "most", "mostly", "move", "much", "must", "my", "myself", "name",
    "namely", "neither", "never", "nevertheless", "next", "nine", "no", "nobody",
    "none", "noone", "nor", "not", "nothing", "now", "nowhere", "of",
    "off", "often", "on", "once", "one", "only", "onto", "or",
    "other", "others", "otherwise", "our", "ours", "ourselves", "out", "over",
    "own", "part", "per", "perhaps", "please", "put", "rather", "re",
    "same", "see", "seem", "seemed", "seeming", "seems", "serious", "several",
    "she", "should", "show", "side", "since", "sincere", "six", "sixty",
    "so", "some", "somehow", "someone", "something", "sometime", "sometimes", "somewhere",
    "still", "such", "system", "take", "ten", "than", "that", "the",
    "their", "them", "themselves", "then", "thence", "there", "thereafter", "thereby",
    "therefore", "therein", "thereupon", "these", "they", "thick", "thin", "third",
    "this", "those", "though", "three", "through", "throughout", "thru", "thus",
    "to", "together", "too", "top", "toward", "towards", "twelve", "twenty",
    "two", "un", "under", "until", "up", "upon", "us", "very",
    "via", "was", "we", "well", "were", "what", "whatever", "when",
    "whence", "whenever", "where", "whereafter", "whereas", "whereby", "wherein", "whereupon",
    "wherever", "whether", "which", "while", "whither", "who", "whoever", "whole",
    "whom", "whose", "why", "will", "with", "within", "without", "would",
    "yet", "you", "your", "yours", "yourself", "yourselves",
})


def _tokenize(text: str) -> list[str]:
    tokens = []
    for t in _TOKEN.findall(text.lower()):
        if t in _STOP or len(t) <= 2:
            continue
        # Light suffix stemming so 'authorizations'~'authorization',
        # 'enforce'~'enforcement' co-rank in BM25. Crude but effective;
        # dense retrieval is unaffected.
        for suffix in ("ations", "ation", "ments", "ment", "ings", "ing",
                       "ies", "es", "ed", "s"):
            if t.endswith(suffix) and len(t) - len(suffix) >= 4:
                t = t[: -len(suffix)]
                break
        tokens.append(t)
    return tokens


class NISTRetriever:
    def __init__(self, chunks: list[dict], persist_dir: str | None = None):
        self.chunks = chunks
        self._bm25 = BM25Okapi([_tokenize(c["search_text"]) for c in chunks])
        self._dense = self._try_init_dense(persist_dir) if persist_dir else None
        self.mode = "hybrid (BM25 + dense, RRF-fused)" if self._dense else "BM25-only (lexical)"
        log.info("NISTRetriever ready: %d controls, mode=%s", len(chunks), self.mode)

    # ---- dense backend (optional) ---------------------------------------
    def _try_init_dense(self, persist_dir: str):
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
            client = chromadb.PersistentClient(path=persist_dir)
            coll = client.get_or_create_collection(
                "nist_800_53", metadata={"hnsw:space": "cosine"}
            )
            if coll.count() != len(self.chunks):
                # Unique per CHUNK now, not per control -- a control can
                # have multiple chunks since the chunking rewrite.
                ids = [f"{c['control_id']}::{c['chunk_index']}" for c in self.chunks]
                embeddings = model.encode(
                    [c["search_text"] for c in self.chunks],
                    batch_size=64, show_progress_bar=False,
                ).tolist()
                # rebuild deterministically
                if coll.count():
                    client.delete_collection("nist_800_53")
                    coll = client.get_or_create_collection(
                        "nist_800_53", metadata={"hnsw:space": "cosine"}
                    )
                coll.add(ids=ids, embeddings=embeddings,
                         documents=[c["search_text"] for c in self.chunks])
            metrics.increment("retriever_backend_init", backend="dense", status="success")
            return {"model": model, "collection": coll}
        except Exception as exc:  # noqa: BLE001
            log.warning("Dense backend unavailable (%s); BM25-only mode", exc)
            metrics.increment("retriever_backend_init", backend="dense", status="failed")
            alert(
                "dense_retrieval_unavailable",
                "Embedding model / Chroma unavailable; retriever degraded to "
                "BM25-only (lexical) mode -- semantic recall for vocabulary "
                "mismatches (e.g. 'patch the VPN' -> SI-2) is lost for this run.",
                error=str(exc),
            )
            return None

    # ---- search -----------------------------------------------------------
    def search(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        return self.search_multi([query], k=k)

    def search_multi(self, queries: list[str], k: int = 5) -> list[dict[str, Any]]:
        """Multi-query retrieval: each query is ranked by every backend and all
        rankings are RRF-fused. A focused vulnerability-class query prevents the
        broad evidence query (patching, monitoring, ...) from drowning out
        class-specific controls (e.g. AC-3 for an authorization flaw)."""
        pool = max(k * 4, 20)
        ranked_lists: list[list[int]] = []
        for query in queries:
            ranked_lists.append(self._bm25_rank(query, pool))
            if self._dense:
                ranked_lists.append(self._dense_rank(query, pool))

        fused = self._rrf(ranked_lists)
        results = []
        seen_controls: set[str] = set()
        for idx, rrf_score in fused:
            c = self.chunks[idx]
            if c["control_id"] in seen_controls:
                continue  # a control can span multiple chunks now; keep
                          # only its best (highest-fused-rank) chunk
            seen_controls.add(c["control_id"])
            results.append({
                "control_id": c["control_id"],
                "title": c["title"],
                "family": c["family"],
                "statement": c["statement"],
                "guidance": c["guidance"],
                "rrf_score": round(rrf_score, 4),
            })
            if len(results) >= k:
                break
        return results

    def _bm25_rank(self, query: str, pool: int) -> list[int]:
        scores = self._bm25.get_scores(_tokenize(query))
        order = sorted(range(len(scores)), key=lambda i: -scores[i])
        return [i for i in order[:pool] if scores[i] > 0]

    def _dense_rank(self, query: str, pool: int) -> list[int]:
        emb = self._dense["model"].encode([query]).tolist()
        res = self._dense["collection"].query(query_embeddings=emb, n_results=pool)
        # Chroma IDs are per-chunk ("control_id::chunk_index"), matching how
        # they were written in _try_init_dense -- not the control_id alone.
        id_to_idx = {f"{c['control_id']}::{c['chunk_index']}": i
                    for i, c in enumerate(self.chunks)}
        return [id_to_idx[cid] for cid in res["ids"][0] if cid in id_to_idx]

    @staticmethod
    def _rrf(ranked_lists: list[list[int]], k: int = 60) -> list[tuple[int, float]]:
        scores: dict[int, float] = {}
        for ranking in ranked_lists:
            for rank, idx in enumerate(ranking):
                scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + rank + 1)
        return sorted(scores.items(), key=lambda kv: -kv[1])


# --------------------------------------------------------------------------
# Query construction from a scored risk entry
# --------------------------------------------------------------------------
# Deterministic vulnerability-class -> NIST vocabulary map. BM25/dense retrieval
# needs the *control language* for the flaw class, not just its product name:
# an IDOR is an authorization failure (AC-3/AC-6/SI-10 territory), not a
# patching story. Matched on the vulnerability name; first match wins.
VULN_CLASS_VOCAB = [
    (re.compile(r"insecure direct object|authoriz|idor|privilege", re.I),
     "enforce approved authorizations logical access enforcement least privilege information input validation"),
    (re.compile(r"session token|session leak|session hijack", re.I),
     "session authenticity invalidate session identifiers session termination"),
    (re.compile(r"admin (api|interface)|exposed.*(admin|management)|management interface", re.I),
     "least functionality boundary protection restrict management interface disable nonessential"),
    (re.compile(r"sql injection|command injection|xss|cross-site|deserializ", re.I),
     "information input validation error handling"),
    (re.compile(r"default (credential|password)|weak password|hardcoded", re.I),
     "authenticator management password-based authentication account management"),
    (re.compile(r"end[- ]of[- ]life|unsupported|legacy", re.I),
     "unsupported system components replacement"),
    (re.compile(r"misconfig|open (bucket|share)|public (bucket|storage)", re.I),
     "configuration settings least functionality baseline configuration"),
]


def match_remediation_hint(vuln_name: str, component: str, hints) -> str:
    """Best-overlap hint row; its action vocabulary expands the query."""
    target = set(_tokenize(f"{vuln_name} {component}"))
    best_row, best_overlap = None, 0
    for _, row in hints.iterrows():
        overlap = len(target & set(_tokenize(str(row["finding_type"]))))
        if overlap > best_overlap:
            best_row, best_overlap = row, overlap
    return str(best_row["recommended_action"]) if best_row is not None else ""


def build_retrieval_queries(risk: dict, hints, llm=None) -> list[str]:
    """Deterministic, evidence-driven queries for NIST control retrieval.
    Returns [broad evidence query] + optionally [focused class query]
    + optionally [LLM-expanded query].

    VULN_CLASS_VOCAB above is a fixed, hand-written list of 7 patterns. It is
    a free zero-cost fast path for the handful of vulnerability types we
    anticipated, NOT a complete taxonomy — measured on this project's own
    114 findings, it matches only 21/96 distinct vulnerability names (and
    misses 2 of the actual top-5 risks: "Remote Code Execution in Web
    Framework" and "Fortinet FortiOS Authentication Bypass"). Enumerating
    more regex patterns does not scale to real-world vulnerability naming,
    which is open-ended free text.

    `llm` (optional) is the fix: instead of matching a vulnerability against
    a hand list, ask the model once to translate it into NIST vocabulary —
    generative, not enumerated, so it covers types we never anticipated.
    Only called when the hand list above actually missed (class_vocab is
    empty) -- measured in a live trace costing 5+ seconds for no real gain
    when the free list already matched, so it's skipped entirely there, not
    just when llm=None (the default, used by scripts/run_stage4.py's keyless
    retrieval eval and by tests). Either way every deterministic query below
    is built regardless.
    """
    parts = [risk["vulnerability_name"], risk["finding"]["affected_component"],
             risk["asset"]["asset_type"]]
    class_vocab = ""
    for pattern, vocab in VULN_CLASS_VOCAB:
        if pattern.search(risk["vulnerability_name"]):
            class_vocab = vocab
            parts.append(vocab)
            break
    if risk["finding"]["patch_available"]:
        parts.append("flaw remediation security patches software updates")
    if risk["threat_context"]["ransomware_linked"]:
        parts.append("incident handling response malicious code")
    if risk["asset"]["edr_missing"]:
        parts.append("system monitoring endpoint detection")
    if not risk["finding"]["auth_required"]:
        parts.append("remote access boundary protection")
    hint = match_remediation_hint(
        risk["vulnerability_name"], risk["finding"]["affected_component"], hints
    )
    if hint:
        parts.append(hint)
    queries = [" ".join(parts)]
    if class_vocab:
        queries.append(f"{risk['vulnerability_name']} {class_vocab}")

    # LLM vocabulary expansion is comparatively expensive (a real round-trip,
    # confirmed in a live trace to cost 5+ seconds) -- only worth paying for
    # when the free deterministic list actually missed. Calling it
    # unconditionally was measured wasting that cost on risks the hand list
    # already covered (e.g. "Insecure Direct Object Reference" -> the LLM's
    # own answer largely restated the free match).
    if llm is not None and not class_vocab:
        expanded = _expand_vocabulary_with_llm(risk, llm)
        if expanded:
            queries.append(f"{risk['vulnerability_name']} {expanded}")

    return queries


def _expand_vocabulary_with_llm(risk: dict, llm) -> str:
    """One cheap, best-effort call: 'what NIST vocabulary addresses this
    vulnerability type'. Never the only source of a query — returns "" (and
    the caller silently proceeds without it) if unconfigured or on any
    failure, so this can never be the reason retrieval breaks."""
    from .llm import LLMUnavailable

    if not llm.configured:
        return ""
    try:
        prompt = (
            f"Vulnerability: {risk['vulnerability_name']}\n"
            f"Affected component: {risk['finding']['affected_component']}\n\n"
            "In 10-15 words, name the NIST SP 800-53 control family and key "
            "terms that address this specific vulnerability type (e.g. "
            "'access enforcement least privilege authorization' for an IDOR; "
            "'session authenticity invalidate session identifiers' for a "
            "session-token flaw). Words only — no explanation, no control IDs."
        )
        return llm.chat("NIST 800-53 vocabulary lookup.", prompt, max_tokens=40).strip()
    except LLMUnavailable:
        return ""


def build_retrieval_query(risk: dict, hints) -> str:
    """Primary (broad) query — kept for compatibility and logging."""
    return build_retrieval_queries(risk, hints)[0]