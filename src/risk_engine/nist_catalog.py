"""Download and parse NIST SP 800-53 Rev 5 into retrieval chunks.

Source: NIST's official OSCAL content repository on GitHub (usnistgov/oscal-content)
— the machine-readable form of the actual publication, NOT a summary CSV and NOT
LLM training memory.

Chunking: a control's STATEMENT often has genuine sub-requirements NIST's own
authors wrote as separate parts (verified empirically: 58% of controls have
2+ statement items, up to 21 for AC-2) — these are preserved as real
boundaries, not flattened away. GUIDANCE has no such structure (verified:
every control's guidance is one continuous prose block), so it's left to the
splitter's own sentence/paragraph logic. A real text splitter (not a hand
rolled character slice) then packs these pieces into the embedding model's
ACTUAL token window, using its real tokenizer when available -- falling back
to a character-based version of the same splitter (same structural
preference, no model download needed) if sentence-transformers or the model
can't be loaded, e.g. no network. Same resilience pattern as the rest of
this codebase: dense retrieval -> BM25, LLM -> template, here: exact
tokenizer -> character approximation.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import requests

log = logging.getLogger(__name__)

NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# OSCAL prose embeds parameter/insertion markup; strip to readable text.
_ODP_PATTERN = re.compile(r"\{\{\s*insert:\s*param,\s*([^}]+?)\s*\}\}")


def fetch_catalog(snapshot_path: str | Path, timeout: int = 60) -> dict:
    snapshot_path = Path(snapshot_path)
    try:
        resp = requests.get(NIST_OSCAL_URL, timeout=timeout)
        resp.raise_for_status()
        catalog = resp.json()
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(json.dumps(catalog), encoding="utf-8")
        log.info("NIST catalog fetched live (version %s)",
                 catalog["catalog"]["metadata"]["version"])
        return catalog
    except Exception as exc:  # noqa: BLE001
        log.warning("NIST live fetch failed (%s); using cached snapshot", exc)
        return json.loads(snapshot_path.read_text(encoding="utf-8"))


def _clean(prose: str) -> str:
    prose = _ODP_PATTERN.sub("[organization-defined value]", prose)
    return re.sub(r"\s+", " ", prose).strip()


def _collect_prose(part: dict) -> list[str]:
    """Recursively collect prose from a part and its nested items."""
    out = []
    if part.get("prose"):
        out.append(_clean(part["prose"]))
    for sub in part.get("parts", []):
        if sub.get("name") in {"statement", "item", "guidance"}:
            out.extend(_collect_prose(sub))
    return out


def _is_withdrawn(control: dict) -> bool:
    return any(
        p.get("name") == "status" and p.get("value") == "withdrawn"
        for p in control.get("props", [])
    )


def _build_splitter():
    """Exact, model-aware splitter when the real embedding model can be
    loaded; a character-based splitter with the same structural preference
    (blank line, then sentence, then word) when it can't. tokens_per_chunk
    is set below the model's real 256-token max to leave room for the
    control_id+title prefix added to every resulting piece afterward."""
    try:
        from langchain_text_splitters import SentenceTransformersTokenTextSplitter
        splitter = SentenceTransformersTokenTextSplitter(
            model_name=EMBED_MODEL_NAME, chunk_overlap=20, tokens_per_chunk=240,
        )
        log.info("chunking: exact tokenizer (%s, max %d tokens)",
                 EMBED_MODEL_NAME, splitter.maximum_tokens_per_chunk)
        return splitter
    except Exception as exc:  # noqa: BLE001
        log.warning("Exact tokenizer splitter unavailable (%s); "
                    "falling back to character-based splitting", exc)
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        return RecursiveCharacterTextSplitter(
            chunk_size=1000, chunk_overlap=100,
            separators=["\n\n", ". ", " ", ""], keep_separator=False,
        )


def _control_to_chunks(control: dict, family: str, splitter) -> list[dict]:
    if _is_withdrawn(control):
        return []
    statement_items, guidance_items = [], []
    for part in control.get("parts", []):
        if part.get("name") == "statement":
            statement_items.extend(_collect_prose(part))
        elif part.get("name") == "guidance":
            guidance_items.extend(_collect_prose(part))
    statement_txt = " ".join(statement_items)
    guidance_txt = " ".join(guidance_items)
    if not statement_txt and not guidance_txt:
        return []
    control_id = control["id"].upper().replace("SMT", "").strip()
    title = control["title"]

    # Blank-line join: NIST's own item boundaries become the splitter's
    # preferred cut points (its separator hierarchy tries "\n\n" first),
    # so small adjacent requirements get packed together and only a
    # genuinely oversized control (AC-2's 21 items) gets cut mid-list.
    body = "\n\n".join(statement_items)
    if guidance_txt:
        body = f"{body}\n\n{guidance_txt}" if body else guidance_txt

    prefix = f"{control_id} {title}. "
    raw_pieces = splitter.split_text(body) if body else [""]
    # Defensive: strip any stray leading punctuation a splitter's separator
    # handling might leave behind (verified needed for the fallback path;
    # protects the exact-tokenizer path the same way even though that one
    # can't be exercised in this environment -- see module docstring).
    pieces = [re.sub(r"^[\s.,;:]+", "", p) for p in raw_pieces if p.strip()]

    return [
        {
            "control_id": control_id,
            "title": title,
            "family": family,
            # Full text, unaffected by chunking -- every piece can cite and
            # display the complete control regardless of which piece matched.
            "statement": statement_txt,
            "guidance": guidance_txt,
            "chunk_index": i,
            "chunk_count": len(pieces),
            "search_text": f"{prefix}{piece}".strip(),
        }
        for i, piece in enumerate(pieces)
    ]


def build_chunks(catalog: dict) -> list[dict]:
    splitter = _build_splitter()
    chunks: list[dict] = []
    for group in catalog["catalog"]["groups"]:
        family = group["title"]
        for control in group.get("controls", []):
            chunks.extend(_control_to_chunks(control, family, splitter))
            for enh in control.get("controls", []):  # enhancements, e.g. AC-2.1
                chunks.extend(_control_to_chunks(enh, family, splitter))
    return chunks


def load_or_build_chunks(snapshot_path: str | Path, chunks_path: str | Path) -> list[dict]:
    chunks_path = Path(chunks_path)
    if chunks_path.exists():
        return json.loads(chunks_path.read_text(encoding="utf-8"))
    catalog = fetch_catalog(snapshot_path)
    chunks = build_chunks(catalog)
    chunks_path.parent.mkdir(parents=True, exist_ok=True)
    chunks_path.write_text(json.dumps(chunks), encoding="utf-8")
    return chunks