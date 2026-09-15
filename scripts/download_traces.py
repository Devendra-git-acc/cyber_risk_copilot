"""Download LangSmith traces to local JSON files for offline debugging.

By default downloads every root trace in LANGSMITH_PROJECT (or --project),
each as one file: outputs/traces/<start_time>_<run_name>_<run_id8>.json,
containing the full run tree (every child span: build_query, retrieve,
grade, generate, verify, llm_chat, ... with their inputs/outputs/timing).

Usage:
    python scripts/download_traces.py                       # last 20 traces
    python scripts/download_traces.py --limit 5
    python scripts/download_traces.py --tag eval             # only tagged runs
    python scripts/download_traces.py --project cyber-risk-copilot-scratch
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from dotenv import load_dotenv

load_dotenv()

from langsmith import Client
from langsmith.schemas import Run


def _run_to_dict(run: Run) -> dict:
    """Full run tree -> plain dict (Run objects aren't directly JSON-safe)."""
    d = {
        "id": str(run.id),
        "name": run.name,
        "run_type": run.run_type,
        "status": run.status,
        "start_time": str(run.start_time) if run.start_time else None,
        "end_time": str(run.end_time) if run.end_time else None,
        "tags": run.tags,
        "error": run.error,
        "inputs": run.inputs,
        "outputs": run.outputs,
        "extra": run.extra,
    }
    if run.child_runs:
        d["child_runs"] = [_run_to_dict(c) for c in run.child_runs]
    return d


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project", default=None, help="defaults to LANGSMITH_PROJECT env var")
    ap.add_argument("--limit", type=int, default=20, help="max root traces to download")
    ap.add_argument("--tag", default=None, help="only download runs with this tag")
    ap.add_argument("--out", default=str(ROOT / "outputs" / "traces"), help="output directory")
    args = ap.parse_args()

    client = Client()
    project_name = (args.project or os.getenv("LANGSMITH_PROJECT")
                    or os.getenv("LANGCHAIN_PROJECT") or "default")
    filter_str = f'has(tags, "{args.tag}")' if args.tag else None

    root_runs = list(client.list_runs(
        project_name=project_name, is_root=True, filter=filter_str, limit=args.limit,
    ))
    if not root_runs:
        print("No traces found.")
        sys.exit(0)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for r in root_runs:
        full = client.read_run(r.id, load_child_runs=True)
        safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in (full.name or "run"))
        ts = str(full.start_time).replace(":", "-").replace(" ", "_").split(".")[0]
        path = out_dir / f"{ts}_{safe_name}_{str(full.id)[:8]}.json"
        path.write_text(json.dumps(_run_to_dict(full), indent=2, default=str), encoding="utf-8")
        n_children = len(full.child_runs) if full.child_runs else 0
        print(f"  saved {path.relative_to(ROOT)}  ({n_children} child spans)")

    print(f"\n{len(root_runs)} trace(s) downloaded to {out_dir.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
