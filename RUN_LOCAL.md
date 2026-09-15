# Run locally (5 minutes)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...        # your key (or LLM_API_KEY / LLM_BASE_URL / LLM_MODEL for Groq etc.)

python scripts/smoke_llm.py         # live LLM path: one risk through the agent
pytest                              # full test suite (was: python tests/test_agent.py)
python scripts/run_stage3.py        # scoring engine + 7 sanity tests
python scripts/run_stage4.py        # NIST retrieval eval (5/5 expected)
python scripts/run_stage5.py        # FULL pipeline -> outputs/risk_report.md

streamlit run App.py                # the actual UI
```

## Dev setup (tests + lint)

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest                              # 50+ tests: score/enrich/validate units,
                                     # retriever/tokenizer units, agent graph
                                     # control-flow (mock LLMs), observability
pytest --cov=risk_engine --cov-report=term-missing   # coverage
ruff check .                        # lint (matches CI)
```

## Docker

```bash
docker build -t cyber-risk-copilot .
docker run -p 8501:8501 --env-file .env cyber-risk-copilot
```
The image bakes in the sentence-transformers embedding model at build time
(so dense retrieval works even on a network-restricted host) and ships a
non-root user + a `/_stcore/health` healthcheck. `data/chroma/` (the vector
index) and `outputs/` are runtime-generated; mount them as volumes in
production so they survive container restarts.

## Observability

`LOG_LEVEL` (default `INFO`) and `LOG_FORMAT` (`text` or `json`, default
`text`; the Dockerfile sets `json`) control logging. Every degradation path
(CISA KEV live-feed failure, dense-retrieval unavailable, LLM call failures,
persistent citation-verification failure, a batch's template-fallback rate
crossing 50%) is both logged and counted in an in-process metrics registry —
visible in the app's sidebar under "System health," and in the logs/CI
output. Set `ALERT_WEBHOOK_URL` to a Slack-compatible incoming webhook to
also ship those as alerts; unset, they still log at WARNING/ERROR.

Notes
- First run downloads the sentence-transformers model (~90MB) and builds the
  Chroma index; retriever mode should then read "hybrid (BM25 + dense, RRF-fused)".
- Without an API key everything still runs; cards are built by the deterministic
  template (generation_mode: template_fallback).
- Free-tier alternative to OpenAI (assignment-compliant):
  export LLM_BASE_URL=https://api.groq.com/openai/v1
  export LLM_MODEL=openai/gpt-oss-120b   # check console.groq.com/docs/models -- Groq's
                                          # lineup changes over time, confirm before assuming
  export LLM_API_KEY=gsk_...
- Tracing (optional, off by default): set these to see every agent step
  (build_query -> retrieve -> grade -> generate -> verify) plus the raw LLM
  call as a run tree at smith.langchain.com — get a free key there first.
  export LANGSMITH_TRACING=true
  export LANGSMITH_API_KEY=lsv2_...
  export LANGSMITH_PROJECT=cyber-risk-copilot   # optional, groups runs
