# syntax=docker/dockerfile:1
#
# Multi-stage build for the Streamlit app.
#   builder: installs deps into a venv, pre-downloads the sentence-transformers
#            embedding model so the dense retriever works offline at runtime
#            and the first request isn't paying a cold-start download.
#   runtime: slim image, non-root user, only what's needed to serve the app.

FROM python:3.10-slim AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Bake the embedding model into the image (~90MB) so the dense retriever
# (retriever.py's hybrid BM25+dense mode) doesn't silently degrade to
# BM25-only on a network-restricted container at first run.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"


FROM python:3.10-slim AS runtime

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOG_FORMAT=json \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    HF_HOME=/home/appuser/.cache/huggingface

COPY --from=builder /opt/venv /opt/venv
# Baked model cache lives under the builder's HOME (root's ~/.cache) --
# copy it to where HF_HOME above points for the unprivileged runtime user.
COPY --from=builder /root/.cache/huggingface /home/appuser/.cache/huggingface

COPY App.py ./
COPY src/ ./src/
COPY config/ ./config/
COPY data/raw/ ./data/raw/
COPY data/external/ ./data/external/
COPY .streamlit/ ./.streamlit/

# data/chroma (the vector index) and outputs/ (generated reports/traces) are
# runtime-generated, not part of the image -- mount them as a volume in
# production so the index survives container restarts instead of being
# rebuilt (from the already-baked model, so still offline-safe) every time.
RUN mkdir -p /app/data/chroma /app/outputs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1

ENTRYPOINT ["streamlit", "run", "App.py"]
