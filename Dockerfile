FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python dependencies and pre-bake spaCy model at build time (zero runtime download)
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && python -m spacy download en_core_web_sm

# Create dedicated non-root user and writable audit log directory
RUN addgroup --system guardian \
    && adduser --system --ingroup guardian guardian \
    && mkdir -p /app/data \
    && chown -R guardian:guardian /app

COPY --chown=guardian:guardian app/ ./app/
COPY --chown=guardian:guardian tests/ ./tests/
COPY --chown=guardian:guardian scripts/ ./scripts/
COPY --chown=guardian:guardian pytest.ini ./pytest.ini

USER guardian

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
