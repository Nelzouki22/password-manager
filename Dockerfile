FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/vault.db \
    LOG_DIR=/data/logs

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser && mkdir /data && chown appuser /data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser . .
USER appuser
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

# ONE worker process: unlocked vault keys are held in that process's memory (see README).
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "app:create_app()"]
