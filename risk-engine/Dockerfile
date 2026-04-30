FROM python:3.12-slim

WORKDIR /app

# Switch to root for installs
USER root

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements-api.txt* ./
RUN pip install --no-cache-dir \
    flask \
    flask-cors \
    requests \
    PyJWT \
    azure-identity \
    azure-keyvault-secrets

COPY api-server.py .
COPY risk-analyzer.py .

RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/reports && \
    chown -R appuser:appuser /app

USER appuser

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "api-server.py"]