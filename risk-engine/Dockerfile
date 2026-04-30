FROM python:3.12-slim

WORKDIR /app

# Copy only risk-engine files
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

COPY api-server.py .
COPY risk-analyzer.py .

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/reports && \
    chown -R appuser:appuser /app

USER appuser

# Environment
ENV PYTHONUNBUFFERED=1
EXPOSE 5000

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Run API server
CMD ["python", "api-server.py"]