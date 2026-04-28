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

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run API server
CMD ["python", "api-server.py"]