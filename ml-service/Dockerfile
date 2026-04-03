# ─────────────────────────────────────────────
# Trust-Flow ML Service — Dockerfile
# ─────────────────────────────────────────────
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and model
COPY app.py .
COPY model.pkl .

# Non-root user for security
RUN adduser --disabled-password --gecos '' tfuser && chown -R tfuser /app
USER tfuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Run with Gunicorn (4 workers)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "30", "--access-logfile", "-", "app:app"]
