# Multi-stage build for LUKi Security & Privacy Module
FROM python:3.11-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy Railway-optimised requirements and install dependencies
COPY requirements-railway.txt .
RUN pip install --no-cache-dir -r requirements-railway.txt

# Production stage
FROM python:3.11-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 8000

# Health check - use httpx (installed via requirements) and respect PORT when provided
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD python -c "import httpx, os; httpx.get(f'http://127.0.0.1:{os.getenv(\"PORT\", \"8000\")}/health', timeout=5)" || exit 1

# Start command - bind to Railway-provided PORT if set, otherwise default to 8000
CMD ["sh", "-c", "uvicorn luki_sec.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
