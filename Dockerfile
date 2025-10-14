# =================================================================
# Canary Scanner - Production Docker Configuration
# =================================================================
# Multi-stage build for optimized security and performance
# Features:
# - Non-root user execution
# - Minimal attack surface 
# - Optimized layer caching
# - Health checks
# - Security best practices

# =================================================================
# STAGE 1: Builder - Install dependencies and prepare application
# =================================================================
FROM python:3.11-slim AS builder

# Set metadata labels for better container management
LABEL maintainer="Security Engineering Team"
LABEL version="2.0.0"
LABEL description="Canary Scanner - Secret Detection Tool"

# Set working directory
WORKDIR /app

# Install system dependencies needed for building Python packages
# Combine RUN commands to reduce layers and optimize caching
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better layer caching
# (requirements rarely change compared to source code)
COPY requirements.txt .

# Install Python dependencies to user directory for security
RUN pip install --no-cache-dir --user --upgrade pip \
    && pip install --no-cache-dir --user -r requirements.txt

# =================================================================
# STAGE 2: Production - Create lightweight runtime container
# =================================================================
FROM python:3.11-slim

# Set metadata for production image
LABEL stage="production"
LABEL security.scan="enabled"

# Create non-root user for security best practices
RUN groupadd -r canary && useradd -r -g canary canary

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage (not from system packages)
COPY --from=builder /root/.local /home/canary/.local

# Set ownership before copying application files
RUN chown -R canary:canary /app

# Copy application source code with correct ownership
COPY --chown=canary:canary scanner/ ./scanner/
COPY --chown=canary:canary canary.py .
COPY --chown=canary:canary patterns.yml .

# Switch to non-root user (security requirement)
USER canary

# Set environment variables for optimal Python behavior in containers
ENV PATH=/home/canary/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONIOENCODING=utf-8

# Add health check to ensure scanner is working correctly
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from scanner.patterns import load_patterns; load_patterns('patterns.yml')" || exit 1

# Set default entrypoint and command
# Entrypoint is fixed, CMD can be overridden
ENTRYPOINT ["python", "canary.py"]

# Default command - scan mounted directory with CI mode
CMD ["/scan", "--ci-mode"]

# Document the expected usage
# Example: docker run --rm -v "$(pwd):/scan" canary-scanner /scan --output-json
