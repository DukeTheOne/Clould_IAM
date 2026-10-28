# ==============================================================================
# Uncertainty-Aware Least-Privilege Repair for Cloud IAM under Partial Observability
# Artifact Evaluation & Reproducibility Container (USENIX Security / IEEE S&P Badging)
# ==============================================================================

FROM python:3.11-slim

LABEL maintainer="Duke <jack618618@gmail.com>"
LABEL description="Reproducible research artifact container for IAM graph learning & policy repair"
LABEL version="1.0.0"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/root/.cargo/bin:/app/.venv/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    bash \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv for deterministic dependency locking
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Set working directory
WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install Python dependencies using uv
RUN uv sync --frozen --all-extras

# Copy complete repository contents
COPY . .

# Ensure executable permissions on reproduction script
RUN chmod +x ./reproduce_results.sh

# Default entrypoint runs fast verification smoke suite
ENTRYPOINT ["/bin/bash", "./reproduce_results.sh"]
CMD ["--fast"]
