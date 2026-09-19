# Prowler MCP Server
# Cloud security assessment for AWS, Azure, GCP

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Prowler MCP Server - Cloud security assessment"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Create non-root user
RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Prowler in its own venv, isolated from the MCP server's
# dependencies. prowler==4.3.0 hard-pins pydantic==1.10.15, while the MCP
# library below requires pydantic>=2 — installing both into the same
# site-packages breaks prowler's schema generation at runtime (verified:
# `prowler --version` crashes with PydanticSchemaGenerationError). The venv's
# bin/ is added to PATH so the bare `prowler` command still resolves, but its
# shebang pins it to this venv's own interpreter and dependencies.
ARG PROWLER_VERSION=4.3.0
RUN python3 -m venv /opt/prowler-venv && \
    /opt/prowler-venv/bin/pip install --no-cache-dir prowler==${PROWLER_VERSION}

# Verify prowler installation (isolated venv, PATH not modified yet)
RUN /opt/prowler-venv/bin/prowler --version

WORKDIR /app

COPY --chown=mcpuser:mcpuser requirements.txt ./

# Uses the base image's pip, not the prowler venv's — the two dependency
# trees must never share a site-packages.
RUN pip install --no-cache-dir -r requirements.txt

# Expose only the `prowler` binary on PATH (not the whole venv bin/, which
# would also shadow `python`/`pip` and break the main app's own imports).
# The symlink's target has its own shebang, so it still runs fully isolated.
RUN ln -s /opt/prowler-venv/bin/prowler /usr/local/bin/prowler

COPY --chown=mcpuser:mcpuser . .

RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app

USER mcpuser

# Create AWS config directory
RUN mkdir -p /home/mcpuser/.aws

# Environment variables
ENV PROWLER_OUTPUT_DIR=/app/output
ENV PROWLER_TIMEOUT=1800
ENV PROWLER_MAX_CONCURRENT=1
ENV PYTHONUNBUFFERED=1

# AWS credentials should be mounted or passed via env
# ENV AWS_ACCESS_KEY_ID=
# ENV AWS_SECRET_ACCESS_KEY=
# ENV AWS_DEFAULT_REGION=us-east-1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
