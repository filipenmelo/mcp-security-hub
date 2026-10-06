# Volatility3 MCP Server
# Memory-forensics analysis via Volatility 3, in the audited yara-mcp pattern:
# vectorized subprocess, no shell=True, non-root, plugin allowlist.
#
# Debian slim base (not Alpine) so capstone / yara-python / pefile install
# from manylinux wheels instead of building from source.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/filipenmelo/mcp-security-hub"
LABEL org.opencontainers.image.description="Volatility3 MCP Server - memory forensics"
LABEL org.opencontainers.image.licenses="MIT"

# Security: non-root user
RUN groupadd -g 1000 mcpuser && \
    useradd -m -u 1000 -g mcpuser mcpuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Verify Volatility is importable and the CLI resolves
RUN vol --help > /dev/null

COPY . .

RUN mkdir -p /home/mcpuser/images && chown -R mcpuser:mcpuser /home/mcpuser /app

USER mcpuser

ENV VOL_IMAGES_DIR=/home/mcpuser/images
ENV VOL_TIMEOUT=600
ENV VOL_MAX_CONCURRENT=1
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
