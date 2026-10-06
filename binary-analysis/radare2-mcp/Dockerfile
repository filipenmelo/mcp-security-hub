# Radare2 MCP Server
# Curated, read-only binary analysis via radare2 (sandboxed batch mode).
# In-house Python server (not the upstream C r2mcp) to match the audited
# yara-mcp pattern: vectorized subprocess, no shell=True, non-root.

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/filipenmelo/mcp-security-hub"
LABEL org.opencontainers.image.description="Radare2 MCP Server - sandboxed binary analysis"
LABEL org.opencontainers.image.licenses="MIT"

# Security: non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

# radare2 lives in the Alpine community repo
RUN apk add --no-cache \
    ca-certificates \
    tini \
    radare2 \
    && rm -rf /var/cache/apk/*

# Verify radare2 is present
RUN r2 -v

WORKDIR /app

COPY --chown=mcpuser:mcpuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=mcpuser:mcpuser . .

RUN mkdir -p /home/mcpuser/samples && chown -R mcpuser:mcpuser /home/mcpuser /app

USER mcpuser

ENV R2_SAMPLES_DIR=/home/mcpuser/samples
ENV R2_TIMEOUT=180
ENV R2_MAX_CONCURRENT=2
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]
