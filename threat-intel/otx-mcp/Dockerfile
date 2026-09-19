# OTX MCP Server
# Built from mrwadams/otx-mcp source for multi-arch support
# Based on: https://github.com/mrwadams/otx-mcp

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/mcp-security-hub"
LABEL org.opencontainers.image.description="OTX MCP Server - AlienVault Open Threat Exchange"
LABEL org.opencontainers.image.licenses="MIT"

RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache git tini

WORKDIR /app

RUN git clone --depth 1 https://github.com/mrwadams/otx-mcp.git . && \
    pip install --no-cache-dir -r requirements.txt && \
    chown -R mcpuser:mcpuser /app

# Upstream requirements.txt doesn't pin mcp, so it installs mcp 2.x by
# default — but main.py imports mcp.server.fastmcp.FastMCP, removed in
# mcp 2.x (verified: ModuleNotFoundError at startup). Pin back to 1.x.
RUN pip install --no-cache-dir "mcp>=1.0.0,<2.0.0"

USER mcpuser

ENV OTX_API_KEY=

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "main.py"]
