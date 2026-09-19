# RoadRecon MCP Server
# Built from atomicchonk/roadrecon_mcp_server source
# Based on: https://github.com/atomicchonk/roadrecon_mcp_server

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/mcp-security-hub"
LABEL org.opencontainers.image.description="RoadRecon MCP Server - Azure AD enumeration"
LABEL org.opencontainers.image.licenses="MIT"

RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache git tini gcc musl-dev libffi-dev

WORKDIR /app

RUN git clone --depth 1 https://github.com/atomicchonk/roadrecon_mcp_server.git . && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir roadrecon && \
    chown -R mcpuser:mcpuser /app

# The upstream repo's requirements.txt doesn't pin mcp, so pip installs the
# latest mcp 2.x by default — but roadrecon_mcp_server.py imports
# mcp.server.fastmcp.FastMCP, which was renamed/removed in mcp 2.x (verified:
# ModuleNotFoundError at startup). Pin back to the last 1.x release.
RUN pip install --no-cache-dir "mcp>=1.0.0,<2.0.0"

USER mcpuser

ENV ROADRECON_URL=http://localhost:5000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "roadrecon_mcp_server.py"]
