# BloodHound MCP Server
# Wrapper for MorDavid/BloodHound-MCP-AI
# Based on: https://github.com/MorDavid/BloodHound-MCP-AI

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="BloodHound MCP Server - Active Directory attack path analysis"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    tini \
    git \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Clone BloodHound-MCP-AI
RUN git clone --depth 1 https://github.com/MorDavid/BloodHound-MCP-AI.git /tmp/bloodhound-mcp && \
    cp -r /tmp/bloodhound-mcp/* /app/ && \
    rm -rf /tmp/bloodhound-mcp

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Upstream requirements.txt doesn't pin mcp, so it installs mcp 2.x by
# default — but BloodHound-MCP.py imports mcp.server.fastmcp.FastMCP,
# removed in mcp 2.x (verified: ModuleNotFoundError at startup). Pin to 1.x.
RUN pip install --no-cache-dir "mcp>=1.0.0,<2.0.0"

# Upstream also doesn't pin the neo4j driver, so it installs the latest 6.x.
# BloodHound CE's own docker-compose pins Neo4j server to 4.4.42 (SpecterOps'
# choice, not ours). Driver 6.x fails Bolt auth against that server even with
# correct credentials (verified: HTTP Basic auth to the same Neo4j succeeds,
# but the neo4j-python driver 6.3.1 gets "Unauthorized" over Bolt). Pin to
# the 5.x driver line, which still supports Neo4j 4.4.
RUN pip install --no-cache-dir "neo4j>=5.0,<6.0"

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "BloodHound-MCP.py"]
