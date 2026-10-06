#!/usr/bin/env python3
"""
Radare2 MCP Server

A Model Context Protocol server that exposes a curated, read-only set of
radare2 binary-analysis operations. Every radare2 invocation runs in batch
mode with the reverse-engineering sandbox enabled (cfg.sandbox=true), which
disables the `!` shell escape and any on-disk writes, so a crafted binary or
command can never pivot into command execution on the host.

Design mirrors yara-mcp: low-level mcp.Server over stdio, vectorized
subprocess calls (never shell=True), in-memory result store, and resources.

Tools:
    - r2_info: target file / header / binary metadata
    - r2_functions: enumerate functions (after analysis)
    - r2_disassemble: disassemble a function or N instructions at an offset
    - r2_strings: extract strings
    - r2_imports: list imported symbols
    - r2_xrefs: cross-references to a symbol or address
    - r2_command: run an arbitrary r2 command (sandboxed, read-only)
    - get_analysis_results: retrieve a previous analysis by id
    - list_active_analyses: show running analyses
"""

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("radare2-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    samples_dir: str = Field(default="/home/mcpuser/samples", alias="R2_SAMPLES_DIR")
    default_timeout: int = Field(default=180, alias="R2_TIMEOUT")
    max_concurrent: int = Field(default=2, alias="R2_MAX_CONCURRENT")
    max_output: int = Field(default=200000, alias="R2_MAX_OUTPUT")  # chars returned

    class Config:
        env_prefix = "R2_"


settings = Settings()


class AnalysisResult(BaseModel):
    """Model for one radare2 analysis run."""

    analysis_id: str
    target: str
    operation: str
    command: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    parsed: Any = None
    raw_output: str | None = None
    error: str | None = None


analyses: dict[str, AnalysisResult] = {}
active: set[str] = set()

# r2 commands are constructed internally for the curated tools. For the raw
# r2_command tool we still enforce the sandbox and reject the shell-escape
# operators as defense in depth (the sandbox already blocks them).
_FORBIDDEN = re.compile(r"(^|;)\s*#?!|R!|\bcfg\.sandbox\s*=\s*false", re.IGNORECASE)


def _resolve_target(target: str) -> Path | None:
    """Resolve a target path and keep it inside the samples directory."""
    p = Path(target)
    if not p.is_absolute():
        p = Path(settings.samples_dir) / target
    try:
        p = p.resolve()
        samples_root = Path(settings.samples_dir).resolve()
        p.relative_to(samples_root)
    except (ValueError, OSError):
        return None
    return p if p.is_file() else None


async def run_r2(target: Path, operation: str, r2_cmd: str,
                 timeout: int | None = None, json_output: bool = True) -> AnalysisResult:
    """Run radare2 in sandboxed batch mode and capture the result."""
    analysis_id = str(uuid.uuid4())[:8]
    result = AnalysisResult(
        analysis_id=analysis_id,
        target=str(target),
        operation=operation,
        command=r2_cmd,
        started_at=datetime.now(),
    )
    analyses[analysis_id] = result
    active.add(analysis_id)

    # The target file is opened before -c runs, so the sandbox is enabled as the
    # first -c command (after load): enabling it via -e at launch would block the
    # initial file open itself. Once true it cannot be turned back off.
    sandboxed_cmd = f"e cfg.sandbox=true; {r2_cmd}"
    cmd = [
        "r2", "-q",
        "-e", "scr.color=0",
        "-e", "scr.interactive=false",
        "-c", sandboxed_cmd,
        str(target),
    ]
    logger.info(f"Analysis {analysis_id} [{operation}] on {target.name}: {r2_cmd!r}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=float(timeout or settings.default_timeout)
        )
        result.completed_at = datetime.now()
        out = stdout.decode(errors="replace")[: settings.max_output]
        result.raw_output = out

        if json_output and out.strip():
            try:
                result.parsed = json.loads(out)
            except json.JSONDecodeError:
                result.parsed = None  # keep raw_output; some cmds emit text

        err = stderr.decode(errors="replace").strip()
        if proc.returncode == 0:
            result.status = "completed"
        else:
            result.status = "failed"
            result.error = err or f"r2 exited with code {proc.returncode}"
    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Analysis timed out after {timeout or settings.default_timeout}s"
        result.completed_at = datetime.now()
    except Exception as e:  # noqa: BLE001
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Analysis {analysis_id} error: {e}")
    finally:
        active.discard(analysis_id)
        analyses[analysis_id] = result

    return result


def summarize(result: AnalysisResult, include_raw: bool = False) -> dict[str, Any]:
    out = {
        "analysis_id": result.analysis_id,
        "target": result.target,
        "operation": result.operation,
        "status": result.status,
        "error": result.error,
    }
    if result.parsed is not None:
        out["result"] = result.parsed
    elif result.raw_output is not None:
        out["result"] = result.raw_output[:20000]
    if include_raw and result.raw_output is not None:
        out["raw_output"] = result.raw_output
    return out


app = Server("radare2-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    target_prop = {
        "type": "string",
        "description": "Binary file to analyze (path, resolved inside the samples dir)",
    }
    timeout_prop = {"type": "integer", "description": "Timeout in seconds", "default": 180}
    return [
        Tool(
            name="r2_info",
            description="Show binary metadata: file type, headers, architecture, "
            "sections, security mitigations (NX/PIE/canary/RELRO).",
            inputSchema={
                "type": "object",
                "properties": {"target": target_prop, "timeout": timeout_prop},
                "required": ["target"],
            },
        ),
        Tool(
            name="r2_functions",
            description="Run auto-analysis (aa) and enumerate discovered functions "
            "with addresses, sizes, and names.",
            inputSchema={
                "type": "object",
                "properties": {"target": target_prop, "timeout": timeout_prop},
                "required": ["target"],
            },
        ),
        Tool(
            name="r2_disassemble",
            description="Disassemble a function by name (e.g. 'sym.main', 'main') or "
            "N instructions at a hex offset (e.g. '0x401000').",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": target_prop,
                    "location": {
                        "type": "string",
                        "description": "Function name/symbol or hex offset to disassemble",
                    },
                    "instructions": {
                        "type": "integer",
                        "description": "Number of instructions when location is an offset",
                        "default": 64,
                    },
                    "timeout": timeout_prop,
                },
                "required": ["target", "location"],
            },
        ),
        Tool(
            name="r2_strings",
            description="Extract strings from the whole binary (data and code sections).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": target_prop,
                    "min_length": {
                        "type": "integer",
                        "description": "Minimum string length",
                        "default": 5,
                    },
                    "timeout": timeout_prop,
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="r2_imports",
            description="List imported symbols / linked library functions.",
            inputSchema={
                "type": "object",
                "properties": {"target": target_prop, "timeout": timeout_prop},
                "required": ["target"],
            },
        ),
        Tool(
            name="r2_xrefs",
            description="Find cross-references to a symbol name or hex address "
            "(requires analysis; runs aa first).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": target_prop,
                    "location": {
                        "type": "string",
                        "description": "Symbol name or hex address to find xrefs to",
                    },
                    "timeout": timeout_prop,
                },
                "required": ["target", "location"],
            },
        ),
        Tool(
            name="r2_command",
            description="Run an arbitrary radare2 command string in read-only sandbox "
            "mode (the '!' shell escape and disk writes are disabled). Use the JSON "
            "variants (e.g. 'aflj', 'izzj') for structured output. Advanced use only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": target_prop,
                    "command": {
                        "type": "string",
                        "description": "radare2 command(s), e.g. 'aa; afl' or 'pdf @ main'",
                    },
                    "analyze": {
                        "type": "boolean",
                        "description": "Prepend 'aa' auto-analysis before the command",
                        "default": False,
                    },
                    "timeout": timeout_prop,
                },
                "required": ["target", "command"],
            },
        ),
        Tool(
            name="get_analysis_results",
            description="Retrieve a previous analysis by its id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {"type": "string"},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "required": ["analysis_id"],
            },
        ),
        Tool(
            name="list_active_analyses",
            description="List currently running analyses.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


def _at_capacity() -> TextContent | None:
    if len(active) >= settings.max_concurrent:
        return TextContent(
            type="text",
            text=f"Maximum concurrent analyses ({settings.max_concurrent}) reached.",
        )
    return None


def _bad_target(target: str) -> TextContent | None:
    if _resolve_target(target) is None:
        return TextContent(
            type="text",
            text=f"Target not found or outside samples dir ({settings.samples_dir}): {target}",
        )
    return None


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name in ("r2_info", "r2_functions", "r2_disassemble", "r2_strings",
                    "r2_imports", "r2_xrefs", "r2_command"):
            cap = _at_capacity()
            if cap:
                return [cap]
            bad = _bad_target(arguments["target"])
            if bad:
                return [bad]
            target = _resolve_target(arguments["target"])
            timeout = arguments.get("timeout")

            if name == "r2_info":
                r = await run_r2(target, "info", "ij; iHj", timeout)
                # ij emits one json object; some builds need ij alone
                if r.parsed is None:
                    r = await run_r2(target, "info", "ij", timeout)
            elif name == "r2_functions":
                r = await run_r2(target, "functions", "aa; aflj", timeout)
            elif name == "r2_disassemble":
                loc = str(arguments["location"]).strip()
                if _FORBIDDEN.search(loc):
                    return [TextContent(type="text", text="Invalid location.")]
                if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", loc):
                    n = int(arguments.get("instructions", 64))
                    cmd = f"aa; pdj {n} @ {loc}"
                else:
                    cmd = f"aa; pdfj @ {loc}"
                r = await run_r2(target, "disassemble", cmd, timeout)
            elif name == "r2_strings":
                _ = int(arguments.get("min_length", 5))  # izzj uses bin.minstr
                cmd = f"e bin.minstr={_}; izzj"
                r = await run_r2(target, "strings", cmd, timeout)
            elif name == "r2_imports":
                r = await run_r2(target, "imports", "iij", timeout)
            elif name == "r2_xrefs":
                loc = str(arguments["location"]).strip()
                if _FORBIDDEN.search(loc):
                    return [TextContent(type="text", text="Invalid location.")]
                r = await run_r2(target, "xrefs", f"aa; axtj {loc}", timeout)
            else:  # r2_command
                user_cmd = str(arguments["command"])
                if _FORBIDDEN.search(user_cmd):
                    return [TextContent(
                        type="text",
                        text="Command rejected: shell-escape / sandbox-disable operators "
                        "are not permitted.",
                    )]
                full = f"aa; {user_cmd}" if arguments.get("analyze") else user_cmd
                r = await run_r2(target, "command", full, timeout,
                                 json_output=user_cmd.strip().endswith("j"))

            return [TextContent(type="text", text=json.dumps(summarize(r), indent=2))]

        elif name == "get_analysis_results":
            r = analyses.get(arguments["analysis_id"])
            if not r:
                return [TextContent(type="text", text=f"Analysis '{arguments['analysis_id']}' not found")]
            return [TextContent(
                type="text",
                text=json.dumps(summarize(r, arguments.get("include_raw", False)), indent=2),
            )]

        elif name == "list_active_analyses":
            running = [
                {
                    "analysis_id": aid,
                    "target": analyses[aid].target,
                    "operation": analyses[aid].operation,
                    "started_at": analyses[aid].started_at.isoformat(),
                }
                for aid in active if aid in analyses
            ]
            return [TextContent(type="text", text=json.dumps(
                {"active": running, "count": len(running),
                 "max_concurrent": settings.max_concurrent}, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:  # noqa: BLE001
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    res = []
    for aid, r in analyses.items():
        if r.status == "completed":
            res.append(Resource(
                uri=f"radare2://analysis/{aid}",
                name=f"{r.operation}: {Path(r.target).name}",
                description=f"{r.operation} completed at {r.completed_at}",
                mimeType="application/json",
            ))
    return res


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("radare2://analysis/"):
        aid = uri.replace("radare2://analysis/", "")
        r = analyses.get(aid)
        if r:
            return json.dumps(summarize(r), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main() -> None:
    logger.info("Starting Radare2 MCP Server")
    logger.info(f"Samples directory: {settings.samples_dir}")
    Path(settings.samples_dir).mkdir(parents=True, exist_ok=True)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
