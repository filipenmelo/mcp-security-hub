#!/usr/bin/env python3
"""
Volatility3 MCP Server

A Model Context Protocol server that exposes memory-forensics analysis via
Volatility 3. Follows the audited yara-mcp pattern: low-level mcp.Server over
stdio, vectorized subprocess calls (never shell=True), in-memory result store,
and resources.

Plugin selection is restricted to an allowlist / strict regex so the model can
only run recognized Volatility plugins against a read-only memory image; no
arbitrary command string is ever passed to a shell.

Tools:
    - vol_image_info: identify OS / profile of a memory image
    - vol_pslist / vol_pstree / vol_psscan: process enumeration
    - vol_netscan: network connections and sockets
    - vol_malfind: injected / hidden code regions
    - vol_cmdline: process command lines
    - vol_dlllist: loaded modules per process
    - vol_run_plugin: run any allowlisted Volatility3 plugin
    - list_plugins: show the curated plugin catalog
    - get_scan_results / list_active_scans
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
logger = logging.getLogger("volatility3-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    images_dir: str = Field(default="/home/mcpuser/images", alias="VOL_IMAGES_DIR")
    vol_bin: str = Field(default="vol", alias="VOL_BIN")
    default_timeout: int = Field(default=600, alias="VOL_TIMEOUT")
    max_concurrent: int = Field(default=1, alias="VOL_MAX_CONCURRENT")
    max_output: int = Field(default=400000, alias="VOL_MAX_OUTPUT")

    class Config:
        env_prefix = "VOL_"


settings = Settings()

# Curated catalog of commonly used plugins (full Volatility3 identifiers).
PLUGIN_CATALOG: dict[str, str] = {
    "windows.info.Info": "OS build, kernel base, architecture",
    "windows.pslist.PsList": "Active processes from the process list",
    "windows.pstree.PsTree": "Process tree (parent/child)",
    "windows.psscan.PsScan": "Processes found by pool scanning (incl. hidden)",
    "windows.cmdline.CmdLine": "Per-process command lines",
    "windows.dlllist.DllList": "Loaded DLLs per process",
    "windows.handles.Handles": "Open handles per process",
    "windows.netscan.NetScan": "Network connections (pool scan)",
    "windows.netstat.NetStat": "Network connections (list traversal)",
    "windows.malfind.Malfind": "Injected / hidden executable memory",
    "windows.filescan.FileScan": "File objects in memory",
    "windows.svcscan.SvcScan": "Windows services",
    "windows.hashdump.Hashdump": "Cached credential hashes",
    "linux.pslist.PsList": "Active processes (Linux)",
    "linux.pstree.PsTree": "Process tree (Linux)",
    "linux.bash.Bash": "Recovered bash command history",
    "linux.lsof.Lsof": "Open file descriptors (Linux)",
    "mac.pslist.PsList": "Active processes (macOS)",
}

_PLUGIN_RE = re.compile(r"^(windows|linux|mac)\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
# Plugin option values must be simple tokens — no shell metacharacters even
# though we never use a shell; defense in depth for the vectorized args.
_OPT_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_OPT_VAL_RE = re.compile(r"^[A-Za-z0-9_.,:/=\-]{1,256}$")


class ScanResult(BaseModel):
    scan_id: str
    image: str
    plugin: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    rows: list[Any] = []
    row_count: int = 0
    raw_output: str | None = None
    error: str | None = None


scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()


def _resolve_image(image: str) -> Path | None:
    p = Path(image)
    if not p.is_absolute():
        p = Path(settings.images_dir) / image
    try:
        p = p.resolve()
        p.relative_to(Path(settings.images_dir).resolve())
    except (ValueError, OSError):
        return None
    return p if p.is_file() else None


async def run_vol(image: Path, plugin: str, options: dict[str, str] | None = None,
                  timeout: int | None = None) -> ScanResult:
    scan_id = str(uuid.uuid4())[:8]
    result = ScanResult(
        scan_id=scan_id, image=str(image), plugin=plugin, started_at=datetime.now()
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    cmd = [settings.vol_bin, "-q", "-r", "json", "-f", str(image), plugin]
    for k, v in (options or {}).items():
        cmd.extend([f"--{k}", v])

    logger.info(f"Scan {scan_id}: {plugin} on {image.name} opts={options or {}}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=float(timeout or settings.default_timeout)
        )
        result.completed_at = datetime.now()
        out = stdout.decode(errors="replace")[: settings.max_output]
        result.raw_output = out
        err = stderr.decode(errors="replace").strip()

        if out.strip():
            try:
                parsed = json.loads(out)
                if isinstance(parsed, list):
                    result.rows = parsed[:1000]
                    result.row_count = len(parsed)
                else:
                    result.rows = [parsed]
                    result.row_count = 1
            except json.JSONDecodeError:
                result.rows = []

        if proc.returncode == 0:
            result.status = "completed"
        else:
            result.status = "failed"
            result.error = err or f"vol exited with code {proc.returncode}"
    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout}s"
        result.completed_at = datetime.now()
    except FileNotFoundError:
        result.status = "error"
        result.error = f"Volatility binary '{settings.vol_bin}' not found"
        result.completed_at = datetime.now()
    except Exception as e:  # noqa: BLE001
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")
    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def summarize(result: ScanResult, include_raw: bool = False) -> dict[str, Any]:
    out = {
        "scan_id": result.scan_id,
        "image": result.image,
        "plugin": result.plugin,
        "status": result.status,
        "row_count": result.row_count,
        "rows": result.rows[:200],
        "error": result.error,
    }
    if include_raw and result.raw_output is not None:
        out["raw_output"] = result.raw_output
    return out


def _validate_options(options: dict[str, Any] | None) -> tuple[dict[str, str] | None, str | None]:
    if not options:
        return None, None
    clean: dict[str, str] = {}
    for k, v in options.items():
        sk, sv = str(k), str(v)
        if not _OPT_KEY_RE.match(sk) or not _OPT_VAL_RE.match(sv):
            return None, f"Invalid plugin option: {sk}={sv}"
        clean[sk] = sv
    return clean, None


app = Server("volatility3-mcp")

_IMG = {"type": "string", "description": "Memory image file (resolved inside the images dir)"}
_TIMEOUT = {"type": "integer", "description": "Timeout in seconds", "default": 600}
_PID = {"type": "string", "description": "Optional PID to filter (comma-separated for several)"}


@app.list_tools()
async def list_tools() -> list[Tool]:
    def simple(desc: str, pid: bool = False) -> dict:
        props = {"image": _IMG, "timeout": _TIMEOUT}
        if pid:
            props["pid"] = _PID
        return {"type": "object", "properties": props, "required": ["image"]}

    return [
        Tool(name="vol_image_info",
             description="Identify the OS, kernel build and architecture of a memory image "
                         "(windows.info). Run this first to confirm the image is readable.",
             inputSchema=simple("info")),
        Tool(name="vol_pslist",
             description="List active processes (windows.pslist / pass os='linux' or 'mac').",
             inputSchema={"type": "object", "properties": {
                 "image": _IMG, "os": {"type": "string", "enum": ["windows", "linux", "mac"],
                                       "default": "windows"}, "pid": _PID, "timeout": _TIMEOUT},
                 "required": ["image"]}),
        Tool(name="vol_pstree",
             description="Show the process tree (parent/child relationships).",
             inputSchema={"type": "object", "properties": {
                 "image": _IMG, "os": {"type": "string", "enum": ["windows", "linux", "mac"],
                                       "default": "windows"}, "timeout": _TIMEOUT},
                 "required": ["image"]}),
        Tool(name="vol_psscan",
             description="Pool-scan for processes, including terminated/hidden ones "
                         "(Windows only).",
             inputSchema=simple("psscan")),
        Tool(name="vol_netscan",
             description="Recover network connections and listening sockets (Windows).",
             inputSchema=simple("netscan")),
        Tool(name="vol_malfind",
             description="Find injected or hidden executable memory regions (Windows).",
             inputSchema=simple("malfind", pid=True)),
        Tool(name="vol_cmdline",
             description="Show per-process command lines (Windows).",
             inputSchema=simple("cmdline", pid=True)),
        Tool(name="vol_dlllist",
             description="List loaded modules/DLLs per process (Windows).",
             inputSchema=simple("dlllist", pid=True)),
        Tool(name="vol_run_plugin",
             description="Run any allowlisted Volatility3 plugin by its full identifier "
                         "(e.g. 'windows.svcscan.SvcScan'). See list_plugins for the catalog; "
                         "any plugin matching '<os>.<module>.<Class>' is also accepted.",
             inputSchema={"type": "object", "properties": {
                 "image": _IMG,
                 "plugin": {"type": "string", "description": "Full plugin identifier"},
                 "options": {"type": "object",
                             "description": "Optional plugin flags, e.g. {\"pid\": \"1234\"}"},
                 "timeout": _TIMEOUT},
                 "required": ["image", "plugin"]}),
        Tool(name="list_plugins",
             description="List the curated Volatility3 plugin catalog.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_scan_results",
             description="Retrieve a previous scan by id.",
             inputSchema={"type": "object", "properties": {
                 "scan_id": {"type": "string"},
                 "include_raw": {"type": "boolean", "default": False}},
                 "required": ["scan_id"]}),
        Tool(name="list_active_scans",
             description="List currently running scans.",
             inputSchema={"type": "object", "properties": {}}),
    ]


_FIXED = {
    "vol_image_info": "windows.info.Info",
    "vol_psscan": "windows.psscan.PsScan",
    "vol_netscan": "windows.netscan.NetScan",
    "vol_malfind": "windows.malfind.Malfind",
    "vol_cmdline": "windows.cmdline.CmdLine",
    "vol_dlllist": "windows.dlllist.DllList",
}
_OS_PLUGIN = {
    "vol_pslist": {"windows": "windows.pslist.PsList", "linux": "linux.pslist.PsList",
                   "mac": "mac.pslist.PsList"},
    "vol_pstree": {"windows": "windows.pstree.PsTree", "linux": "linux.pstree.PsTree",
                   "mac": "mac.pstree.PsTree"},
}


async def _run_image_tool(image_arg: str, plugin: str, options: dict[str, str] | None,
                          timeout: int | None) -> list[TextContent]:
    if len(active_scans) >= settings.max_concurrent:
        return [TextContent(type="text",
                            text=f"Maximum concurrent scans ({settings.max_concurrent}) reached.")]
    image = _resolve_image(image_arg)
    if image is None:
        return [TextContent(type="text",
                            text=f"Image not found or outside images dir "
                                 f"({settings.images_dir}): {image_arg}")]
    result = await run_vol(image, plugin, options, timeout)
    return [TextContent(type="text", text=json.dumps(summarize(result), indent=2))]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "list_plugins":
            return [TextContent(type="text", text=json.dumps(
                {"plugins": PLUGIN_CATALOG, "count": len(PLUGIN_CATALOG)}, indent=2))]

        if name == "get_scan_results":
            r = scan_results.get(arguments["scan_id"])
            if not r:
                return [TextContent(type="text", text=f"Scan '{arguments['scan_id']}' not found")]
            return [TextContent(type="text",
                                text=json.dumps(summarize(r, arguments.get("include_raw", False)),
                                                indent=2))]

        if name == "list_active_scans":
            running = [{"scan_id": s, "image": scan_results[s].image,
                        "plugin": scan_results[s].plugin,
                        "started_at": scan_results[s].started_at.isoformat()}
                       for s in active_scans if s in scan_results]
            return [TextContent(type="text", text=json.dumps(
                {"active_scans": running, "count": len(running),
                 "max_concurrent": settings.max_concurrent}, indent=2))]

        timeout = arguments.get("timeout")

        # pid-filtering tools
        opts: dict[str, str] = {}
        if arguments.get("pid"):
            pid = str(arguments["pid"])
            if not re.fullmatch(r"\d+(,\d+)*", pid):
                return [TextContent(type="text", text="Invalid pid filter.")]
            opts["pid"] = pid

        if name in _FIXED:
            return await _run_image_tool(arguments["image"], _FIXED[name], opts or None, timeout)

        if name in _OS_PLUGIN:
            os_name = arguments.get("os", "windows")
            plugin = _OS_PLUGIN[name].get(os_name)
            if not plugin:
                return [TextContent(type="text", text=f"Unsupported os: {os_name}")]
            return await _run_image_tool(arguments["image"], plugin, opts or None, timeout)

        if name == "vol_run_plugin":
            plugin = str(arguments["plugin"])
            if plugin not in PLUGIN_CATALOG and not _PLUGIN_RE.match(plugin):
                return [TextContent(type="text",
                                    text=f"Plugin '{plugin}' not allowed. Must be in the catalog "
                                         f"or match '<os>.<module>.<Class>'.")]
            clean, err = _validate_options(arguments.get("options"))
            if err:
                return [TextContent(type="text", text=err)]
            return await _run_image_tool(arguments["image"], plugin, clean, timeout)

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:  # noqa: BLE001
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    res = []
    for sid, r in scan_results.items():
        if r.status == "completed":
            res.append(Resource(
                uri=f"volatility3://results/{sid}",
                name=f"{r.plugin}: {Path(r.image).name} ({r.row_count} rows)",
                description=f"completed at {r.completed_at}",
                mimeType="application/json",
            ))
    return res


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("volatility3://results/"):
        sid = uri.replace("volatility3://results/", "")
        r = scan_results.get(sid)
        if r:
            return json.dumps(summarize(r), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main() -> None:
    logger.info("Starting Volatility3 MCP Server")
    logger.info(f"Images directory: {settings.images_dir}")
    Path(settings.images_dir).mkdir(parents=True, exist_ok=True)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
