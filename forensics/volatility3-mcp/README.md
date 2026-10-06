# Volatility3 MCP Server

A Model Context Protocol server for memory forensics using
[Volatility 3](https://github.com/volatilityfoundation/volatility3).

Matches the audited `yara-mcp` pattern: low-level MCP server over stdio,
**vectorized subprocess** calls (never `shell=True`), and an in-memory result
store. Plugin selection is restricted to a curated catalog or a strict
`<os>.<module>.<Class>` regex, and plugin option values are validated — the
model can only run recognized Volatility plugins against a **read-only** image.

## Tools

| Tool | Description |
|------|-------------|
| `vol_image_info` | Identify OS / kernel build / arch (run first) |
| `vol_pslist` | Active processes (`os`: windows/linux/mac) |
| `vol_pstree` | Process tree |
| `vol_psscan` | Pool-scan processes incl. hidden (Windows) |
| `vol_netscan` | Network connections / sockets (Windows) |
| `vol_malfind` | Injected / hidden executable memory |
| `vol_cmdline` | Per-process command lines |
| `vol_dlllist` | Loaded modules per process |
| `vol_run_plugin` | Any allowlisted plugin by full identifier |
| `list_plugins` | Show the curated plugin catalog |
| `get_scan_results` / `list_active_scans` | Result retrieval |

## Security

- Runs as non-root (`uid 1000`), stdio only — **no network port exposed**.
- Plugin names are allowlisted / regex-validated; option values are sanitized.
- Image path is resolved and confined to the images directory (no traversal).
- Mount memory images **read-only**.

## Symbols note

Volatility 3 downloads symbol tables (ISF) on demand from the Volatility
symbol server. In an air-gapped lab, pre-seed the symbol packs into the image
(or mount them) or the first Windows/Linux run may fail to resolve symbols.

## Docker

```bash
docker build -t volatility3-mcp .
docker run -i --rm -v /home/soc/memory-images:/home/mcpuser/images:ro volatility3-mcp:latest
```

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `VOL_IMAGES_DIR` | `/home/mcpuser/images` | Allowed input directory |
| `VOL_TIMEOUT` | `600` | Per-scan timeout (s) |
| `VOL_MAX_CONCURRENT` | `1` | Max concurrent scans |
| `VOL_MAX_OUTPUT` | `400000` | Max chars captured per run |

## License

MIT
