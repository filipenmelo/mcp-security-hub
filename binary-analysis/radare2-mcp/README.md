# Radare2 MCP Server

A Model Context Protocol server exposing a curated, **read-only** set of
[radare2](https://rada.re/) binary-analysis operations.

Unlike the upstream C `r2mcp`, this is an in-house Python server that matches
the audited `yara-mcp` pattern: every radare2 call is a **vectorized
subprocess** (never `shell=True`) run in **sandbox mode** (`cfg.sandbox=true`),
which disables radare2's `!` shell escape and all on-disk writes. A malicious
binary or command cannot pivot into host command execution.

## Tools

| Tool | Description |
|------|-------------|
| `r2_info` | File type, headers, arch, sections, NX/PIE/canary/RELRO |
| `r2_functions` | Auto-analysis + function list (addresses, sizes, names) |
| `r2_disassemble` | Disassemble a function or N instructions at an offset |
| `r2_strings` | Extract strings (configurable min length) |
| `r2_imports` | Imported symbols / linked functions |
| `r2_xrefs` | Cross-references to a symbol or address |
| `r2_command` | Arbitrary r2 command, sandboxed (advanced) |
| `get_analysis_results` | Retrieve a previous analysis by id |
| `list_active_analyses` | Show running analyses |

## Security

- Runs as non-root (`uid 1000`), stdio only — **no network port exposed**.
- radare2 runs with `cfg.sandbox=true`; `!`/`#!`/`R!` and `cfg.sandbox=false`
  are additionally rejected before execution.
- Sample path is resolved and confined to the samples directory (no traversal).
- Mount samples **read-only**.

## Docker

```bash
docker build -t radare2-mcp .
docker run -i --rm -v /home/soc/scan-targets:/home/mcpuser/samples:ro radare2-mcp:latest
```

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `R2_SAMPLES_DIR` | `/home/mcpuser/samples` | Allowed input directory |
| `R2_TIMEOUT` | `180` | Per-analysis timeout (s) |
| `R2_MAX_CONCURRENT` | `2` | Max concurrent analyses |
| `R2_MAX_OUTPUT` | `200000` | Max chars captured per run |

## License

MIT
