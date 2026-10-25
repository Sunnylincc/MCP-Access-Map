# MCP Access Map

**See what your MCP configuration can connect to — before you trust it.**

MCP Access Map is a lightweight, open-source **offline and read-only** MCP configuration inspector that produces a standalone HTML report. It does not need API keys, a database, or cloud services.

## Quick start

Requires Python 3.10+:

```bash
git clone https://github.com/Sunnylincc/MCP-Access-Map.git
cd MCP-Access-Map
python mcp_access_map.py examples/sample-mcp.json
```

Open **mcp-access-report.html** in your browser.

To inspect your own JSON MCP config:

```bash
python mcp_access_map.py /path/to/mcp-config.json -o my-report.html --json report.json
```

Optional command-line installation:

```bash
python -m pip install .
mcp-access-map examples/sample-mcp.json
```

## Features

- Supports JSON objects named `mcpServers` and `servers`.
- Summarizes local commands and remote MCP endpoints.
- Flags shell launchers, suspicious arguments, broad or sensitive paths, non-HTTPS endpoints, and possible embedded credentials.
- Generates an easy-to-read offline HTML report and optional JSON output.
- Does **not** execute servers, probe tools, or send your configuration to the cloud.
- Redacts environment values and URL path/query components from reports.

## Scope and security limitations

**This is a static configuration review, not a runtime firewall or vulnerability certification.** Actual server tools and effective permissions are **unknown** unless verified separately. Heuristics may miss dangerous setups or create false alarms. Currently the "access map" is a connection-and-capability summary, not a full graph of runtime permissions.

Reports may include server names, executable names, paths in some arguments, and environment variable names. Review them before sharing. Run on a trusted device and never upload secret-bearing configs to public issue trackers.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Contributing

Contributions are welcome: more MCP client formats, stronger static checks, tests, and accessible visualizations. Read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
