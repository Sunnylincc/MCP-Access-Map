"""MCP Access Map: offline, read-only MCP configuration inspector.

This tool never launches MCP servers, accesses external services, or reads
referenced directories. Its findings are heuristics about configuration,
not verified runtime tool permissions.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SECRET_NAME = re.compile(r"(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)", re.I)
SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
RISKY_ARGS = re.compile(r"(?:\brm\s+-rf\b|\bcurl\b.*\|\s*(?:sh|bash)\b|\bwget\b.*\|\s*(?:sh|bash)\b|--dangerously|--allow-all|--no-sandbox)", re.I)
SENSITIVE_PATH = re.compile(r"(?:^|[/\\])(?:\.ssh|\.aws|\.config|\.gnupg|\.kube)(?:[/\\]|$)|(?:^|[/\\])(?:id_rsa|id_ed25519)(?:$|[/\\])", re.I)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str


@dataclass
class Server:
    name: str
    transport: str
    target: str
    findings: list[Finding]
    capabilities: list[str]


def _safe_target(url: str) -> str:
    """Show scheme and hostname only; strip usernames, paths and query tokens."""
    try:
        p = urlsplit(url)
        if p.hostname:
            return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
    except ValueError:
        pass
    return "[invalid or unsupported URL]"


def _extract_servers(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("Configuration root must be a JSON object")
    for key in ("mcpServers", "servers"):
        if key in obj:
            servers = obj[key]
            if not isinstance(servers, dict):
                raise ValueError(f"'{key}' must be an object")
            return servers
    raise ValueError("No 'mcpServers' or 'servers' object found")


def _inspect(name: str, value: Any) -> Server:
    if not isinstance(value, dict):
        return Server(name, "unknown", "Invalid entry", [Finding("high", "Invalid server entry", "Expected a JSON object.")], [])
    findings: list[Finding] = []
    capabilities: list[str] = []
    command = value.get("command", "")
    url = value.get("url", "")
    args = value.get("args", [])
    env = value.get("env", {})
    if not isinstance(command, str):
        command = ""
        findings.append(Finding("medium", "Invalid command", "Command must be a string."))
    if not isinstance(url, str):
        url = ""
        findings.append(Finding("medium", "Invalid URL", "URL must be a string."))
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        args = []
        findings.append(Finding("medium", "Invalid arguments", "Arguments must be an array of strings."))
    if not isinstance(env, dict):
        env = {}
        findings.append(Finding("medium", "Invalid environment", "Environment must be an object."))
    if command:
        transport = "stdio"
        target = Path(command.replace("\\", "/")).name or "[command]"
        capabilities.append("Launch local process")
        if target.lower() in SHELLS:
            findings.append(Finding("high", "Shell execution", "Configuration launches a shell interpreter. Review the command before use."))
        if target.lower() in {"npx", "uvx", "pipx", "bunx"}:
            findings.append(Finding("info", "Package runner", "A package runner may retrieve or execute third-party packages; check package provenance."))
        if RISKY_ARGS.search(" ".join(args)):
            findings.append(Finding("high", "Potentially dangerous arguments", "Arguments contain a potentially risky execution pattern."))
        for arg in args:
            if SENSITIVE_PATH.search(arg):
                findings.append(Finding("high", "Sensitive path referenced", "Arguments mention a potentially sensitive credential/configuration path."))
                break
        if any(a in {"/", "~", "."} for a in args):
            findings.append(Finding("medium", "Broad path argument", "A broad directory argument may expose more data than intended."))
        if any("filesystem" in a.lower() for a in [command, *args]):
            capabilities.append("Possible filesystem access (not verified)")
    elif url:
        transport = str(value.get("type", "remote"))
        target = _safe_target(url)
        capabilities.append("Connect to remote service")
        try:
            scheme = urlsplit(url).scheme.lower()
        except ValueError:
            scheme = ""
        if scheme != "https":
            findings.append(Finding("medium", "Non-HTTPS endpoint", "Remote endpoint is not an HTTPS URL. Verify transport security."))
        findings.append(Finding("info", "Remote endpoint", "Requests to this remote MCP server may share data with its operator."))
    else:
        transport = "unknown"
        target = "[no command or URL]"
        findings.append(Finding("medium", "No supported connection", "Expected a command or URL to identify the connection."))

    # Deliberately do not include environment values, even in warnings/JSON.
    for key, val in env.items():
        if isinstance(key, str) and SECRET_NAME.search(key) and isinstance(val, str) and val and not re.fullmatch(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*", val):
            findings.append(Finding("high", "Possible embedded credential", f"Environment variable '{key}' may contain a literal secret. Its value is never shown."))
    if not findings:
        findings.append(Finding("info", "No obvious configuration flags", "Static checks found no matched patterns; this is not a security guarantee."))
    return Server(name, transport, target, findings, capabilities)


def inspect_config(raw: Any) -> list[Server]:
    entries = _extract_servers(raw)
    return [_inspect(str(k), v) for k, v in entries.items()]


def report_data(servers: list[Server]) -> dict[str, Any]:
    return {
        "disclaimer": "Static, configuration-only review. Runtime permissions and actual MCP tools are unknown.",
        "servers": [asdict(s) for s in servers],
        "summary": {
            "servers": len(servers),
            "high": sum(f.severity == "high" for s in servers for f in s.findings),
            "medium": sum(f.severity == "medium" for s in servers for f in s.findings),
        },
    }


def render_html(data: dict[str, Any]) -> str:
    esc = lambda v: html.escape(str(v), quote=True)
    cards = []
    for server in data["servers"]:
        findings = "".join(
            f'<li><span class="pill {esc(f["severity"])}">{esc(f["severity"])}</span> '
            f'<strong>{esc(f["title"])}</strong><p>{esc(f["detail"])}</p></li>'
            for f in server["findings"]
        )
        caps = ", ".join(server["capabilities"]) or "Unknown from configuration"
        cards.append(
            f'<article><div class="edge"></div><div class="body"><h2>{esc(server["name"])}</h2>'
            f'<p class="meta">Connection: {esc(server["transport"])} · Target: {esc(server["target"])}</p>'
            f'<p class="meta">Inferred capabilities: {esc(caps)}</p>'
            f'<h3>Review notes</h3><ul>{findings}</ul></div></article>'
        )
    server_cards = "\n".join(cards) or '<p>No servers found in configuration.</p>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Access Map Report</title>
<style>
:root{{color-scheme:dark;font-family:Inter,system-ui,-apple-system,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;background:#0a1220;color:#e9f2fa;line-height:1.55}}
main{{max-width:1000px;padding:56px 24px;margin:auto}}
header{{padding-bottom:30px;border-bottom:1px solid #304257}}
.kicker{{color:#7dd3b0;text-transform:uppercase;letter-spacing:.18em;font-size:12px;font-weight:700}}
h1{{font-size:clamp(30px,5vw,52px);margin:10px 0}}h2{{margin:0 0 8px}}h3{{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:#a4bdd0}}
.muted,.meta{{color:#a9bdcc}}.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:26px 0}}
.stat{{background:#18293a;border:1px solid #324458;border-radius:12px;padding:15px 22px;min-width:140px}}
.stat b{{font-size:26px;display:block}}article{{display:flex;background:#132236;border:1px solid #34485b;border-radius:15px;overflow:hidden;margin:18px 0}}
.edge{{width:5px;background:#65c8a8;flex-shrink:0}}.body{{padding:24px;min-width:0;overflow-wrap:anywhere}}
ul{{padding-left:22px}}li{{margin:12px 0}}li p{{margin:3px 0 0;color:#b5c7d6;font-size:14px}}
.pill{{font-size:11px;text-transform:uppercase;border-radius:6px;padding:3px 7px;font-weight:bold;background:#385066;color:#fff}}
.pill.high{{background:#8e3943}}.pill.medium{{background:#89652e}}.pill.info{{background:#255b63}}
aside{{background:#163029;padding:16px 20px;border-radius:12px;border:1px solid #326e60;color:#d4f7e7;margin:25px 0}}
footer{{color:#9eb2c6;font-size:12px;margin-top:40px}}
</style></head><body><main><header><div class="kicker">Local-first · Read-only · Open source</div>
<h1>MCP Access Map</h1><p class="muted">Understand what your MCP configuration may allow.</p></header>
<section class="stats"><div class="stat"><b>{data["summary"]["servers"]}</b>Servers</div>
<div class="stat"><b>{data["summary"]["high"]}</b>High flags</div>
<div class="stat"><b>{data["summary"]["medium"]}</b>Medium flags</div></section>
<aside><strong>Configuration analysis only.</strong> The tool does not connect to servers or discover runtime tools.
These findings do not prove a vulnerability or establish effective file permissions.</aside>
{server_cards}<footer>Generated offline by MCP Access Map. Sensitive environment values are not included.</footer>
</main></body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline MCP config inspector; never executes MCP servers.")
    parser.add_argument("config", type=Path, help="Path to a JSON file containing mcpServers or servers")
    parser.add_argument("-o", "--output", type=Path, default=Path("mcp-access-report.html"), help="HTML report path")
    parser.add_argument("--json", dest="json_output", type=Path, help="Optional sanitized JSON report path")
    args = parser.parse_args(argv)
    try:
        # Avoid reading unbounded files or binary inputs.
        if args.config.stat().st_size > 2_000_000:
            raise ValueError("Configuration file is too large (2 MB limit)")
        obj = json.loads(args.config.read_text(encoding="utf-8"))
        data = report_data(inspect_config(obj))
        args.output.write_text(render_html(data), encoding="utf-8")
        if args.json_output:
            args.json_output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Could not inspect configuration: {exc}", file=sys.stderr)
        return 1
    print(f"Inspected {data['summary']['servers']} server(s); HTML report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
