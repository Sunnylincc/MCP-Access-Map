import json
import tempfile
import unittest
from pathlib import Path

from mcp_access_map import inspect_config, main, render_html, report_data


class ScannerTests(unittest.TestCase):
    def test_common_keys(self):
        self.assertEqual(len(inspect_config({"mcpServers": {"a": {"command": "node"}}})), 1)
        self.assertEqual(len(inspect_config({"servers": {"a": {"url": "https://example.com"}}})), 1)

    def test_secret_redaction_and_html_escaping(self):
        secret = "NEVER_PRINT_THIS_SECRET_923"
        servers = inspect_config({"mcpServers": {
            "danger": {"command": "bash", "args": ["-c", "echo hello"], "env": {"API_TOKEN": secret}},
            "<script>alert(1)</script>": {"url": "https://name:pass@host.example/path?key=othersecret"}
        }})
        data = report_data(servers)
        serialized = json.dumps(data)
        page = render_html(data)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret, page)
        self.assertNotIn("othersecret", serialized)
        self.assertNotIn("name:pass", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_suspicious_flags(self):
        servers = inspect_config({"mcpServers": {"shell": {
            "command": "bash", "args": ["-c", "ls", "/home/user/.ssh"]
        }}})
        titles = [f.title for f in servers[0].findings]
        self.assertIn("Shell execution", titles)
        self.assertIn("Sensitive path referenced", titles)

    def test_malformed_configs(self):
        self.assertEqual(inspect_config({"mcpServers": {}}), [])
        with self.assertRaises(ValueError):
            inspect_config({"unrelated": {}})
        with self.assertRaises(ValueError):
            inspect_config({"servers": []})

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = root / "config.json"
            cfg.write_text('{"mcpServers":{"one":{"command":"node"}}}', encoding="utf-8")
            html = root / "report.html"
            output = root / "report.json"
            self.assertEqual(main([str(cfg), "-o", str(html), "--json", str(output)]), 0)
            self.assertIn("MCP Access Map", html.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["servers"], 1)


if __name__ == "__main__":
    unittest.main()
