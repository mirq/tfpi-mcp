"""The MCP protocol layer: stdio and HTTP transports, tool listing/calls."""

import io
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

from helpers import ROOT, Env, Rig

from tfmcp import __version__, mcp, tools


def rpc(method, req_id=1, **params):
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


class Protocol(Env):
    def setUp(self):
        super().setUp()
        self.server = mcp.Server("tfpi-mcp", __version__, tools.build(), tools.INSTRUCTIONS)

    def test_initialize_and_list(self):
        reply = self.server.handle(rpc("initialize", protocolVersion="2025-06-18", capabilities={},
                                       clientInfo={"name": "t", "version": "1"}))
        self.assertEqual(reply["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", reply["result"]["capabilities"])
        self.assertIn("amiga_status", reply["result"]["instructions"])
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        listed = self.server.handle(rpc("tools/list", 2))["result"]["tools"]
        names = {t["name"] for t in listed}
        for name in ("amiga_run", "screenshot", "debug_launch", "crash_report", "files_write"):
            self.assertIn(name, names)
        for t in listed:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"])
        self.assertEqual(self.server.handle(rpc("initialize", 3, protocolVersion="1999-01-01"))
                         ["result"]["protocolVersion"], mcp.PROTOCOL_VERSIONS[0])

    def test_errors(self):
        self.assertEqual(self.server.handle(rpc("nope"))["error"]["code"], mcp.METHOD_NOT_FOUND)
        bad = self.server.handle(rpc("tools/call", name="files_read", arguments={"wrong": 1}))
        self.assertTrue(bad["result"]["isError"])
        unknown = self.server.handle(rpc("tools/call", name="nope", arguments={}))
        self.assertTrue(unknown["result"]["isError"])
        self.assertIn("parse error", self.server.handle_text("{not json"))

    def test_bridge_down_is_a_tool_error(self):
        result = self.server.handle(rpc("tools/call", name="list_tasks", arguments={}))["result"]
        self.assertTrue(result["isError"])
        self.assertIn("bridge is not running", result["content"][0]["text"])

    def test_stdio(self):
        lines = [json.dumps(rpc("initialize", 1, protocolVersion="2025-06-18")),
                 json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                 json.dumps(rpc("tools/call", 2, name="alert_decode", arguments={"code": "80000003"}))]
        out = io.BytesIO()
        self.server.serve_stdio(io.BytesIO(("\n".join(lines) + "\n").encode()), out)
        import time
        deadline = time.time() + 5
        while out.getvalue().count(b"\n") < 2 and time.time() < deadline:
            time.sleep(0.01)
        replies = {r["id"]: r for r in map(json.loads, out.getvalue().splitlines())}
        self.assertEqual(replies[1]["result"]["serverInfo"]["name"], "tfpi-mcp")
        text = replies[2]["result"]["content"][0]["text"]
        self.assertIn("address error", text)
        self.assertEqual(replies[2]["result"]["structuredContent"]["code"], "80000003")

    def test_cli_entry_point(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        proc = subprocess.run([sys.executable, "-m", "tfmcp"], input=json.dumps(rpc("tools/list")) + "\n",
                              capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("debug_launch", proc.stdout)
        proc = subprocess.run([sys.executable, "-m", "tfmcp", "call", "alert_decode", '{"code": "81000009"}'],
                              capture_output=True, text=True, env=env, timeout=30)
        self.assertIn("AN_FreeTwice", proc.stdout)


class Http(Rig):
    def test_token_and_calls(self):
        server = mcp.Server("tfpi-mcp", __version__, tools.build(self.tools), tools.INSTRUCTIONS)
        httpd = server.http_server("127.0.0.1", 0, "secret-token")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{httpd.server_address[1]}/mcp"

        def post(body, token="secret-token"):
            req = urllib.request.Request(url, json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/json, text/event-stream",
                                                  **({"Authorization": f"Bearer {token}"} if token else {})})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        try:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                post(rpc("ping"), token="wrong")
            self.assertEqual(caught.exception.code, 401)
            status, body = post(rpc("tools/call", name="memory_stats", arguments={}))
            self.assertEqual(status, 200)
            self.assertIn("chip_free", json.loads(body)["result"]["content"][0]["text"])
            status, body = post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.assertEqual((status, body), (202, b""))
        finally:
            httpd.shutdown()
