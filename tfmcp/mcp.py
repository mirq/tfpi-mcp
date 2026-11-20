"""A small Model Context Protocol server (JSON-RPC 2.0), standard library only.

Transports: stdio (newline-delimited JSON, e.g. `ssh pi tfpi-mcp`) and
streamable HTTP without server-sent streams (POST /mcp answers with JSON).
"""

import hmac
import json
import logging
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("tfmcp.mcp")

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = (
    -32700, -32600, -32601, -32602, -32603)


class ToolError(Exception):
    """A failure to report to the model as a tool result (isError)."""


class Tool:
    def __init__(self, name, description, schema, func, read_only=False, destructive=False, title=None):
        self.name = name
        self.description = description
        self.schema = schema
        self.func = func
        self.read_only = read_only
        self.destructive = destructive
        self.title = title

    def spec(self):
        spec = {"name": self.name, "description": self.description, "inputSchema": self.schema,
                "annotations": {"readOnlyHint": self.read_only, "destructiveHint": self.destructive,
                                "openWorldHint": False}}
        if self.title:
            spec["title"] = self.title
            spec["annotations"]["title"] = self.title
        return spec


class Server:
    def __init__(self, name, version, tools, instructions=""):
        self.name = name
        self.version = version
        self.tools = {t.name: t for t in tools}
        self.instructions = instructions

    def _result(self, value):
        """Tool return value -> CallToolResult. Lists of content items pass
        through; anything else becomes JSON text (and structuredContent)."""
        if isinstance(value, dict) and "_content" in value:
            content = value.pop("_content")
            text = json.dumps(value, indent=1, default=str) if value else None
            items = ([{"type": "text", "text": text}] if text else []) + content
            return {"content": items, "isError": False}
        if isinstance(value, str):
            return {"content": [{"type": "text", "text": value}], "isError": False}
        text = json.dumps(value, indent=1, default=str)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        if isinstance(value, dict):
            result["structuredContent"] = json.loads(text)
        return result

    def call_tool(self, name, args):
        tool = self.tools.get(name)
        if tool is None:
            return {"content": [{"type": "text", "text": f"unknown tool {name!r}"}], "isError": True}
        try:
            return self._result(tool.func(**(args or {})))
        except ToolError as error:
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}
        except TypeError as error:
            return {"content": [{"type": "text", "text": f"bad arguments for {name}: {error}"}], "isError": True}
        except Exception as error:     # report, don't kill the session
            log.error("tool %s failed: %s", name, traceback.format_exc())
            return {"content": [{"type": "text", "text": f"{name} failed: {type(error).__name__}: {error}"}],
                    "isError": True}

    def handle(self, msg):
        """One JSON-RPC message -> response dict, or None for notifications."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return self._error(msg.get("id") if isinstance(msg, dict) else None, INVALID_REQUEST, "invalid request")
        method = msg["method"]
        params = msg.get("params") or {}
        if "id" not in msg:
            return None             # notifications (initialized, cancelled, ...)
        req_id = msg["id"]
        if method == "initialize":
            wanted = params.get("protocolVersion")
            version = wanted if wanted in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return self._ok(req_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": self.version},
                "instructions": self.instructions,
            })
        if method == "ping":
            return self._ok(req_id, {})
        if method == "tools/list":
            return self._ok(req_id, {"tools": [t.spec() for t in self.tools.values()]})
        if method == "tools/call":
            if not isinstance(params.get("name"), str):
                return self._error(req_id, INVALID_PARAMS, "tools/call needs a name")
            return self._ok(req_id, self.call_tool(params["name"], params.get("arguments")))
        if method in ("resources/list", "prompts/list"):
            return self._ok(req_id, {method.split("/")[0]: []})
        if method == "resources/templates/list":
            return self._ok(req_id, {"resourceTemplates": []})
        return self._error(req_id, METHOD_NOT_FOUND, f"method {method!r} not found")

    @staticmethod
    def _ok(req_id, result):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id, code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def handle_text(self, text):
        """Raw JSON text (a message or a batch) -> response text or None."""
        try:
            msg = json.loads(text)
        except ValueError:
            return json.dumps(self._error(None, PARSE_ERROR, "parse error"))
        if isinstance(msg, list):
            replies = [r for r in (self.handle(m) for m in msg) if r is not None]
            return json.dumps(replies) if replies else None
        reply = self.handle(msg)
        return json.dumps(reply) if reply is not None else None

    # ---- transports ------------------------------------------------------------------

    def serve_stdio(self, stdin=None, stdout=None):
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        lock = threading.Lock()

        def answer(line):
            reply = self.handle_text(line)
            if reply is not None:
                with lock:
                    stdout.write(reply.encode() + b"\n")
                    stdout.flush()

        workers = []
        for raw in stdin:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            # tool calls may wait for the Amiga: answer them concurrently
            worker = threading.Thread(target=answer, args=(line,), daemon=True)
            worker.start()
            workers = [w for w in workers if w.is_alive()] + [worker]
        for worker in workers:          # stdin closed: finish what was asked
            worker.join(600)

    def http_server(self, bind, port, token):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log.debug("http: " + fmt, *args)

            def _send(self, code, body=b"", ctype="application/json", extra=None):
                self.send_response(code)
                if body:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _authorized(self):
                auth = self.headers.get("Authorization", "")
                given = auth[7:] if auth.lower().startswith("bearer ") else ""
                return bool(token) and hmac.compare_digest(given.encode(), token.encode())

            def do_POST(self):
                if self.path.split("?")[0] not in ("/mcp", "/mcp/"):
                    return self._send(404)
                if not self._authorized():
                    return self._send(401, b'{"error":"bearer token required"}',
                                      extra={"WWW-Authenticate": "Bearer"})
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                reply = server.handle_text(body)
                if reply is None:
                    return self._send(202)
                return self._send(200, reply.encode())

            def do_GET(self):
                self._send(405, extra={"Allow": "POST"})

            def do_DELETE(self):
                self._send(405, extra={"Allow": "POST"})

        httpd = ThreadingHTTPServer((bind, port), Handler)
        httpd.daemon_threads = True
        return httpd
