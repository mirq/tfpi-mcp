"""tfpi-mcp command line.

  tfpi-mcp                      MCP server on stdio (what MCP clients run, e.g. over ssh)
  tfpi-mcp serve                the bridge daemon (+ HTTP MCP if enabled); systemd runs this
  tfpi-mcp tools                list the tools
  tfpi-mcp call TOOL [JSON]     call one tool and print the result (testing)
  tfpi-mcp config show|set KEY VALUE|token
"""

import json
import logging
import signal
import sys
import threading

from . import __version__, bridge, config, mcp, tools


def make_server():
    return mcp.Server("tfpi-mcp", __version__, tools.build(), tools.INSTRUCTIONS)


def cmd_serve():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    conf = config.load()
    b = bridge.Bridge()
    if conf["http"]["enabled"]:
        token = config.ensure_token(conf)
        httpd = make_server().http_server(conf["http"]["bind"], int(conf["http"]["port"]), token)
        threading.Thread(target=httpd.serve_forever, daemon=True, name="http").start()
        logging.info("MCP over HTTP on %s:%s/mcp", conf["http"]["bind"], conf["http"]["port"])

    def stop(*_):
        b.stop()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    b.serve()


def cmd_config(args):
    if not args or args[0] == "show":
        conf = config.load()
        if conf["http"].get("token"):
            conf["http"]["token"] = "(set; tfpi-mcp config token shows it)"
        print(json.dumps(conf, indent=2))
    elif args[0] == "set" and len(args) == 3:
        try:
            value = config.set_value(args[1], args[2])
        except KeyError:
            sys.exit(f"unknown setting {args[1]!r}; see: tfpi-mcp config show")
        print(f"{args[1]} = {json.dumps(value)}  (restart for http.*: sudo systemctl restart tfpi-mcp)")
    elif args[0] == "token":
        print(config.ensure_token(config.load()))
    else:
        sys.exit(__doc__)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "stdio"
    if cmd in ("stdio", "--stdio"):
        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
        make_server().serve_stdio()
    elif cmd == "serve":
        cmd_serve()
    elif cmd == "tools":
        for t in tools.build():
            print(f"{t.name:18} {t.description}")
    elif cmd == "call":
        if len(argv) < 2:
            sys.exit("tfpi-mcp call TOOL [JSON-ARGS]")
        args = json.loads(argv[2]) if len(argv) > 2 else {}
        result = make_server().call_tool(argv[1], args)
        for item in result["content"]:
            if item["type"] == "text":
                print(item["text"])
            else:
                print(f"[{item['type']} {item.get('mimeType', '')}, {len(item.get('data', ''))} base64 chars]")
        sys.exit(1 if result["isError"] else 0)
    elif cmd == "config":
        cmd_config(argv[1:])
    elif cmd in ("--version", "version"):
        print(__version__)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
