#!/usr/bin/env bash
# tfpi-mcp installer: an MCP server for AI agents on a TF Pi (TerribleFire
# TF4060 + Raspberry Pi with a314). Install TF Pi first. Safe to run again
# (that's also how to update).
#
#   curl -fsSL https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash
#   wget -qO- https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash
#   ... | sudo bash -s -- --uninstall
#
# Environment: TFPI_MCP_REPO, TFPI_MCP_REF (branch/tag/commit), TFPI_USER
set -euo pipefail

REPO=${TFPI_MCP_REPO:-https://github.com/mirq/tfpi-mcp}
REF=${TFPI_MCP_REF:-main}
PREFIX=/opt/tfpi-mcp
UNIT=/etc/systemd/system/tfpi-mcp.service

if [ "$(id -u)" != 0 ]; then
	echo "Run as root: curl -fsSL https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash" >&2
	exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
	systemctl disable --now tfpi-mcp.service 2>/dev/null || true
	rm -f "$UNIT" /usr/local/bin/tfpi-mcp
	rm -rf "$PREFIX"
	systemctl daemon-reload
	echo "tfpi-mcp removed. Settings stay in /etc/tfpi-mcp; the agent copy in PI0:.tfmcp too."
	exit 0
fi

# --- Stage 1: fetch the repo, then run the installer from it ----------------
self_dir=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
	self_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
if [ "${TFPI_MCP_STAGE:-1}" = 1 ] || [ ! -d "$self_dir/tfmcp" ]; then
	command -v git >/dev/null || { apt-get update; apt-get install -y git ca-certificates; }
	mkdir -p "$PREFIX"
	# A checkout damaged by a power cut (the Pi loses power with the Amiga) is cloned again.
	if ! { [ -d "$PREFIX/src/.git" ] && git -C "$PREFIX/src" fetch --quiet --tags origin; }; then
		rm -rf "$PREFIX/src"
		git clone --quiet "$REPO" "$PREFIX/src"
	fi
	git -C "$PREFIX/src" checkout --quiet --force --detach "origin/$REF" 2>/dev/null \
		|| git -C "$PREFIX/src" checkout --quiet --force --detach "$REF"
	echo "tfpi-mcp at $(git -C "$PREFIX/src" rev-parse --short HEAD)"
	TFPI_MCP_STAGE=2 exec bash "$PREFIX/src/install.sh" "$@"
fi
cd "$self_dir"

# --- Checks -------------------------------------------------------------------
PI_USER=${TFPI_USER:-$(getent passwd 1000 | cut -d: -f1)}
if [ -z "$PI_USER" ]; then
	echo "No user with uid 1000 (the a314 user). Set TFPI_USER=name." >&2
	exit 1
fi
PI_GROUP=$(id -gn "$PI_USER")
PI_HOME=$(getent passwd "$PI_USER" | cut -d: -f6)
if [ ! -x /opt/a314/a314d ]; then
	echo "WARNING: /opt/a314/a314d not found. Install TF Pi first:" >&2
	echo "  curl -fsSL https://terriblefire.github.io/tfpi/install.sh | sudo bash" >&2
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Python 3.9+ needed" >&2; exit 1; }

# --- Packages: a 68k disassembler for the debugger (optional) -----------------
if ! command -v m68k-linux-gnu-objdump >/dev/null; then
	apt-get install -y --no-install-recommends binutils-m68k-linux-gnu \
		|| { apt-get update && apt-get install -y --no-install-recommends binutils-m68k-linux-gnu; } \
		|| echo "WARNING: binutils-m68k-linux-gnu not installed: the disassemble tool won't work"
fi

# --- Files ----------------------------------------------------------------------
install -d "$PREFIX/lib"
rm -rf "$PREFIX/lib/tfmcp"
cp -r "$self_dir/tfmcp" "$PREFIX/lib/tfmcp"
find "$PREFIX/lib/tfmcp" -name __pycache__ -prune -exec rm -rf {} +
install -m755 "$self_dir/bin/tfpi-mcp" /usr/local/bin/tfpi-mcp

# settings belong to the service user (tokens are written there)
install -d -m750 -o "$PI_USER" -g "$PI_GROUP" /etc/tfpi-mcp
chown "$PI_USER:$PI_GROUP" /etc/tfpi-mcp/config.json 2>/dev/null || true

# the agent where the Amiga can run it: PI0:.tfmcp/tfdbgd
share=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["devices"]; print((d.get("PI0") or next(iter(d.values())))["path"])' \
	/etc/opt/a314/a314fs.conf 2>/dev/null || echo "$PI_HOME/a314shared")
if [ -d "$share" ]; then
	install -d -o "$PI_USER" -g "$PI_GROUP" "$share/.tfmcp"
	install -m755 -o "$PI_USER" -g "$PI_GROUP" "$self_dir/tfmcp/amiga/tfdbgd" "$share/.tfmcp/tfdbgd"
	echo "Agent: PI0:.tfmcp/tfdbgd ($share/.tfmcp/tfdbgd)"
else
	echo "WARNING: a314fs share $share not found; agent_start will copy the agent once it exists"
fi

sed -e "s/##USER##/$PI_USER/" -e "s/##GROUP##/$PI_GROUP/" "$self_dir/systemd/tfpi-mcp.service" > "$UNIT"
chmod 644 "$UNIT"
git -C "$self_dir" rev-parse HEAD > "$PREFIX/version" 2>/dev/null || true
systemctl daemon-reload
systemctl enable tfpi-mcp.service
systemctl restart tfpi-mcp.service
sync    # the Pi may lose power with the Amiga at any time

host=$(hostname)
cat <<EOF

=== tfpi-mcp installed ($(cat "$PREFIX/version" 2>/dev/null | cut -c1-7))

Connect an MCP client over SSH (key login as $PI_USER), e.g. Claude Code:
  claude mcp add amiga -- ssh $PI_USER@$host.local tfpi-mcp

or in an MCP JSON config:
  {"mcpServers": {"amiga": {"command": "ssh", "args": ["$PI_USER@$host.local", "tfpi-mcp"]}}}

HTTP instead of SSH (bearer token):
  sudo tfpi-mcp config set http.enabled true && sudo systemctl restart tfpi-mcp
  tfpi-mcp config token        # then use http://$host.local:8765/mcp

On the Amiga the agent starts with the agent_start tool, or by hand:
  run >NIL: PI0:.tfmcp/tfdbgd
Check everything: tfpi-mcp call amiga_status
EOF
