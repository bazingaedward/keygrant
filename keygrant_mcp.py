#!/usr/bin/env python3
"""keygrant MCP server (prototype) — stdio JSON-RPC, zero dependencies.

Exposes the DPAPI vault to AI agents WITHOUT ever returning secret values:
  - list_secrets: names, descriptions, usage metadata only
  - exec_with_secrets: run a shell command with chosen secrets injected as env
    vars; stdout/stderr are redacted (plaintext values masked) BEFORE being
    returned into the model's context.

Deliberately absent: any set/get tool. Storing a secret through the model
would place the value in model context; values enter only out-of-band via
`keygrant set` (stdin) or a future local UI.

Register in Claude Code (.mcp.json):
  {
    "mcpServers": {
      "keygrant": {
        "command": "python",
        "args": ["<path>/keygrant_mcp.py"]
      }
    }
  }
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keygrant import (  # noqa: E402
    GrantStore, load_vault, save_vault, decrypt_value, request_approval, redact,
    record_event,
)

# One MCP server process = one agent session. Its grants live only here, in
# memory, so other sessions, bare CLI calls and files on disk cannot reuse them.
GRANTS = GrantStore()

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "list_secrets",
        "description": (
            "List the names and descriptions of secrets available in the local "
            "vault. Values are never returned. Use exec_with_secrets to run a "
            "command that needs one of these secrets."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "exec_with_secrets",
        "description": (
            "Run a shell command with the named secrets injected as environment "
            "variables (reference them as %NAME% / $env:NAME / $NAME inside the "
            "command). The user must approve access via a native dialog that "
            "shows the full command; approval covers that exact command string "
            "for 15 minutes, so reuse the identical command for retries. "
            "Commands over 2000 characters are refused: put long logic in a "
            "script. A denial is final — never retry it. Output is "
            "returned with any plaintext secret values redacted. This is the "
            "ONLY way to use a secret; values never appear in conversation "
            "context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to run (executed via cmd /c on Windows).",
                },
                "secrets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Names of vault secrets to inject as env vars.",
                },
                "cwd": {
                    "type": "string",
                    "description": "Optional working directory.",
                },
            },
            "required": ["command", "secrets"],
        },
    },
]


def tool_list_secrets(_args: dict) -> str:
    vault = load_vault()
    if not vault:
        return "(vault empty — add secrets out-of-band with: keygrant set NAME)"
    lines = []
    for name, meta in sorted(vault.items()):
        lines.append(
            f"- {name}: {meta.get('desc') or '(no description)'} "
            f"[used {meta.get('use_count', 0)}x, last: {meta.get('last_used') or 'never'}]"
        )
    return "\n".join(lines)


def tool_exec_with_secrets(args: dict) -> str:
    command = args["command"]
    names = args["secrets"]
    vault = load_vault()

    for name in names:
        if name not in vault:
            return f"error: no such secret: {name} (use list_secrets)"

    allowed, reason = request_approval(names, command, GRANTS)
    if not allowed:
        return (
            f"denied: {reason}. Do not retry automatically; "
            "ask the user whether they want to grant access."
        )

    secrets: dict[str, str] = {}
    for name in names:
        secrets[name] = decrypt_value(vault[name])

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for name in names:
        vault[name]["last_used"] = now
        vault[name]["use_count"] = vault[name].get("use_count", 0) + 1
    save_vault(vault)
    record_event("exec", names, command)

    env = os.environ.copy()
    env.update(secrets)
    proc = subprocess.run(
        ["cmd", "/c", command] if os.name == "nt" else ["sh", "-c", command],
        env=env,
        cwd=args.get("cwd") or None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
    )

    out = redact(proc.stdout or "", secrets)
    err = redact(proc.stderr or "", secrets)

    parts = [f"exit code: {proc.returncode}"]
    if out.strip():
        parts.append(f"stdout:\n{out.rstrip()}")
    if err.strip():
        parts.append(f"stderr:\n{err.rstrip()}")
    return "\n".join(parts)


HANDLERS = {
    "list_secrets": tool_list_secrets,
    "exec_with_secrets": tool_exec_with_secrets,
}


def handle(msg: dict):
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "keygrant", "version": "0.1.4"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"unknown tool: {name}"},
            }
        try:
            text = handler(params.get("arguments", {}))
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }
        except Exception as exc:  # tool errors go back as tool results
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                    "isError": True,
                },
            }
    if msg_id is not None:  # unknown request → error; notifications ignored
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    return None


def main() -> None:
    # one server process = one agent session; label it for approvers and audit
    os.environ.setdefault("KEYGRANT_REQUESTER", f"mcp:{os.getpid()}")
    for line in sys.stdin:
        line = line.strip().lstrip("﻿")
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
