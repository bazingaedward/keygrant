# secretctl

Per-command secret injection for AI coding agents. Secrets live in a local
DPAPI-encrypted vault; the model's context only ever sees secret **names** —
values are injected into the child process environment at exec time, and all
output is redacted before it returns to the model.

**Why:** anything placed in an LLM's context can be exfiltrated (prompt
injection, logs, generated code). The fix is architectural: keys never enter
context, only the execution environment.

## Components

- `secretctl.py` — vault + CLI
  - `secretctl set NAME [--desc TEXT]` — store a secret (value via stdin, never argv)
  - `secretctl list` / `rm NAME`
  - `secretctl exec [--redact] NAMES -- CMD` — run CMD with secrets injected
  - `secretctl revoke NAME|--all` — revoke active approval grants
- `secretctl_mcp.py` — MCP server (stdio JSON-RPC, zero deps)
  - `list_secrets` — names/descriptions/usage only, never values
  - `exec_with_secrets` — server-side exec with injection + forced output redaction
  - deliberately **no** set/store tool: writing a value through the model would
    put it in context; values enter out-of-band via the CLI only

## Claude Code setup

`.mcp.json` in your project:

```json
{
  "mcpServers": {
    "secretctl": {
      "command": "python",
      "args": ["D:/Projects/secretctl/secretctl_mcp.py"]
    }
  }
}
```

## Approval

Every use of a secret — via the CLI or the MCP server — requires the user's
approval through a native, topmost dialog (deny by default on a 60s timeout).
Approving grants access to that secret for **15 minutes**, tracked in
`grants.json`; `secretctl revoke` withdraws a grant early. Both channels share
the same grant store, so an agent cannot bypass MCP approval by shelling out
to the CLI. The dialog will be replaced by a resident tray app with toast
notifications; the grant semantics stay the same.

## Storage

`%APPDATA%\secretctl\vault.json` — values encrypted with Windows DPAPI
(per-user), plus usage metadata (use count, last used) as the seed of an
audit trail. Prototype is Windows-only; macOS Keychain / libsecret are next.

## Roadmap (prototype → product)

1. Resident tray app (replaces the modal dialog; approval history, revoke UI)
2. Per-requester grants (today a grant is per-secret: any process may use it
   during the TTL window)
3. macOS/Linux keystores
4. Harden exec surface (shell injection) and redaction (encoding variants)
5. Open-source release; later: zero-knowledge cloud control plane (team
   sharing, mobile approvals, audit) as the paid tier
