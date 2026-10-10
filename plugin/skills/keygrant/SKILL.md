---
name: keygrant
description: Use whenever a task needs an API key, token, password or other secret, for example calling an authenticated API, deploying, or publishing a package. Covers finding available secrets with keygrant's list_secrets tool, running commands with exec_with_secrets so values never enter the conversation, and what to tell the user when a secret is missing or a request is denied.
---

# Using secrets with keygrant

Secrets are managed by keygrant and must never appear in this conversation.
The model works only with secret **names**; keygrant injects the values into the
one process that needs them, after the user approves the exact command.

## Rules

- Never ask the user to paste a secret value, and never echo, log, print or
  hardcode one. Don't read `.env` files or shell profiles to find credentials.
- To see which secrets exist, call the `list_secrets` MCP tool. It returns names
  and descriptions, never values.
- To run a command that needs a secret, call `exec_with_secrets` with the command
  and the secret names. Reference each secret as an environment variable inside
  the command:
  - macOS and Linux (runs through `sh -c`): `$STRIPE_KEY`
  - Windows (runs through `cmd /c`): `%STRIPE_KEY%`
- The user approves each command in a native dialog that shows it in full. Keep
  commands short and readable, and under 2000 characters; put longer logic in a
  script file first and show it to the user before running it.
- An approval covers that exact command for 15 minutes. Reuse the identical
  command for retries instead of rewording it.
- If access is denied, do not retry. Ask the user what they want to do.
- Output comes back with secret values redacted, as `[NAME:REDACTED]`. Never try
  to recover a value from output, for example by decoding it.

## When a secret is missing

If `list_secrets` doesn't have what the task needs, ask the user to add it from
their own terminal, outside this conversation, so the value is never typed into
the chat. The value is read from stdin:

```bash
uvx keygrant==0.1.6 set STRIPE_KEY --desc "stripe, test mode"
```

They paste the value, then press Enter and Ctrl+D (Ctrl+Z then Enter on Windows).
If they installed the CLI with `uv tool install keygrant`, `keygrant set ...` works
too. Then call `list_secrets` again.

Full documentation: https://keygrant.app/docs/
