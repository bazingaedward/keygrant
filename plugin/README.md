# keygrant for Claude Code

Let Claude use your API keys without ever seeing them. keygrant keeps secret
values out of the model's context: Claude works with secret **names**, the value
is injected only into the process of the command that needs it, you approve
every command in a native dialog, and output is redacted before Claude sees it.

## What this plugin adds

- **An MCP server, `keygrant`**, with two tools:
  - `list_secrets` returns the names and descriptions of your secrets, never
    their values;
  - `exec_with_secrets` runs one command with the named secrets set as
    environment variables of that command only, after you approve the exact
    command, and returns its output with secret values redacted.
- **A skill, `keygrant`**, that tells Claude to reference secrets as `$NAME`,
  never to ask you to paste a value, and not to retry a denied request.

There is deliberately no tool for storing a secret: a value typed into a tool
call would be in the model's context.

## Requirements

- [uv](https://docs.astral.sh/uv/getting-started/installation/), which provides
  `uvx`. uv downloads a suitable Python automatically.
- macOS, Windows, or Linux with a Secret Service keyring (`secret-tool`) and
  `zenity` for approval dialogs.

## Add a secret

Values go in from your own terminal, never through the chat. The value is read
from stdin:

```bash
uvx keygrant==0.1.6 set STRIPE_KEY --desc "stripe, test mode"
```

Then ask Claude, for example: "List the five most recent Stripe charges using
STRIPE_KEY." Approve the command in the dialog that appears.

## What it runs, stores, and sends

- **Runs:** `uvx keygrant==0.1.6 mcp`, which downloads the `keygrant` package,
  version 0.1.6, from PyPI the first time and runs it locally as a stdio MCP
  server. Source: https://github.com/bazingaedward/keygrant
- **Stores:** secret values in your operating system's credential store (DPAPI on
  Windows, the login Keychain on macOS, Secret Service on Linux), plus metadata
  such as names, descriptions and use counts in a local `keygrant` config folder.
- **Sends:** nothing, by default. keygrant makes no network requests of its own
  unless you opt in to its end-to-end encrypted cloud sync with
  `keygrant cloud init`, which is separate from this plugin and documented at
  https://keygrant.app/docs/cloud-sync/
- **Your commands:** commands Claude runs through `exec_with_secrets` do whatever
  they do, including network calls, with the secrets you approved. The dialog
  shows each command in full before it runs.

## Limits

An approved command can still send a secret anywhere it likes, so read the
command before you approve it. Redaction is a second line of defense and can
miss encodings it doesn't know. keygrant doesn't protect against malware running
as your user. Threat model: https://keygrant.app/why/

Documentation: https://keygrant.app/docs/ · Privacy: https://keygrant.app/privacy/
· License: Apache-2.0
