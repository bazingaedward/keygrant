# Session grants: "Allow 30 min"

Status: implemented · Owner: Edward · 2026-10-21

## Problem

Since the P0 hardening (`p0-security-hardening.md`), a grant covers one exact
command string. That closed grant riding, but in real agent work almost every
command differs, so the user clicks Allow on every single call. During a burst
of work (deploys, API debugging) the prompts are pure friction, and frequent
rubber-stamping erodes the value of reviewing each one anyway.

## Solution

The approval dialog gains a third button, **Allow 30 min**, next to Deny and
Allow:

- **Allow** — unchanged: this exact command, 15 minutes.
- **Allow 30 min** — a *session grant*: this MCP session may use the secrets
  shown in the dialog in **any** command for 30 minutes
  (`SESSION_GRANT_TTL_SECONDS`), with no further dialogs.

What stays the same:

- Session grants live only in the `GrantStore` of the MCP server process, keyed
  by secret name. Nothing is written to disk; other sessions are unaffected.
- They cover only the secrets the user saw; a new secret still prompts.
- `keygrant revoke NAME|--all` voids them like any other grant.
- The CLI never offers the button and never reuses a grant, so an agent can't
  shell out to `keygrant exec` to get one.
- The default button remains Deny; timeout still means deny (or remote
  approval, which only ever issues a per-command grant).
- Audit events record a session approval as `grant_session`.

Platforms: macOS (`osascript`, 3 buttons) and Linux (zenity
`--extra-button`). The Windows MessageBox has no custom buttons, and mapping
the session grant to Cancel would make Esc grant access, so Windows keeps
per-command approval only.

## Trade-off

This deliberately re-opens gap 1 of the P0 hardening — any command can use the
secret without a dialog — but only after the user explicitly opts in, scoped to
one session and the secrets shown, for 30 minutes. While it lasts, a
prompt-injected agent can use those secrets silently. The dialog text says so,
and the per-command button remains the alternative.
