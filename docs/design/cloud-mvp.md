# keygrant Cloud MVP: zero-knowledge sync, teams, audit

Status: draft for review · Owner: Edward · 2026-10-08

## Problem

keygrant 0.x is single-machine and single-user. That blocks the three things
teams need before they can rely on it:

1. **The same secrets on every device and for every teammate.** Today each
   person re-enters values by hand, or keeps them in a shared doc in
   plaintext — which is how this project's own team stored keys until
   2026-10-08.
2. **Visibility.** Nobody can see which agent used which secret, when, for
   what command. Usage metadata lives only in each local `vault.json`.
3. **Central control.** No way to share a secret with a team, remove a
   leaver's access, or rotate a value once for everyone.

Constraint that shapes everything below: **the server must never be able to
read a secret value.** A free cloud that stores plaintext keys would be the
most valuable target we own; a breach would end the project.

## Goals / non-goals

Goals (MVP)
- GitHub sign-in from the CLI (device flow).
- End-to-end encrypted sync of secrets across one user's devices.
- Teams: an org shares vaults; members are added and removed; removal
  triggers rotation guidance.
- Audit: every approval decision (approved/denied, secret names, command,
  device, time) is uploaded and viewable per org.
- Local behaviour unchanged: exec, approval dialogs and redaction stay
  on-device; the cloud is only a sync and audit backend.

Non-goals (later)
- Billing and plan limits (pricing is decided separately).
- Policy distribution (per-secret egress hosts, allowed commands).
- Web dashboard beyond a minimal read-only audit page.
- SSO/SCIM, self-hosting.

## Solution

### Architecture

```
 device (CLI + MCP)                         Cloudflare
 ┌───────────────────────────┐   HTTPS   ┌──────────────────────────────┐
 │ keygrant / keygrant-mcp   │ ────────▶ │ Worker  api.keygrant.app     │
 │  local keystore (values)  │           │  auth · devices · vaults ·   │
 │  device X25519 keypair    │ ◀──────── │  secrets(ciphertext) · audit │
 │  encrypt/decrypt here     │           │ D1 (SQLite): metadata +      │
 └───────────────────────────┘           │  ciphertext only             │
                                         └──────────────────────────────┘
```

### Identity and auth

- The CLI runs GitHub's OAuth **device flow** directly against GitHub
  (`keygrant login` prints a code; the user confirms in a browser). Device
  flow needs only a public client ID.
- The CLI sends the GitHub token to `POST /v1/auth/github` once. The Worker
  verifies it with GitHub's `/user` API, then issues **its own** short-lived
  access token (15 min) plus a rotating refresh token, and discards the GitHub
  token. Our API never accepts GitHub tokens elsewhere (no token passthrough).
- Our tokens are stored in the local keystore under a reserved account, never
  in a plain file.

### Key hierarchy (zero-knowledge)

| Key | Where it lives | Purpose |
|---|---|---|
| Device keypair (X25519) | Private key in the device's local keystore; public key on the server | Receives wrapped vault keys |
| Vault key (256-bit symmetric) | Never on the server in the clear; stored as **envelopes**, one per authorised device, each sealed to that device's public key | Encrypts secret values |
| Recovery key | Shown once at first login for the user to keep offline; also wraps the vault keys | Recovering when all devices are lost |

- Secret values are encrypted on the device with the vault key
  (AES-256-GCM, fresh 96-bit nonce, secret name + vault ID + version as
  associated data, so ciphertexts can't be swapped between names).
- **Adding a device:** the new device registers its public key and shows a
  short fingerprint. On an existing device, `keygrant devices approve`
  shows the same fingerprint; on confirmation it seals the vault keys to the
  new device. The server only relays envelopes.
- **Adding a teammate:** the same mechanism. An admin's device seals the
  team vault key to each of the new member's approved devices.
- **Removing a member or device:** the server deletes the envelopes and
  revokes tokens immediately. Because the removed party may have kept
  plaintext copies, the CLI then lists the affected secrets and recommends
  rotating them, plus rotating the vault key (re-encrypting everything) on
  the next write.

The server sees: user IDs, device public keys, vault and secret **names**,
ciphertexts, envelopes, audit events. It never sees values or vault keys.

### Sync model

- `keygrant sync` pulls ciphertexts newer than the last sync cursor, decrypts
  them on the device, and stores the values in the local keystore exactly
  like `keygrant set` does (marked `source: cloud:<vault>`). Exec and
  approval paths do not change.
- `keygrant set NAME --vault TEAM` encrypts and pushes. Writes carry the
  version they were based on; the server rejects stale writes (optimistic
  concurrency) and the CLI asks the user to resolve.
- The MCP server never talks to the cloud for values; it only appends audit
  events to a local queue that the CLI or a background flush uploads.

### Audit

Event: `{org, vault, device, user, secret_names[], command, decision:
approved|denied|timeout, ts}`. Commands reference secrets by `$NAME`, not
value, and are stored in full by default so admins can see what an agent
actually ran. Because a command may still contain sensitive arguments, an org
can switch the command field to `sha256`. Events are append-only:
there is no update or delete API.

### Server

- Cloudflare Worker (TypeScript) + D1, in a `cloud/` directory of this repo
  with its own `wrangler.toml` and SQL migrations.
- Tables: `users`, `devices`, `refresh_tokens`, `orgs`, `memberships`,
  `vaults`, `vault_envelopes`, `secrets`, `audit_events`.
- Endpoints (all JSON, `Authorization: Bearer <our access token>`):

| Method & path | Purpose |
|---|---|
| `POST /v1/auth/github` | Exchange a GitHub token for our tokens |
| `POST /v1/auth/refresh` | Rotate the refresh token |
| `POST /v1/devices` · `GET /v1/devices` · `DELETE /v1/devices/:id` | Register, list, remove devices |
| `POST /v1/vaults/:id/envelopes` | Upload envelopes sealed to other devices |
| `GET /v1/vaults/:id/secrets?since=` | Pull ciphertexts |
| `PUT /v1/vaults/:id/secrets/:name` · `DELETE …` | Push or delete a ciphertext (versioned) |
| `POST /v1/orgs` · `POST /v1/orgs/:id/members` · `DELETE …/members/:user` | Teams |
| `POST /v1/audit` · `GET /v1/orgs/:id/audit` | Upload and read audit events |

- Rate limiting per token; request bodies capped; CORS closed (CLI only).

### Client

- New module `keygrant_cloud.py` with commands `login`, `logout`, `sync`,
  `devices list|approve|rm`, `org create|invite|rm`, `audit`.
- **Dependency:** Python's standard library has no X25519 or AES-GCM, so the
  cloud features need `cryptography`. It ships as an optional extra
  (`uv tool install 'keygrant[cloud]'`); the local tool stays dependency-free.

## Phasing

1. **Skeleton:** Worker + D1 schema + GitHub login + device registration;
   `keygrant login` end to end on staging.
2. **Personal sync:** key hierarchy, envelopes, device approval, recovery
   key, `sync`, `set --vault`.
3. **Teams and audit:** orgs, membership, envelope fan-out, removal flow,
   audit upload and `keygrant audit`.
4. **Later:** policy distribution, web dashboard, billing.

## Security review checklist (before public beta)

- Server code paths never log request bodies or ciphertexts.
- AEAD associated data binds ciphertext to vault, name and version.
- Device approval requires matching fingerprints on both devices.
- Refresh tokens are single-use and rotate; reuse revokes the whole family.
- Audit events can't be modified or deleted through the API.
- External review of the crypto design before the beta announcement.

## Decisions (2026-10-08)

- GitHub OAuth App is owned by the personal `bazingaedward` account.
- Audit command field defaults to `full`; orgs can switch to `sha256`.

## Open questions

- Domain: `api.keygrant.app` (the homepage domain in `pyproject.toml`)?
- Which Cloudflare account hosts it — personal or company?
