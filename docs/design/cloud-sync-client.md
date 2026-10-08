# Cloud sync client (preview)

Status: implemented on `feat/cloud-client` · Owner: Edward · 2026-10-08

## Problem

keygrant keeps secrets on one machine. Using the same secrets on a second
machine means re-entering every value by hand, or keeping them in a shared
document in plaintext — the exact exposure keygrant exists to prevent.

## Solution

An optional, end-to-end encrypted sync client (`keygrant_cloud.py`,
`keygrant[cloud]` extra). The server stores ciphertext only; decryption,
approval and injection stay on the device. Nothing is uploaded unless the
user runs `keygrant push`.

### Keys

| Key | Where | Purpose |
|---|---|---|
| Device signing key (Ed25519) | OS keystore | Signs every API request (`METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body)`) |
| Secret Key (128-bit) | OS keystore; printed once as the Emergency Kit | Second factor of the account unlock key |
| AUK = HKDF(scrypt(password)) ⊕ HKDF(Secret Key) | Cached in the OS keystore | Derives `K_enc` (encrypts the user private key) and `K_mac` |
| User key pair (X25519) | Private half encrypted under `K_enc` on the server | Opens the vault key |
| Vault key (256-bit) | Sealed box to the user public key on the server; cached locally | Encrypts items (XChaCha20-Poly1305) |

### Defences built into the client

- **Item binding.** Each item is encrypted with associated data
  `vault_id | item_id | name | rev`, so the server cannot move a ciphertext
  to another name or vault, or replay an old revision as a new one.
- **Key substitution.** Sealed boxes are anonymous — anyone with the public
  key can make one. The vault key and the user public key each carry an
  HMAC under `K_mac`; the client refuses a key whose MAC does not verify.
- **Pairing.** A new device joins only after the user confirms on an
  existing device that both screens show the same fingerprint. The Secret
  Key travels sealed to the new device's one-time key, and the new device
  still needs the password.
- **No scripted answers.** Passwords and confirmations are read from the
  terminal (`/dev/tty`, or the console on Windows), never from stdin, so an
  agent cannot approve a pairing or supply a password by piping input.

### Local merge rules

- `sync` stores pulled values like `keygrant set` does and links them to
  their cloud item.
- A local-only secret with the same name is never overwritten.
- A local edit to a linked secret is marked dirty. `sync` keeps it, adopts
  the cloud revision as its base and warns; the next `push` overwrites the
  cloud copy deliberately.
- Stale pushes get `409` and change nothing locally.
- A cloud deletion removes the local copy only if it came from the cloud
  and has no unpushed edit.

## Not yet

- Recovering with the Emergency Kit when no device is left.
- Removing a device and rotating the vault key.
- Team vaults, phone approval, audit upload.

## Verification

- `tests/test_cloud_crypto.py`: HKDF against the RFC 5869 vector, item
  binding and tampering, a wrong password, and a substituted vault key and
  user public key. Mutation-checked: removing the vault-key MAC check fails
  the substitution test.
- `tests/test_cloud_sync.py`: the merge rules above. Against the old
  `keygrant set`, which dropped the cloud link, 4 of them fail.
- A manual two-device run against a local server covering sign-up, push,
  pairing, unlock, two-way sync, a 409 conflict, keep-local then
  overwrite, and delete. A database dump afterwards contained no plaintext
  values.
