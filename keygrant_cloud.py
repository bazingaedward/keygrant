"""keygrant cloud client — v1 personal sync.

Zero-knowledge: values are encrypted on this device and the server only
stores ciphertext. Protocol: keygrant-cloud SPEC §10. Needs PyNaCl:
`uv tool install 'keygrant[cloud]'`.

  keygrant cloud init               create an account on this device
  keygrant cloud status             show account, device and sync state
  keygrant devices                  list devices and their fingerprints
  keygrant devices add              let a new device join (shows a pairing code)
  keygrant pair                     join an account from this device
  keygrant sync                     pull changes into the local vault
  keygrant push [--delete] NAME...  upload local secrets (never implicit)

Key material (device signing key, Secret Key, account unlock key, vault key)
lives in the OS keystore; cloud.json holds references and public data only.
Passwords and confirmations are read from the terminal, never from stdin, so
an agent cannot answer them by piping input.
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import platform
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import keygrant as kg

API = os.environ.get("KEYGRANT_API", "https://api.keygrant.app").rstrip("/")
SCRYPT_N = 2 ** 17
MIN_PASSWORD = 10
_sleep = time.sleep


class CloudError(OSError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _nacl():
    try:
        import nacl.bindings
        import nacl.public
        import nacl.signing
        return nacl
    except ImportError:
        raise CloudError("cloud features need PyNaCl — install with: "
                         "uv tool install 'keygrant[cloud]'") from None


# ---------- primitives ----------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def _lp(*parts) -> bytes:
    """Length-prefixed concatenation, so ("ab","c") and ("a","bc") differ."""
    out = b""
    for p in parts:
        p = p.encode() if isinstance(p, str) else p
        out += len(p).to_bytes(4, "big") + p
    return out


def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_auk(password: str, secret_key: bytes, account_id: str) -> bytes:
    """Account Unlock Key = HKDF(scrypt(password)) XOR HKDF(Secret Key)."""
    p = hashlib.scrypt(password.encode(), salt=account_id.encode(), n=SCRYPT_N,
                       r=8, p=1, maxmem=512 * 1024 * 1024, dklen=32)
    a = hkdf(p, b"keygrant/auk/password/v1")
    b = hkdf(secret_key, b"keygrant/auk/secret-key/v1")
    return bytes(x ^ y for x, y in zip(a, b))


def subkeys(auk: bytes) -> tuple[bytes, bytes]:
    return hkdf(auk, b"keygrant/k-enc/v1"), hkdf(auk, b"keygrant/k-mac/v1")


def mac(k_mac: bytes, *parts) -> str:
    return b64e(hmac.new(k_mac, _lp(*parts), hashlib.sha256).digest())


def mac_ok(k_mac: bytes, expected: str | None, *parts) -> bool:
    return hmac.compare_digest(mac(k_mac, *parts), expected or "")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """XChaCha20-Poly1305; output is base64(nonce || ciphertext)."""
    nonce = os.urandom(24)
    ct = _nacl().bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return b64e(nonce + ct)


def unseal(key: bytes, blob: str, aad: bytes) -> bytes:
    raw = b64d(blob)
    try:
        return _nacl().bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(raw[24:], aad, raw[:24], key)
    except Exception:
        raise CloudError("decryption failed: wrong key or tampered data") from None


def item_aad(vault_id: str, item_id: str, name: str, rev: int) -> bytes:
    return _lp("keygrant/item/v1", vault_id, item_id, name, str(rev))


def user_key_aad(account_id: str) -> bytes:
    return _lp("keygrant/user-key/v1", account_id)


def pair_statement(account_id: str, pubkey_b64: str) -> bytes:
    return f"keygrant/pair/v1\n{account_id}\n{pubkey_b64}".encode()


def recover_statement(account_id: str, challenge: str, pubkey_b64: str) -> bytes:
    return f"keygrant/recover/v1\n{account_id}\n{challenge}\n{pubkey_b64}".encode()


def approval_request_hash(requester: str, names: list[str], command: str) -> str:
    """Canonical request hash (SPEC §10.1 E). The verdict signs over this, and
    the CLI recomputes it locally — so the approver provably saw THIS request."""
    return hashlib.sha256(
        _lp("keygrant/approval-request/v1", requester, ",".join(names), command)).hexdigest()


def verdict_statement(approval_id: str, command_hash: str, verdict: str, ttl: int) -> bytes:
    return f"keygrant/verdict/v1\n{approval_id}\n{command_hash}\n{verdict}\n{ttl}".encode()


def recovery_signer(auk: bytes):
    """Deterministic Ed25519 key from the AUK: anyone who can derive the AUK
    (password + Secret Key) can prove account ownership to the server, which
    stores only the public half."""
    return _nacl().signing.SigningKey(hkdf(auk, b"keygrant/recovery/v1"))


def parse_secret_key(text: str) -> bytes:
    s = text.strip().upper().replace("-", "").removeprefix("A3")
    try:
        sk = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        raise CloudError("that does not look like a Secret Key (A3-XXXXX-…)") from None
    if len(sk) != 16:
        raise CloudError("Secret Key has the wrong length")
    return sk


def fingerprint(pubkey: bytes) -> str:
    h = hashlib.sha256(pubkey).hexdigest()[:16]
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


def format_secret_key(sk: bytes) -> str:
    s = base64.b32encode(sk).decode().rstrip("=")
    return "A3-" + "-".join(s[i:i + 5] for i in range(0, len(s), 5))


# ---------- terminal input (never stdin) ----------

def _tty_line(prompt: str) -> str:
    if os.name == "nt":
        import msvcrt
        sys.stderr.write(prompt)
        sys.stderr.flush()
        chars = []
        while (ch := msvcrt.getwche()) not in "\r\n":
            chars.append(ch)
        sys.stderr.write("\n")
        return "".join(chars).strip()
    try:
        # two handles: buffered "r+" needs a seekable stream, which a tty is not
        with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty_out:
            tty_out.write(prompt)
            tty_out.flush()
            return tty_in.readline().strip()
    except OSError:
        raise CloudError("this step needs an interactive terminal; it never reads "
                         "stdin, so it cannot be answered by a script or an agent") from None


def ask(prompt: str) -> str:
    return _tty_line(prompt)


def ask_secret(prompt: str) -> str:
    if os.name != "nt":
        try:
            os.close(os.open("/dev/tty", os.O_RDWR))  # getpass falls back to stdin otherwise
        except OSError:
            raise CloudError("password entry needs an interactive terminal") from None
    return getpass.getpass(prompt)


def ask_new_password() -> str:
    while True:
        pw = ask_secret(f"Choose an account password (min {MIN_PASSWORD} characters): ")
        if len(pw) < MIN_PASSWORD:
            print("too short", file=sys.stderr)
            continue
        if ask_secret("Repeat the password: ") == pw:
            return pw
        print("passwords do not match", file=sys.stderr)


# ---------- local state ----------

def state_path() -> str:
    return os.path.join(kg.VAULT_DIR, "cloud.json")


def load_state() -> dict:
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    os.makedirs(kg.VAULT_DIR, exist_ok=True)
    tmp = state_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, state_path())


def _secret(state: dict, key: str) -> bytes:
    return b64d(kg.decrypt_value(state[key]))


def _store(state: dict, key: str, value: bytes) -> None:
    old = state.get(key)
    state[key] = kg.encrypt_value(b64e(value))
    if old:
        kg.delete_value(old)


def require_account(state: dict) -> dict:
    if not state.get("account_id"):
        raise CloudError("no cloud account on this device — run `keygrant cloud init` "
                         "or `keygrant pair`")
    return state


def require_unlocked(state: dict) -> dict:
    require_account(state)
    if not state.get("vault_key"):
        raise CloudError("vault is locked on this device — finish `keygrant pair`")
    return state


# ---------- HTTP ----------

def api(state: dict | None, method: str, path: str, body: dict | None = None,
        timeout: float = 30) -> dict:
    """Call the API; signs with the device key unless state is None."""
    data = b"" if body is None else json.dumps(body).encode()
    headers = {"content-type": "application/json", "user-agent": "keygrant-cli"}
    if state is not None:
        ts = _now_iso()
        nonce = base64.urlsafe_b64encode(os.urandom(18)).decode()
        payload = f"{method}\n{path}\n{ts}\n{nonce}\n{hashlib.sha256(data).hexdigest()}"
        signer = _nacl().signing.SigningKey(_secret(state, "device_key"))
        headers.update({"x-device": state["device_id"], "x-timestamp": ts, "x-nonce": nonce,
                        "x-signature": b64e(signer.sign(payload.encode()).signature)})
    req = urllib.request.Request(API + path, data=data or None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return json.load(res)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error")
        except ValueError:
            detail = None
        if exc.code == 401 and state is not None:
            detail = ("the server no longer recognises this device — it was removed, "
                      "or the cloud account was deleted")
        elif exc.code == 502:
            detail = f"HTTP 502 — if you use an HTTP proxy, check it can reach {API} (no_proxy)"
        raise CloudError(f"{method} {path}: {detail or f'HTTP {exc.code}'}", exc.code) from None
    except urllib.error.URLError as exc:
        raise CloudError(f"cannot reach {API}: {exc.reason}") from None


def _now_iso() -> str:
    """Same shape as the server's Date.toISOString(), so strings compare."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _device_name() -> str:
    return (platform.node() or "device")[:100]


# ---------- account ----------

def cloud_init() -> int:
    state = load_state()
    if state.get("account_id"):
        print(f"this device already belongs to account {state['account_id']}")
        return 0
    nacl = _nacl()
    password = ask_new_password()
    signing = nacl.signing.SigningKey.generate()
    pub = b64e(signing.verify_key.encode())
    reg = api(None, "POST", "/devices", {"pubkey": pub, "name": _device_name()})
    account_id = reg["account_id"]
    state = {"api": API, "account_id": account_id, "device_id": reg["device_id"],
             "device_pub": pub, "cursor": 0, "items": {}}
    _store(state, "device_key", signing.encode())
    save_state(state)

    sk = os.urandom(16)
    auk = derive_auk(password, sk, account_id)
    k_enc, k_mac = subkeys(auk)
    user = nacl.public.PrivateKey.generate()
    user_pub = user.public_key.encode()
    api(state, "POST", "/accounts/keys", {
        "user_pubkey": b64e(user_pub),
        "user_pubkey_mac": mac(k_mac, "user-pubkey", account_id, user_pub),
        "enc_user_privkey": seal(k_enc, user.encode(), user_key_aad(account_id)),
        "recovery_pubkey": b64e(recovery_signer(auk).verify_key.encode()),
    })
    vault_id, vault_key = str(uuid.uuid4()), os.urandom(32)
    api(state, "POST", "/vaults", {
        "id": vault_id, "name": "personal",
        "enc_vault_key": b64e(nacl.public.SealedBox(user.public_key).encrypt(vault_key)),
        "vault_key_mac": mac(k_mac, "vault", vault_id, vault_key),
    })
    _store(state, "secret_key", sk)
    _store(state, "auk", auk)
    _store(state, "vault_key", vault_key)
    state["vault_id"] = vault_id
    save_state(state)

    print("\nAccount created. EMERGENCY KIT — write this down and keep it offline:\n")
    print(f"  Account ID:  {account_id}")
    print(f"  Secret Key:  {format_secret_key(sk)}\n")
    print("Your data can only be decrypted with your password AND this Secret Key.")
    print("keygrant cannot recover either one for you.")
    print(f"\nthis device: {_device_name()}  fingerprint {fingerprint(b64d(pub))}")
    return 0


def unlock(state: dict, password: str) -> None:
    """Derive the AUK, verify the account key and vault key, cache them."""
    nacl = _nacl()
    account_id = state["account_id"]
    keys = api(state, "GET", "/accounts/keys")
    auk = derive_auk(password, _secret(state, "secret_key"), account_id)
    k_enc, k_mac = subkeys(auk)
    user_pub = b64d(keys["user_pubkey"])
    if not mac_ok(k_mac, keys.get("user_pubkey_mac"), "user-pubkey", account_id, user_pub):
        raise CloudError("wrong password (or the account key on the server was tampered with)")
    user = nacl.public.PrivateKey(unseal(k_enc, keys["enc_user_privkey"], user_key_aad(account_id)))
    if user.public_key.encode() != user_pub:
        raise CloudError("account key pair mismatch; refusing to continue")
    vaults = api(state, "GET", "/vaults")["vaults"]
    if not vaults:
        raise CloudError("account has no vault")
    v = vaults[0]
    vault_key = nacl.public.SealedBox(user).decrypt(b64d(v["enc_vault_key"]))
    # Sealed boxes are anonymous: anyone with the public key can make one.
    # The MAC under K_mac proves the vault key came from the account owner.
    if not mac_ok(k_mac, v.get("vault_key_mac"), "vault", v["id"], vault_key):
        raise CloudError("vault key failed verification — refusing it (possible key substitution)")
    _store(state, "auk", auk)
    _store(state, "vault_key", vault_key)
    state["vault_id"] = v["id"]
    save_state(state)


def cloud_status() -> int:
    state = require_account(load_state())
    devices = api(state, "GET", "/devices")["devices"]
    print(f"account:  {state['account_id']}")
    print(f"device:   {_device_name()}  fingerprint {fingerprint(b64d(state['device_pub']))}")
    print(f"devices:  {len(devices)}")
    print(f"vault:    {state.get('vault_id') or '(locked)'}")
    print(f"synced:   {len(state.get('items', {}))} item(s), cursor {state.get('cursor', 0)}")
    return 0


def cloud_enable_recovery() -> int:
    """Backfill for accounts created before recovery existed."""
    state = require_account(load_state())
    password = ask_secret("Account password: ")
    auk = derive_auk(password, _secret(state, "secret_key"), state["account_id"])
    _, k_mac = subkeys(auk)
    keys = api(state, "GET", "/accounts/keys")
    if not mac_ok(k_mac, keys.get("user_pubkey_mac"), "user-pubkey",
                  state["account_id"], b64d(keys["user_pubkey"])):
        raise CloudError("wrong password")
    api(state, "POST", "/accounts/recovery-key",
        {"recovery_pubkey": b64e(recovery_signer(auk).verify_key.encode())})
    print("recovery enabled — a new device can now join on its own with")
    print("`keygrant recover` using the emergency kit (`keygrant cloud kit`)")
    return 0


def cloud_kit() -> int:
    state = require_account(load_state())
    print("\nEMERGENCY KIT — write this down and keep it offline:\n")
    print(f"  Account ID:  {state['account_id']}")
    print(f"  Secret Key:  {format_secret_key(_secret(state, 'secret_key'))}\n")
    print("With these plus your password, `keygrant recover` can join a new")
    print("device without any old device online. Guard them accordingly.")
    return 0


def cloud_delete() -> int:
    """Destroy the cloud account (all devices, all ciphertext). Local secrets
    stay in the OS keystore and keep working, as local-only entries."""
    state = require_account(load_state())
    account_id = state["account_id"]
    print("This permanently deletes the cloud account, its ciphertext and every")
    print("paired device, for ALL your machines. Secrets stay on each machine")
    print("as local-only entries. This cannot be undone.\n")
    if ask(f"Type the account ID ({account_id}) to confirm: ") != account_id:
        print("not confirmed")
        return 1
    api(state, "DELETE", "/accounts", {"confirm": account_id})
    # local teardown: key material out of the keystore, cloud links off records
    for key in ("device_key", "secret_key", "auk", "vault_key"):
        if state.get(key):
            kg.delete_value(state[key])
    try:
        os.remove(state_path())
    except FileNotFoundError:
        pass
    vault = kg.load_vault()
    unlinked = 0
    for record in vault.values():
        unlinked += 1 if record.pop("cloud", None) else 0
    kg.save_vault(vault)
    print(f"cloud account deleted; {unlinked} local secret(s) kept as local-only")
    print("other machines keep their local copies but can no longer sync")
    return 0


def cmd_cloud(args: list[str]) -> int:
    sub = args[0] if args else "status"
    if sub == "init":
        return cloud_init()
    if sub == "status":
        return cloud_status()
    if sub == "enable-recovery":
        return cloud_enable_recovery()
    if sub == "kit":
        return cloud_kit()
    if sub == "delete":
        return cloud_delete()
    print("usage: keygrant cloud init | status | enable-recovery | kit | delete", file=sys.stderr)
    return 2


# ---------- devices & pairing ----------

def cmd_devices(args: list[str]) -> int:
    if args == ["add"]:
        return devices_add()
    if args == ["trust"]:
        return devices_trust()
    if args:
        print("usage: keygrant devices [add|trust]", file=sys.stderr)
        return 2
    state = require_account(load_state())
    for d in api(state, "GET", "/devices")["devices"]:
        mark = "  (this device)" if d["id"] == state["device_id"] else ""
        print(f"{fingerprint(b64d(d['pubkey']))}  {d['name']}  {d['id']}{mark}")
    return 0


def _poll(fetch, done, timeout: float = 600, interval: float = 2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = fetch()
        if done(result):
            return result
        _sleep(interval)
    raise CloudError("timed out waiting for the other device")


def devices_add() -> int:
    nacl = _nacl()
    state = require_unlocked(load_state())
    p = api(state, "POST", "/pairings")
    print(f"\nPairing code:  {p['code']}   (valid 10 minutes)")
    print("On the new device run:  keygrant pair\n")
    seen = _poll(lambda: api(state, "GET", f"/pairings/{p['id']}"),
                 lambda r: r["status"] != "open" or r["expires_at"] < _now_iso())
    if seen["status"] != "claimed":
        raise CloudError("pairing expired before a device claimed it")
    kind = seen.get("new_kind") or "cli"
    fp = fingerprint(b64d(seen["new_pubkey"]))
    print(f"Device '{seen['new_name']}' ({kind}) wants to join, fingerprint:\n\n    {fp}\n")
    if kind == "browser":
        print("Browser device: can approve requests and view metadata only —")
        print("it will NOT receive the Secret Key and can never decrypt values.\n")
    if ask("Does the new device show exactly this fingerprint? Type 'yes' to approve: ") != "yes":
        print("not approved")
        return 1
    signer = nacl.signing.SigningKey(_secret(state, "device_key"))
    approval = {
        "signature": b64e(signer.sign(pair_statement(state["account_id"], seen["new_pubkey"])).signature),
    }
    if kind != "browser":
        # Only full CLI devices receive the (sealed) Secret Key.
        sealed_sk = nacl.public.SealedBox(nacl.public.PublicKey(b64d(seen["new_eph_pubkey"])))
        approval["enc_secret_key"] = b64e(sealed_sk.encrypt(_secret(state, "secret_key")))
    resp = api(state, "POST", f"/pairings/{p['id']}/approve", approval)
    if kind == "browser":
        # This CLI verified the fingerprint itself, so it may trust verdicts
        # signed by this approver (used by remote approval).
        state.setdefault("approvers", {})[resp["device_id"]] = {
            "pubkey": seen["new_pubkey"], "name": seen["new_name"]}
        save_state(state)
    print(f"approved '{seen['new_name']}'")
    return 0


def devices_trust() -> int:
    """Backfill: trust browser devices paired before the approver list existed
    (or by another CLI device). Verify each fingerprint against the one shown
    on that browser's console page before saying yes."""
    state = require_account(load_state())
    approvers = state.setdefault("approvers", {})
    candidates = [d for d in api(state, "GET", "/devices")["devices"]
                  if d.get("kind") == "browser" and d["id"] not in approvers]
    if not candidates:
        print("no untrusted browser devices")
        return 0
    added = 0
    for d in candidates:
        fp = fingerprint(b64d(d["pubkey"]))
        print(f"\nbrowser device '{d['name']}', fingerprint:\n\n    {fp}\n")
        if ask("Does that browser's console page show exactly this fingerprint? "
               "Type 'yes' to trust its verdicts: ") == "yes":
            approvers[d["id"]] = {"pubkey": d["pubkey"], "name": d["name"]}
            added += 1
    save_state(state)
    print(f"\ntrusted {added} approver(s)")
    return 0


# ---------- remote approval (C2) ----------

def remote_approval(names: list[str], command: str, requester: str):
    """Relay an approval request to trusted browser approvers and verify the
    signed verdict. True allowed, False denied/invalid, None not configured."""
    state = load_state()
    approvers = state.get("approvers") or {}
    if not state.get("account_id") or not approvers:
        return None
    command_hash = approval_request_hash(requester, names, command)
    created = api(state, "POST", "/approvals", {
        "names": names, "command_preview": command,
        "command_hash": command_hash, "requester": requester,
        "ttl_seconds": 120,
    })
    print("keygrant: no local answer — asking your approver at "
          "https://keygrant.app/app (2 min window)", file=sys.stderr)
    try:
        r = _poll(lambda: api(state, "GET", f"/approvals/{created['id']}"),
                  lambda r: r["status"] != "pending", timeout=125)
    except CloudError:
        return "remote approval timed out"
    if r["status"] != "allowed":
        return False
    approver = approvers.get(r.get("verdict_device") or "")
    if not approver:
        print("keygrant: verdict signed by an untrusted device — refusing",
              file=sys.stderr)
        return False
    try:
        _nacl().signing.VerifyKey(b64d(approver["pubkey"])).verify(
            verdict_statement(created["id"], command_hash, "allowed", r["verdict_ttl"]),
            b64d(r["verdict_sig"]))
    except Exception:
        print("keygrant: verdict signature failed verification — refusing",
              file=sys.stderr)
        return False
    print(f"keygrant: allowed remotely by '{approver['name']}'", file=sys.stderr)
    return True


def cmd_pair(_args: list[str]) -> int:
    nacl = _nacl()
    if load_state().get("account_id"):
        raise CloudError("this device already belongs to a cloud account")
    code = ask("Pairing code shown on your other device: ").replace(" ", "").upper()
    signing = nacl.signing.SigningKey.generate()
    eph = nacl.public.PrivateKey.generate()
    pub = b64e(signing.verify_key.encode())
    token = api(None, "POST", "/pairings/claim", {
        "code": code, "pubkey": pub, "eph_pubkey": b64e(eph.public_key.encode()),
        "name": _device_name()})["claim_token"]
    print(f"\nOn your other device, confirm this fingerprint:\n\n    {fingerprint(b64d(pub))}\n")
    r = _poll(lambda: api(None, "GET", f"/pairings/claim/{token}"),
              lambda r: r["status"] != "waiting")
    if r["status"] != "approved":
        raise CloudError("pairing expired or was not approved")
    approver = nacl.signing.VerifyKey(b64d(r["approver"]["pubkey"]))
    try:
        approver.verify(pair_statement(r["account_id"], pub), b64d(r["signature"]))
    except Exception:
        raise CloudError("approval signature is invalid; refusing to join") from None
    sk = nacl.public.SealedBox(eph).decrypt(b64d(r["enc_secret_key"]))
    state = {"api": API, "account_id": r["account_id"], "device_id": r["device_id"],
             "device_pub": pub, "cursor": 0, "items": {}}
    _store(state, "device_key", signing.encode())
    _store(state, "secret_key", sk)
    save_state(state)
    print(f"approved by '{r['approver']['name']}' "
          f"(fingerprint {fingerprint(b64d(r['approver']['pubkey']))})")
    unlock(state, ask_secret("Account password: "))
    print("joined — run `keygrant sync` to pull your secrets")
    return 0


# ---------- sync ----------

AUTO_SYNC_INTERVAL = 60  # seconds between best-effort pulls from list/exec


def auto_sync() -> None:
    """Best-effort pull before `list`/`exec`: silent when offline, locked or
    without an account, and throttled so back-to-back commands stay fast.
    Never prompts and never pushes."""
    try:
        state = load_state()
        if not state.get("vault_key"):
            return
        if time.time() - state.get("last_sync", 0) < AUTO_SYNC_INTERVAL:
            return
        pull(state, timeout=3)
    except Exception:
        pass


def cmd_sync(_args: list[str]) -> int:
    pulled, removed, skipped = pull(require_unlocked(load_state()))
    print(f"sync: {pulled} updated, {removed} removed, {skipped} skipped")
    return 0


def pull(state: dict, timeout: float = 30) -> tuple[int, int, int]:
    vid, vault_key = state["vault_id"], _secret(state, "vault_key")
    known = state.setdefault("items", {})
    cursor = state.get("cursor", 0)
    items = api(state, "GET", f"/vaults/{vid}/items?since_seq={cursor}", timeout=timeout)["items"]
    vault = kg.load_vault()
    pulled = removed = skipped = 0
    for it in items:
        cursor = max(cursor, it["seq"])
        iid, name, rev = it["id"], it["name"], it["rev"]
        prev = known.get(iid)
        if prev and rev <= prev["rev"]:
            if rev < prev["rev"]:
                print(f"warning: {name}: server returned an older revision; ignored", file=sys.stderr)
            continue
        local = vault.get(name)
        ours = bool(local) and local.get("cloud", {}).get("item_id") == iid
        known[iid] = {"name": name, "rev": rev}
        if ours and local["cloud"].get("dirty"):
            # An unpushed local edit wins locally; adopting the remote rev as
            # the base means the next `push` overwrites the cloud on purpose.
            if it["deleted"]:
                local.pop("cloud")
                print(f"warning: {name}: deleted in the cloud; kept your local edit "
                      "(now local-only)", file=sys.stderr)
            else:
                local["cloud"]["rev"] = rev
                print(f"warning: {name}: changed in the cloud while you edited it locally; "
                      f"kept your local value — `keygrant push {name}` overwrites the cloud copy",
                      file=sys.stderr)
            skipped += 1
            continue
        if it["deleted"]:
            if ours:
                kg.delete_value(local)
                del vault[name]
                removed += 1
            continue
        payload = json.loads(unseal(vault_key, it["enc"], item_aad(vid, iid, name, rev)))
        if local and not ours:
            print(f"warning: {name}: a local-only secret has this name; not overwritten",
                  file=sys.stderr)
            skipped += 1
            continue
        record = kg.encrypt_value(payload["value"])
        record.update({
            "desc": payload.get("desc", ""),
            "created": local.get("created") if local else
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_used": local.get("last_used") if local else None,
            "use_count": local.get("use_count", 0) if local else 0,
            "cloud": {"vault": vid, "item_id": iid, "rev": rev},
        })
        if local:
            kg.delete_value(local)
        vault[name] = record
        pulled += 1
    kg.save_vault(vault)
    state["cursor"] = cursor
    state["last_sync"] = time.time()
    save_state(state)
    return pulled, removed, skipped


def cmd_push(args: list[str]) -> int:
    delete = "--delete" in args
    names = [a for a in args if a != "--delete"]
    if not names:
        print("usage: keygrant push [--delete] NAME...", file=sys.stderr)
        return 2
    state = require_unlocked(load_state())
    vid, vault_key = state["vault_id"], _secret(state, "vault_key")
    known = state.setdefault("items", {})
    vault = kg.load_vault()
    failed = 0
    for name in names:
        local = vault.get(name)
        if not local:
            print(f"error: no local secret named {name}", file=sys.stderr)
            failed += 1
            continue
        cloud = local.get("cloud")
        if delete and not cloud:
            print(f"error: {name} is not in the cloud", file=sys.stderr)
            failed += 1
            continue
        item_id = cloud["item_id"] if cloud else str(uuid.uuid4())
        base_rev = cloud["rev"] if cloud else None
        new_rev = (base_rev or 0) + 1
        payload = {"value": "" if delete else kg.decrypt_value(local), "desc": local.get("desc", "")}
        body = {"vault_id": vid, "name": name, "base_rev": base_rev, "deleted": delete,
                "enc": seal(vault_key, json.dumps(payload).encode(),
                            item_aad(vid, item_id, name, new_rev))}
        try:
            r = api(state, "PUT", f"/items/{item_id}", body)
        except CloudError as exc:
            if exc.status != 409:
                raise
            print(f"conflict: {name} changed elsewhere — run `keygrant sync`, then push again",
                  file=sys.stderr)
            failed += 1
            continue
        if r["rev"] != new_rev:
            raise CloudError(f"{name}: server assigned rev {r['rev']}, expected {new_rev}")
        known[item_id] = {"name": name, "rev": new_rev}
        if delete:
            local.pop("cloud", None)
        else:
            local["cloud"] = {"vault": vid, "item_id": item_id, "rev": new_rev}
        print(f"{'deleted from cloud' if delete else 'pushed'}: {name} (rev {new_rev})")
    kg.save_vault(vault)
    save_state(state)
    return 1 if failed else 0


def cmd_recover(_args: list[str]) -> int:
    """Join this device to an account using only the emergency kit."""
    nacl = _nacl()
    if load_state().get("account_id"):
        raise CloudError("this device already belongs to a cloud account")
    account_id = ask("Account ID: ").strip()
    sk = parse_secret_key(ask("Secret Key (A3-…): "))
    password = ask_secret("Account password: ")
    auk = derive_auk(password, sk, account_id)
    start = api(None, "POST", "/recovery/start", {"account_id": account_id})
    signing = nacl.signing.SigningKey.generate()
    pub = b64e(signing.verify_key.encode())
    sig = recovery_signer(auk).sign(
        recover_statement(account_id, start["challenge"], pub)).signature
    try:
        done = api(None, "POST", "/recovery/complete", {
            "recovery_id": start["recovery_id"], "signature": b64e(sig),
            "pubkey": pub, "name": _device_name()})
    except CloudError as exc:
        if len(exc.args) > 1 and exc.args[1] == 403:
            raise CloudError("recovery rejected: wrong password or Secret Key") from None
        raise
    state = {"api": API, "account_id": account_id, "device_id": done["device_id"],
             "device_pub": pub, "cursor": 0, "items": {}}
    _store(state, "device_key", signing.encode())
    _store(state, "secret_key", sk)
    save_state(state)
    unlock(state, password)
    print(f"recovered — '{_device_name()}' joined account {account_id}")
    print(f"this device fingerprint: {fingerprint(b64d(pub))}")
    print("run `keygrant sync` to pull your secrets")
    return 0


COMMANDS = {"cloud": cmd_cloud, "devices": cmd_devices, "pair": cmd_pair,
            "sync": cmd_sync, "push": cmd_push, "recover": cmd_recover}
