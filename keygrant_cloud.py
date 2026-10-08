"""keygrant cloud client — phase 1: sign-in and device registration.

Design: docs/design/cloud-mvp.md. Needs the optional `cryptography`
dependency (`uv tool install 'keygrant[cloud]'`) for the device key pair.

  keygrant login               sign in with GitHub, register this device
  keygrant logout              end this device's session
  keygrant whoami              show the signed-in user and this device
  keygrant devices [rm ID]     list devices, or remove one (revokes its session)

The refresh token and the device private key live in the OS keystore;
cloud.json holds only references to them plus public metadata.
"""

import base64
import hashlib
import json
import os
import platform
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from keygrant import VAULT_DIR, decrypt_value, delete_value, encrypt_value

CLOUD_PATH = os.path.join(VAULT_DIR, "cloud.json")
API = os.environ.get("KEYGRANT_API", "https://api.keygrant.app").rstrip("/")
# Public client ID of the keygrant GitHub OAuth App (device flow enabled).
GITHUB_CLIENT_ID = os.environ.get("KEYGRANT_GITHUB_CLIENT_ID", "REPLACE_WITH_GITHUB_OAUTH_CLIENT_ID")
GITHUB = "https://github.com"


class CloudError(OSError):
    pass


# ---------- HTTP ----------

def _post_form(url: str, fields: dict) -> dict:
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(fields).encode(),
        headers={"accept": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.load(res)


def api(method: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"accept": "application/json", "user-agent": "keygrant-cli"}
    data = None
    if body is not None:
        headers["content-type"] = "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.load(res)
    except urllib.error.HTTPError as exc:
        try:
            err = json.load(exc)
            detail = f"{err.get('error')}: {err.get('message')}"
        except ValueError:
            detail = f"HTTP {exc.code}"
        raise CloudError(f"{method} {path} failed — {detail}") from None
    except urllib.error.URLError as exc:
        raise CloudError(f"cannot reach {API}: {exc.reason}") from None


# ---------- local state ----------

def load_state() -> dict:
    try:
        with open(CLOUD_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = CLOUD_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, CLOUD_PATH)


def _replace_secret(state: dict, key: str, value: str) -> None:
    """Store value in the keystore under state[key], deleting the old item."""
    old = state.get(key)
    state[key] = encrypt_value(value)
    if old:
        delete_value(old)


def session_token(state: dict) -> str:
    """Rotate the refresh token and return a fresh access token."""
    if not state.get("refresh"):
        raise CloudError("not signed in — run: keygrant login")
    tokens = api("POST", "/v1/auth/refresh",
                 body={"refresh_token": decrypt_value(state["refresh"])})
    _replace_secret(state, "refresh", tokens["refresh_token"])
    save_state(state)
    return tokens["access_token"]


def fingerprint(public_key_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()[:16]
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


# ---------- GitHub device flow ----------

def github_device_flow(sleep=time.sleep) -> str:
    code = _post_form(f"{GITHUB}/login/device/code", {"client_id": GITHUB_CLIENT_ID})
    if "device_code" not in code:
        raise CloudError(f"GitHub device flow unavailable: {code.get('error_description') or code}")
    print(f"\nOpen {code['verification_uri']} and enter the code:  {code['user_code']}\n")
    try:
        webbrowser.open(code["verification_uri"])
    except Exception:
        pass
    interval = int(code.get("interval", 5))
    deadline = time.time() + int(code.get("expires_in", 900))
    while time.time() < deadline:
        sleep(interval)
        res = _post_form(f"{GITHUB}/login/oauth/access_token", {
            "client_id": GITHUB_CLIENT_ID,
            "device_code": code["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        })
        if "access_token" in res:
            return res["access_token"]
        error = res.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = int(res.get("interval", interval + 5))
            continue
        raise CloudError(f"GitHub sign-in failed: {res.get('error_description') or error}")
    raise CloudError("GitHub sign-in timed out")


# ---------- device key ----------

def generate_device_key() -> tuple[str, str]:
    """Return (private_b64, public_b64) for a new X25519 key pair."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        raise CloudError("cloud features need the cryptography package — "
                         "install with: uv tool install 'keygrant[cloud]'") from None
    key = X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    private = key.private_bytes(raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


# ---------- commands ----------

def cmd_login(_args: list[str]) -> int:
    state = load_state()
    if state.get("refresh"):
        print(f"already signed in as {state['user']['login']} — run keygrant logout first")
        return 0
    if not state.get("device_private"):
        private, public = generate_device_key()  # fail before any network I/O
        state["device_private"] = encrypt_value(private)
        state["public_key"] = public
        save_state(state)
    github_token = github_device_flow()
    tokens = api("POST", "/v1/auth/github", body={"github_token": github_token})
    state["api"] = API
    state["user"] = tokens["user"]
    _replace_secret(state, "refresh", tokens["refresh_token"])
    save_state(state)
    device = api("POST", "/v1/devices", token=tokens["access_token"],
                 body={"name": platform.node() or "device", "public_key": state["public_key"]})
    state["device_id"] = device["id"]
    save_state(state)
    print(f"signed in as {tokens['user']['login']}")
    print(f"device fingerprint: {fingerprint(state['public_key'])}")
    return 0


def cmd_logout(_args: list[str]) -> int:
    state = load_state()
    if not state.get("refresh"):
        print("not signed in")
        return 0
    try:
        api("POST", "/v1/auth/logout", token=session_token(state))
    except CloudError as exc:
        print(f"warning: server logout failed ({exc}); clearing local session", file=sys.stderr)
    delete_value(state.pop("refresh"))
    state.pop("user", None)
    save_state(state)
    print("signed out (device key kept; it is reused on the next login)")
    return 0


def cmd_whoami(_args: list[str]) -> int:
    state = load_state()
    me = api("GET", "/v1/me", token=session_token(state))
    print(f"user:   {me['user']['login']}")
    print(f"device: {state.get('device_id')}  fingerprint {fingerprint(state['public_key'])}")
    return 0


def cmd_devices(args: list[str]) -> int:
    state = load_state()
    token = session_token(state)
    if args[:1] == ["rm"] and len(args) == 2:
        api("DELETE", f"/v1/devices/{args[1]}", token=token)
        print(f"removed device {args[1]} and revoked its session")
        return 0
    if args:
        print("usage: keygrant devices [rm DEVICE_ID]", file=sys.stderr)
        return 2
    for d in api("GET", "/v1/devices", token=token)["devices"]:
        mark = "  (this device)" if d["id"] == state.get("device_id") else ""
        print(f"{d['id']}  {fingerprint(d['public_key'])}  {d['name']}{mark}")
    return 0


COMMANDS = {"login": cmd_login, "logout": cmd_logout,
            "whoami": cmd_whoami, "devices": cmd_devices}
