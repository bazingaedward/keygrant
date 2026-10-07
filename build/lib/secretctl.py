#!/usr/bin/env python3
"""secretctl — per-command secret injection for AI coding agents (prototype).

Secrets are stored in an OS-native keystore: DPAPI-encrypted values inside
%APPDATA%\\secretctl\\vault.json on Windows; the login Keychain on macOS (the
vault file then holds only metadata). The agent's model context only ever sees
secret NAMES; values are decrypted at exec time and injected into the child
process environment only.

Commands:
  secretctl set NAME [--desc TEXT]        read value from stdin, store encrypted
  secretctl list                          list secret names + metadata (never values)
  secretctl rm NAME                       delete a secret
  secretctl exec [--redact] NAMES -- CMD  run CMD with NAMES (comma-separated)
                                          injected as env vars; --redact captures
                                          output and masks any plaintext leaks
  secretctl revoke NAME|--all             revoke active approval grants
  secretctl init                          wire up the current project: .mcp.json
                                          entry + CLAUDE.md guidance for agents

Using a secret requires user approval via a native dialog; approval grants
access for 15 minutes (stored in grants.json, bound to the requesting
session). Timeout = deny.
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

if IS_WIN:
    _config_root = os.environ["APPDATA"]
else:
    _config_root = os.path.join(os.path.expanduser("~"), ".config")

VAULT_DIR = os.path.join(_config_root, "secretctl")
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")
GRANTS_PATH = os.path.join(VAULT_DIR, "grants.json")
GRANT_TTL_SECONDS = 15 * 60
KEYCHAIN_SERVICE = "secretctl"


# ---------- keystore backends ----------

if IS_WIN:
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> DATA_BLOB:
        buf = ctypes.create_string_buffer(data, len(data))
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def _call_dpapi(func, data: bytes) -> bytes:
        blob_in = _blob(data)
        blob_out = DATA_BLOB()
        # CRYPTPROTECT_UI_FORBIDDEN = 0x01: never pop legacy UI, fail instead
        if not func(ctypes.byref(blob_in), None, None, None, None, 0x01,
                    ctypes.byref(blob_out)):
            raise OSError(f"{func.__name__} failed (wrong user or corrupted blob?)")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    def protect(data: bytes) -> bytes:
        return _call_dpapi(ctypes.windll.crypt32.CryptProtectData, data)

    def unprotect(data: bytes) -> bytes:
        return _call_dpapi(ctypes.windll.crypt32.CryptUnprotectData, data)


def _security_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _keychain(command: str) -> subprocess.CompletedProcess:
    """Run one command through `security -i` so secret values stay out of argv."""
    return subprocess.run(
        ["security", "-i"], input=command + "\n",
        capture_output=True, text=True,
    )


def encrypt_value(value: str) -> dict:
    """Store a value in the platform keystore; return vault record fields."""
    if IS_WIN:
        return {"blob": base64.b64encode(protect(value.encode())).decode()}
    if IS_MAC:
        account = uuid.uuid4().hex
        proc = _keychain(
            f"add-generic-password -s {KEYCHAIN_SERVICE} -a {account} "
            f"-w {_security_quote(value)} -U"
        )
        if proc.returncode != 0:
            raise OSError(f"keychain add failed: {proc.stderr.strip()}")
        return {"keychain": account}
    raise OSError(f"unsupported platform: {sys.platform}")


def decrypt_value(record: dict) -> str:
    if "blob" in record:
        if not IS_WIN:
            raise OSError("this secret was stored with Windows DPAPI")
        return unprotect(base64.b64decode(record["blob"])).decode()
    if "keychain" in record:
        proc = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE,
             "-a", record["keychain"], "-w"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise OSError(f"keychain read failed: {proc.stderr.strip()}")
        return proc.stdout.rstrip("\n")
    raise OSError("unknown vault record format")


def delete_value(record: dict) -> None:
    if "keychain" in record:
        subprocess.run(
            ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE,
             "-a", record["keychain"]],
            capture_output=True, text=True,
        )


# ---------- vault ----------

def load_vault() -> dict:
    if not os.path.exists(VAULT_PATH):
        return {}
    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault(vault: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)
    os.replace(tmp, VAULT_PATH)


# ---------- redaction ----------

def _variants(name: str, value: str) -> list[tuple[str, str]]:
    """Encodings of a secret value an agent might emit to evade plain matching."""
    b64 = base64.b64encode(value.encode()).decode()
    variants = [
        (value, name),
        (b64, f"{name}:base64"),
        (b64.rstrip("="), f"{name}:base64"),
        (value.encode().hex(), f"{name}:hex"),
        (value.encode().hex().upper(), f"{name}:hex"),
        (urllib.parse.quote(value, safe=""), f"{name}:urlencoded"),
    ]
    seen: set[str] = set()
    out = []
    for v, label in variants:
        if v and v not in seen:
            seen.add(v)
            out.append((v, label))
    return out


def redact(text: str, secrets: dict[str, str]) -> str:
    for name, value in secrets.items():
        for variant, label in _variants(name, value):
            text = text.replace(variant, f"[{label}:REDACTED]")
    return text


# ---------- approval ----------

def current_requester() -> str:
    """Identity a grant is bound to. The MCP server sets SECRETCTL_REQUESTER to
    its per-session id; bare CLI calls fall back to their parent process id, so
    a grant approved for one agent session cannot be reused by another."""
    return os.environ.get("SECRETCTL_REQUESTER") or f"ppid:{os.getppid()}"


def load_grants() -> dict:
    try:
        with open(GRANTS_PATH, "r", encoding="utf-8") as f:
            grants = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    now = time.time()
    return {
        name: g for name, g in grants.items()
        if isinstance(g, dict) and g.get("exp", 0) > now
    }


def save_grants(grants: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = GRANTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(grants, f, indent=2)
    os.replace(tmp, GRANTS_PATH)


def _dialog_text(names: list[str], command: str) -> str:
    preview = command if len(command) <= 200 else command[:200] + "…"
    return (
        "An AI agent requests access to secret(s):\n\n"
        + "\n".join(f"    {n}" for n in names)
        + f"\n\nCommand:\n    {preview}\n\n"
        + f"Allow for {GRANT_TTL_SECONDS // 60} minutes?"
    )


def _approval_dialog_win(text: str, timeout_ms: int) -> bool:
    MB_YESNO, MB_ICONWARNING = 0x4, 0x30
    MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = 0x1000, 0x10000, 0x40000
    IDYES = 6
    fn = ctypes.windll.user32.MessageBoxTimeoutW
    fn.argtypes = [wt.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p,
                   wt.UINT, wt.WORD, wt.DWORD]
    fn.restype = ctypes.c_int
    result = fn(
        None, text, "secretctl — secret access request",
        MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST,
        0, timeout_ms,
    )
    return result == IDYES


def _approval_dialog_mac(text: str, timeout_ms: int) -> bool:
    timeout_s = max(1, timeout_ms // 1000)
    body = json.dumps(text, ensure_ascii=False)
    script = (
        f"display dialog {body} with title \"secretctl\" "
        f"buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" "
        f"cancel button \"Deny\" with icon caution giving up after {timeout_s}"
    )
    proc = subprocess.run(["osascript", "-e", script],
                          capture_output=True, text=True)
    return (
        proc.returncode == 0
        and "button returned:Allow" in proc.stdout
        and "gave up:false" in proc.stdout
    )


def _approval_dialog(names: list[str], command: str, timeout_ms: int) -> bool:
    """Native, topmost yes/no dialog. Timeout or No = deny."""
    text = _dialog_text(names, command)
    if IS_WIN:
        return _approval_dialog_win(text, timeout_ms)
    if IS_MAC:
        return _approval_dialog_mac(text, timeout_ms)
    return False  # no interactive channel on this platform: deny by default


def request_approval(names: list[str], command: str) -> tuple[bool, str]:
    """Return (allowed, denial_reason). Prompts for names not granted to the
    current requester; grants made for other requesters do not carry over."""
    requester = current_requester()
    grants = load_grants()
    pending = [
        n for n in names
        if not (n in grants and grants[n].get("req") == requester)
    ]
    if not pending:
        return True, ""
    timeout_ms = int(os.environ.get("SECRETCTL_APPROVAL_TIMEOUT_MS", "60000"))
    if not _approval_dialog(pending, command, timeout_ms):
        return False, (
            f"user denied access to: {', '.join(pending)} "
            "(approval dialog declined or timed out)"
        )
    grants = load_grants()
    expiry = time.time() + GRANT_TTL_SECONDS
    for name in pending:
        grants[name] = {"exp": expiry, "req": requester}
    save_grants(grants)
    return True, ""


# ---------- commands ----------

def cmd_set(args: list[str]) -> int:
    if not args:
        print("usage: secretctl set NAME [--desc TEXT]", file=sys.stderr)
        return 2
    name = args[0]
    desc = ""
    if "--desc" in args:
        desc = args[args.index("--desc") + 1]
    value = sys.stdin.read().lstrip("﻿").strip()
    if not value:
        print("error: empty value on stdin", file=sys.stderr)
        return 1
    vault = load_vault()
    if name in vault:
        delete_value(vault[name])
    record = encrypt_value(value)
    record.update({
        "desc": desc,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_used": None,
        "use_count": 0,
    })
    vault[name] = record
    save_vault(vault)
    print(f"stored: {name}")
    return 0


def cmd_list(_args: list[str]) -> int:
    vault = load_vault()
    if not vault:
        print("(vault empty)")
        return 0
    width = max(len(n) for n in vault)
    for name, meta in sorted(vault.items()):
        used = f"used {meta.get('use_count', 0)}x" if meta.get("use_count") else "never used"
        desc = meta.get("desc") or "-"
        print(f"{name:<{width}}  {used:<12}  {desc}")
    return 0


def cmd_rm(args: list[str]) -> int:
    vault = load_vault()
    if not args or args[0] not in vault:
        print("error: no such secret", file=sys.stderr)
        return 1
    delete_value(vault[args[0]])
    del vault[args[0]]
    save_vault(vault)
    print(f"removed: {args[0]}")
    return 0


def cmd_exec(args: list[str]) -> int:
    redact_output = False
    if args and args[0] == "--redact":
        redact_output = True
        args = args[1:]
    if "--" not in args or args.index("--") == 0:
        print("usage: secretctl exec [--redact] NAME[,NAME...] -- COMMAND [ARGS...]",
              file=sys.stderr)
        return 2
    sep = args.index("--")
    names = [n for n in args[0].split(",") if n]
    command = args[sep + 1:]
    if not command:
        print("error: no command after --", file=sys.stderr)
        return 2

    vault = load_vault()
    for name in names:
        if name not in vault:
            print(f"error: no such secret: {name}", file=sys.stderr)
            return 1

    allowed, reason = request_approval(names, subprocess.list2cmdline(command))
    if not allowed:
        print(f"denied: {reason}", file=sys.stderr)
        return 3

    secrets: dict[str, str] = {}
    for name in names:
        secrets[name] = decrypt_value(vault[name])

    # audit trail: usage metadata, never values
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for name in names:
        vault[name]["last_used"] = now
        vault[name]["use_count"] = vault[name].get("use_count", 0) + 1
    save_vault(vault)

    env = os.environ.copy()
    env.update(secrets)

    if not redact_output:
        proc = subprocess.run(command, env=env)
        return proc.returncode

    proc = subprocess.run(command, env=env, capture_output=True, text=True)
    out = redact(proc.stdout, secrets)
    err = redact(proc.stderr, secrets)
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return proc.returncode


def cmd_revoke(args: list[str]) -> int:
    if not args:
        print("usage: secretctl revoke NAME | --all", file=sys.stderr)
        return 2
    if args[0] == "--all":
        save_grants({})
        print("revoked: all grants")
        return 0
    grants = load_grants()
    if args[0] not in grants:
        print(f"no active grant for: {args[0]}")
        return 0
    del grants[args[0]]
    save_grants(grants)
    print(f"revoked: {args[0]}")
    return 0


CLAUDE_MD_MARKER = "<!-- secretctl-guidance -->"
CLAUDE_MD_SNIPPET = f"""
{CLAUDE_MD_MARKER}
## Secrets (secretctl)

API keys and other secrets are managed by secretctl and must NEVER appear in
this conversation. Rules:

- Never ask the user to paste a secret value; never echo, log, or hardcode one.
- To see which secrets exist, use the `list_secrets` MCP tool.
- To run a command that needs a secret, use the `exec_with_secrets` MCP tool
  and reference the secret as an environment variable (e.g. `$STRIPE_KEY` /
  `%STRIPE_KEY%`). The user approves each use via a native dialog.
- If access is denied, do not retry; ask the user what they want to do.
"""


def cmd_init(_args: list[str]) -> int:
    """Wire the current project up for Claude Code."""
    # .mcp.json: merge, don't clobber other servers
    mcp_path = os.path.join(os.getcwd(), ".mcp.json")
    config = {}
    if os.path.exists(mcp_path):
        try:
            with open(mcp_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except json.JSONDecodeError:
            print(f"error: {mcp_path} exists but is not valid JSON", file=sys.stderr)
            return 1
    config.setdefault("mcpServers", {})["secretctl"] = {"command": "secretctl-mcp"}
    with open(mcp_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print(f"wrote: {mcp_path} (server: secretctl-mcp)")

    # CLAUDE.md: append guidance once
    claude_md = os.path.join(os.getcwd(), "CLAUDE.md")
    existing = ""
    if os.path.exists(claude_md):
        with open(claude_md, "r", encoding="utf-8") as f:
            existing = f.read()
    if CLAUDE_MD_MARKER in existing:
        print(f"ok: {claude_md} already has secretctl guidance")
    else:
        with open(claude_md, "a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(CLAUDE_MD_SNIPPET)
        print(f"updated: {claude_md}")

    print("\nnext steps:")
    print("  1. add a secret:   secretctl set MY_KEY --desc \"what it is\"")
    print("  2. restart Claude Code in this folder to load the MCP server")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = sys.argv[1], sys.argv[2:]
    handlers = {"set": cmd_set, "list": cmd_list, "rm": cmd_rm,
                "exec": cmd_exec, "revoke": cmd_revoke, "init": cmd_init}
    if cmd not in handlers:
        print(f"error: unknown command: {cmd}", file=sys.stderr)
        return 2
    return handlers[cmd](args)


if __name__ == "__main__":
    sys.exit(main())
