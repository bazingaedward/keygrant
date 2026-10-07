#!/usr/bin/env python3
"""secretctl — per-command secret injection for AI coding agents (prototype).

Secrets are stored DPAPI-encrypted (per Windows user) in %APPDATA%\\secretctl\\vault.json.
The agent's model context only ever sees secret NAMES; values are decrypted at
exec time and injected into the child process environment only.

Commands:
  secretctl set NAME [--desc TEXT]        read value from stdin, store encrypted
  secretctl list                          list secret names + metadata (never values)
  secretctl rm NAME                       delete a secret
  secretctl exec [--redact] NAMES -- CMD  run CMD with NAMES (comma-separated)
                                          injected as env vars; --redact captures
                                          output and masks any plaintext leaks
  secretctl revoke NAME|--all             revoke active approval grants

Using a secret requires user approval via a native dialog; approval grants
access for 15 minutes (stored in grants.json). Timeout = deny.
"""

import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

VAULT_DIR = os.path.join(os.environ["APPDATA"], "secretctl")
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")
GRANTS_PATH = os.path.join(VAULT_DIR, "grants.json")
GRANT_TTL_SECONDS = 15 * 60


# ---------- DPAPI ----------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _call_dpapi(func, data: bytes) -> bytes:
    blob_in = _blob(data)
    blob_out = DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x01: never pop legacy UI, fail instead
    if not func(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out)):
        raise OSError(f"{func.__name__} failed (wrong user or corrupted blob?)")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def protect(data: bytes) -> bytes:
    return _call_dpapi(ctypes.windll.crypt32.CryptProtectData, data)


def unprotect(data: bytes) -> bytes:
    return _call_dpapi(ctypes.windll.crypt32.CryptUnprotectData, data)


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


# ---------- approval ----------

def load_grants() -> dict:
    try:
        with open(GRANTS_PATH, "r", encoding="utf-8") as f:
            grants = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    now = time.time()
    return {name: exp for name, exp in grants.items() if exp > now}


def save_grants(grants: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = GRANTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(grants, f, indent=2)
    os.replace(tmp, GRANTS_PATH)


def _approval_dialog(names: list[str], command: str, timeout_ms: int) -> bool:
    """Native, topmost yes/no dialog. Timeout or No = deny."""
    preview = command if len(command) <= 200 else command[:200] + "…"
    text = (
        "An AI agent requests access to secret(s):\n\n"
        + "\n".join(f"    {n}" for n in names)
        + f"\n\nCommand:\n    {preview}\n\n"
        + f"Allow for {GRANT_TTL_SECONDS // 60} minutes?"
    )
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


def request_approval(names: list[str], command: str) -> tuple[bool, str]:
    """Return (allowed, denial_reason). Prompts only for ungranted names."""
    grants = load_grants()
    pending = [n for n in names if n not in grants]
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
        grants[name] = expiry
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
    vault[name] = {
        "blob": base64.b64encode(protect(value.encode())).decode(),
        "desc": desc,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_used": None,
        "use_count": 0,
    }
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
    del vault[args[0]]
    save_vault(vault)
    print(f"removed: {args[0]}")
    return 0


def cmd_exec(args: list[str]) -> int:
    redact = False
    if args and args[0] == "--redact":
        redact = True
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
        secrets[name] = unprotect(base64.b64decode(vault[name]["blob"])).decode()

    # audit trail: usage metadata, never values
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for name in names:
        vault[name]["last_used"] = now
        vault[name]["use_count"] = vault[name].get("use_count", 0) + 1
    save_vault(vault)

    env = os.environ.copy()
    env.update(secrets)

    if not redact:
        proc = subprocess.run(command, env=env)
        return proc.returncode

    proc = subprocess.run(command, env=env, capture_output=True, text=True)
    out, err = proc.stdout, proc.stderr
    for name, value in secrets.items():
        if value:
            out = out.replace(value, f"[{name}:REDACTED]")
            err = err.replace(value, f"[{name}:REDACTED]")
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


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = sys.argv[1], sys.argv[2:]
    handlers = {"set": cmd_set, "list": cmd_list, "rm": cmd_rm,
                "exec": cmd_exec, "revoke": cmd_revoke}
    if cmd not in handlers:
        print(f"error: unknown command: {cmd}", file=sys.stderr)
        return 2
    return handlers[cmd](args)


if __name__ == "__main__":
    sys.exit(main())
