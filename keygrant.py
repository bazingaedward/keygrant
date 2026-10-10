#!/usr/bin/env python3
"""keygrant — per-command secret injection for AI coding agents (prototype).

Secrets are stored in an OS-native keystore: DPAPI-encrypted values inside
%APPDATA%\\keygrant\\vault.json on Windows; the login Keychain on macOS; the
Secret Service keyring via secret-tool on Linux (the vault file then holds
only metadata). The agent's model context only ever sees
secret NAMES; values are decrypted at exec time and injected into the child
process environment only.

Commands:
  keygrant set NAME [--desc TEXT]        read value from stdin, store encrypted
  keygrant list                          list secret names + metadata (never values)
  keygrant rm NAME                       delete a secret
  keygrant exec [--redact] NAMES -- CMD  run CMD with NAMES (comma-separated)
                                          injected as env vars; --redact captures
                                          output and masks any plaintext leaks
  keygrant revoke NAME|--all             void approval grants in every session
  keygrant init                          wire up the current project: .mcp.json
                                          entry + CLAUDE.md guidance for agents
  keygrant mcp                           run the MCP server on stdio (same as
                                          keygrant-mcp)
  keygrant cloud init|status|enable-recovery|kit|delete   zero-knowledge cloud sync
  keygrant devices [add] | pair          (see keygrant_cloud.py; needs
  keygrant sync | push [--delete] NAMES   `keygrant[cloud]`)
  keygrant recover                       join a new device with the emergency
                                          kit alone (no old device online)

Using a secret requires user approval via a native dialog showing the full
command. Through the MCP server, approval covers that exact command for 15
minutes, held in the server's memory only; the CLI prompts on every exec.
Timeout = deny.
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
IS_LINUX = sys.platform.startswith("linux")

if IS_WIN:
    _config_root = os.environ["APPDATA"]
else:
    _config_root = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")

VAULT_DIR = os.path.join(_config_root, "keygrant")
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")
REVOCATIONS_PATH = os.path.join(VAULT_DIR, "revocations.json")
GRANT_TTL_SECONDS = 15 * 60
MAX_COMMAND_CHARS = 2000  # longer commands can't be reviewed in a dialog
KEYCHAIN_SERVICE = "keygrant"


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


def _secret_tool(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["secret-tool", *args],
                              capture_output=True, text=True, **kwargs)
    except FileNotFoundError:
        raise OSError(
            "secret-tool not found — install libsecret-tools (Debian/Ubuntu) "
            "or libsecret (Fedora/Arch), and ensure a keyring daemon is running"
        ) from None


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
    if IS_LINUX:
        account = uuid.uuid4().hex
        # value travels via stdin, never argv
        proc = _secret_tool(
            ["store", f"--label=keygrant: {account}",
             "service", KEYCHAIN_SERVICE, "account", account],
            input=value,
        )
        if proc.returncode != 0:
            raise OSError(f"secret-tool store failed: {proc.stderr.strip()}")
        return {"secret_tool": account}
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
    if "secret_tool" in record:
        proc = _secret_tool(
            ["lookup", "service", KEYCHAIN_SERVICE,
             "account", record["secret_tool"]],
        )
        if proc.returncode != 0:
            raise OSError(f"secret-tool lookup failed: {proc.stderr.strip()}")
        return proc.stdout.rstrip("\n")
    raise OSError("unknown vault record format")


def delete_value(record: dict) -> None:
    if "keychain" in record:
        subprocess.run(
            ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE,
             "-a", record["keychain"]],
            capture_output=True, text=True,
        )
    elif "secret_tool" in record:
        _secret_tool(["clear", "service", KEYCHAIN_SERVICE,
                      "account", record["secret_tool"]])


# ---------- vault ----------

VAULT_FORMAT_VERSION = 1


def load_vault() -> dict:
    """Return the name -> record mapping. Accepts the pre-versioning flat
    format and migrates it transparently on the next save."""
    if not os.path.exists(VAULT_PATH):
        return {}
    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data.get("version"), int):
        return data.get("secrets", {})
    return data  # legacy flat format


def save_vault(vault: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": VAULT_FORMAT_VERSION, "secrets": vault}, f, indent=2)
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
#
# A grant authorises one exact command string to use the secrets shown in the
# dialog. Grants live only in the memory of a GrantStore (one per MCP server
# process = one agent session), so there is no file an agent could forge. The
# CLI passes no store and therefore prompts on every exec.

class GrantStore:
    """In-memory grants for one agent session: (command, name) -> issued_at."""

    def __init__(self) -> None:
        self._issued: dict[tuple[str, str], float] = {}

    def covers(self, name: str, command: str, revocations: dict) -> bool:
        issued = self._issued.get((command, name))
        if issued is None:
            return False
        if time.time() >= issued + GRANT_TTL_SECONDS:
            return False
        revoked = max(revocations.get(name, 0), revocations.get("*", 0))
        return issued > revoked

    def add(self, names: list[str], command: str) -> None:
        now = time.time()
        for name in names:
            self._issued[(command, name)] = now


def load_revocations() -> dict:
    """name|"*" -> unix time; grants issued before it are void. A tampered
    file can only revoke more, so it is safe for it to be user-writable. An
    unreadable file revokes everything (fail closed)."""
    try:
        with open(REVOCATIONS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {"*": float("inf")}
    if not isinstance(data, dict):
        return {"*": float("inf")}
    return {k: v for k, v in data.items() if isinstance(v, (int, float))}


def save_revocations(revocations: dict) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = REVOCATIONS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(revocations, f, indent=2)
    os.replace(tmp, REVOCATIONS_PATH)


def _dialog_text(names: list[str], command: str) -> str:
    return (
        "An AI agent requests access to secret(s):\n\n"
        + "\n".join(f"    {n}" for n in names)
        + f"\n\nCommand:\n    {command}\n\n"
        + f"Allow this exact command for {GRANT_TTL_SECONDS // 60} minutes?"
    )


def _approval_dialog_win(text: str, timeout_ms: int) -> str:
    MB_YESNO, MB_ICONWARNING = 0x4, 0x30
    MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = 0x1000, 0x10000, 0x40000
    IDYES, IDNO = 6, 7
    fn = ctypes.windll.user32.MessageBoxTimeoutW
    fn.argtypes = [wt.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p,
                   wt.UINT, wt.WORD, wt.DWORD]
    fn.restype = ctypes.c_int
    result = fn(
        None, text, "keygrant — secret access request",
        MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST,
        0, timeout_ms,
    )
    if result == IDYES:
        return "allow"
    return "deny" if result == IDNO else "timeout"


def _approval_dialog_mac(text: str, timeout_ms: int) -> str:
    timeout_s = max(1, timeout_ms // 1000)
    body = json.dumps(text, ensure_ascii=False)
    script = (
        f"display dialog {body} with title \"keygrant\" "
        f"buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" "
        f"cancel button \"Deny\" with icon caution giving up after {timeout_s}"
    )
    proc = subprocess.run(["osascript", "-e", script],
                          capture_output=True, text=True)
    if proc.returncode == 0 and "gave up:true" in proc.stdout:
        return "timeout"
    if proc.returncode == 0 and "button returned:Allow" in proc.stdout:
        return "allow"
    return "deny"


def _approval_dialog_linux(text: str, timeout_ms: int) -> str:
    timeout_s = max(1, timeout_ms // 1000)
    try:
        proc = subprocess.run(
            ["zenity", "--question", "--title=keygrant",
             f"--text={text}", "--default-cancel",
             f"--timeout={timeout_s}",
             "--ok-label=Allow", "--cancel-label=Deny"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        # headless box: no local channel, let remote approval take over
        return "timeout"
    if proc.returncode == 0:
        return "allow"
    return "timeout" if proc.returncode == 5 else "deny"


def _approval_dialog(names: list[str], command: str, timeout_ms: int) -> str:
    """Native, topmost dialog. Returns 'allow', 'deny' or 'timeout' — an
    explicit Deny is final, a timeout may escalate to a remote approver."""
    text = _dialog_text(names, command)
    if IS_WIN:
        return _approval_dialog_win(text, timeout_ms)
    if IS_MAC:
        return _approval_dialog_mac(text, timeout_ms)
    if IS_LINUX:
        return _approval_dialog_linux(text, timeout_ms)
    return "timeout"  # no local channel; remote approval or deny


def _remote_approval(names: list[str], command: str):
    """Escalate to the web approver console. True allowed, False denied,
    or a string/None explaining why remote approval was unavailable."""
    try:
        import keygrant_cloud
    except Exception:
        return None
    try:
        return keygrant_cloud.remote_approval(names, command, current_requester())
    except Exception as exc:
        return str(exc)


def request_approval(names: list[str], command: str,
                     store: "GrantStore | None" = None) -> tuple[bool, str]:
    """Return (allowed, denial_reason). Prompts for names the store does not
    already grant for this exact command; with no store, always prompts."""
    if len(command) > MAX_COMMAND_CHARS:
        return False, (
            f"command is longer than {MAX_COMMAND_CHARS} characters and cannot "
            "be shown in full for review; put the logic in a script file and "
            "run that instead"
        )
    revocations = load_revocations()
    pending = [
        n for n in names
        if store is None or not store.covers(n, command, revocations)
    ]
    if not pending:
        return True, ""
    timeout_ms = int(os.environ.get("KEYGRANT_APPROVAL_TIMEOUT_MS", "60000"))
    decision = _approval_dialog(pending, command, timeout_ms)
    if decision == "deny":
        return False, f"user denied access to: {', '.join(pending)}"
    if decision == "timeout":
        remote = _remote_approval(pending, command)
        if remote is False:
            return False, f"denied by the remote approver: {', '.join(pending)}"
        if remote is not True:
            why = f"; remote approval unavailable: {remote}" if remote else ""
            return False, (
                f"user denied access to: {', '.join(pending)} "
                f"(approval dialog timed out{why})"
            )
        # remote allow falls through to grant
    if store is not None:
        store.add(pending, command)
    return True, ""


# ---------- commands ----------

def cmd_set(args: list[str]) -> int:
    if not args:
        print("usage: keygrant set NAME [--desc TEXT]", file=sys.stderr)
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
    old = vault.get(name)
    if old:
        delete_value(old)
    record = encrypt_value(value)
    record.update({
        "desc": desc,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_used": None,
        "use_count": 0,
    })
    if old and old.get("cloud"):
        # keep the cloud link so `keygrant push` updates the same item;
        # "dirty" stops `keygrant sync` from overwriting the unpushed edit
        record["cloud"] = {**old["cloud"], "dirty": True}
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
        print("usage: keygrant exec [--redact] NAME[,NAME...] -- COMMAND [ARGS...]",
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
        print("usage: keygrant revoke NAME | --all", file=sys.stderr)
        return 2
    key = "*" if args[0] == "--all" else args[0]
    revocations = load_revocations()
    if revocations.get("*") == float("inf"):
        revocations = {}  # rewrite an unreadable file
    revocations[key] = time.time()
    save_revocations(revocations)
    print(f"revoked: {'all grants' if key == '*' else key} "
          "(grants issued before now are void in every session)")
    return 0


CLAUDE_MD_MARKER = "<!-- keygrant-guidance -->"
CLAUDE_MD_SNIPPET = f"""
{CLAUDE_MD_MARKER}
## Secrets (keygrant)

API keys and other secrets are managed by keygrant and must NEVER appear in
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
    config.setdefault("mcpServers", {})["keygrant"] = {"command": "keygrant-mcp"}
    with open(mcp_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print(f"wrote: {mcp_path} (server: keygrant-mcp)")

    # CLAUDE.md: append guidance once
    claude_md = os.path.join(os.getcwd(), "CLAUDE.md")
    existing = ""
    if os.path.exists(claude_md):
        with open(claude_md, "r", encoding="utf-8") as f:
            existing = f.read()
    if CLAUDE_MD_MARKER in existing:
        print(f"ok: {claude_md} already has keygrant guidance")
    else:
        with open(claude_md, "a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(CLAUDE_MD_SNIPPET)
        print(f"updated: {claude_md}")

    print("\nnext steps:")
    print("  1. add a secret:   keygrant set MY_KEY --desc \"what it is\"")
    print("  2. restart Claude Code in this folder to load the MCP server")
    return 0


def cmd_mcp(args: list[str]) -> int:
    import keygrant_mcp
    keygrant_mcp.main()
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = sys.argv[1], sys.argv[2:]
    handlers = {"set": cmd_set, "list": cmd_list, "rm": cmd_rm,
                "exec": cmd_exec, "revoke": cmd_revoke, "init": cmd_init,
                "mcp": cmd_mcp}
    if cmd in ("cloud", "devices", "pair", "sync", "push", "recover"):
        import keygrant_cloud
        handlers.update(keygrant_cloud.COMMANDS)
    if cmd not in handlers:
        print(f"error: unknown command: {cmd}", file=sys.stderr)
        return 2
    try:
        return handlers[cmd](args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
