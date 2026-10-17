"""End-to-end: `keygrant exec` and the MCP exec tool run a real child process
and return its output redacted."""

import io
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant  # noqa: E402
import keygrant_mcp  # noqa: E402

SECRET = "sk-live-51HxDEMOonly0000"
VAULT = {"K": {"blob": "x", "desc": "", "use_count": 0}}

# Prints the secret in plain text and right after a multi-byte character,
# as raw UTF-8 bytes regardless of the child's locale
CHILD = (
    "import os, sys; v = os.environ['K'].encode(); "
    "sys.stdout.buffer.write(b'plain ' + v + b' \\xe4\\xb8\\xad' + v + b'\\n')"
)


class ExecTestCase(unittest.TestCase):
    def setUp(self):
        for module in (keygrant, keygrant_mcp):
            for name, value in {
                "load_vault": lambda: {k: dict(v) for k, v in VAULT.items()},
                "save_vault": lambda vault: None,
                "decrypt_value": lambda record: SECRET,
                "record_event": lambda *a, **k: None,
            }.items():
                if hasattr(module, name):
                    mock.patch.object(module, name, side_effect=value).start()
        mock.patch.object(keygrant, "_auto_sync", lambda: None).start()
        mock.patch.object(keygrant, "request_approval", return_value=(True, "ok")).start()
        mock.patch.object(keygrant_mcp, "request_approval", return_value=(True, "ok")).start()
        mock.patch.object(keygrant.locale, "getpreferredencoding", return_value="gbk").start()
        self.addCleanup(mock.patch.stopall)


class CliExec(ExecTestCase):
    def test_redact_flag_masks_output(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            code = keygrant.cmd_exec(["--redact", "K", "--", sys.executable, "-c", CHILD])
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET[1:], out.getvalue())
        self.assertEqual(out.getvalue(), "plain [K:REDACTED] 中[K:REDACTED]\n")

    def test_output_a_gbk_console_cannot_encode_is_replaced(self):
        # wrangler prints emoji; a GBK console can't encode them
        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="gbk", newline="\n")
        child = "import sys; sys.stdout.buffer.write('⛅ ok 中\\n'.encode())"
        with mock.patch.object(sys, "stdout", console):
            code = keygrant.cmd_exec(["--redact", "K", "--", sys.executable, "-c", child])
            console.flush()
        self.assertEqual(code, 0)
        self.assertEqual(raw.getvalue().decode("gbk"), "? ok 中\n")


class McpExec(ExecTestCase):
    def test_tool_masks_output(self):
        # a script file keeps shell quoting (cmd /c vs sh -c) out of the test
        with tempfile.TemporaryDirectory() as d:
            script = os.path.join(d, "child.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write(CHILD.replace("; ", "\n"))
            command = subprocess.list2cmdline([sys.executable, script]) if os.name == "nt" \
                else f"{shlex.quote(sys.executable)} {shlex.quote(script)}"
            result = keygrant_mcp.tool_exec_with_secrets({"command": command, "secrets": ["K"]})
        self.assertIn("exit code: 0", result)
        self.assertNotIn(SECRET[1:], result)
        self.assertIn("plain [K:REDACTED] 中[K:REDACTED]", result)


if __name__ == "__main__":
    unittest.main()
