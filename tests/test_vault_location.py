"""Where the vault lives, and merging the pre-0.1.7 Windows vault into it.

Run: python -m unittest discover -s tests
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant as kg  # noqa: E402


class DefaultLocation(unittest.TestCase):
    def test_keygrant_home_wins_everywhere(self):
        with mock.patch.dict(os.environ, {"KEYGRANT_HOME": "/x/kg"}):
            self.assertEqual(kg._default_vault_dir(), "/x/kg")

    def test_windows_uses_profile_root_not_appdata(self):
        env = {"APPDATA": r"C:\Users\u\AppData\Roaming"}
        with mock.patch.object(kg, "IS_WIN", True), mock.patch.dict(os.environ, env), \
                mock.patch.dict(os.environ, {"KEYGRANT_HOME": ""}), \
                mock.patch.object(kg.os.path, "expanduser", return_value=r"C:\Users\u"):
            got = kg._default_vault_dir()
        self.assertEqual(got, os.path.join(r"C:\Users\u", ".keygrant"))
        self.assertNotIn("AppData", got)

    def test_other_platforms_keep_xdg(self):
        with mock.patch.object(kg, "IS_WIN", False), \
                mock.patch.dict(os.environ, {"KEYGRANT_HOME": "", "XDG_CONFIG_HOME": "/cfg"}):
            self.assertEqual(kg._default_vault_dir(), os.path.join("/cfg", "keygrant"))


class LegacyMigration(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.old = os.path.join(tmp.name, "AppData", "keygrant")
        self.new = os.path.join(tmp.name, ".keygrant")
        os.makedirs(self.old)
        for attr, value in [("VAULT_DIR", self.new), ("VAULT_PATH", os.path.join(self.new, "vault.json")),
                            ("REVOCATIONS_PATH", os.path.join(self.new, "revocations.json")),
                            ("LEGACY_VAULT_DIR", self.old)]:
            p = mock.patch.object(kg, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def write(self, directory, name, data):
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            json.dump(data, f)

    def read(self, directory, name):
        with open(os.path.join(directory, name), encoding="utf-8") as f:
            return json.load(f)

    def migrate(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            kg.migrate_legacy_vault()
        return err.getvalue()

    def test_adds_missing_names_and_never_overwrites(self):
        self.write(self.old, "vault.json", {"version": 1, "secrets": {
            "A": {"value": "old-a"}, "B": {"value": "old-b"}}})
        self.write(self.new, "vault.json", {"version": 1, "secrets": {
            "B": {"value": "new-b"}, "C": {"value": "new-c"}}})
        msg = self.migrate()
        self.assertEqual(kg.load_vault(), {"A": {"value": "old-a"}, "B": {"value": "new-b"},
                                           "C": {"value": "new-c"}})
        self.assertIn("merged A", msg)
        # The old file stays so a 0.1.6 install keeps working during the upgrade.
        self.assertEqual(self.read(self.old, "vault.json")["secrets"]["A"], {"value": "old-a"})

    def test_reads_the_pre_versioning_flat_format(self):
        self.write(self.old, "vault.json", {"A": {"value": "a"}})
        self.migrate()
        self.assertEqual(kg.load_vault(), {"A": {"value": "a"}})

    def test_deleted_names_do_not_come_back(self):
        self.write(self.old, "vault.json", {"version": 1, "secrets": {"A": {"value": "a"}}})
        self.migrate()
        kg.save_vault({})  # the user deletes A in the new vault
        self.assertEqual(self.migrate(), "")
        self.assertEqual(kg.load_vault(), {})

    def test_names_stored_later_by_an_old_install_are_picked_up(self):
        self.write(self.old, "vault.json", {"version": 1, "secrets": {"A": {"value": "a"}}})
        self.migrate()
        self.write(self.old, "vault.json", {"version": 1, "secrets": {
            "A": {"value": "a"}, "G": {"value": "g"}}})
        self.assertIn("merged G", self.migrate())
        self.assertEqual(sorted(kg.load_vault()), ["A", "G"])

    def test_two_views_of_appdata_both_merge(self):
        # The packaged app sees a stale private copy; the terminal sees the real file.
        self.write(self.old, "vault.json", {"version": 1, "secrets": {"A": {"value": "a"}}})
        self.migrate()
        self.write(self.old, "vault.json", {"version": 1, "secrets": {
            "A": {"value": "a"}, "GOOGLE": {"value": "g"}}})
        self.migrate()
        self.assertEqual(sorted(kg.load_vault()), ["A", "GOOGLE"])

    def test_revocations_keep_the_latest_epoch(self):
        self.write(self.old, "vault.json", {"version": 1, "secrets": {}})
        self.write(self.old, "revocations.json", {"A": 200.0, "B": 50.0})
        self.write(self.new, "revocations.json", {"A": 100.0, "C": 10.0})
        self.migrate()
        self.assertEqual(self.read(self.new, "revocations.json"), {"A": 200.0, "B": 50.0, "C": 10.0})
        before = os.path.getmtime(os.path.join(self.new, "revocations.json"))
        self.migrate()  # nothing newer: no rewrite
        self.assertEqual(os.path.getmtime(os.path.join(self.new, "revocations.json")), before)

    def test_copies_other_files_only_when_missing(self):
        self.write(self.old, "vault.json", {"version": 1, "secrets": {}})
        self.write(self.old, "cloud.json", {"device": "old"})
        self.write(self.old, "audit-outbox.jsonl", {"e": 1})
        self.write(self.new, "cloud.json", {"device": "new"})
        self.migrate()
        self.assertEqual(self.read(self.new, "cloud.json"), {"device": "new"})
        self.assertEqual(self.read(self.new, "audit-outbox.jsonl"), {"e": 1})

    def test_unreadable_old_vault_is_left_alone(self):
        with open(os.path.join(self.old, "vault.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        msg = self.migrate()
        self.assertIn("could not read the old vault", msg)
        self.assertTrue(os.path.exists(os.path.join(self.old, "vault.json")))
        self.assertEqual(kg.load_vault(), {})

    def test_nothing_to_do_without_an_old_vault_or_when_dirs_match(self):
        self.assertEqual(self.migrate(), "")
        self.write(self.new, "vault.json", {"version": 1, "secrets": {"A": {"value": "a"}}})
        with mock.patch.object(kg, "LEGACY_VAULT_DIR", self.new):
            self.assertEqual(self.migrate(), "")
        with mock.patch.object(kg, "LEGACY_VAULT_DIR", None):
            self.assertEqual(self.migrate(), "")
        self.assertTrue(os.path.exists(os.path.join(self.new, "vault.json")))


if __name__ == "__main__":
    unittest.main()
