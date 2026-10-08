"""Local merge rules of `keygrant sync` / `push` (keygrant-cloud SPEC §10.4).

Run: python -m unittest discover -s tests   (needs PyNaCl; skipped otherwise)
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant as kg  # noqa: E402
import keygrant_cloud as kc  # noqa: E402

VID, KEY = "vault-1", bytes(range(32))


@unittest.skipUnless(importlib.util.find_spec("nacl"), "needs PyNaCl")
class SyncRules(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = {}
        patches = [
            mock.patch.object(kg, "VAULT_DIR", tmp.name),
            mock.patch.object(kg, "VAULT_PATH", os.path.join(tmp.name, "vault.json")),
            mock.patch.object(kg, "encrypt_value", self._enc),
            mock.patch.object(kg, "decrypt_value", lambda r: self.store[r["k"]]),
            mock.patch.object(kg, "delete_value", lambda r: self.store.pop(r["k"], None)),
            mock.patch("builtins.print"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        state = {"account_id": "a", "vault_id": VID, "cursor": 0, "items": {}}
        kc._store(state, "vault_key", KEY)
        kc.save_state(state)
        self.remote = []  # items the fake server returns on the next sync

    def _enc(self, value):
        k = os.urandom(4).hex()
        self.store[k] = value
        return {"k": k}

    def remote_item(self, name, value, iid="item-1", rev=1, seq=1, deleted=False):
        enc = kc.seal(KEY, json.dumps({"value": value, "desc": ""}).encode(),
                      kc.item_aad(VID, iid, name, rev))
        self.remote.append({"id": iid, "name": name, "rev": rev, "seq": seq,
                            "enc": enc, "deleted": deleted})

    def sync(self):
        with mock.patch.object(kc, "api", lambda *a, **k: {"items": self.remote}):
            kc.cmd_sync([])
        self.remote = []

    def set_local(self, name, value):
        with mock.patch.object(sys, "stdin", io.StringIO(value)):
            kg.cmd_set([name])

    def value(self, name):
        rec = kg.load_vault().get(name)
        return rec and kg.decrypt_value(rec)

    def test_sync_pulls_and_links_items(self):
        self.remote_item("K", "v1")
        self.sync()
        self.assertEqual(self.value("K"), "v1")
        self.assertEqual(kg.load_vault()["K"]["cloud"], {"vault": VID, "item_id": "item-1", "rev": 1})

    def test_local_set_keeps_cloud_link_and_marks_dirty(self):
        self.remote_item("K", "v1")
        self.sync()
        self.set_local("K", "edited")
        cloud = kg.load_vault()["K"]["cloud"]
        self.assertEqual((cloud["item_id"], cloud["rev"], cloud["dirty"]), ("item-1", 1, True))

    def test_sync_updates_clean_items(self):
        self.remote_item("K", "v1")
        self.sync()
        self.remote_item("K", "v2", rev=2, seq=2)
        self.sync()
        self.assertEqual(self.value("K"), "v2")

    def test_sync_keeps_unpushed_local_edit_and_adopts_remote_rev(self):
        self.remote_item("K", "v1")
        self.sync()
        self.set_local("K", "mine")
        self.remote_item("K", "theirs", rev=2, seq=2)
        self.sync()
        self.assertEqual(self.value("K"), "mine")
        self.assertEqual(kg.load_vault()["K"]["cloud"]["rev"], 2)  # next push overwrites rev 2

    def test_sync_never_overwrites_a_local_only_secret(self):
        self.set_local("K", "local-only")
        self.remote_item("K", "cloud")
        self.sync()
        self.assertEqual(self.value("K"), "local-only")
        self.assertNotIn("cloud", kg.load_vault()["K"])

    def test_tombstone_removes_only_cloud_copies(self):
        self.remote_item("K", "v1")
        self.set_local("LOCAL", "x")
        self.sync()
        self.remote_item("K", "", rev=2, seq=2, deleted=True)
        self.remote_item("LOCAL", "", iid="item-2", rev=1, seq=3, deleted=True)
        self.sync()
        self.assertIsNone(self.value("K"))
        self.assertEqual(self.value("LOCAL"), "x")

    def test_push_conflict_leaves_local_state_alone(self):
        self.remote_item("K", "v1")
        self.sync()
        self.set_local("K", "mine")

        def conflict(*_a, **_k):
            raise kc.CloudError("conflict", 409)

        with mock.patch.object(kc, "api", conflict):
            self.assertEqual(kc.cmd_push(["K"]), 1)
        self.assertEqual(self.value("K"), "mine")
        self.assertTrue(kg.load_vault()["K"]["cloud"]["dirty"])

    def test_push_sends_next_rev_bound_into_the_ciphertext(self):
        self.remote_item("K", "v1")
        self.sync()
        self.set_local("K", "mine")
        sent = {}

        def fake_api(_state, method, path, body=None):
            sent.update(body)
            return {"rev": 2, "seq": 9}

        with mock.patch.object(kc, "api", fake_api):
            self.assertEqual(kc.cmd_push(["K"]), 0)
        self.assertEqual(sent["base_rev"], 1)
        payload = json.loads(kc.unseal(KEY, sent["enc"], kc.item_aad(VID, "item-1", "K", 2)))
        self.assertEqual(payload["value"], "mine")
        self.assertNotIn("dirty", kg.load_vault()["K"]["cloud"])


if __name__ == "__main__":
    unittest.main()
