"""Vault key rotation after a device revocation, with real crypto against a
fake server: performing a pending rotation, and following one done elsewhere."""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant_cloud as kc  # noqa: E402

HAVE_NACL = importlib.util.find_spec("nacl") is not None


@unittest.skipUnless(HAVE_NACL, "needs PyNaCl")
class Rotation(unittest.TestCase):
    def setUp(self):
        import nacl.public
        self.nacl = nacl
        self.store = {}
        for name, fn in [("encrypt_value", self._enc), ("decrypt_value", lambda r: self.store[r["k"]]),
                         ("delete_value", lambda r: self.store.pop(r["k"], None))]:
            p = mock.patch.object(kc.kg, name, fn)
            p.start()
            self.addCleanup(p.stop)
        for p in (mock.patch.object(kc, "save_state", lambda s: None), mock.patch("builtins.print")):
            p.start()
            self.addCleanup(p.stop)

        self.account, self.vid = "acct-1", "vault-1"
        self.auk = os.urandom(32)
        k_enc, self.k_mac = kc.subkeys(self.auk)
        self.user = nacl.public.PrivateKey.generate()
        self.keys = {
            "user_pubkey": kc.b64e(self.user.public_key.encode()),
            "user_pubkey_mac": kc.mac(self.k_mac, "user-pubkey", self.account, self.user.public_key.encode()),
            "enc_user_privkey": kc.seal(k_enc, self.user.encode(), kc.user_key_aad(self.account)),
        }
        self.old_key = os.urandom(32)
        self.vault = self._vault_for(self.old_key, version=1)
        self.plain = {}
        self.items = []
        for i, (name, rev) in enumerate([("STRIPE", 1), ("OPENAI", 3)]):
            iid = f"item-{i}"
            payload = json.dumps({"value": f"secret-{i}", "desc": ""}).encode()
            self.plain[iid] = payload
            self.items.append({"id": iid, "name": name, "rev": rev, "seq": i + 1, "deleted": False,
                               "enc": kc.seal(self.old_key, payload, kc.item_aad(self.vid, iid, name, rev))})
        self.state = {"account_id": self.account, "vault_id": self.vid, "vault_key_version": 1,
                      "auk": self._enc(kc.b64e(self.auk)), "vault_key": self._enc(kc.b64e(self.old_key))}
        self.rotate_body = None

    def _enc(self, value):
        k = str(len(self.store) + 1)
        self.store[k] = value
        return {"k": k}

    def _vault_for(self, key, version, pending=0):
        return {"id": self.vid, "key_version": version, "key_rotation_pending": pending,
                "enc_vault_key": kc.b64e(self.nacl.public.SealedBox(self.user.public_key).encrypt(key)),
                "vault_key_mac": kc.mac(self.k_mac, "vault", self.vid, key)}

    def _api(self, _state, method, path, body=None, **_kw):
        if path == "/accounts/keys":
            return self.keys
        if path == "/vaults":
            return {"vaults": [self.vault]}
        if path.startswith(f"/vaults/{self.vid}/items"):
            return {"items": self.items}
        if path == f"/vaults/{self.vid}/rotate":
            self.rotate_body = body
            return {"ok": True, "key_version": self.vault["key_version"] + 1}
        raise AssertionError(path)

    def refresh(self):
        with mock.patch.object(kc, "api", self._api):
            kc.refresh_vault_key(self.state)

    def test_pending_rotation_rekeys_every_item_under_a_verified_new_key(self):
        self.vault["key_rotation_pending"] = 1
        self.refresh()

        body = self.rotate_body
        new_key = self.nacl.public.SealedBox(self.user).decrypt(kc.b64d(body["enc_vault_key"]))
        self.assertNotEqual(new_key, self.old_key)
        self.assertTrue(kc.mac_ok(self.k_mac, body["vault_key_mac"], "vault", self.vid, new_key))
        by_id = {it["id"]: it for it in self.items}
        self.assertEqual({it["id"] for it in body["items"]}, set(by_id))
        for it in body["items"]:
            src = by_id[it["id"]]
            self.assertEqual(it["rev"], src["rev"])  # rev unchanged: AAD unchanged
            aad = kc.item_aad(self.vid, it["id"], src["name"], src["rev"])
            self.assertEqual(kc.unseal(new_key, it["enc"], aad), self.plain[it["id"]])
        self.assertEqual(kc._secret(self.state, "vault_key"), new_key)
        self.assertEqual(self.state["vault_key_version"], 2)

    def test_lost_race_leaves_key_and_flag_for_the_next_sync(self):
        self.vault["key_rotation_pending"] = 1

        def racing(_s, method, path, body=None, **kw):
            if path.endswith("/rotate"):
                raise kc.CloudError("vault changed", 409)
            return self._api(_s, method, path, body, **kw)
        with mock.patch.object(kc, "api", racing):
            kc.refresh_vault_key(self.state)
        self.assertEqual(kc._secret(self.state, "vault_key"), self.old_key)

    def test_follows_a_rotation_done_on_another_device(self):
        new_key = os.urandom(32)
        self.vault = self._vault_for(new_key, version=2)
        self.refresh()
        self.assertEqual(kc._secret(self.state, "vault_key"), new_key)
        self.assertEqual(self.state["vault_key_version"], 2)

    def test_refuses_a_rotated_key_without_a_valid_mac(self):
        # a server swapping in its own key at a "rotation" cannot forge K_mac
        planted = os.urandom(32)
        self.vault = self._vault_for(planted, version=2)
        self.vault["vault_key_mac"] = kc.mac(os.urandom(32), "vault", self.vid, planted)
        with self.assertRaisesRegex(kc.CloudError, "key substitution"):
            self.refresh()
        self.assertEqual(kc._secret(self.state, "vault_key"), self.old_key)


if __name__ == "__main__":
    unittest.main()
