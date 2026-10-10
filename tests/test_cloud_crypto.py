"""Cloud client cryptography (keygrant-cloud SPEC §10).

Run: python -m unittest discover -s tests   (needs PyNaCl; skipped otherwise)
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant_cloud as kc  # noqa: E402

HAVE_NACL = importlib.util.find_spec("nacl") is not None


class Primitives(unittest.TestCase):
    def test_hkdf_matches_rfc5869_case_3(self):
        okm = kc.hkdf(bytes([0x0B] * 22), b"", 42)
        self.assertEqual(okm.hex(), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f"
                                    "3c738d2d9d201395faa4b61a96c8")

    def test_length_prefixing_is_unambiguous(self):
        self.assertNotEqual(kc._lp("ab", "c"), kc._lp("a", "bc"))

    def test_auk_depends_on_password_secret_key_and_account(self):
        with mock.patch.object(kc, "SCRYPT_N", 2 ** 10):
            base = kc.derive_auk("correct horse", b"k" * 16, "acct")
            self.assertEqual(base, kc.derive_auk("correct horse", b"k" * 16, "acct"))
            self.assertNotEqual(base, kc.derive_auk("wrong horse", b"k" * 16, "acct"))
            self.assertNotEqual(base, kc.derive_auk("correct horse", b"j" * 16, "acct"))
            self.assertNotEqual(base, kc.derive_auk("correct horse", b"k" * 16, "other"))

    def test_secret_key_format(self):
        self.assertRegex(kc.format_secret_key(os.urandom(16)), r"^A3(-[A-Z2-7]{1,5}){6}$")


@unittest.skipUnless(HAVE_NACL, "needs PyNaCl")
class ItemEncryption(unittest.TestCase):
    key = bytes(range(32))

    def test_round_trip(self):
        aad = kc.item_aad("v", "i", "STRIPE_KEY", 3)
        self.assertEqual(kc.unseal(self.key, kc.seal(self.key, b"sk_live", aad), aad), b"sk_live")

    def test_ciphertext_is_bound_to_item_name_and_rev(self):
        blob = kc.seal(self.key, b"sk_live", kc.item_aad("v", "i", "STRIPE_KEY", 3))
        for aad in (kc.item_aad("v", "i", "OTHER_KEY", 3),   # moved to another name
                    kc.item_aad("v", "j", "STRIPE_KEY", 3),   # moved to another item
                    kc.item_aad("w", "i", "STRIPE_KEY", 3),   # moved to another vault
                    kc.item_aad("v", "i", "STRIPE_KEY", 2)):  # replayed as another rev
            with self.assertRaises(kc.CloudError):
                kc.unseal(self.key, blob, aad)

    def test_tampering_is_detected(self):
        aad = kc.item_aad("v", "i", "K", 1)
        raw = bytearray(kc.b64d(kc.seal(self.key, b"value", aad)))
        raw[-1] ^= 1
        with self.assertRaises(kc.CloudError):
            kc.unseal(self.key, kc.b64e(bytes(raw)), aad)


@unittest.skipUnless(HAVE_NACL, "needs PyNaCl")
class Unlock(unittest.TestCase):
    """unlock() against a fake server: wrong password and key substitution."""

    def setUp(self):
        import nacl.public
        self.nacl = nacl
        p = mock.patch.object(kc, "SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)
        self.store = {}
        for name, fn in [("encrypt_value", self._enc), ("decrypt_value", lambda r: self.store[r["k"]]),
                         ("delete_value", lambda r: self.store.pop(r["k"], None))]:
            q = mock.patch.object(kc.kg, name, fn)
            q.start()
            self.addCleanup(q.stop)
        q = mock.patch.object(kc, "save_state", lambda s: None)
        q.start()
        self.addCleanup(q.stop)

        self.account, self.sk, self.vault_id = "acct-1", os.urandom(16), "vault-1"
        auk = kc.derive_auk("the password", self.sk, self.account)
        k_enc, k_mac = kc.subkeys(auk)
        self.user = nacl.public.PrivateKey.generate()
        self.vault_key = os.urandom(32)
        self.keys = {
            "user_pubkey": kc.b64e(self.user.public_key.encode()),
            "user_pubkey_mac": kc.mac(k_mac, "user-pubkey", self.account, self.user.public_key.encode()),
            "enc_user_privkey": kc.seal(k_enc, self.user.encode(), kc.user_key_aad(self.account)),
        }
        self.vault = {"id": self.vault_id,
                      "enc_vault_key": kc.b64e(nacl.public.SealedBox(self.user.public_key).encrypt(self.vault_key)),
                      "vault_key_mac": kc.mac(k_mac, "vault", self.vault_id, self.vault_key)}

    def _enc(self, value):
        k = str(len(self.store) + 1)
        self.store[k] = value
        return {"k": k}

    def _unlock(self, password):
        state = {"account_id": self.account, "secret_key": self._enc(kc.b64e(self.sk))}

        def fake_api(_state, method, path, body=None, **_kw):
            return self.keys if path == "/accounts/keys" else {"vaults": [self.vault]}

        with mock.patch.object(kc, "api", fake_api):
            kc.unlock(state, password)
        return state

    def test_correct_password_unlocks_vault_key(self):
        state = self._unlock("the password")
        self.assertEqual(kc._secret(state, "vault_key"), self.vault_key)
        self.assertEqual(state["vault_id"], self.vault_id)

    def test_wrong_password_is_rejected(self):
        with self.assertRaisesRegex(kc.CloudError, "wrong password"):
            self._unlock("not the password")

    def test_substituted_vault_key_is_rejected(self):
        # Anyone with the public key can make a sealed box; without K_mac they
        # cannot make a matching MAC, so the planted key must be refused.
        planted = os.urandom(32)
        self.vault["enc_vault_key"] = kc.b64e(
            self.nacl.public.SealedBox(self.user.public_key).encrypt(planted))
        with self.assertRaisesRegex(kc.CloudError, "key substitution"):
            self._unlock("the password")

    def test_substituted_user_public_key_is_rejected(self):
        self.keys["user_pubkey"] = kc.b64e(self.nacl.public.PrivateKey.generate().public_key.encode())
        with self.assertRaises(kc.CloudError):
            self._unlock("the password")


if __name__ == "__main__":
    unittest.main()
