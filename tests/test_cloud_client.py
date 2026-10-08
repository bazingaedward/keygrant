"""keygrant_cloud client behaviour (docs/design/cloud-mvp.md, phase 1).

Run: python -m unittest discover -s tests   (needs `cryptography` for login)
"""

import base64
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant_cloud as kc  # noqa: E402


class FakeKeystore:
    """Stands in for the OS keystore: record -> value, tracks deletions."""

    def __init__(self):
        self.items: dict[str, str] = {}
        self.n = 0

    def encrypt(self, value):
        self.n += 1
        ref = f"item{self.n}"
        self.items[ref] = value
        return {"keychain": ref}

    def decrypt(self, record):
        return self.items[record["keychain"]]

    def delete(self, record):
        self.items.pop(record["keychain"], None)


class CloudTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ks = FakeKeystore()
        for target, new in [("VAULT_DIR", tmp.name),
                            ("CLOUD_PATH", os.path.join(tmp.name, "cloud.json")),
                            ("encrypt_value", self.ks.encrypt),
                            ("decrypt_value", self.ks.decrypt),
                            ("delete_value", self.ks.delete)]:
            p = mock.patch.object(kc, target, new)
            p.start()
            self.addCleanup(p.stop)


class DeviceFlow(CloudTestCase):
    def poll(self, responses):
        code = {"device_code": "dc", "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "interval": 5, "expires_in": 900}
        sleeps = []
        with mock.patch.object(kc, "_post_form", side_effect=[code, *responses]), \
                mock.patch.object(kc.webbrowser, "open"), \
                mock.patch("builtins.print"):
            token = kc.github_device_flow(sleep=sleeps.append)
        return token, sleeps

    def test_waits_while_pending_and_backs_off_on_slow_down(self):
        token, sleeps = self.poll([
            {"error": "authorization_pending"},
            {"error": "slow_down", "interval": 10},
            {"access_token": "gho_x"},
        ])
        self.assertEqual(token, "gho_x")
        self.assertEqual(sleeps, [5, 5, 10])

    def test_denial_raises(self):
        with self.assertRaises(kc.CloudError):
            self.poll([{"error": "access_denied", "error_description": "denied"}])


class Sessions(CloudTestCase):
    def test_refresh_rotates_and_deletes_old_token(self):
        state = {"refresh": self.ks.encrypt("kgr_old")}
        with mock.patch.object(kc, "api", return_value={
                "access_token": "kga_new", "refresh_token": "kgr_new"}) as api:
            self.assertEqual(kc.session_token(state), "kga_new")
        api.assert_called_once_with("POST", "/v1/auth/refresh",
                                    body={"refresh_token": "kgr_old"})
        self.assertEqual(list(self.ks.items.values()), ["kgr_new"])
        self.assertEqual(kc.load_state()["refresh"], state["refresh"])

    def test_not_signed_in(self):
        with self.assertRaises(kc.CloudError):
            kc.session_token({})

    def test_fingerprint_format(self):
        fp = kc.fingerprint(base64.b64encode(bytes(32)).decode())
        self.assertRegex(fp, r"^[0-9a-f]{4}(-[0-9a-f]{4}){3}$")


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"),
                     "needs cryptography")
class Login(CloudTestCase):
    def test_login_stores_secrets_only_in_keystore(self):
        calls = []

        def fake_api(method, path, token=None, body=None):
            calls.append((method, path, token, body))
            if path == "/v1/auth/github":
                return {"access_token": "kga_1", "refresh_token": "kgr_1",
                        "user": {"id": "u1", "login": "alice"}}
            if path == "/v1/devices":
                return {"id": "dev-1"}
            raise AssertionError(path)

        with mock.patch.object(kc, "github_device_flow", return_value="gho_secret"), \
                mock.patch.object(kc, "api", side_effect=fake_api), \
                mock.patch("builtins.print"):
            self.assertEqual(kc.cmd_login([]), 0)

        with open(kc.CLOUD_PATH, encoding="utf-8") as f:
            on_disk = f.read()
        for secret in ("gho_secret", "kga_1", "kgr_1"):
            self.assertNotIn(secret, on_disk)
        state = kc.load_state()
        self.assertEqual(self.ks.decrypt(state["refresh"]), "kgr_1")
        self.assertEqual(len(base64.b64decode(self.ks.decrypt(state["device_private"]))), 32)
        self.assertEqual(state["device_id"], "dev-1")
        _, _, token, body = calls[1]
        self.assertEqual(token, "kga_1")
        self.assertEqual(body["public_key"], state["public_key"])
        self.assertNotEqual(body["public_key"], self.ks.decrypt(state["device_private"]))

    def test_login_fails_before_network_without_cryptography(self):
        with mock.patch.object(kc, "generate_device_key",
                               side_effect=kc.CloudError("need cryptography")), \
                mock.patch.object(kc, "github_device_flow") as flow:
            with self.assertRaises(kc.CloudError):
                kc.cmd_login([])
        flow.assert_not_called()


if __name__ == "__main__":
    unittest.main()
