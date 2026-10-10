"""Output redaction must catch a secret's base64 at any byte alignment."""

import base64
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import keygrant as kg  # noqa: E402

SECRETS = ["sk-live-51HxDEMOonly0000", "sk-live-51HxDEMOonly00001", "sk-live-51HxDEMOonly000012"]


def recoverable(output: str, secret: str) -> bool:
    """Can the secret still be decoded from what is left around the marker?"""
    for part in re.split(r"\[[^\]]*REDACTED\]", output):
        for alphabet in ("+/", "-_"):
            chunk = part.translate(str.maketrans(alphabet, "+/"))
            for cut in range(4):  # try every alignment of the leftover
                body = chunk[cut:]
                try:
                    decoded = base64.b64decode(body + "=" * (-len(body) % 4))
                except ValueError:
                    continue
                if secret.encode() in decoded:
                    return True
    return False


class Base64Alignment(unittest.TestCase):
    def test_secret_after_any_prefix_is_redacted(self):
        # e.g. `echo "Authorization: Bearer $KEY" | base64` puts the key 22
        # bytes into the stream; before the fix only 3-byte-aligned offsets
        # were caught and the full key decoded straight out of the output
        for v in SECRETS:
            for prefix in ["", "k=", "key=", "Bearer ", "Authorization: Bearer ", '{"key":"']:
                for suffix in ["", "\n", '"}']:
                    raw = (prefix + v + suffix).encode()
                    for enc in (base64.b64encode, base64.urlsafe_b64encode):
                        with self.subTest(v=len(v), prefix=prefix, suffix=suffix, enc=enc.__name__):
                            out = kg.redact(enc(raw).decode(), {"K": v})
                            self.assertIn("REDACTED", out)
                            self.assertFalse(recoverable(out, v))

    def test_unrelated_text_is_untouched(self):
        text = "build ok aGVsbG8gd29ybGQ= 68656c6c6f"
        self.assertEqual(kg.redact(text, {"K": SECRETS[0]}), text)


if __name__ == "__main__":
    unittest.main()
