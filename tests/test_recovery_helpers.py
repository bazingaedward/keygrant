import pytest

import keygrant_cloud as kc


def test_secret_key_roundtrip():
    sk = bytes(range(16))
    text = kc.format_secret_key(sk)
    assert text.startswith("A3-")
    assert kc.parse_secret_key(text) == sk
    # tolerant of case, stray spaces and missing dashes
    assert kc.parse_secret_key(" " + text.lower().replace("-", "") + " ") == sk


def test_parse_secret_key_rejects_garbage():
    with pytest.raises(OSError):
        kc.parse_secret_key("A3-NOT!VALID")
    with pytest.raises(OSError):
        kc.parse_secret_key("A3-AAAAA")  # wrong length


def test_recovery_signer_is_deterministic():
    pytest.importorskip("nacl")
    auk = b"\x01" * 32
    a = kc.recovery_signer(auk).verify_key.encode()
    b = kc.recovery_signer(auk).verify_key.encode()
    assert a == b
    assert kc.recovery_signer(b"\x02" * 32).verify_key.encode() != a


def test_recover_statement_shape():
    s = kc.recover_statement("acc", "CHAL", "PUB")
    assert s == b"keygrant/recover/v1\nacc\nCHAL\nPUB"
