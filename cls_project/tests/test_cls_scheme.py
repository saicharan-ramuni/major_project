"""
Tests for all CLS algorithms from Qiao et al., IEEE IoT Journal, July 2025.

Run:  python -m pytest tests/test_cls_scheme.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from crypto.cls_scheme import (
    setup, partial_priv_key_gen, secret_value_gen, key_gen,
    sign, verify, batch_verify,
    serialize_signature, deserialize_signature,
    serialize_pk_record, deserialize_pk_record,
    serialize_point, deserialize_point,
    _point_mul, _point_add, _G, _N, H1,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def params_msk():
    return setup(256)


# In this CLS scheme the "identity" used throughout (key gen, sign, verify)
# is the pseudonym RID — not the real username.  The fixture uses a fixed RID
# string so that key generation and signing are consistent.
ALICE_RID = "alice_rid_abc123"
BOB_RID   = "bob_rid_xyz789"


@pytest.fixture(scope="module")
def alice_keys(params_msk):
    params, msk = params_msk
    D  = partial_priv_key_gen(params, msk, ALICE_RID)
    x  = secret_value_gen(params)
    pk, SK = key_gen(params, ALICE_RID, D, x)
    return pk, SK, D


@pytest.fixture(scope="module")
def bob_keys(params_msk):
    params, msk = params_msk
    D  = partial_priv_key_gen(params, msk, BOB_RID)
    x  = secret_value_gen(params)
    pk, SK = key_gen(params, BOB_RID, D, x)
    return pk, SK, D


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def test_setup_returns_valid_params(params_msk):
    params, msk = params_msk
    assert params.G == _G
    assert params.q == _N
    assert params.P_pub is not None
    assert 1 <= msk < _N


def test_setup_ppub_equals_s_times_G(params_msk):
    """P_pub must equal s·G — the fundamental KGC key relationship."""
    params, msk = params_msk
    expected = _point_mul(msk, _G)
    assert params.P_pub == expected


# ---------------------------------------------------------------------------
# Partial Private Key Generation
# ---------------------------------------------------------------------------

def test_partial_key_gen_consistency(params_msk):
    """
    Core correctness property: d·G = R + H1(ID,R)·P_pub

    Because d = r + s·H1(ID,R), so d·G = r·G + s·H1·G = R + H1·P_pub
    """
    params, msk = params_msk
    identity = "test_user_123"
    D = partial_priv_key_gen(params, msk, identity)
    R = D["R"]
    d = D["d"]

    lhs = _point_mul(d, _G)
    h = H1(params.P_pub, identity, R)
    rhs = _point_add(R, _point_mul(h, params.P_pub))
    assert lhs == rhs, "d·G != R + H1(P_pub,ID,R)·P_pub — partial key generation broken"


def test_partial_key_gen_different_identities(params_msk):
    """Different identities produce different partial keys."""
    params, msk = params_msk
    D1 = partial_priv_key_gen(params, msk, "user_a")
    D2 = partial_priv_key_gen(params, msk, "user_b")
    assert D1["R"] != D2["R"] or D1["d"] != D2["d"]


def test_partial_key_gen_same_identity_randomised(params_msk):
    """Same identity called twice gives different R (due to fresh random r)."""
    params, msk = params_msk
    D1 = partial_priv_key_gen(params, msk, "alice")
    D2 = partial_priv_key_gen(params, msk, "alice")
    # With overwhelming probability r1 != r2, so R1 != R2
    assert D1["R"] != D2["R"]


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def test_key_gen_pk_equals_x_times_G(params_msk, alice_keys):
    """PK = x·G must hold."""
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    expected_PK = _point_mul(SK["x"], _G)
    assert pk_record["PK"] == expected_PK


def test_key_gen_r_matches_partial_key(alice_keys):
    """R in pk_record must equal R from partial key D."""
    pk_record, SK, D = alice_keys
    assert pk_record["R"] == D["R"]
    assert SK["R"] == D["R"]


# ---------------------------------------------------------------------------
# Sign & Verify — Happy Path
# ---------------------------------------------------------------------------

def test_sign_verify_roundtrip(params_msk, alice_keys):
    """Basic: sign then verify should return True."""
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    rid = ALICE_RID
    message = "Heart rate: 72 bpm, BP: 120/80"

    sig = sign(params, SK, rid, message)
    assert verify(params, rid, pk_record, message, sig)


def test_sign_produces_valid_point_T(params_msk, alice_keys):
    """Signature T must be a valid EC point (not infinity)."""
    params, _ = params_msk
    _, SK, _ = alice_keys
    sig = sign(params, SK, ALICE_RID,"test message")
    assert sig["T"] is not None
    assert isinstance(sig["T"], tuple)
    assert len(sig["T"]) == 2


def test_sign_sigma_in_range(params_msk, alice_keys):
    """Signature scalar σ must be in [1, q-1]."""
    params, _ = params_msk
    _, SK, _ = alice_keys
    sig = sign(params, SK, ALICE_RID,"test")
    assert 1 <= sig["sigma"] < params.q


def test_sign_randomised(params_msk, alice_keys):
    """Two signatures on the same message use different k → different T."""
    params, _ = params_msk
    _, SK, _ = alice_keys
    sig1 = sign(params, SK, ALICE_RID,"same message")
    sig2 = sign(params, SK, ALICE_RID,"same message")
    assert sig1["T"] != sig2["T"]  # different k each time


# ---------------------------------------------------------------------------
# Verify — Failure Cases
# ---------------------------------------------------------------------------

def test_verify_fails_wrong_message(params_msk, alice_keys):
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    rid = ALICE_RID
    sig = sign(params, SK, rid, "original message")
    assert not verify(params, rid, pk_record, "tampered message", sig)


def test_verify_fails_wrong_identity(params_msk, alice_keys):
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    sig = sign(params, SK, ALICE_RID, "message")
    assert not verify(params, "eve_different_rid", pk_record, "message", sig)


def test_verify_fails_modified_sigma(params_msk, alice_keys):
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    rid = ALICE_RID
    sig = sign(params, SK, rid, "message")
    bad_sig = {"T": sig["T"], "sigma": (sig["sigma"] + 1) % params.q}
    assert not verify(params, rid, pk_record, "message", bad_sig)


def test_verify_fails_modified_T(params_msk, alice_keys):
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    rid = ALICE_RID
    sig = sign(params, SK, rid, "message")
    bad_sig = {"T": _G, "sigma": sig["sigma"]}  # replace T with generator
    assert not verify(params, rid, pk_record, "message", bad_sig)


def test_verify_fails_wrong_pk(params_msk, alice_keys, bob_keys):
    """Alice's signature should not verify under Bob's public key."""
    params, _ = params_msk
    alice_pk, alice_SK, _ = alice_keys
    bob_pk, _, _ = bob_keys
    rid = ALICE_RID
    sig = sign(params, alice_SK, rid, "message")
    assert not verify(params, rid, bob_pk, "message", sig)


# ---------------------------------------------------------------------------
# Batch Verification
# ---------------------------------------------------------------------------

def _make_item(params, msk, identity, message):
    """Helper: create a fully signed batch item."""
    D  = partial_priv_key_gen(params, msk, identity)
    x  = secret_value_gen(params)
    pk, SK = key_gen(params, identity, D, x)
    sig = sign(params, SK, identity, message)
    return {"identity": identity, "pk_record": pk, "message": message, "signature": sig}


def test_batch_verify_empty(params_msk):
    params, _ = params_msk
    ok, passed, failed = batch_verify(params, [])
    assert ok is True
    assert passed == 0
    assert failed == 0


def test_batch_verify_single_valid(params_msk):
    params, msk = params_msk
    items = [_make_item(params, msk, "device_1", "temp=36.5")]
    ok, passed, failed = batch_verify(params, items)
    assert ok is True
    assert passed == 1
    assert failed == 0


def test_batch_verify_all_valid(params_msk):
    """10 valid signatures should all pass batch verify."""
    params, msk = params_msk
    items = [_make_item(params, msk, f"device_{i}", f"reading_{i}") for i in range(10)]
    ok, passed, failed = batch_verify(params, items)
    assert ok is True
    assert passed == 10
    assert failed == 0


def test_batch_verify_one_tampered(params_msk):
    """Tampering one message should cause batch verify to fail and isolate the failure."""
    params, msk = params_msk
    items = [_make_item(params, msk, f"dev_{i}", f"data_{i}") for i in range(5)]
    # Tamper message of item 2
    items[2] = {**items[2], "message": "TAMPERED_DATA"}

    ok, passed, failed = batch_verify(params, items)
    assert ok is False
    assert failed >= 1
    assert passed + failed == 5


def test_batch_verify_all_tampered(params_msk):
    params, msk = params_msk
    items = [_make_item(params, msk, f"dev_{i}", f"data_{i}") for i in range(3)]
    for i in range(3):
        items[i] = {**items[i], "message": "BAD"}
    ok, passed, failed = batch_verify(params, items)
    assert ok is False
    assert failed == 3


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_serialize_deserialize_signature(params_msk, alice_keys):
    params, _ = params_msk
    _, SK, _ = alice_keys
    sig = sign(params, SK, ALICE_RID, "msg")
    serialized = serialize_signature(sig)
    assert isinstance(serialized["T"], str)
    assert len(serialized["T"]) == 128
    restored = deserialize_signature(serialized)
    assert restored["T"] == sig["T"]
    assert restored["sigma"] == sig["sigma"]


def test_serialize_deserialize_pk_record(alice_keys):
    pk_record, _, _ = alice_keys
    serialized = serialize_pk_record(pk_record)
    assert isinstance(serialized["PK"], str)
    assert isinstance(serialized["R"], str)
    restored = deserialize_pk_record(serialized)
    assert restored["PK"] == pk_record["PK"]
    assert restored["R"] == pk_record["R"]


def test_serialize_deserialize_point_roundtrip():
    p = _point_mul(12345, _G)
    encoded = serialize_point(p)
    assert len(encoded) == 128
    assert deserialize_point(encoded) == p


def test_sign_verify_after_serialization(params_msk, alice_keys):
    """Verify should still work after sig and pk are serialized and deserialized."""
    params, _ = params_msk
    pk_record, SK, _ = alice_keys
    rid = ALICE_RID
    msg = "test after serialization"
    sig = sign(params, SK, rid, msg)
    pk_s  = serialize_pk_record(pk_record)
    sig_s = serialize_signature(sig)
    pk_r  = deserialize_pk_record(pk_s)
    sig_r = deserialize_signature(sig_s)
    assert verify(params, rid, pk_r, msg, sig_r)
