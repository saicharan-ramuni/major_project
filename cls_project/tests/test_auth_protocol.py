"""
Tests for the 3-step Mutual Authentication Protocol (Section VI of the paper).

Run:  python -m pytest tests/test_auth_protocol.py -v
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
from crypto.cls_scheme import (
    setup, partial_priv_key_gen, secret_value_gen, key_gen
)
from crypto.auth_protocol import MutualAuthProtocol, AuthenticationError


@pytest.fixture(scope="module")
def system():
    params, msk = setup(256)

    # In this scheme, the identity used in all CLS operations IS the pseudonym (RID).
    # The KGC issues partial keys for the RID, not the real username.
    RID_A = "rid_alice_001"
    RID_B = "rid_bob_001"

    # Patient (Ua) — key generated for RID_A
    D_a = partial_priv_key_gen(params, msk, RID_A)
    x_a = secret_value_gen(params)
    pk_a, SK_a = key_gen(params, RID_A, D_a, x_a)

    # Doctor (Ub) — key generated for RID_B
    D_b = partial_priv_key_gen(params, msk, RID_B)
    x_b = secret_value_gen(params)
    pk_b, SK_b = key_gen(params, RID_B, D_b, x_b)

    protocol = MutualAuthProtocol(params)
    return {
        "params": params,
        "protocol": protocol,
        "pk_a": pk_a, "SK_a": SK_a, "RID_a": RID_A,
        "pk_b": pk_b, "SK_b": SK_b, "RID_b": RID_B,
    }


# ---------------------------------------------------------------------------
# Full 3-step protocol
# ---------------------------------------------------------------------------

def test_full_mutual_auth_succeeds(system):
    """Complete 3-step protocol runs without errors."""
    p = system["protocol"]

    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, sess_b = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    K_ab_a = p.initiator_step3(msg2, system["pk_b"], sess_a)

    assert K_ab_a is not None
    assert len(K_ab_a) == 32


def test_session_keys_match_both_sides(system):
    """K_ab derived by Ua and Ub must be identical."""
    p = system["protocol"]

    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, sess_b = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    K_ab_a = p.initiator_step3(msg2, system["pk_b"], sess_a)

    assert K_ab_a == sess_b.session_key


def test_session_key_is_32_bytes(system):
    p = system["protocol"]
    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, sess_b = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    K_ab = p.initiator_step3(msg2, system["pk_b"], sess_a)
    assert isinstance(K_ab, bytes)
    assert len(K_ab) == 32


def test_different_sessions_produce_different_keys(system):
    """Two independent sessions between same parties → different K_ab (due to fresh w)."""
    p = system["protocol"]

    msg1a, sess_a1 = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2a, sess_b1 = p.responder_step2(msg1a, system["pk_a"], system["SK_b"], system["RID_b"])
    K1 = p.initiator_step3(msg2a, system["pk_b"], sess_a1)

    msg1b, sess_a2 = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2b, sess_b2 = p.responder_step2(msg1b, system["pk_a"], system["SK_b"], system["RID_b"])
    K2 = p.initiator_step3(msg2b, system["pk_b"], sess_a2)

    assert K1 != K2


# ---------------------------------------------------------------------------
# Step 1 message structure
# ---------------------------------------------------------------------------

def test_step1_message_has_required_fields(system):
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    assert "RID_a" in msg1
    assert "T_a" in msg1
    assert "W_a" in msg1
    assert "sig_a" in msg1


def test_step1_W_a_is_128char_hex(system):
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    assert len(msg1["W_a"]) == 128


def test_step1_timestamp_is_recent(system):
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    assert abs(time.time() - msg1["T_a"]) < 5


# ---------------------------------------------------------------------------
# Step 2 — failure cases
# ---------------------------------------------------------------------------

def test_step2_rejects_tampered_sig_a(system):
    """Doctor rejects message with modified sigma."""
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    # Tamper sigma in sig_a
    msg1["sig_a"]["sigma"] = (msg1["sig_a"]["sigma"] + 1) % (2**256)

    with pytest.raises(AuthenticationError):
        p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])


def test_step2_rejects_expired_timestamp(system):
    """Doctor rejects message with timestamp older than 5 minutes."""
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg1["T_a"] = int(time.time()) - 400   # 6.7 minutes old

    with pytest.raises(AuthenticationError, match="timestamp"):
        p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])


def test_step2_rejects_future_timestamp(system):
    """Doctor rejects messages with timestamp far in the future (replay protection)."""
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg1["T_a"] = int(time.time()) + 400

    with pytest.raises(AuthenticationError, match="timestamp"):
        p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])


def test_step2_rejects_wrong_pk_a(system):
    """Doctor rejects message if wrong (Bob's) public key used to verify Alice's sig."""
    p = system["protocol"]
    msg1, _ = p.initiator_step1(system["SK_a"], system["RID_a"])
    # Use Bob's PK instead of Alice's
    with pytest.raises(AuthenticationError):
        p.responder_step2(msg1, system["pk_b"], system["SK_b"], system["RID_b"])


# ---------------------------------------------------------------------------
# Step 3 — failure cases
# ---------------------------------------------------------------------------

def test_step3_rejects_tampered_sig_b(system):
    """Patient rejects doctor response with modified sigma."""
    p = system["protocol"]
    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, _ = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    msg2["sig_b"]["sigma"] = (msg2["sig_b"]["sigma"] + 1) % (2**256)

    with pytest.raises(AuthenticationError):
        p.initiator_step3(msg2, system["pk_b"], sess_a)


def test_step3_rejects_expired_timestamp(system):
    p = system["protocol"]
    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, _ = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    msg2["T_b"] = int(time.time()) - 400

    with pytest.raises(AuthenticationError, match="timestamp"):
        p.initiator_step3(msg2, system["pk_b"], sess_a)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

def test_session_stores_both_rids(system):
    p = system["protocol"]
    msg1, sess_a = p.initiator_step1(system["SK_a"], system["RID_a"])
    msg2, _ = p.responder_step2(msg1, system["pk_a"], system["SK_b"], system["RID_b"])
    p.initiator_step3(msg2, system["pk_b"], sess_a)
    assert sess_a.RID_a == system["RID_a"]
    assert sess_a.RID_b == system["RID_b"]
