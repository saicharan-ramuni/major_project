"""
Tests for the PseudonymManager (anonymity module).

Run:  python -m pytest tests/test_anonymity.py -v
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
from crypto.anonymity import PseudonymManager, set_authority_token, _compute_rid

set_authority_token("test-kgc-token")


@pytest.fixture
def pm():
    return PseudonymManager()


# ---------------------------------------------------------------------------
# RID generation
# ---------------------------------------------------------------------------

def test_compute_rid_deterministic():
    """Same inputs → same RID."""
    r1 = _compute_rid("alice", 1000000)
    r2 = _compute_rid("alice", 1000000)
    assert r1 == r2


def test_compute_rid_different_user():
    """Different users → different RIDs."""
    assert _compute_rid("alice", 100) != _compute_rid("bob", 100)


def test_compute_rid_different_timestamp():
    """Same user, different V_i → different RIDs (unlinkability)."""
    assert _compute_rid("alice", 1000) != _compute_rid("alice", 2000)


def test_compute_rid_length():
    """RID is 32 hex characters."""
    rid = _compute_rid("user", 9999)
    assert len(rid) == 32
    assert all(c in "0123456789abcdef" for c in rid)


# ---------------------------------------------------------------------------
# generate_pseudonym
# ---------------------------------------------------------------------------

def test_generate_pseudonym_returns_rid(pm):
    result = pm.generate_pseudonym("alice")
    assert "RID" in result
    assert len(result["RID"]) == 32


def test_generate_pseudonym_sets_active(pm):
    result = pm.generate_pseudonym("alice")
    assert pm.is_valid(result["RID"])


def test_generate_pseudonym_different_timestamps_produce_different_rids(pm):
    """Two calls at different times produce different RIDs."""
    r1 = pm.generate_pseudonym("alice")
    with patch("time.time", return_value=time.time() + 1000):
        r2 = pm.generate_pseudonym("alice_other")
    assert r1["RID"] != r2["RID"]


def test_generate_pseudonym_deactivates_old_rid(pm):
    """Generating a new pseudonym deactivates the previous one."""
    r1 = pm.generate_pseudonym("bob")
    r2 = pm.generate_pseudonym("bob")
    assert not pm.is_valid(r1["RID"])
    assert pm.is_valid(r2["RID"])


# ---------------------------------------------------------------------------
# is_valid
# ---------------------------------------------------------------------------

def test_is_valid_returns_false_for_unknown_rid(pm):
    assert not pm.is_valid("nonexistent00000000000000000000")


def test_is_valid_returns_false_after_expiry(pm):
    """Pseudonym with validity_seconds=0 should expire immediately."""
    result = pm.generate_pseudonym("charlie", validity_seconds=1)
    with patch("time.time", return_value=time.time() + 10):
        assert not pm.is_valid(result["RID"])


# ---------------------------------------------------------------------------
# get_current_pseudonym
# ---------------------------------------------------------------------------

def test_get_current_pseudonym(pm):
    pm.generate_pseudonym("dave")
    rid = pm.get_current_pseudonym("dave")
    assert rid is not None
    assert len(rid) == 32


def test_get_current_pseudonym_returns_none_for_unknown(pm):
    assert pm.get_current_pseudonym("nobody") is None


def test_get_current_pseudonym_after_rotation(pm):
    """After rotation, returns new RID not old one."""
    r1 = pm.generate_pseudonym("eve")
    r2 = pm.rotate_pseudonym("eve")
    current = pm.get_current_pseudonym("eve")
    assert current == r2["RID"]
    assert current != r1["RID"]


# ---------------------------------------------------------------------------
# rotate_pseudonym
# ---------------------------------------------------------------------------

def test_rotate_pseudonym_old_becomes_invalid(pm):
    r1 = pm.generate_pseudonym("frank")
    pm.rotate_pseudonym("frank")
    assert not pm.is_valid(r1["RID"])


def test_rotate_pseudonym_new_is_valid(pm):
    pm.generate_pseudonym("grace")
    r2 = pm.rotate_pseudonym("grace")
    assert pm.is_valid(r2["RID"])


# ---------------------------------------------------------------------------
# revoke_pseudonym
# ---------------------------------------------------------------------------

def test_revoke_pseudonym_invalidates(pm):
    result = pm.generate_pseudonym("henry")
    rid = result["RID"]
    assert pm.is_valid(rid)
    pm.revoke_pseudonym(rid, "test revocation")
    assert not pm.is_valid(rid)


def test_revoke_nonexistent_returns_false(pm):
    assert not pm.revoke_pseudonym("00000000000000000000000000000000", "reason")


def test_revoke_adds_to_revocation_list(pm):
    result = pm.generate_pseudonym("ivan")
    rid = result["RID"]
    pm.revoke_pseudonym(rid, "legal order")
    rl = pm.get_revocation_list()
    rids = [r["RID"] for r in rl]
    assert rid in rids


# ---------------------------------------------------------------------------
# trace_identity
# ---------------------------------------------------------------------------

def test_trace_identity_returns_real_id(pm):
    pm.generate_pseudonym("judy")
    rid = pm.get_current_pseudonym("judy")
    real = pm.trace_identity(rid, "test-kgc-token")
    assert real == "judy"


def test_trace_identity_wrong_token_returns_none(pm):
    pm.generate_pseudonym("kate")
    rid = pm.get_current_pseudonym("kate")
    real = pm.trace_identity(rid, "wrong-token")
    assert real is None


def test_trace_identity_logs_event(pm):
    pm.generate_pseudonym("leo")
    rid = pm.get_current_pseudonym("leo")
    before = len(pm.get_trace_log())
    pm.trace_identity(rid, "test-kgc-token")
    after = len(pm.get_trace_log())
    assert after == before + 1


def test_trace_identity_failed_attempt_also_logged(pm):
    pm.generate_pseudonym("mia")
    rid = pm.get_current_pseudonym("mia")
    before = len(pm.get_trace_log())
    pm.trace_identity(rid, "bad-token")
    after = len(pm.get_trace_log())
    assert after == before + 1
    last = pm.get_trace_log()[-1]
    assert last["success"] is False
