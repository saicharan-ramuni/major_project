"""
EHR Signature Verification — Algorithm 7
==========================================
Executed by Blockchain Nodes (consensus servers).

Part A — Single EHR Signature Verification
Part B — Doctor Decryption  (in user.py: decrypt_ehr)
Part C — Batch Verification (for n EHR records simultaneously)
"""

import time
import secrets
from typing import Tuple, List

from .ecc_utils import (ECPoint, G, N, H1, H2, H3, multi_scalar_mul,
                        mul_G, mul_fixed, build_fixed_table)
from .params_store import load_params, get_user, is_revoked

# Module-level P_pub fixed-base table (built once when params are first loaded).
_ppub_table: list = []


def _ensure_ppub_table(Ppub: ECPoint) -> list:
    """Return the cached P_pub table, building it on first call."""
    global _ppub_table
    if not _ppub_table:
        _ppub_table = build_fixed_table(Ppub)
    return _ppub_table

MAX_TIMESTAMP_DELTA = 300   # ΔT = 5 minutes tolerance


# ---------------------------------------------------------------------------
# Part A — Single EHR Signature Verification
# ---------------------------------------------------------------------------

def verify_ehr(ehr_msg: dict) -> Tuple[bool, str]:
    """
    Algorithm 7 Part A — Blockchain node verifies one EHR signature.

    Verification equation:
      σ_i · G = gpk_i + h_{1,i} · P_pub + h_{2,i} · KID_{i,k} + h_{3,i} · upk_i

    Parameters
    ----------
    ehr_msg : dict — EHR message from patient (output of user.sign_ehr)
              Keys: sigma_i, ID_i, E_i, upk_i, gpk_i, KID_k, c_i, Q_k, T_i

    Returns
    -------
    (valid: bool, reason: str)
    """
    params = load_params()
    if params is None:
        return False, "System params not initialised."

    Ppub  = params["Ppub"]
    Ppub1 = params["Ppub1"]
    Ppub2 = params["Ppub2"]

    ID_i    = ehr_msg["ID_i"]
    E_i     = ECPoint.from_hex(ehr_msg["E_i"])
    upk_i   = ECPoint.from_hex(ehr_msg["upk_i"])
    gpk_i   = ECPoint.from_hex(ehr_msg["gpk_i"])
    KID_k   = ECPoint.from_hex(ehr_msg["KID_k"])
    Q_k     = ECPoint.from_hex(ehr_msg["Q_k"])
    c_i     = bytes.fromhex(ehr_msg["c_i"])
    T_i     = int(ehr_msg["T_i"])
    sigma_i = int(ehr_msg["sigma_i"])

    # Step 1: Timestamp freshness check
    T_cur = int(time.time())
    if abs(T_cur - T_i) > MAX_TIMESTAMP_DELTA:
        return False, f"Timestamp expired: |{T_cur} - {T_i}| > {MAX_TIMESTAMP_DELTA}s"

    # Check revocation
    if is_revoked(ID_i):
        return False, f"User {ID_i[:16]}... is REVOKED."

    # Step 2: Recompute h_{1,i}, h_{2,i}, h_{3,i}
    h1_i = H1(ID_i, gpk_i, upk_i, Ppub, E_i)
    h2_i = H2(ID_i, KID_k, Q_k, Ppub1)
    h3_i = H3(c_i, upk_i, gpk_i, Ppub2, T_i)

    # Step 3: Verify  σ_i · G == gpk_i + h_{1,i} · P_pub + h_{2,i} · KID_{i,k} + h_{3,i} · upk_i
    # LHS: fixed-base G table — 0 doublings + ≤128 mixed-adds + 1 inversion (~9.7× vs naive).
    # RHS: h1·P_pub via fixed-base table + 3-point Straus-Shamir for the rest.
    ppub_table = _ensure_ppub_table(Ppub)
    lhs = mul_G(sigma_i)
    ppub_term = mul_fixed(h1_i, ppub_table)
    rhs = gpk_i + ppub_term + multi_scalar_mul([(h2_i, KID_k), (h3_i, upk_i)])

    if lhs != rhs:
        return False, "Signature equation FAILED."

    return True, "EHR signature VALID."


# ---------------------------------------------------------------------------
# Part C — Batch Verification (n EHR records simultaneously)
# ---------------------------------------------------------------------------

def batch_verify_ehr(ehr_msgs: List[dict]) -> Tuple[bool, str]:
    """
    Algorithm 7 Part C — Batch verification of n EHR signatures.

    For n EHR messages, choose random λ_i ∈ [1, 2^t] and verify:
      (Σ λ_i · σ_i) · G = Σ λ_i · gpk_i
                         + (Σ λ_i · h_{1,i}) · P_pub
                         + Σ λ_i · h_{2,i} · KID_{i,k}
                         + Σ λ_i · h_{3,i} · upk_i

    This verifies all n signatures with only 4 EC multiplications (vs 4n).

    Parameters
    ----------
    ehr_msgs : list[dict]  — List of EHR messages to batch-verify

    Returns
    -------
    (valid: bool, reason: str)
    """
    if not ehr_msgs:
        return False, "Empty batch."

    params = load_params()
    Ppub   = params["Ppub"]
    Ppub1  = params["Ppub1"]
    Ppub2  = params["Ppub2"]

    T_BIT  = 80      # λ_i ∈ [1, 2^80]  (small exponent test)
    T_cur  = int(time.time())

    sum_lambda_sigma = 0   # Σ λ_i · σ_i  (scalar accumulator for LHS)
    sum_lam_h1       = 0   # Σ λ_i · h_{1,i}  (P_pub scalar — 1 mult total)
    rhs_points_accum = None  # running point sum for per-user Shamir results

    for msg in ehr_msgs:
        ID_i    = msg["ID_i"]
        E_i     = ECPoint.from_hex(msg["E_i"])
        upk_i   = ECPoint.from_hex(msg["upk_i"])
        gpk_i   = ECPoint.from_hex(msg["gpk_i"])
        KID_k   = ECPoint.from_hex(msg["KID_k"])
        Q_k     = ECPoint.from_hex(msg["Q_k"])
        c_i     = bytes.fromhex(msg["c_i"])
        T_i     = int(msg["T_i"])
        sigma_i = int(msg["sigma_i"])

        # Timestamp check
        if abs(T_cur - T_i) > MAX_TIMESTAMP_DELTA:
            return False, f"Batch: message timestamp expired (T_i={T_i})."

        if is_revoked(ID_i):
            return False, f"Batch: user {ID_i[:16]}... is REVOKED."

        # Random λ_i
        lam_i = secrets.randbelow(1 << T_BIT) + 1

        # Recompute hashes
        h1_i = H1(ID_i, gpk_i, upk_i, Ppub, E_i)
        h2_i = H2(ID_i, KID_k, Q_k, Ppub1)
        h3_i = H3(c_i, upk_i, gpk_i, Ppub2, T_i)

        # Accumulate scalar LHS
        sum_lambda_sigma = (sum_lambda_sigma + lam_i * sigma_i) % N

        # Accumulate P_pub scalar (one mult at the end, not per-user)
        sum_lam_h1 = (sum_lam_h1 + lam_i * h1_i) % N

        # Per-user 3-point Shamir: λ_i·gpk_i + (λ_i·h_{2,i})·KID_k + (λ_i·h_{3,i})·upk_i
        # ~0.4 effective mults per user vs 3 sequential mults previously.
        user_rhs = multi_scalar_mul([
            (lam_i % N,            gpk_i),
            ((lam_i * h2_i) % N,  KID_k),
            ((lam_i * h3_i) % N,  upk_i),
        ])
        rhs_points_accum = (user_rhs if rhs_points_accum is None
                            else rhs_points_accum + user_rhs)

    # LHS: (Σ λ_i · σ_i) · G — fixed-base G table (~9.7× faster than naive)
    lhs = mul_G(sum_lambda_sigma)

    # RHS: (Σ λ_i·h1_i)·P_pub — fixed-base P_pub table (~9.7× faster)
    #      + Σ per-user Shamir results
    from .ecc_utils import INF as _INF
    ppub_table = _ensure_ppub_table(Ppub)
    ppub_term = mul_fixed(sum_lam_h1, ppub_table)
    rhs = ppub_term + (rhs_points_accum if rhs_points_accum is not None else _INF)

    if lhs != rhs:
        return False, "Batch signature verification FAILED."

    return True, f"Batch of {len(ehr_msgs)} EHR signatures VALID."
