"""
EHR Access Revocation — Algorithms 9 & 10
===========================================
Executed by Hospital Admin (HA).

Algorithm 9: Revoke a malicious user (patient or doctor)
  - Reveal real identity via pseudonym decryption
  - Create a Chameleon Hash evidence entry on Evidence Chain
  - Publish revocation → all nodes reject future signatures from ID_i

Algorithm 10: Modify evidence on-chain
  - HA can correct false reports or add new evidence
  - Chameleon Hash ensures block hash remains unchanged
"""

import json
import time
from typing import Optional

from .ecc_utils import (ECPoint, G, N, rand_scalar, H1)
from .chameleon_hash import ch_setup, ch_hash, ch_verify, ch_forge, rand_j
from .params_store import (load_params, load_ha_secret, get_user, revoke_user,
                            add_evidence_entry, get_evidence_by_id,
                            update_evidence_entry)
from .pkg import trace_identity


# ---------------------------------------------------------------------------
# Algorithm 9: Revoke a User
# ---------------------------------------------------------------------------

def revoke_user_access(pseudo_id: str, evidence_text: str,
                        E_i_hex: str) -> dict:
    """
    Algorithm 9 — HA revokes a malicious user.

    Steps:
      1. Auditors report ID_i to HA with evidence Evid_i.
      2. HA decrypts pseudonym to get RID_i ‖ Role_i.
      3. HA creates Chameleon Hash evidence entry:
           theta_i ∈ Z*_q,  ck_i = H₁(s, theta_i),  HK_i = ck_i · G
           zeta_i ∈ Z*_q,   j_i ∈ Z*_q
           cred_i = {ID_i, RID_i, Role_i, Evid_i}
           CH_i = (zeta_i · ck_i + H₁(j_i, cred_i, HK_i)) · G
      4. Upload to Evidence Chain.
      5. Mark user as revoked.

    Parameters
    ----------
    pseudo_id     : str — Pseudonym ID_i (string/hex from on-chain registration)
    evidence_text : str — Human-readable evidence description
    E_i_hex       : str — User's E_i point (from registration record)

    Returns
    -------
    evidence_entry : dict — The evidence chain entry (uploaded to blockchain)
    """
    s, y = load_ha_secret()
    if s is None:
        raise RuntimeError("HA not initialised.")

    # Step 2: Reveal real identity
    identity = trace_identity(pseudo_id, E_i_hex)
    RID_i  = identity["RID"]
    Role_i = identity["role"]

    # Step 3: Build chameleon hash evidence entry
    theta_i, ck_i, HK_i = ch_setup(s)
    j_i   = rand_j()
    zeta_i = rand_scalar()

    cred_i = json.dumps({
        "ID_i"      : pseudo_id,
        "RID_i"     : RID_i,
        "Role_i"    : Role_i,
        "evidence"  : evidence_text,
        "timestamp" : int(time.time()),
    })

    CH_i, zeta_confirmed = ch_hash(ck_i, HK_i, j_i, cred_i, zeta_i)

    # Evidence entry stored on-chain (public)
    evidence_entry = {
        "pseudo_id" : pseudo_id,
        "HK_i"      : HK_i.to_hex(),    # public hash key
        "CH_i"      : CH_i.to_hex(),    # chameleon hash value (EC point)
        "j_i"       : str(j_i),
        "cred_i"    : cred_i,
        "revoked"   : True,
        "timestamp" : int(time.time()),
    }

    # HA's private record (contains trapdoor — NOT on-chain)
    ha_private = {
        "pseudo_id" : pseudo_id,
        "theta_i"   : str(theta_i),
        "ck_i"      : str(ck_i),
        "zeta_i"    : str(zeta_confirmed),
        "j_i"       : str(j_i),
    }

    # Step 4 & 5: Store and revoke
    add_evidence_entry(evidence_entry)
    revoke_user(pseudo_id)

    # Save HA private trapdoor data (in production: encrypted secure DB)
    _save_ha_private_evid(pseudo_id, ha_private)

    print(f"[HA] User {pseudo_id[:16]}... REVOKED. Evidence uploaded to Evidence Chain.")
    return evidence_entry


# ---------------------------------------------------------------------------
# Algorithm 10: Modify Evidence On-Chain
# ---------------------------------------------------------------------------

def modify_evidence(pseudo_id: str, new_evidence_text: str) -> dict:
    """
    Algorithm 10 — HA modifies evidence on Evidence Chain.

    The Chameleon Hash CH_i remains UNCHANGED (block hash preserved),
    while the content cred_i is updated.

    Steps:
      1. Retrieve theta_i, ck_i, zeta_i, j_i from HA private DB.
      2. Build updated credentials cred'_i.
      3. Compute new randomness:
           zeta'_i = ck_i⁻¹ · (H₁(j_i, cred_i, HK_i) − H₁(j_i, cred'_i, HK_i)) + zeta_i  mod N
      4. Verify CH(zeta'_i, cred'_i) == CH(zeta_i, cred_i).
      5. Update evidence entry on-chain.

    Parameters
    ----------
    pseudo_id         : str — User's pseudonym ID
    new_evidence_text : str — Updated evidence description

    Returns
    -------
    updated_entry : dict — Updated evidence chain entry
    """
    # Load HA private trapdoor
    ha_priv = _load_ha_private_evid(pseudo_id)
    if ha_priv is None:
        raise ValueError(f"No HA private trapdoor found for {pseudo_id[:16]}...")

    ck_i    = int(ha_priv["ck_i"])
    zeta_i  = int(ha_priv["zeta_i"])
    j_i     = int(ha_priv["j_i"])

    # Load current evidence entry
    old_entry = get_evidence_by_id(pseudo_id)
    if old_entry is None:
        raise ValueError(f"Evidence entry not found for {pseudo_id[:16]}...")

    HK_i   = ECPoint.from_hex(old_entry["HK_i"])
    CH_old = ECPoint.from_hex(old_entry["CH_i"])
    cred_old = old_entry["cred_i"]

    # Parse old cred
    cred_data = json.loads(cred_old)
    cred_data["evidence"]  = new_evidence_text
    cred_data["timestamp"] = int(time.time())
    cred_new = json.dumps(cred_data)

    # Step 3: Compute new zeta
    zeta_new = ch_forge(ck_i, HK_i, j_i, cred_old, zeta_i, cred_new)

    # Step 4: Verify collision (block hash unchanged)
    CH_new, _ = ch_hash(ck_i, HK_i, j_i, cred_new, zeta_new)
    assert CH_new == CH_old, "Chameleon hash collision computation FAILED!"

    # Step 5: Update on-chain entry
    updated_entry = dict(old_entry)
    updated_entry["cred_i"] = cred_new   # updated content, same CH_i

    update_evidence_entry(pseudo_id, updated_entry)

    # Update HA private record with new zeta
    ha_priv["zeta_i"] = str(zeta_new)
    _save_ha_private_evid(pseudo_id, ha_priv)

    print(f"[HA] Evidence for {pseudo_id[:16]}... updated. Block hash UNCHANGED ✓")
    return updated_entry


# ---------------------------------------------------------------------------
# HA private trapdoor storage (in production: HSM / encrypted secure DB)
# ---------------------------------------------------------------------------

import os

_HA_EVID_DIR = os.path.join(os.path.dirname(__file__), "..", "bcca_data", "ha_evid")


def _save_ha_private_evid(pseudo_id: str, data: dict):
    os.makedirs(_HA_EVID_DIR, exist_ok=True)
    safe_name = pseudo_id[:32].replace("/", "_").replace("\\", "_")
    path = os.path.join(_HA_EVID_DIR, f"{safe_name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _load_ha_private_evid(pseudo_id: str) -> Optional[dict]:
    safe_name = pseudo_id[:32].replace("/", "_").replace("\\", "_")
    path = os.path.join(_HA_EVID_DIR, f"{safe_name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)
