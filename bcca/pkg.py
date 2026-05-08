"""
Hospital Admin (HA) Algorithms
================================
Implements Algorithm 1 (Setup) and Algorithm 3 (Partial Private Key Extraction)
from healthcare_ehr_scheme.md.

HA is the trusted authority, analogous to PKG in the original BCCA paper.
"""

import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .ecc_utils import (ECPoint, G, N, P_FIELD, rand_scalar, modinv,
                         H1, H2, H3)
from .params_store import (save_params, save_ha_secret, load_params,
                            load_ha_secret, register_user)


# ---------------------------------------------------------------------------
# Algorithm 1: System Setup
# ---------------------------------------------------------------------------

def setup() -> dict:
    """
    Algorithm 1 — System Setup executed by Hospital Admin (HA).

    Steps (from healthcare_ehr_scheme.md):
      1. Select elliptic curve E, group G, generator P, order q.
      2. Choose master key s ∈ Z*_q.
      3. CLA-based public key splitting:
           P_x = x-coordinate(G) mod N
           G_cla = (s · P_x) mod N
           Prop  = (s ^ P_x) mod N        [XOR]
           s₁    = G_cla
           s₂    = (G_cla + Prop) mod N
      4. Compute:
           P_pub  = s  · G
           P_pub1 = s₁ · G
           P_pub2 = s₂ · G
      5. Doctor decrypt key pair: y ∈ Z*_q, dpk = y · G
      6. Publish params = {E, G, q, P_pub, P_pub1, P_pub2, dpk, H₁, H₂, H₃}

    Returns
    -------
    params : dict  — public system parameters (saved to params.json)
    """
    # Step 2: master key
    s = rand_scalar()

    # Step 3: CLA-based splitting
    P_x   = G.x % N                    # x-coordinate of generator mod q
    G_cla = (s * P_x) % N
    Prop  = (s ^ P_x) % N              # XOR
    s1    = G_cla
    s2    = (G_cla + Prop) % N

    # Step 4: system public keys
    Ppub  = s  * G
    Ppub1 = s1 * G
    Ppub2 = s2 * G

    # Step 5: doctor decryption key pair
    y   = rand_scalar()
    dpk = y * G

    # Build public params dict
    params = {
        "Ppub" : Ppub,
        "Ppub1": Ppub1,
        "Ppub2": Ppub2,
        "dpk"  : dpk,
        # Store s1, s2 as public knowledge? No — they're derivable from s.
        # We only publish the points, not the scalars.
    }

    # Persist
    save_params(params)
    save_ha_secret(s, y)

    print("[HA Setup] System parameters generated and saved.")
    return params


# ---------------------------------------------------------------------------
# Algorithm 3: Partial Private Key Extraction
# ---------------------------------------------------------------------------

def extract_partial_key(reg: dict) -> dict:
    """
    Algorithm 3 — Partial Private Key Extraction by HA.

    Input reg (from Algorithm 2 / patient or doctor registration):
      {
        'upk'   : ECPoint hex,   # upk_i = x_i · G
        'RID'   : str,           # real identity
        'UPW'   : int,           # H₁(RID_i, PW_i)
        'alpha' : int,           # H₁(DOB_i, SA_i, OtherDetails_i)
        'role'  : str,           # 'PATIENT' or 'DOCTOR'
      }

    Process:
      1. Choose d_i ∈ Z*_q, compute E_i = d_i · G, E*_i = s · E_i
      2. Pseudonym: ID_i = AES_Enc_{E*_{i,x}}(RID_i ‖ Role_i)
      3. Choose k_i ∈ Z*_q, compute gpk_i = k_i · G
         h_{1,i} = H₁(ID_i, gpk_i, upk_i, P_pub, E_i)
         psk_i   = (k_i + s · h_{1,i}) mod N
      4. Login credentials:
         A_i = psk_i · UPW_i  mod N
         B_i = H₁(alpha_i, UPW_i, psk_i)
      5. If DOCTOR: also provide y (decryption key)

    Returns partial key material sent to user.
    """
    s, y = load_ha_secret()
    if s is None:
        raise RuntimeError("HA not initialised. Run setup() first.")

    params = load_params()
    Ppub   = params["Ppub"]

    upk_hex = reg["upk"]
    RID     = reg["RID"]
    UPW     = int(reg["UPW"])
    alpha   = int(reg["alpha"])
    role    = reg["role"]       # 'PATIENT' or 'DOCTOR'
    upk     = ECPoint.from_hex(upk_hex)

    # Step 1
    d_i  = rand_scalar()
    E_i  = d_i * G
    E_st = s * E_i              # E*_i = s · E_i
    E_st_x = E_st.x % N

    # Step 2: pseudonym  ID_i = Enc_{E*_{i,x}}(RID_i ‖ Role_i)
    plaintext = f"{RID}|{role}".encode("utf-8")
    ID_i      = _aes_encrypt(E_st_x, plaintext)   # bytes → hex string

    # Step 3: partial private key
    k_i    = rand_scalar()
    gpk_i  = k_i * G
    h1_i   = H1(ID_i, gpk_i, upk, Ppub, E_i)
    psk_i  = (k_i + s * h1_i) % N

    # Step 4: login credentials
    A_i = (psk_i * UPW) % N
    B_i = H1(alpha, UPW, psk_i)

    result = {
        "ID_i"  : ID_i,          # pseudonym (hex-encoded ciphertext)
        "gpk_i" : gpk_i.to_hex(),
        "psk_i" : str(psk_i),
        "E_i"   : E_i.to_hex(),
        "d_i"   : str(d_i),      # needed for mutual auth: x_b + d_b computation
        "A_i"   : str(A_i),
        "B_i"   : str(B_i),
        "h1_i"  : str(h1_i),     # pre-computed for user convenience
        "role"  : role,
    }
    if role == "DOCTOR":
        result["y"] = str(y)     # doctor's EHR decryption key

    # Register user's public info on the blockchain / local store
    register_user(ID_i, {
        "pseudo_id": ID_i,
        "gpk"      : gpk_i.to_hex(),
        "upk"      : upk_hex,
        "E_i"      : E_i.to_hex(),
        "h1_i"     : str(h1_i),
        "role"     : role,
        "revoked"  : False,
    })

    print(f"[HA] Partial key extracted for {role}: pseudonym={ID_i[:16]}...")
    return result


# ---------------------------------------------------------------------------
# Identity tracing (conditional anonymity)
# ---------------------------------------------------------------------------

def trace_identity(ID_i: str, E_i_hex: str) -> dict:
    """
    HA decrypts pseudonym to reveal RID and Role.
    Called during revocation (Algorithm 9) or law-enforcement audit.

    E*_i = s · E_i;  decrypt ID_i using E*_{i,x} as AES key.
    """
    s, _ = load_ha_secret()
    if s is None:
        raise RuntimeError("HA not initialised.")

    E_i  = ECPoint.from_hex(E_i_hex)
    E_st = s * E_i
    E_st_x = E_st.x % N

    plaintext = _aes_decrypt(E_st_x, ID_i)
    parts = plaintext.decode("utf-8").split("|")
    if len(parts) != 2:
        raise ValueError("Invalid pseudonym decryption result.")
    return {"RID": parts[0], "role": parts[1]}


# ---------------------------------------------------------------------------
# AES helpers  (used for pseudonym encryption/decryption)
# ---------------------------------------------------------------------------

def _aes_encrypt(key_int: int, plaintext: bytes) -> str:
    """AES-256-GCM encrypt; returns hex string of nonce||ciphertext."""
    key = hashlib.sha256(key_int.to_bytes(32, "big")).digest()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return (nonce + ct).hex()


def _aes_decrypt(key_int: int, token_hex: str) -> bytes:
    """AES-256-GCM decrypt; token_hex is hex string of nonce||ciphertext."""
    raw   = bytes.fromhex(token_hex)
    nonce = raw[:12]
    ct    = raw[12:]
    key   = hashlib.sha256(key_int.to_bytes(32, "big")).digest()
    return AESGCM(key).decrypt(nonce, ct, None)
