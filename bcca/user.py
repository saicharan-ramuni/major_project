"""
Patient / Doctor Algorithms
==============================
Implements Algorithms 2, 4, 5, 6 from healthcare_ehr_scheme.md.

Algorithm 2 — Registration  (patient or doctor)
Algorithm 4 — Key Generation (with full precomputation)
Algorithm 5 — Login (multi-factor, no biometric hardware needed)
Algorithm 6 — EHR Upload: Sign & Encrypt (ZERO EC multiplications for device)
"""

import os
import json
import secrets
import hashlib
import time

from .ecc_utils import (ECPoint, G, N, rand_scalar, modinv,
                         H1, H2, H3, xor_encrypt, xor_decrypt, mul_G)
from .params_store import load_params


# ---------------------------------------------------------------------------
# Algorithm 2: Patient / Doctor Registration
# ---------------------------------------------------------------------------

def register(rid: str, password: str, dob: str, security_answer: str,
             other_details: str, role: str) -> dict:
    """
    Algorithm 2 — Registration (Patient P_a or Doctor D_b).

    Parameters
    ----------
    rid             : str  — Real Identity (Aadhaar/SSN for patient; Medical License ID for doctor)
    password        : str  — User's password PW_i
    dob             : str  — Date of birth (DD/MM/YYYY)
    security_answer : str  — Security answer SA_i
    other_details   : str  — Blood group (patient) or medical reg. no (doctor)
    role            : str  — 'PATIENT' or 'DOCTOR'

    Returns
    -------
    reg : dict  — Registration packet to send to HA
    Also returns private material that must be stored on the user's device.
    """
    role = role.upper()
    assert role in ("PATIENT", "DOCTOR"), "role must be PATIENT or DOCTOR"

    # Step 1: secret key x_i, public key upk_i = x_i · G
    x_i   = rand_scalar()
    upk_i = x_i * G

    # Step 2: UPW_i = H₁(RID_i, PW_i)
    UPW_i = H1(rid, password)

    # Step 3-4: Deterministic BIO factor (replaces fuzzy extractor)
    #   alpha_i = H₁(DOB_i, SA_i, OtherDetails_i)
    alpha_i = H1(dob, security_answer, other_details)

    # Registration packet (sent to HA via secure channel)
    reg = {
        "upk"  : upk_i.to_hex(),
        "RID"  : rid,
        "UPW"  : str(UPW_i),
        "alpha": str(alpha_i),
        "role" : role,
    }

    # Local device material (kept on device, NOT sent to HA)
    local = {
        "x_i"   : str(x_i),
        "upk_i" : upk_i.to_hex(),
        "UPW_i" : str(UPW_i),
        "alpha_i": str(alpha_i),
        "role"  : role,
        "rid"   : rid,      # stored locally for login reconstruction
    }

    return reg, local


# ---------------------------------------------------------------------------
# Algorithm 4: Key Generation (full precomputation)
# ---------------------------------------------------------------------------

PRECOMPUTE_N = 100  # number of precomputed (SID, KID) and (Q, ek) pairs


def generate_keys(partial_material: dict, local: dict, n: int = PRECOMPUTE_N) -> dict:
    """
    Algorithm 4 — Full Key Generation by Patient or Doctor.

    Parameters
    ----------
    partial_material : dict  — Output from HA's extract_partial_key()
                               Contains: ID_i, gpk_i, psk_i, E_i, A_i, B_i, h1_i, role
    local            : dict  — Local device material from register()
                               Contains: x_i, upk_i, UPW_i, alpha_i
    n                : int   — Number of precomputed pairs

    Returns
    -------
    full_key : dict  — Complete key material stored on device
    """
    params = load_params()
    if params is None:
        raise RuntimeError("System params not initialised. HA must run setup() first.")

    Ppub  = params["Ppub"]

    # Unpack
    psk_i  = int(partial_material["psk_i"])
    gpk_i  = ECPoint.from_hex(partial_material["gpk_i"])
    upk_i  = ECPoint.from_hex(local["upk_i"])
    x_i    = int(local["x_i"])
    h1_i   = int(partial_material["h1_i"])
    ID_i   = partial_material["ID_i"]
    E_i    = ECPoint.from_hex(partial_material["E_i"])
    A_i    = int(partial_material["A_i"])
    B_i    = int(partial_material["B_i"])
    role   = partial_material["role"]
    UPW_i  = int(local["UPW_i"])
    alpha_i= int(local["alpha_i"])
    rid    = local["rid"]

    # Step 4.1 — Verify partial key
    # psk_i · G == gpk_i + h_{1,i} · P_pub
    lhs = psk_i * G
    rhs = gpk_i + h1_i * Ppub
    assert lhs == rhs, ("Partial key verification FAILED. "
                        "HA may have sent incorrect key material.")

    # Step 4.2 — Precompute SID / KID sets
    # SID_{i,j} = (v_{i,j} · x_i + H₁(RID_i, alpha_i)) mod N
    # KID_{i,j} = SID_{i,j} · G
    base_h = H1(rid, alpha_i)
    SID_set = []
    KID_set = []
    for _ in range(n):
        v_j    = rand_scalar()
        sid_j  = (v_j * x_i + base_h) % N
        kid_j  = mul_G(sid_j)          # fixed-base G table: ~8× faster than sid_j * G
        SID_set.append(str(sid_j))
        KID_set.append(kid_j.to_hex())

    # Step 4.3 — Precompute Encryption set (primarily for patients uploading EHR)
    Q_set  = []
    ek_set = []
    dpk    = params["dpk"]   # doctor's public decrypt key
    for _ in range(n):
        q_j   = rand_scalar()
        Q_j   = mul_G(q_j)             # fixed-base G table: ~8× faster than q_j * G
        ek_j  = H1(q_j * dpk)    # H₁(q_{i,j} · dpk) — encryption key scalar
        Q_set.append(Q_j.to_hex())
        ek_set.append(str(ek_j))

    full_key = {
        "ID_i"  : ID_i,
        "gpk_i" : gpk_i.to_hex(),
        "upk_i" : upk_i.to_hex(),
        "x_i"   : str(x_i),
        "psk_i" : str(psk_i),
        "h1_i"  : str(h1_i),
        "E_i"   : E_i.to_hex(),
        "A_i"   : str(A_i),
        "B_i"   : str(B_i),
        "UPW_i" : str(UPW_i),
        "alpha_i": str(alpha_i),
        "role"  : role,
        "rid"   : rid,
        "SID"   : SID_set,         # list of N precomputed scalars (SECRET)
        "KID"   : KID_set,         # list of N precomputed points (PUBLIC)
        "Q"     : Q_set,           # list of N encryption commitment points
        "ek"    : ek_set,          # list of N encryption key scalars (SECRET)
        "SID_index": 0,            # tracks which SID/KID pair to use next
        "Q_index"  : 0,
    }

    # If DOCTOR: store y (decryption key)
    if role == "DOCTOR" and "y" in partial_material:
        full_key["y"] = partial_material["y"]

    print(f"[{role}] Key generation complete. {n} precomputed pairs ready.")
    return full_key


# ---------------------------------------------------------------------------
# Algorithm 5: Login (Multi-Factor Authentication)
# ---------------------------------------------------------------------------

def login(stored_keys: dict, rid: str, password: str,
          dob: str, security_answer: str, other_details: str) -> bool:
    """
    Algorithm 5 — Multi-factor Login on patient's wearable or doctor's workstation.

    Factors:
      - Something you know : password, DOB, security answer
      - Something you have : device storing A_i, B_i

    Steps:
      1. Recompute alpha_i = H₁(DOB_i, SA_i, OD_i)
      2. Recompute UPW_i   = H₁(RID_i, PW_i)
      3. Recover  psk_i    = A_i · UPW_i⁻¹  mod N
      4. Check    B_i      = H₁(alpha_i, UPW_i, psk_i)

    Parameters
    ----------
    stored_keys : dict  — Full key material on device (from generate_keys())
    rid, password, dob, security_answer, other_details : str — user inputs

    Returns
    -------
    True if login succeeds, False otherwise.
    """
    # Step 1-2
    alpha_i = H1(dob, security_answer, other_details)
    UPW_i   = H1(rid, password)

    # Step 3: recover psk_i
    A_i     = int(stored_keys["A_i"])
    UPW_inv = modinv(UPW_i, N)
    psk_i   = (A_i * UPW_inv) % N

    # Step 4: verify B_i
    B_stored = int(stored_keys["B_i"])
    B_check  = H1(alpha_i, UPW_i, psk_i)

    if B_check != B_stored:
        print("[Login] FAILED — invalid credentials.")
        return False

    print(f"[{stored_keys['role']}] Login SUCCESSFUL for pseudonym {stored_keys['ID_i'][:16]}...")
    return True


# ---------------------------------------------------------------------------
# Algorithm 6: EHR Upload — Sign & Encrypt
# ---------------------------------------------------------------------------

def sign_ehr(ehr_data: bytes, stored_keys: dict) -> dict:
    """
    Algorithm 6 — Patient P_a signs and encrypts EHR for upload.

    EHR data m_i: vital signs, lab reports, imaging refs, etc.
    ZERO EC scalar multiplications on patient device (all precomputed).

    Steps:
      1. Retrieve k-th precomputed SID_{i,k}, KID_{i,k}, Q_{i,k}, ek_{i,k}
      2. Encrypt: c_i = m_i ⊕ ek_{i,k}   (XOR with precomputed key)
      3. h_{2,i} = H₂(ID_i, KID_{i,k}, Q_{i,k}, P_pub1)
         h_{3,i} = H₃(c_i, pk_i, P_pub2, T_i)
      4. σ_i = psk_i + h_{2,i} · SID_{i,k} + h_{3,i} · x_i   (scalar only)
      5. Output EHR_Msg_i = {σ_i, ID_i, E_i, pk_i, KID_{i,k}, c_i, Q_{i,k}, T_i}

    Parameters
    ----------
    ehr_data    : bytes  — Raw EHR (vital signs, reports, etc.)
    stored_keys : dict   — Full key material from generate_keys()

    Returns
    -------
    EHR_Msg : dict — Signed and encrypted EHR message for blockchain upload
    """
    params = load_params()
    Ppub1  = params["Ppub1"]
    Ppub2  = params["Ppub2"]

    # Step 1: retrieve precomputed values
    k = stored_keys["SID_index"] % PRECOMPUTE_N
    q = stored_keys["Q_index"]   % PRECOMPUTE_N

    SID_k = int(stored_keys["SID"][k])
    KID_k = ECPoint.from_hex(stored_keys["KID"][k])
    Q_k   = ECPoint.from_hex(stored_keys["Q"][q])
    ek_k  = int(stored_keys["ek"][q])

    psk_i = int(stored_keys["psk_i"])
    x_i   = int(stored_keys["x_i"])
    ID_i  = stored_keys["ID_i"]
    upk_i = ECPoint.from_hex(stored_keys["upk_i"])
    gpk_i = ECPoint.from_hex(stored_keys["gpk_i"])
    E_i   = ECPoint.from_hex(stored_keys["E_i"])

    # Step 2: encrypt EHR  c_i = m_i ⊕ ek_{i,k}
    c_i = xor_encrypt(ehr_data, ek_k)

    # Step 3: compute hashes
    T_i   = int(time.time())
    pk_i  = (upk_i, gpk_i)        # pk_i = {upk_i, gpk_i}

    h2_i  = H2(ID_i, KID_k, Q_k, Ppub1)
    h3_i  = H3(c_i, upk_i, gpk_i, Ppub2, T_i)

    # Step 4: signature scalar   — NO EC multiplication on patient device!
    sigma_i = (psk_i + h2_i * SID_k + h3_i * x_i) % N

    # Advance index for forward secrecy
    stored_keys["SID_index"] = k + 1
    stored_keys["Q_index"]   = q + 1

    ehr_msg = {
        "sigma_i": str(sigma_i),
        "ID_i"   : ID_i,
        "E_i"    : E_i.to_hex(),
        "upk_i"  : upk_i.to_hex(),
        "gpk_i"  : gpk_i.to_hex(),
        "KID_k"  : KID_k.to_hex(),
        "c_i"    : c_i.hex(),        # ciphertext as hex
        "Q_k"    : Q_k.to_hex(),
        "T_i"    : str(T_i),
        "h1_i"   : stored_keys["h1_i"],
        "h2_i"   : str(h2_i),
        "h3_i"   : str(h3_i),
    }

    print(f"[PATIENT] EHR signed. sigma_i={sigma_i}, T_i={T_i}")
    return ehr_msg


# ---------------------------------------------------------------------------
# Doctor EHR Decryption (Algorithm 7 Part B)
# ---------------------------------------------------------------------------

def decrypt_ehr(c_i_hex: str, Q_k_hex: str, stored_keys: dict) -> bytes:
    """
    Doctor D_b decrypts EHR ciphertext.

    m_i = c_i ⊕ H₁(y · Q_{i,k})

    Parameters
    ----------
    c_i_hex   : str  — Hex-encoded ciphertext from EHR message
    Q_k_hex   : str  — Hex-encoded Q_{i,k} from EHR message
    stored_keys : dict  — Doctor's full key material (contains y)

    Returns
    -------
    plaintext : bytes — Decrypted EHR data
    """
    if "y" not in stored_keys:
        raise PermissionError("Only authorised doctors with decryption key y can decrypt EHR.")

    y   = int(stored_keys["y"])
    Q_k = ECPoint.from_hex(Q_k_hex)
    c_i = bytes.fromhex(c_i_hex)

    # Decryption key: H₁(y · Q_{i,k})
    dec_key = H1(y * Q_k)
    m_i     = xor_decrypt(c_i, dec_key)

    print("[DOCTOR] EHR decrypted successfully.")
    return m_i
