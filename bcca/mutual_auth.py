"""
Mutual Patient–Doctor Authentication — Algorithm 8
====================================================
Before sharing sensitive EHR, patient and doctor authenticate each other
and establish a shared session key K_ab.

Key Insight:
  Patient P_a computes W_a = SID^a_k · (upk_b + gpk_b + h^b₁ · P_pub)
  Doctor  D_b verifies:  W'_a = (x_b + psk_b) · KID^a_k
  Correctness: (x_b + psk_b)·KID^a_k = SID^a_k·(x_b·G + psk_b·G)
                                      = SID^a_k·(upk_b + gpk_b + h^b₁·P_pub) = W_a ✓

Session key: K_ab = H₅(ID_a, ID_b, z_a · z_b · G)
Both sides compute the same K_ab via ECDH on ephemeral scalars z_a, z_b.
"""

import time
import json
from typing import Tuple

from .ecc_utils import (ECPoint, G, N, rand_scalar, H1, H2, H3,
                         H_auth, H5, sym_encrypt, sym_decrypt)
from .params_store import load_params, is_revoked

MAX_TIMESTAMP_DELTA = 300


# ---------------------------------------------------------------------------
# Step 1 — Patient P_a sends authentication request
# ---------------------------------------------------------------------------

def patient_auth_request(patient_keys: dict, doctor_pub: dict) -> dict:
    """
    Algorithm 8 Step 1 — Patient builds authentication request.

    Parameters
    ----------
    patient_keys : dict  — Patient's full key material
    doctor_pub   : dict  — Doctor's public registration info
                           {ID_b, upk_b, gpk_b, h1_b, E_b}

    Returns
    -------
    auth_req : dict — Sent to cloud server, forwarded to doctor
               {Z_a, C_a, sigma_a, KID_a_k, Time_a}
    ephemeral : dict — (z_a, Z_a) stored locally by patient for session key
    """
    params = load_params()
    Ppub   = params["Ppub"]
    Ppub1  = params["Ppub1"]
    Ppub2  = params["Ppub2"]

    ID_a   = patient_keys["ID_i"]
    upk_a  = ECPoint.from_hex(patient_keys["upk_i"])
    gpk_a  = ECPoint.from_hex(patient_keys["gpk_i"])
    psk_a  = int(patient_keys["psk_i"])
    x_a    = int(patient_keys["x_i"])
    E_a    = ECPoint.from_hex(patient_keys["E_i"])

    # Retrieve precomputed SID^a_k, KID^a_k
    k = patient_keys["SID_index"] % len(patient_keys["SID"])
    SID_a_k = int(patient_keys["SID"][k])
    KID_a_k = ECPoint.from_hex(patient_keys["KID"][k])
    patient_keys["SID_index"] = k + 1   # advance for forward secrecy

    # Doctor's public info
    upk_b  = ECPoint.from_hex(doctor_pub["upk"])
    gpk_b  = ECPoint.from_hex(doctor_pub["gpk"])
    h1_b   = int(doctor_pub["h1_i"])

    # Compute shared secret
    # W_a = SID^a_k · (upk_b + gpk_b + h^b₁ · P_pub)
    W_a = SID_a_k * (upk_b + gpk_b + h1_b * Ppub)
    k_a = H_auth(W_a)

    Time_a  = int(time.time())
    Role_a  = "PATIENT"

    # C_a = Enc(k_a, KID^a_k ‖ ID_a ‖ Role_a ‖ Time_a)
    payload = json.dumps({
        "KID_a_k": KID_a_k.to_hex(),
        "ID_a"   : ID_a,
        "Role_a" : Role_a,
        "Time_a" : Time_a,
    }).encode("utf-8")
    C_a = sym_encrypt(k_a, payload)

    # Compute auth signature
    h1_a = H1(ID_a, gpk_a, upk_a, Ppub, E_a)
    h2_a = H2(ID_a, KID_a_k, C_a, Ppub1)
    h3_a = H3(C_a, upk_a, gpk_a, Ppub2, Time_a)
    sigma_a = (psk_a + h2_a * SID_a_k + h3_a * x_a) % N

    # Ephemeral scalar for session key (ECDH)
    z_a = rand_scalar()
    Z_a = z_a * G

    auth_req = {
        "Z_a"    : Z_a.to_hex(),
        "C_a"    : C_a.hex(),
        "sigma_a": str(sigma_a),
        "KID_a_k": KID_a_k.to_hex(),
        "Time_a" : str(Time_a),
        "ID_a"   : ID_a,
        "E_a"    : E_a.to_hex(),
        "upk_a"  : upk_a.to_hex(),
        "gpk_a"  : gpk_a.to_hex(),
        "h1_a"   : str(h1_a),
    }
    ephemeral = {"z_a": str(z_a), "Z_a": Z_a.to_hex()}
    return auth_req, ephemeral


# ---------------------------------------------------------------------------
# Step 2 — Doctor D_b verifies patient & responds
# ---------------------------------------------------------------------------

def doctor_verify_and_respond(auth_req: dict, doctor_keys: dict,
                               patient_pub: dict) -> Tuple[dict, dict]:
    """
    Algorithm 8 Steps 2-3 — Doctor verifies patient's auth request and responds.

    Parameters
    ----------
    auth_req     : dict — From patient (output of patient_auth_request)
    doctor_keys  : dict — Doctor's full key material
    patient_pub  : dict — Patient's public registration info {ID_a, upk_a, gpk_a, h1_a}

    Returns
    -------
    auth_resp    : dict — Doctor's response (Z_b, C_b, sigma_b, KID_b_k, Time_b)
    ephemeral    : dict — (z_b, Z_b, W_a) stored by doctor for session key computation
    """
    params = load_params()
    Ppub   = params["Ppub"]
    Ppub1  = params["Ppub1"]
    Ppub2  = params["Ppub2"]

    # Unpack auth request
    Z_a     = ECPoint.from_hex(auth_req["Z_a"])
    C_a_hex = auth_req["C_a"]
    C_a     = bytes.fromhex(C_a_hex)
    sigma_a = int(auth_req["sigma_a"])
    KID_a_k = ECPoint.from_hex(auth_req["KID_a_k"])
    Time_a  = int(auth_req["Time_a"])
    ID_a    = auth_req["ID_a"]
    E_a     = ECPoint.from_hex(auth_req["E_a"])
    upk_a   = ECPoint.from_hex(auth_req["upk_a"])
    gpk_a   = ECPoint.from_hex(auth_req["gpk_a"])
    h1_a    = int(auth_req["h1_a"])

    # Doctor's own keys
    x_b   = int(doctor_keys["x_i"])
    psk_b = int(doctor_keys["psk_i"])
    ID_b  = doctor_keys["ID_i"]
    upk_b = ECPoint.from_hex(doctor_keys["upk_i"])
    gpk_b = ECPoint.from_hex(doctor_keys["gpk_i"])
    E_b   = ECPoint.from_hex(doctor_keys["E_i"])

    # Step 2.1: Timestamp check
    T_cur = int(time.time())
    if abs(T_cur - Time_a) > MAX_TIMESTAMP_DELTA:
        raise ValueError("Patient auth request timestamp expired.")

    # Step 2.2: Recover W'_a = (x_b + psk_b) · KID^a_k
    # psk_b acts as "d_b" in the formula: (x_b + d_b) · KID^a_k
    W_prime_a = (x_b + psk_b) * KID_a_k
    k_a_prime = H_auth(W_prime_a)

    # Step 2.3: Decrypt C_a
    try:
        payload = sym_decrypt(k_a_prime, C_a)
        p_data  = json.loads(payload.decode("utf-8"))
    except Exception:
        raise ValueError("C_a decryption FAILED — patient identity mismatch.")

    # Step 2.4: Verify Role_a == PATIENT
    if p_data.get("Role_a") != "PATIENT":
        raise ValueError("Access control: sender is not a PATIENT.")

    # Step 2.5: Verify patient's signature
    h2_a_check = H2(ID_a, KID_a_k, C_a, Ppub1)
    h3_a_check = H3(C_a, upk_a, gpk_a, Ppub2, Time_a)
    lhs = sigma_a * G
    rhs = gpk_a + h1_a * Ppub + h2_a_check * KID_a_k + h3_a_check * upk_a
    if lhs != rhs:
        raise ValueError("Patient signature verification FAILED.")

    print(f"[DOCTOR] Patient {ID_a[:16]}... authenticated ✓")

    # Step 2.6: Doctor builds response
    k_idx = doctor_keys["SID_index"] % len(doctor_keys["SID"])
    SID_b_k = int(doctor_keys["SID"][k_idx])
    KID_b_k = ECPoint.from_hex(doctor_keys["KID"][k_idx])
    doctor_keys["SID_index"] = k_idx + 1

    # W_b = SID^b_k · (upk_a + gpk_a + h^a₁ · P_pub)
    W_b = SID_b_k * (upk_a + gpk_a + h1_a * Ppub)
    k_b = H_auth(W_b)

    Time_b = int(time.time())
    payload_b = json.dumps({
        "KID_b_k": KID_b_k.to_hex(),
        "ID_b"   : ID_b,
        "Role_b" : "DOCTOR",
        "Time_b" : Time_b,
    }).encode("utf-8")
    C_b = sym_encrypt(k_b, payload_b)

    h1_b   = H1(ID_b, gpk_b, upk_b, Ppub, E_b)
    h2_b   = H2(ID_b, KID_b_k, C_b, Ppub1)
    h3_b   = H3(C_b, upk_b, gpk_b, Ppub2, Time_b)
    sigma_b = (psk_b + h2_b * SID_b_k + h3_b * x_b) % N

    z_b = rand_scalar()
    Z_b = z_b * G

    auth_resp = {
        "Z_b"    : Z_b.to_hex(),
        "C_b"    : C_b.hex(),
        "sigma_b": str(sigma_b),
        "KID_b_k": KID_b_k.to_hex(),
        "Time_b" : str(Time_b),
        "ID_b"   : ID_b,
        "E_b"    : E_b.to_hex(),
        "upk_b"  : upk_b.to_hex(),
        "gpk_b"  : gpk_b.to_hex(),
        "h1_b"   : str(h1_b),
    }
    ephemeral = {
        "z_b"   : str(z_b),
        "Z_b"   : Z_b.to_hex(),
        "Z_a"   : Z_a.to_hex(),
        "ID_a"  : ID_a,
        "ID_b"  : ID_b,
    }
    return auth_resp, ephemeral


# ---------------------------------------------------------------------------
# Step 3 — Patient verifies doctor & computes session key
# ---------------------------------------------------------------------------

def patient_verify_and_key(auth_resp: dict, patient_keys: dict,
                            doctor_pub: dict, ephemeral_a: dict) -> bytes:
    """
    Algorithm 8 Steps 3-4 — Patient verifies doctor's response and derives session key.

    Returns
    -------
    K_ab : bytes  — Shared session key (use with AES-256-GCM for EHR comms)
    """
    params = load_params()
    Ppub   = params["Ppub"]
    Ppub1  = params["Ppub1"]
    Ppub2  = params["Ppub2"]

    # Unpack
    Z_b     = ECPoint.from_hex(auth_resp["Z_b"])
    C_b     = bytes.fromhex(auth_resp["C_b"])
    sigma_b = int(auth_resp["sigma_b"])
    KID_b_k = ECPoint.from_hex(auth_resp["KID_b_k"])
    Time_b  = int(auth_resp["Time_b"])
    ID_b    = auth_resp["ID_b"]
    E_b     = ECPoint.from_hex(auth_resp["E_b"])
    upk_b   = ECPoint.from_hex(auth_resp["upk_b"])
    gpk_b   = ECPoint.from_hex(auth_resp["gpk_b"])
    h1_b    = int(auth_resp["h1_b"])

    x_a    = int(patient_keys["x_i"])
    psk_a  = int(patient_keys["psk_i"])
    ID_a   = patient_keys["ID_i"]
    z_a    = int(ephemeral_a["z_a"])

    # Timestamp check
    T_cur = int(time.time())
    if abs(T_cur - Time_b) > MAX_TIMESTAMP_DELTA:
        raise ValueError("Doctor auth response timestamp expired.")

    # Recover W'_b = (x_a + psk_a) · KID^b_k
    W_prime_b = (x_a + psk_a) * KID_b_k
    k_b_prime = H_auth(W_prime_b)

    # Decrypt C_b and verify Role_b == DOCTOR
    try:
        payload = sym_decrypt(k_b_prime, C_b)
        b_data  = json.loads(payload.decode("utf-8"))
    except Exception:
        raise ValueError("C_b decryption FAILED — doctor identity mismatch.")

    if b_data.get("Role_b") != "DOCTOR":
        raise ValueError("Access control: responder is not a DOCTOR.")

    # Verify doctor's signature
    h2_b_check = H2(ID_b, KID_b_k, C_b, Ppub1)
    h3_b_check = H3(C_b, upk_b, gpk_b, Ppub2, Time_b)
    lhs = sigma_b * G
    rhs = gpk_b + h1_b * Ppub + h2_b_check * KID_b_k + h3_b_check * upk_b
    if lhs != rhs:
        raise ValueError("Doctor signature verification FAILED.")

    print(f"[PATIENT] Doctor {ID_b[:16]}... authenticated ✓")

    # Step 4: Session key
    # K_a = z_a · Z_b = z_a · z_b · G
    K_a   = z_a * Z_b
    K_ab_scalar = H5(ID_a, ID_b, K_a)
    # Convert to 32-byte AES key
    K_ab = K_ab_scalar.to_bytes(32, "big")

    print(f"[PATIENT] Session key K_ab established with doctor {ID_b[:16]}...")
    return K_ab


def doctor_compute_session_key(ephemeral_b: dict, auth_req: dict) -> bytes:
    """
    Algorithm 8 Step 4 (Doctor side) — Doctor computes session key.

    K_b = z_b · Z_a  =>  K_ab = H₅(ID_a, ID_b, K_b)
    """
    z_b  = int(ephemeral_b["z_b"])
    Z_a  = ECPoint.from_hex(ephemeral_b["Z_a"])
    ID_a = ephemeral_b["ID_a"]
    ID_b = ephemeral_b["ID_b"]

    K_b   = z_b * Z_a
    K_ab_scalar = H5(ID_a, ID_b, K_b)
    K_ab = K_ab_scalar.to_bytes(32, "big")

    print(f"[DOCTOR] Session key K_ab established with patient {ID_a[:16]}...")
    return K_ab
