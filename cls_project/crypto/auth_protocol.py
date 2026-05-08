"""
Mutual Authentication Protocol — Qiao et al., IEEE IoT Journal, July 2025 (Section VI)

3-step challenge-response protocol between a patient (Ua) and doctor (Ub):

  Step 1  Ua → Ub:  (RID_a, T_a, W_a, sig_a)
  Step 2  Ub → Ua:  (RID_b, T_b, W_b, sig_b)   [after verifying sig_a]
  Step 3  Ua:       verify sig_b, derive K_ab

Both parties derive the same 256-bit session key K_ab via HKDF-SHA256.
K_ab is used for subsequent AES-256-GCM encrypted communication.

Replay protection: timestamps must be within TIMESTAMP_WINDOW_SEC of each other.
"""

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .cls_scheme import (
    CLSParams, sign, verify,
    _point_mul, _G, _N,
    serialize_point, deserialize_point,
    serialize_signature, deserialize_signature,
)

# Timestamps older than this are rejected (replay protection)
TIMESTAMP_WINDOW_SEC = 300  # 5 minutes


class AuthenticationError(Exception):
    """Raised when signature verification or timestamp check fails."""


# ---------------------------------------------------------------------------
# AuthSession — ephemeral state held by the initiating party
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    """
    Holds ephemeral state for one in-progress mutual authentication session.
    Stored server-side (in Flask session or DB) between steps 1 and 3.
    """
    w: int          = 0     # ephemeral secret scalar
    W_hex: str      = ""    # serialize_point(W)  — W = w·G
    T: int          = 0     # Unix timestamp of step-1 message
    RID_a: str      = ""    # initiator pseudonym
    RID_b: str      = ""    # responder pseudonym (filled after step 2)
    W_b_hex: str    = ""    # responder ephemeral point (filled after step 2)
    T_b: int        = 0     # responder timestamp (filled after step 2)
    session_key: Optional[bytes] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# MutualAuthProtocol
# ---------------------------------------------------------------------------

class MutualAuthProtocol:
    """
    Implements the 3-step CLS-based mutual authentication and key agreement
    described in Section VI of Qiao et al. (2025).
    """

    def __init__(self, params: CLSParams):
        self.params = params

    # -----------------------------------------------------------------------
    # Step 1 — Initiator (patient Ua) builds the first message
    # -----------------------------------------------------------------------

    def initiator_step1(self, SK: dict, RID_a: str, R_a) -> tuple:
        """
        Ua constructs and signs the first authentication message.

        Returns:
            msg1       (dict): JSON-serialisable message to send to Ub
            session    (AuthSession): local state to keep until step 3
        """
        w_a = secrets.randbelow(_N - 1) + 1
        W_a = _point_mul(w_a, _G)
        W_a_hex = serialize_point(W_a)
        T_a = int(time.time())

        message = f"{RID_a}|{T_a}|{W_a_hex}"
        sig_a = sign(self.params, SK, RID_a, message, R=R_a)

        session = AuthSession(
            w=w_a,
            W_hex=W_a_hex,
            T=T_a,
            RID_a=RID_a,
        )

        msg1 = {
            "RID_a": RID_a,
            "T_a": T_a,
            "W_a": W_a_hex,
            "sig_a": serialize_signature(sig_a),
        }
        return msg1, session

    # -----------------------------------------------------------------------
    # Step 2 — Responder (doctor Ub) verifies msg1 and builds the response
    # -----------------------------------------------------------------------

    def responder_step2(self, msg1: dict, pk_a: dict,
                        SK_b: dict, RID_b: str, R_b) -> tuple:
        """
        Ub verifies Ua's message and constructs the response.

        pk_a = {"PK": point, "R": point}  — Ua's public key record

        Returns:
            msg2       (dict): JSON-serialisable response to send to Ua
            session_b  (AuthSession): Ub's session state (holds K_ab)
        Raises:
            AuthenticationError: if sig_a is invalid or timestamp is stale
        """
        RID_a   = msg1["RID_a"]
        T_a     = int(msg1["T_a"])
        W_a_hex = msg1["W_a"]
        sig_a   = deserialize_signature(msg1["sig_a"])

        # Timestamp freshness check
        if abs(time.time() - T_a) > TIMESTAMP_WINDOW_SEC:
            raise AuthenticationError("Step-1 timestamp expired or too far in future")

        # Verify Ua's signature
        message_a = f"{RID_a}|{T_a}|{W_a_hex}"
        if not verify(self.params, RID_a, pk_a, message_a, sig_a):
            raise AuthenticationError("Invalid signature from initiator (Ua)")

        # Build Ub's response
        w_b = secrets.randbelow(_N - 1) + 1
        W_b = _point_mul(w_b, _G)
        W_b_hex = serialize_point(W_b)
        T_b = int(time.time())

        message_b = f"{RID_b}|{T_b}|{W_b_hex}"
        sig_b = sign(self.params, SK_b, RID_b, message_b, R=R_b)

        # Derive session key (Ub's side)
        K_ab = _derive_session_key(RID_a, RID_b, W_a_hex, W_b_hex, T_a, T_b)

        session_b = AuthSession(
            w=w_b,
            W_hex=W_b_hex,
            T=T_b,
            RID_a=RID_a,
            RID_b=RID_b,
            W_b_hex=W_b_hex,
            T_b=T_b,
            session_key=K_ab,
        )

        msg2 = {
            "RID_b": RID_b,
            "T_b": T_b,
            "W_b": W_b_hex,
            "sig_b": serialize_signature(sig_b),
        }
        return msg2, session_b

    # -----------------------------------------------------------------------
    # Step 3 — Initiator (Ua) verifies response and derives session key
    # -----------------------------------------------------------------------

    def initiator_step3(self, msg2: dict, pk_b: dict,
                        session: AuthSession) -> bytes:
        """
        Ua verifies Ub's response and derives the shared session key K_ab.

        pk_b    = {"PK": point, "R": point}  — Ub's public key record
        session = AuthSession returned from initiator_step1()

        Returns:
            K_ab (bytes): 32-byte session key  [same as Ub's K_ab]
        Raises:
            AuthenticationError: if sig_b is invalid or timestamp is stale
        """
        RID_b   = msg2["RID_b"]
        T_b     = int(msg2["T_b"])
        W_b_hex = msg2["W_b"]
        sig_b   = deserialize_signature(msg2["sig_b"])

        # Timestamp freshness check
        if abs(time.time() - T_b) > TIMESTAMP_WINDOW_SEC:
            raise AuthenticationError("Step-2 timestamp expired or too far in future")

        # Verify Ub's signature
        message_b = f"{RID_b}|{T_b}|{W_b_hex}"
        if not verify(self.params, RID_b, pk_b, message_b, sig_b):
            raise AuthenticationError("Invalid signature from responder (Ub)")

        # Derive session key (Ua's side — same inputs → same K_ab)
        K_ab = _derive_session_key(
            session.RID_a, RID_b,
            session.W_hex, W_b_hex,
            session.T, T_b,
        )

        # Store in session for convenience
        session.RID_b   = RID_b
        session.W_b_hex = W_b_hex
        session.T_b     = T_b
        session.session_key = K_ab

        return K_ab


# ---------------------------------------------------------------------------
# Session Key Derivation
# ---------------------------------------------------------------------------

def _derive_session_key(RID_a: str, RID_b: str,
                        W_a_hex: str, W_b_hex: str,
                        T_a: int, T_b: int) -> bytes:
    """
    K_ab = HKDF-SHA256(material, length=32, info="CLS_SessionKey")

    material = RID_a || "|" || RID_b || "|" || W_a_hex || "|" || W_b_hex
               || "|" || T_a || "|" || T_b

    Using HKDF rather than raw SHA-256 provides proper key stretching and
    domain separation as recommended in the paper's security analysis.
    """
    material = (
        f"{RID_a}|{RID_b}|{W_a_hex}|{W_b_hex}|{T_a}|{T_b}"
    ).encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CLS_SessionKey",
        backend=default_backend(),
    )
    return hkdf.derive(material)


# ---------------------------------------------------------------------------
# AES-256-GCM Session Encryption Helpers
# ---------------------------------------------------------------------------

def encrypt_with_session_key(key: bytes, plaintext: bytes) -> tuple:
    """
    Encrypt plaintext using AES-256-GCM with the derived session key.

    Returns: (ciphertext: bytes, nonce: bytes)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)           # 96-bit nonce (GCM standard)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_with_session_key(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM with the derived session key.

    Returns: plaintext bytes
    Raises: cryptography.exceptions.InvalidTag if authentication fails.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
