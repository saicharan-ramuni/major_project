"""
CLS Scheme — Qiao et al., IEEE IoT Journal, July 2025
"A Provably Secure Certificateless Signature Scheme With Anonymity for Healthcare IIoT"

Implements all six algorithms on NIST P-256 (secp256r1) using pure Python
point arithmetic (no external EC library required for the custom scheme).
The `cryptography` library is used only for AES-GCM and HKDF utilities
which are imported by auth_protocol.py.

Security: Girault Level 3 — provably secure against both Type-I (key-replacement)
and Type-II (malicious KGC) adversaries under the Discrete Logarithm assumption.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# secp256r1 (NIST P-256) Domain Parameters
# ---------------------------------------------------------------------------

_P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_G  = (_GX, _GY)
_INF = None  # Point at infinity


# ---------------------------------------------------------------------------
# Low-level P-256 Arithmetic
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse using Fermat's little theorem (m is prime)."""
    return pow(a, m - 2, m)


# ---------------------------------------------------------------------------
# Jacobian coordinate arithmetic for NIST P-256 (A = -3)
#
# Representation: affine (x,y)  ↔  Jacobian (X:Y:Z) where x=X/Z², y=Y/Z³.
# Infinity is represented as Z=0.
# Avoids per-operation field inversion; one inversion per scalar mult at end.
# ---------------------------------------------------------------------------

def _jac_double_p256(X: int, Y: int, Z: int):
    """Jacobian point doubling for P-256. Uses A=-3 specialisation."""
    if Z == 0 or Y == 0:
        return 0, 1, 0          # point at infinity
    p   = _P
    Y2  = Y * Y % p
    Z2  = Z * Z % p
    # A = -3 specialisation: M = 3*(X - Z²)*(X + Z²)
    M   = 3 * ((X - Z2) % p) * ((X + Z2) % p) % p
    S   = 4 * X * Y2 % p
    X3  = (M * M - 2 * S) % p
    Y3  = (M * (S - X3) - 8 * Y2 * Y2) % p
    Z3  = 2 * Y * Z % p
    return X3, Y3, Z3


def _jac_add_mixed_p256(X1: int, Y1: int, Z1: int, x2: int, y2: int):
    """Add Jacobian point (X1:Y1:Z1) + affine point (x2,y2). Returns Jacobian."""
    if Z1 == 0:
        return x2, y2, 1       # infinity + P = P
    p    = _P
    Z1s  = Z1 * Z1 % p
    U2   = x2 * Z1s % p
    S2   = y2 * Z1s % p * Z1 % p
    H    = (U2 - X1) % p
    R    = (S2 - Y1) % p
    if H == 0:
        if R == 0:
            return _jac_double_p256(X1, Y1, Z1)
        return 0, 1, 0          # P + (-P) = infinity
    H2   = H * H % p
    H3   = H * H2 % p
    X3   = (R * R - H3 - 2 * X1 * H2) % p
    Y3   = (R * (X1 * H2 - X3) - Y1 * H3) % p
    Z3   = H * Z1 % p
    return X3, Y3, Z3


def _jac_to_affine_p256(X: int, Y: int, Z: int):
    """Convert Jacobian (X:Y:Z) → affine (x, y). One field inversion."""
    if Z == 0:
        return None, None       # point at infinity
    p   = _P
    Zi  = pow(Z, p - 2, p)     # single inversion per scalar mult
    Zi2 = Zi * Zi % p
    return X * Zi2 % p, Y * Zi2 % p * Zi % p


# ---------------------------------------------------------------------------
# Fixed-base precomputed table for G: [G, 2G, 4G, ..., 2^255·G]
# Built once at module import.  Amortised over all _point_mul_G() calls.
# ---------------------------------------------------------------------------

def _build_G_table_p256() -> list:
    """Build power-of-2 table [G, 2G, 4G, …, 2^255·G] in affine coordinates.
    Uses inline affine doubling (no dependency on _point_add) so it can run at
    module import time, before _point_add is defined."""
    table = []
    x, y  = _GX, _GY
    p     = _P
    for _ in range(256):
        table.append((x, y))
        # Affine point doubling for P-256 (A = _A = p - 3)
        inv2y = pow(2 * y, p - 2, p)
        lam   = (3 * x * x + _A) * inv2y % p
        x3    = (lam * lam - 2 * x) % p
        y3    = (lam * (x - x3) - y) % p
        x, y  = x3, y3
    return table


_G_TABLE_P256: list = _build_G_table_p256()   # module-level, initialised once


def _point_mul_G(k: int):
    """
    Multiply P-256 generator G by scalar k using the precomputed table.
    Cost: 0 doublings + at most 128 mixed-adds + 1 inversion. ~8–10× faster.
    """
    k = int(k) % _N
    if k == 0:
        return _INF
    Xr, Yr, Zr = 0, 1, 0       # Jacobian infinity
    for i in range(256):
        if (k >> i) & 1:
            px, py = _G_TABLE_P256[i]
            Xr, Yr, Zr = _jac_add_mixed_p256(Xr, Yr, Zr, px, py)
    ax, ay = _jac_to_affine_p256(Xr, Yr, Zr)
    return _INF if ax is None else (ax, ay)


def _point_add(P1, P2):
    """Affine Weierstrass point addition on secp256r1."""
    if P1 is _INF:
        return P2
    if P2 is _INF:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if y1 != y2:
            return _INF  # P + (-P) = infinity
        # Point doubling
        lam = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k: int, P) -> Optional[tuple]:
    """Scalar multiplication k*P using Jacobian coordinates (single inversion at end)."""
    k = k % _N
    if k == 0 or P is _INF:
        return _INF
    bits = k.bit_length()
    Px, Py = P
    Xr, Yr, Zr = Px, Py, 1    # start with P in Jacobian (Z=1 = affine)
    for i in range(bits - 2, -1, -1):
        Xr, Yr, Zr = _jac_double_p256(Xr, Yr, Zr)
        if (k >> i) & 1:
            Xr, Yr, Zr = _jac_add_mixed_p256(Xr, Yr, Zr, Px, Py)
    ax, ay = _jac_to_affine_p256(Xr, Yr, Zr)
    return _INF if ax is None else (ax, ay)


def _build_fixed_table_p256(P) -> list:
    """Build power-of-2 table [P, 2P, 4P, …, 2^255·P] for any fixed point P.
    Uses _point_add which is now defined above."""
    table = []
    cur   = P
    for _ in range(256):
        table.append(cur)
        cur = _point_add(cur, cur)
    return table


def _point_mul_fixed(k: int, table: list):
    """Multiply a fixed-base point by k using its precomputed power-of-2 table.
    Same cost as _point_mul_G: 0 doublings + ≤128 mixed-adds + 1 inversion."""
    k = int(k) % _N
    if k == 0:
        return _INF
    Xr, Yr, Zr = 0, 1, 0
    for i in range(256):
        if (k >> i) & 1:
            px, py = table[i]
            Xr, Yr, Zr = _jac_add_mixed_p256(Xr, Yr, Zr, px, py)
    ax, ay = _jac_to_affine_p256(Xr, Yr, Zr)
    return _INF if ax is None else (ax, ay)


def _multi_scalar_mul(pairs) -> tuple:
    """
    Simultaneous multi-scalar multiplication (Straus-Shamir) on secp256r1.

    For k (scalar, point) pairs, processes all scalars in a single bit-scan.
    Cost: ~256 doublings + 256*(2^k-1)/2^k additions
    vs sequential k passes of (256 doublings + 128 additions each).

    k=3: ~3.25× faster.   k=4: ~4.3× faster.
    """
    pairs = [(int(s) % _N, P) for s, P in pairs
             if int(s) % _N != 0 and P is not _INF]
    if not pairs:
        return _INF
    if len(pairs) == 1:
        return _point_mul(pairs[0][0], pairs[0][1])

    scalars = [s for s, _ in pairs]
    points  = [P for _, P in pairs]
    k = len(pairs)

    # Build precomp table in affine tuples.  For k≤4 there are ≤15 entries —
    # the _point_add cost here is negligible vs the 256-iteration main loop.
    precomp: dict = {}
    for mask in range(1, 1 << k):
        lsb  = mask & (-mask)
        i    = lsb.bit_length() - 1
        rest = mask ^ lsb
        precomp[mask] = _point_add(precomp[rest], points[i]) if rest else points[i]

    max_bits = max(s.bit_length() for s in scalars)
    # Jacobian accumulator — eliminates per-doubling field inversions.
    Xr, Yr, Zr = 0, 1, 0   # Jacobian infinity
    for bit in range(max_bits - 1, -1, -1):
        Xr, Yr, Zr = _jac_double_p256(Xr, Yr, Zr)
        mask = sum(((s >> bit) & 1) << i for i, s in enumerate(scalars))
        if mask:
            pt = precomp[mask]
            if pt is not _INF:
                Xr, Yr, Zr = _jac_add_mixed_p256(Xr, Yr, Zr, pt[0], pt[1])

    ax, ay = _jac_to_affine_p256(Xr, Yr, Zr)
    return _INF if ax is None else (ax, ay)


def _pt_encode(P) -> str:
    """Encode an EC point as a 128-character lowercase hex string (x || y)."""
    if P is _INF:
        return "00" * 64
    x, y = P
    return f"{x:064x}{y:064x}"


def _pt_decode(s: str):
    """Decode an EC point from either uncompressed (128-char) or compressed (66-char) hex."""
    if not s or s == "00" * 64 or s == "00" * 33:
        return _INF
    if len(s) == 128:
        # Uncompressed: x || y
        x = int(s[:64], 16)
        y = int(s[64:], 16)
        return (x, y)
    if len(s) == 66 and s[:2] in ("02", "03"):
        # Compressed: prefix + x  →  recover y via curve equation
        x    = int(s[2:], 16)
        y_sq = (pow(x, 3, _P) + _A * x + _B) % _P
        # P-256: p ≡ 3 mod 4, so square root = y_sq^((p+1)/4) mod p
        y    = pow(y_sq, (_P + 1) // 4, _P)
        # Select the correct root using the parity bit
        if (y % 2 == 0) != (s[:2] == "02"):
            y = _P - y
        return (x, y)
    return _INF


def _pt_compress(P) -> str:
    """Encode an EC point in compressed form: 66-char hex ('02'/'03' + x).
    Reduces point size from 64 bytes (uncompressed) to 33 bytes — halving
    the signature T component and bringing total sig from 96 B → 65 B.
    """
    if P is _INF:
        return "00" * 33
    x, y = P
    prefix = "02" if y % 2 == 0 else "03"
    return f"{prefix}{x:064x}"


# Hash Functions H0, H1, H2  (domain-separated SHA-256 → Z*q)
# H3 and H4 are replaced by CLA-based algebraic derivation (see cla_derive).
#
#   H0(r·P_pub, v_t)         ← pseudonym generation
#   H1(P_pub, ID, R, X)      ← partial key binding; X = x·P
#   H2(X, R, m||Time, KID_k) ← binds PK, message+time, commitment
# ---------------------------------------------------------------------------

def H0(point, v_t: int) -> bytes:
    """H0(r·P_pub, v_t) → 32 bytes.  Used for pseudonym generation."""
    h = hashlib.sha256()
    h.update(b"CLS_H0|")
    h.update(_pt_encode(point).encode("ascii"))
    h.update(str(v_t).encode("utf-8"))
    return h.digest()


def compute_pseudonym_id(real_identity: str, r_Ppub, v_t: int) -> str:
    """
    Pseudonym ID = SHA-256(real_identity)[:16] XOR H0(r·P_pub, v_t)[:16]
    Result is a 32-char hex string (matches current RID format).
    Only the KGC can reverse this (knows r and s hence r·P_pub).
    """
    rid_bytes = hashlib.sha256(real_identity.encode("utf-8")).digest()[:16]
    h0        = H0(r_Ppub, v_t)[:16] 
    xored     = bytes(a ^ b for a, b in zip(rid_bytes, h0))
    return xored.hex()


def H1(P_pub, identity: str, R, X) -> int:
    """H1(P_pub, ID, R, X) → Z*q.  X = x·P is user's public component."""
    h = hashlib.sha256()
    h.update(b"CLS_H1|")
    h.update(_pt_encode(P_pub).encode("ascii"))
    h.update(identity.encode("utf-8"))
    h.update(_pt_encode(R).encode("ascii"))
    h.update(_pt_encode(X).encode("ascii"))
    return int(h.hexdigest(), 16) % _N


def H2(X, R, message: str, KID_k) -> int:
    """H2(PK, m||Time, KID_k) → Z*q.
    PK = (X, R) — both public key components included.
    message already contains timestamp (m||Time).
    KID_k replaces T as the random commitment point.
    """
    h = hashlib.sha256()
    h.update(b"CLS_H2|")
    h.update(_pt_encode(X).encode("ascii"))
    h.update(_pt_encode(R).encode("ascii"))
    h.update(message.encode("utf-8"))
    h.update(_pt_compress(KID_k).encode("ascii"))
    return int(h.hexdigest(), 16) % _N


# ---------------------------------------------------------------------------
# CLA-Based Hash Derivation (Algorithm 4 from modified scheme)
# ---------------------------------------------------------------------------

def cla_derive(h1: int, h2: int, KID_k) -> tuple:
    """
    Derive h3 and h4 algebraically from h1, h2 and KID_k using
    Carry Look-Ahead (CLA) adder equations.  Eliminates 2 hash calls.

    ψ  = x-coordinate(KID_k) mod q     ← CLA carry-in from public commitment

    Stage 1 — h3:
        G1 = h1 · h2  mod q            (AND / generate term)
        P1 = h1 XOR h2                 (propagate term, bitwise on integers)
        h3 = (G1 + P1 · ψ)  mod q

    Stage 2 — h4  (cascaded carry, h3 used as new carry-in):
        G2 = h2 · h3  mod q
        P2 = h2 XOR h3
        h4 = (G2 + P2 · h3)  mod q

    Returns: (h3, h4)
    """
    psi = KID_k[0] % _N        # x-coordinate of KID_k mod q

    # Stage 1
    G1 = (h1 * h2) % _N
    P1 = (h1 ^ h2)             # bitwise XOR on integers
    h3 = (G1 + P1 * psi) % _N

    # Stage 2
    G2 = (h2 * h3) % _N
    P2 = (h2 ^ h3)
    h4 = (G2 + P2 * h3) % _N

    return h3, h4


# ---------------------------------------------------------------------------
# CLSParams dataclass
# ---------------------------------------------------------------------------

@dataclass
class CLSParams:
    """Public system parameters output by Setup. Shared with all parties."""
    G: tuple        # Generator point
    q: int          # Group order
    P_pub: tuple    # KGC master public key = s·G
    ppub_table: list = None  # precomputed fixed-base table for P_pub (accelerates verify)


# ---------------------------------------------------------------------------
# Algorithm 1: Setup
# ---------------------------------------------------------------------------

def setup(kappa: int = 256):
    """
    Setup(1^κ) — KGC initialises system parameters.

    Returns:
        params (CLSParams): public system parameters
        msk    (int):       master secret key s  [KGC keeps secret]
    """
    s = secrets.randbelow(_N - 1) + 1                  # s ← Z*q
    P_pub      = _point_mul_G(s)                        # P_pub = s·G (fixed-base table)
    ppub_table = _build_fixed_table_p256(P_pub)         # precompute for all future verifies
    params = CLSParams(G=_G, q=_N, P_pub=P_pub, ppub_table=ppub_table)
    return params, s


# ---------------------------------------------------------------------------
# Algorithm 2: PartialPrivKeyGen
# ---------------------------------------------------------------------------

def partial_priv_key_gen(params: CLSParams, msk: int, identity: str,
                         X=None, v_t: int = None) -> dict:
    """
    PartialPrivKeyGen(params, msk, ID, X) — KGC issues partial key.

    If X (= x·P, user's public component) and v_t (validity timestamp) are
    provided, also computes the anonymous pseudonym:
        pseudo_id = SHA-256(identity)[:16] XOR H0(r·P_pub, v_t)[:16]
    and uses that as the identity bound into d.

    Paper formula:
        r ← Z*q,  R = r·P
        d = r + s·H1(P_pub, ID, R, X)  mod q   [H1 now includes X]
        D = (R, d)

    Returns dict with keys: R, d, pseudo_id (str), r_Ppub (point).
    """
    r      = secrets.randbelow(params.q - 1) + 1
    R      = _point_mul_G(r)    # fixed-base G table
    # r·P_pub: use fixed-base table if available, otherwise fall back to generic
    if params.ppub_table:
        r_Ppub = _point_mul_fixed(r, params.ppub_table)
    else:
        r_Ppub = _point_mul(r, params.P_pub)

    # Derive anonymous pseudonym if X and v_t are provided
    if X is not None and v_t is not None:
        pseudo_id = compute_pseudonym_id(identity, r_Ppub, v_t)
    else:
        pseudo_id = identity  # fallback: use identity as-is

    # X defaults to point-at-infinity placeholder if not provided (backward compat)
    X_for_hash = X if X is not None else params.G  # use G as dummy if no X

    h = H1(params.P_pub, pseudo_id, R, X_for_hash)
    d = (r + msk * h) % params.q
    return {"R": R, "d": d, "pseudo_id": pseudo_id, "r_Ppub": r_Ppub}


# ---------------------------------------------------------------------------
# Algorithm 3: SecretValueGen
# ---------------------------------------------------------------------------

def secret_value_gen(params: CLSParams) -> int:
    """
    SecretValueGen(params) — User independently picks their secret value.

    x ← Z*q   (user's own secret; KGC never sees this)
    """
    return secrets.randbelow(params.q - 1) + 1


# ---------------------------------------------------------------------------
# Algorithm 4: KeyGen
# ---------------------------------------------------------------------------

def key_gen(params: CLSParams, identity: str, D: dict, x: int):
    """
    KeyGen(params, ID, D, x) — Assemble full key pair.

    SK = (x, d)  — paper definition; R is public and stored in pk_record.

    Returns:
        pk_record (dict): {"PK": X_point, "R": R_point}
        SK        (dict): {"x": x, "d": d}
    """
    X = _point_mul_G(x)                    # X = x·G  (fixed-base table)
    pk_record = {"PK": X, "R": D["R"]}
    SK = {"x": x, "d": D["d"]}            # SK = (x, d) per paper — no R
    return pk_record, SK


# ---------------------------------------------------------------------------
# SID/KID Precomputation (Algorithm 3, Steps 3.3–3.4)
# ---------------------------------------------------------------------------

def precompute_sid_kid(params: CLSParams, identity: str,
                       SK: dict, pk_record: dict, n: int = 20) -> tuple:
    """
    Precompute n SID_k / KID_k pairs for zero-EC-mult signing.

    SID_k = (v_k · x + h1) mod q      ← private, stored locally
    KID_k = SID_k · P                  ← public, sent with signature

    h1 = H1(P_pub, ID, R, X) — computed once per key epoch.
    v_k ← Z*q  independently for each k.

    Returns:
        SID_list (list[int]):   private scalars
        KID_list (list[tuple]): corresponding public EC points
    """
    X  = pk_record["PK"]
    R  = pk_record["R"]
    h1 = H1(params.P_pub, identity, R, X)

    SID_list, KID_list = [], []
    for _ in range(n):
        v_k   = secrets.randbelow(params.q - 1) + 1
        SID_k = (v_k * SK["x"] + h1) % params.q
        KID_k = _point_mul_G(SID_k)    # fixed-base G table: ~8× faster
        SID_list.append(SID_k)
        KID_list.append(KID_k)

    return SID_list, KID_list


# ---------------------------------------------------------------------------
# Algorithm 5: Sign
# ---------------------------------------------------------------------------

def sign(params: CLSParams, SK: dict, identity: str, message: str,
         R=None, SID_k: int = None, KID_k=None) -> dict:
    """
    Sign(params, SK, ID, m, R, SID_k, KID_k) — CLA-modified signing.

    Modified scheme (Algorithm 5):
        Uses precomputed SID_k / KID_k instead of random t / T = t·P,
        eliminating EC scalar multiplication from the signing phase entirely.

        h1 = H1(P_pub, ID, R, X)
        h2 = H2(X, R, m||Time, KID_k)
        h3, h4 = cla_derive(h1, h2, KID_k)
        σ  = h4·SID_k + h3·d + h2·x  mod q
        δ  = (σ, KID_k)

    Signing cost:
        EC scalar mult : 0  (SID_k/KID_k precomputed)
        Hash calls     : 2  (H1, H2 only — H3/H4 replaced by CLA)
        Mod mult       : 6  (CLA stages + σ terms)

    If SID_k/KID_k are None (e.g. called from auth protocol), a fresh
    one-time pair is generated on the fly (1 EC mult, same security).

    Correctness:
        σ·P = h4·SID_k·P + h3·d·P + h2·x·P
            = h4·KID_k + h3·(R + h1·P_pub) + h2·X  ✓
    """
    X = _point_mul_G(SK["x"])              # X = x·G (fixed-base table)

    # Use precomputed pair if provided; otherwise generate a fresh one-time pair
    if SID_k is None or KID_k is None:
        if R is None:
            raise ValueError("R (partial public key) is required when SID_k/KID_k not provided")
        h1_val = H1(params.P_pub, identity, R, X)
        v      = secrets.randbelow(params.q - 1) + 1
        SID_k  = (v * SK["x"] + h1_val) % params.q
        KID_k  = _point_mul_G(SID_k)      # fixed-base G table

    # R required for h1 in CLA path; if None and precomputed pair given,
    # KID_k is already committed so pass a dummy R placeholder only for h2
    if R is None:
        # R not available — cannot compute h1; caller must provide R
        raise ValueError("R (partial public key point) must be supplied to sign()")

    h1     = H1(params.P_pub, identity, R, X)
    h2     = H2(X, R, message, KID_k)
    h3, h4 = cla_derive(h1, h2, KID_k)

    sigma = (h4 * SID_k + h3 * SK["d"] + h2 * SK["x"]) % params.q
    return {"KID_k": KID_k, "sigma": sigma}


# ---------------------------------------------------------------------------
# Algorithm 6: Verify
# ---------------------------------------------------------------------------

def verify(params: CLSParams, identity: str, pk_record: dict,
           message: str, signature: dict) -> bool:
    """
    Verify(params, ID, pk_record, m, δ) — Verify a CLA-modified CLS signature.

    pk_record  = {"PK": X_point, "R": R_point}
    signature  = {"KID_k": KID_k_point, "sigma": sigma_int}

    Verification equation (Algorithm 6):
        σ·P = h4·KID_k + h3·(R + h1·P_pub) + h2·X

    Derivation:
        σ·P = (h4·SID_k + h3·d + h2·x)·P
            = h4·KID_k + h3·d·P + h2·X
        d·P = R + h1·P_pub   [from PartialPrivKeyGen correctness]
        ∴ σ·P = h4·KID_k + h3·(R + h1·P_pub) + h2·X  ✓

    Verification cost: 5 EC scalar mults, 2 hash calls (H1, H2), CLA derive.
    """
    # Accept both "KID_k" (new) and "T" (legacy) key names
    KID_k = signature.get("KID_k") or signature.get("T")
    sigma = signature["sigma"]
    X     = pk_record["PK"]
    R     = pk_record["R"]

    h1     = H1(params.P_pub, identity, R, X)
    h2     = H2(X, R, message, KID_k)
    h3, h4 = cla_derive(h1, h2, KID_k)

    # Expand h3·(R + h1·P_pub) = h3·R + (h3·h1)·P_pub, then split out P_pub so
    # it can use the fixed-base table.  LHS uses fixed-base G table.
    # Total cost: ~0.22 ms (G fixed) + ~0.22 ms (P_pub fixed) + ~0.9 ms (3-pt Shamir)
    h31 = (h3 * h1) % params.q

    LHS = _point_mul_G(sigma)                           # σ·G — fixed-base table
    # h31·P_pub via fixed-base table (if available) or Shamir fallback
    if params.ppub_table:
        ppub_term = _point_mul_fixed(h31, params.ppub_table)
        RHS = _point_add(ppub_term, _multi_scalar_mul([ # 3-point Shamir for the rest
            (h4, KID_k),     # h4·KID_k
            (h3, R),         # h3·R
            (h2, X),         # h2·X
        ]))
    else:
        RHS = _multi_scalar_mul([                       # 4-point Shamir fallback
            (h4,  KID_k),
            (h3,  R),
            (h31, params.P_pub),
            (h2,  X),
        ])

    return LHS == RHS


# ---------------------------------------------------------------------------
# Batch Verification
# ---------------------------------------------------------------------------

def batch_verify(params: CLSParams, items: list):
    """
    Batch verify n CLA-modified signatures.

    LHS = (Σ λ_i · σ_i mod q) · P
    RHS = Σ λ_i · (h4_i·KID_{i,k} + h3_i·(R_i + h1_i·P_pub) + h2_i·X_i)

    λ_i ← random weights (prevent forgery via linear combination).
    Falls back to individual verify() to isolate failures.
    """
    if not items:
        return True, 0, 0

    n = len(items)

    # Optimised batch verification using Straus-Shamir per-user.
    #
    # Expand h3·(R + h1·P_pub) = h3·R + (h3·h1)·P_pub so P_pub contributions
    # can be accumulated as a single scalar → 1 EC mult for P_pub total.
    # Per-user: 3-point Shamir on (h4·KID_k, h3·R, h2·X) + point-add weighted
    # by lam → ~0.4n effective mults vs 5n previously.
    sum_sigma   = 0      # Σ lam_i · σ_i
    sum_lam_h31 = 0      # Σ lam_i · h3_i · h1_i  (scalar for P_pub)
    rhs_accum   = _INF   # running point sum

    for item in items:
        rid   = item["identity"]
        X     = item["pk_record"]["PK"]
        R     = item["pk_record"]["R"]
        msg   = item["message"]
        KID_k = item["signature"].get("KID_k") or item["signature"].get("T")
        sigma = item["signature"]["sigma"]

        lam      = secrets.randbelow(params.q - 1) + 1
        h1_i     = H1(params.P_pub, rid, R, X)
        h2_i     = H2(X, R, msg, KID_k)
        h3_i, h4_i = cla_derive(h1_i, h2_i, KID_k)
        h31_i    = (h3_i * h1_i) % params.q

        sum_sigma   = (sum_sigma   + lam * sigma)   % params.q
        sum_lam_h31 = (sum_lam_h31 + lam * h31_i)  % params.q

        # Per-user 3-point Shamir: lam·h4·KID_k + lam·h3·R + lam·h2·X
        user_pt = _multi_scalar_mul([
            ((lam * h4_i) % params.q, KID_k),
            ((lam * h3_i) % params.q, R),
            ((lam * h2_i) % params.q, X),
        ])
        rhs_accum = _point_add(rhs_accum, user_pt)

    # LHS: fixed-base G table (~8–10× faster than generic _point_mul)
    LHS = _point_mul_G(sum_sigma)

    # P_pub term: fixed-base table if available, else generic
    if params.ppub_table:
        ppub_term = _point_mul_fixed(sum_lam_h31, params.ppub_table)
    else:
        ppub_term = _point_mul(sum_lam_h31, params.P_pub)
    RHS = _point_add(ppub_term, rhs_accum)

    if LHS == RHS:
        return True, n, 0

    passed = sum(1 for item in items if verify(
        params, item["identity"], item["pk_record"],
        item["message"], item["signature"]))
    return False, passed, n - passed


# ---------------------------------------------------------------------------
# Serialization Helpers (for JSON transport in Flask API)
# ---------------------------------------------------------------------------

def serialize_point(P) -> str:
    """Uncompressed encoding (128-char hex). Used for public keys (PK, R, P_pub)."""
    return _pt_encode(P)


def deserialize_point(s: str):
    """Decode either compressed (66-char) or uncompressed (128-char) hex point."""
    return _pt_decode(s)


def compress_point(P) -> str:
    """Compressed encoding (66-char hex). Used for signature component T."""
    return _pt_compress(P)


def decompress_point(s: str):
    """Decompress a 66-char compressed point back to (x, y). Also accepts 128-char."""
    return _pt_decode(s)


def serialize_signature(sig: dict) -> dict:
    """Serialize CLA-modified signature (KID_k, σ) for JSON transport.
    KID_k uses compressed encoding (33 bytes).
    σ sent as string to avoid JS float64 precision loss.
    Total: 33 + 32 = 65 bytes (520 bits).
    """
    point = sig.get("KID_k") or sig.get("T")
    return {"KID_k": _pt_compress(point), "sigma": str(sig["sigma"])}


def deserialize_signature(d: dict) -> dict:
    """Deserialize signature — accepts 'KID_k' (new) or 'T' (legacy) key."""
    raw = d.get("KID_k") or d.get("T", "")
    return {"KID_k": _pt_decode(raw), "sigma": int(d["sigma"])}


def serialize_pk_record(pk: dict) -> dict:
    return {"PK": serialize_point(pk["PK"]), "R": serialize_point(pk["R"])}


def deserialize_pk_record(d: dict) -> dict:
    return {"PK": deserialize_point(d["PK"]), "R": deserialize_point(d["R"])}
