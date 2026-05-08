"""
ECC Utilities for Healthcare BCCA Scheme
==========================================
Pure-Python implementation on secp256k1 curve (no external crypto deps).

Notation (from healthcare_ehr_scheme.md):
  G      - generator point (= P in paper)
  N      - group order q
  s      - HA master key
  P_pub  = s · G           (main public key)
  P_pub1 = s₁ · G          (H₂ domain key for EHR integrity)
  P_pub2 = s₂ · G          (H₃ domain key for temporal freshness)
  H₁, H₂, H₃ : {0,1}* → Z*_q
  H, H₅       : {0,1}* → Z*_q  (for mutual authentication)
"""

import hashlib
import secrets
import json


# ---------------------------------------------------------------------------
# secp256k1 curve parameters
# ---------------------------------------------------------------------------
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A  = 0
_B  = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ECPoint:
    """A point on the secp256k1 elliptic curve, or the point at infinity."""

    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "ECPoint(INF)"
        return f"ECPoint(x={self.x:#066x}, y={self.y:#066x})"

    def __add__(self, other: "ECPoint") -> "ECPoint":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        p = _P
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return INF
            # Point doubling
            lam = (3 * self.x * self.x + _A) * pow(2 * self.y, p - 2, p) % p
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, p - 2, p) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)

    def __neg__(self) -> "ECPoint":
        if self.is_infinity():
            return self
        return ECPoint(self.x, (-self.y) % _P)

    def __sub__(self, other: "ECPoint") -> "ECPoint":
        return self + (-other)

    def __rmul__(self, scalar: int) -> "ECPoint":
        return self.__mul__(scalar)

    def __mul__(self, scalar: int) -> "ECPoint":
        """Scalar multiplication using Jacobian coordinates (single inversion at end).
        Left-to-right binary method: ~3-5x faster than affine double-and-add."""
        scalar = int(scalar) % _N
        if scalar == 0 or self.is_infinity():
            return INF
        bits = scalar.bit_length()
        # Initialise accumulator as self in Jacobian (Z=1 ↔ affine)
        Xr, Yr, Zr = self.x, self.y, 1
        for i in range(bits - 2, -1, -1):
            Xr, Yr, Zr = _jac_double(Xr, Yr, Zr)
            if (scalar >> i) & 1:
                Xr, Yr, Zr = _jac_add_mixed(Xr, Yr, Zr, self.x, self.y)
        ax, ay = _jac_to_affine(Xr, Yr, Zr)
        return INF if ax is None else ECPoint(ax, ay)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Uncompressed SEC encoding (65 bytes: 04 || x || y)."""
        if self.is_infinity():
            return b"\x00"
        return b"\x04" + self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")

    @staticmethod
    def from_bytes(data: bytes) -> "ECPoint":
        if data == b"\x00":
            return INF
        if len(data) != 65 or data[0] != 0x04:
            raise ValueError("Invalid point encoding")
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        return ECPoint(x, y)

    def to_dict(self) -> dict:
        if self.is_infinity():
            return {"x": None, "y": None}
        return {"x": self.x, "y": self.y}

    @staticmethod
    def from_dict(d: dict) -> "ECPoint":
        if d.get("x") is None:
            return INF
        return ECPoint(d["x"], d["y"])

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(h: str) -> "ECPoint":
        return ECPoint.from_bytes(bytes.fromhex(h))


# Public constants
INF     = ECPoint(None, None)   # point at infinity
G       = ECPoint(_GX, _GY)    # generator  (= P in paper)
N       = _N                    # group order q
P_FIELD = _P                    # field prime


# ---------------------------------------------------------------------------
# Random scalar
# ---------------------------------------------------------------------------
def rand_scalar() -> int:
    """Return a cryptographically random scalar in [1, N-1]."""
    return secrets.randbelow(_N - 1) + 1


def modinv(a: int, m: int = _N) -> int:
    """Modular inverse using Fermat's little theorem (m must be prime)."""
    return pow(a, m - 2, m)


# ---------------------------------------------------------------------------
# Jacobian coordinate arithmetic for secp256k1 (A = 0)
#
# Representation: affine (x,y)  ↔  Jacobian (X:Y:Z) where x=X/Z², y=Y/Z³.
# Infinity is represented as Z=0.
# Avoids per-operation field inversion; one inversion per scalar mult at end.
# ---------------------------------------------------------------------------

def _jac_double(X: int, Y: int, Z: int):
    """Jacobian point doubling for secp256k1 (A=0)."""
    if Z == 0 or Y == 0:
        return 0, 1, 0          # point at infinity
    p   = _P
    Y2  = Y * Y % p
    S   = 4 * X * Y2 % p
    M   = 3 * X * X % p        # A=0 → no Z^4 term
    X3  = (M * M - 2 * S) % p
    Y3  = (M * (S - X3) - 8 * Y2 * Y2) % p
    Z3  = 2 * Y * Z % p
    return X3, Y3, Z3


def _jac_add_mixed(X1: int, Y1: int, Z1: int, x2: int, y2: int):
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
            return _jac_double(X1, Y1, Z1)
        return 0, 1, 0          # P + (-P) = infinity
    H2   = H * H % p
    H3   = H * H2 % p
    X3   = (R * R - H3 - 2 * X1 * H2) % p
    Y3   = (R * (X1 * H2 - X3) - Y1 * H3) % p
    Z3   = H * Z1 % p
    return X3, Y3, Z3


def _jac_to_affine(X: int, Y: int, Z: int):
    """Convert Jacobian (X:Y:Z) → affine (x, y). One field inversion."""
    if Z == 0:
        return None, None       # point at infinity
    p   = _P
    Zi  = pow(Z, p - 2, p)     # single inversion per scalar mult
    Zi2 = Zi * Zi % p
    return X * Zi2 % p, Y * Zi2 % p * Zi % p


# ---------------------------------------------------------------------------
# Fixed-base precomputed table for G: [G, 2G, 4G, ..., 2^255·G]
# Built once at module import (~256 doublings with 256 inversions).
# Amortised over all subsequent mul_G() calls.
# ---------------------------------------------------------------------------

def _build_G_table() -> list:
    """Build power-of-2 table [G, 2G, 4G, …, 2^255·G] in affine coordinates."""
    table = []
    x, y  = _GX, _GY
    p     = _P
    for _ in range(256):
        table.append((x, y))
        # Point doubling in affine (affine double is fine here — paid only once)
        lam = 3 * x * x * pow(2 * y, p - 2, p) % p   # A=0
        x3  = (lam * lam - 2 * x) % p
        y3  = (lam * (x - x3) - y) % p
        x, y = x3, y3
    return table


_G_TABLE: list = _build_G_table()   # module-level, initialised once


def mul_G(k: int) -> "ECPoint":
    """
    Multiply generator G by scalar k using the precomputed power-of-2 table.

    Cost: 0 doublings + at most 128 mixed Jacobian-affine additions + 1 inversion.
    ~8–10× faster than generic ECPoint.__mul__ for G-specific multiplications.
    """
    k = int(k) % _N
    if k == 0:
        return INF
    Xr, Yr, Zr = 0, 1, 0       # Jacobian infinity
    for i in range(256):
        if (k >> i) & 1:
            Xr, Yr, Zr = _jac_add_mixed(Xr, Yr, Zr, *_G_TABLE[i])
    ax, ay = _jac_to_affine(Xr, Yr, Zr)
    return INF if ax is None else ECPoint(ax, ay)


def build_fixed_table(P: "ECPoint") -> list:
    """
    Build a power-of-2 affine table [P, 2P, 4P, …, 2^255·P] for any fixed point P.
    Used to accelerate repeated multiplications by a known public parameter (e.g. P_pub).
    """
    table = []
    cur   = P
    for _ in range(256):
        table.append((cur.x, cur.y))
        cur = cur + cur         # uses __add__ (one inversion); acceptable at setup
    return table


def mul_fixed(k: int, table: list) -> "ECPoint":
    """
    Multiply a fixed-base point by k using its precomputed power-of-2 table.
    Same cost profile as mul_G(): 0 doublings + ≤128 mixed-adds + 1 inversion.
    """
    k = int(k) % _N
    if k == 0:
        return INF
    Xr, Yr, Zr = 0, 1, 0
    for i in range(256):
        if (k >> i) & 1:
            Xr, Yr, Zr = _jac_add_mixed(Xr, Yr, Zr, *table[i])
    ax, ay = _jac_to_affine(Xr, Yr, Zr)
    return INF if ax is None else ECPoint(ax, ay)


def multi_scalar_mul(pairs) -> "ECPoint":
    """
    Simultaneous multi-scalar multiplication using Straus-Shamir algorithm.

    For k (scalar, point) pairs, processes all scalars in a single bit-scan
    instead of k independent double-and-add passes.

    Cost: ~256 doublings + 256*(2^k-1)/2^k additions
    vs sequential: k*256 doublings + k*128 additions

    k=3 pairs: ~3.25× faster than sequential.
    k=4 pairs: ~4.3× faster than sequential.
    """
    pairs = [(int(s) % _N, P) for s, P in pairs
             if int(s) % _N != 0 and not P.is_infinity()]
    if not pairs:
        return INF
    if len(pairs) == 1:
        return pairs[0][0] * pairs[0][1]

    scalars = [s for s, _ in pairs]
    points  = [P for _, P in pairs]
    k = len(pairs)

    # Precompute all 2^k - 1 non-zero linear combinations of the points.
    # precomp[mask] = sum of points[i] for each bit i set in mask.
    # Build precomp table in affine (x, y) tuples.
    # For k=3 pairs there are only 7 entries — the ECPoint.__add__ cost here is
    # negligible compared to the 256-iteration main loop.
    precomp: dict = {}
    for mask in range(1, 1 << k):
        lsb  = mask & (-mask)
        i    = lsb.bit_length() - 1
        rest = mask ^ lsb
        p_i  = points[i]
        precomp[mask] = (precomp[rest] + p_i) if rest else p_i

    # Convert to (x, y) tuples for use with Jacobian mixed-add.
    precomp_aff = {mask: (pt.x, pt.y) for mask, pt in precomp.items()}

    max_bits = max(s.bit_length() for s in scalars)
    # Jacobian accumulator — eliminates all per-doubling field inversions.
    Xr, Yr, Zr = 0, 1, 0   # Jacobian infinity
    for bit in range(max_bits - 1, -1, -1):
        Xr, Yr, Zr = _jac_double(Xr, Yr, Zr)
        mask = sum(((s >> bit) & 1) << i for i, s in enumerate(scalars))
        if mask:
            px, py = precomp_aff[mask]
            Xr, Yr, Zr = _jac_add_mixed(Xr, Yr, Zr, px, py)

    ax, ay = _jac_to_affine(Xr, Yr, Zr)
    return INF if ax is None else ECPoint(ax, ay)


# ---------------------------------------------------------------------------
# Hash functions H₁, H₂, H₃, H, H₅
#
# Paper: Hi : {0,1}* → Z*_q
# Domain separation via distinct prefix bytes.
# ---------------------------------------------------------------------------

def _hash_to_scalar(domain: bytes, *items) -> int:
    """Hash multiple items to a non-zero scalar in Z*_N."""
    h = hashlib.sha256()
    h.update(domain)
    for item in items:
        if isinstance(item, ECPoint):
            b = item.to_bytes()
        elif isinstance(item, int):
            length = (item.bit_length() + 7) // 8 or 1
            b = item.to_bytes(length, "big")
        elif isinstance(item, (bytes, bytearray)):
            b = bytes(item)
        elif isinstance(item, str):
            b = item.encode("utf-8")
        else:
            b = str(item).encode("utf-8")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    val = int.from_bytes(h.digest(), "big") % _N
    return val if val != 0 else 1   # never return 0


def H1(*items) -> int:
    """General-purpose hash — used in Setup, Registration, Login, Partial Key,
    and EHR Verification (h_{1,i}). Maps {0,1}* → Z*_q."""
    return _hash_to_scalar(b"\x01HEALTHCARE-H1", *items)


def H2(*items) -> int:
    """EHR integrity binding hash — uses P_pub1 domain.
    h_{2,i} = H₂(ID_i, KID_{i,k}, Q_{i,k}, P_pub1)"""
    return _hash_to_scalar(b"\x02HEALTHCARE-H2", *items)


def H3(*items) -> int:
    """Temporal freshness binding hash — uses P_pub2 domain.
    h_{3,i} = H₃(c_i, pk_i, P_pub2, T_i)"""
    return _hash_to_scalar(b"\x03HEALTHCARE-H3", *items)


def H_auth(*items) -> int:
    """Session key derivation hash H: G → Z*_q  (mutual authentication step)."""
    return _hash_to_scalar(b"\x04HEALTHCARE-H", *items)


def H5(*items) -> int:
    """Session key derivation H₅: {0,1}* → Z*_q."""
    return _hash_to_scalar(b"\x05HEALTHCARE-H5", *items)


def Hgen(*items) -> int:
    """General hash used in chameleon hash and other contexts."""
    return _hash_to_scalar(b"\x00HEALTHCARE-HGEN", *items)


# ---------------------------------------------------------------------------
# XOR-based EHR encryption (stream from SHAKE-256)
# c_i = m_i ⊕ expand(ek_{i,k})
# ---------------------------------------------------------------------------

def xor_encrypt(plaintext: bytes, key_scalar: int) -> bytes:
    """
    XOR-encrypt plaintext with a keystream derived from key_scalar.
    key_scalar = H₁(q_{i,k} · dpk) as an integer.
    """
    key_bytes = key_scalar.to_bytes((key_scalar.bit_length() + 7) // 8 or 1, "big")
    # Expand to required length using SHAKE-256
    shake = hashlib.shake_256(b"EHR-ENC" + key_bytes)
    stream = shake.digest(len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, stream))


def xor_decrypt(ciphertext: bytes, key_scalar: int) -> bytes:
    """XOR-decrypt (identical to encrypt since XOR is self-inverse)."""
    return xor_encrypt(ciphertext, key_scalar)


# ---------------------------------------------------------------------------
# Symmetric encryption helpers (for mutual auth payload C_a, C_b)
# Uses AES-256-GCM with key derived from scalar via SHA-256.
# ---------------------------------------------------------------------------

def sym_encrypt(key_scalar: int, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt using key derived from key_scalar."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    key_bytes = hashlib.sha256(key_scalar.to_bytes(32, "big")).digest()
    nonce = os.urandom(12)
    ct = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    return nonce + ct


def sym_decrypt(key_scalar: int, token: bytes) -> bytes:
    """AES-256-GCM decrypt."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key_bytes = hashlib.sha256(key_scalar.to_bytes(32, "big")).digest()
    nonce, ct = token[:12], token[12:]
    return AESGCM(key_bytes).decrypt(nonce, ct, None)
