"""
Chameleon Hash for Healthcare EHR Evidence Chain
==================================================
Based on Algorithm 9 & 10 of healthcare_ehr_scheme.md.

Construction:
  ck_i  = H₁(s, θ_i)           — scalar trapdoor (known only to HA)
  HK_i  = ck_i · P             — public hash key stored on-chain
  CH_i  = (ζ_i · ck_i + H₁(j_i, cred_i, HK_i)) · P   — chameleon hash value (EC point)

Modification (Algorithm 10):
  Given ck_i (trapdoor), old cred_i, new cred'_i:
  ζ'_i = ck_i⁻¹ · (H₁(j_i, cred_i, HK_i) − H₁(j_i, cred'_i, HK_i)) + ζ_i  mod N
  Then CH(ζ'_i, cred'_i) == CH(ζ_i, cred_i)  [same hash, different content]

The Evidence Chain stores (HK_i, CH_i, j_i, cred_i) publicly.
Only HA who knows ck_i and ζ_i can produce a valid collision (update evidence).
"""

import secrets
from typing import Optional, Tuple, Union
from .ecc_utils import ECPoint, G, N, INF, rand_scalar, modinv, H1, Hgen


def ch_setup(s: int, theta: Optional[int] = None) -> Tuple[int, int, ECPoint]:
    """
    Create a chameleon hash trapdoor for one evidence entry.

    Parameters
    ----------
    s     : int   — HA master key
    theta : int   — random salt (generated if None)

    Returns
    -------
    theta : int      — random salt (stored in HA private DB)
    ck_i  : int      — trapdoor scalar  (kept secret by HA)
    HK_i  : ECPoint  — public hash key  (stored on-chain)
    """
    if theta is None:
        theta = rand_scalar()
    ck_i = H1(s, theta)              # ck_i = H₁(s, θ_i)  — scalar
    HK_i = ck_i * G                  # HK_i = ck_i · P
    return theta, ck_i, HK_i


def ch_hash(ck_i: int, HK_i: ECPoint, j_i: int, cred: Union[str, bytes], zeta: Optional[int] = None
            ) -> Tuple[ECPoint, int]:
    """
    Compute the chameleon hash CH_i.

    CH_i = (ζ_i · ck_i + H₁(j_i, cred_i, HK_i)) · P

    Parameters
    ----------
    ck_i  : int        — trapdoor scalar
    HK_i  : ECPoint    — public hash key
    j_i   : int        — salt
    cred  : str/bytes  — evidence credentials string
    zeta  : int        — random ζ_i (generated if None)

    Returns
    -------
    CH_i  : ECPoint — chameleon hash value
    zeta  : int     — the ζ_i used (store in HA private DB)
    """
    if zeta is None:
        zeta = rand_scalar()
    if isinstance(cred, str):
        cred = cred.encode("utf-8")
    h_cred = H1(j_i, cred, HK_i)                  # H₁(j_i, cred_i, HK_i)
    scalar  = (zeta * ck_i + h_cred) % N           # ζ_i · ck_i + H₁(...)
    CH_i    = scalar * G                            # CH_i = scalar · P
    return CH_i, zeta


def ch_verify(ck_i: int, HK_i: ECPoint, j_i: int, cred: Union[str, bytes],
              zeta: int, CH_i: ECPoint) -> bool:
    """
    Verify that CH_i is a valid chameleon hash of cred under ζ_i.
    (Used by HA; third parties only trust HA's commitment.)
    """
    expected, _ = ch_hash(ck_i, HK_i, j_i, cred, zeta)
    return expected == CH_i


def ch_forge(ck_i: int, HK_i: ECPoint, j_i: int,
             cred_old: Union[str, bytes], zeta_old: int,
             cred_new: Union[str, bytes]) -> int:
    """
    Algorithm 10: Compute new ζ'_i such that CH(ζ'_i, cred'_i) == CH(ζ_i, cred_i).

    Formula:
      ζ'_i = ck_i⁻¹ · (H₁(j_i, cred_i, HK_i) − H₁(j_i, cred'_i, HK_i)) + ζ_i  mod N

    Parameters
    ----------
    ck_i      : int        — trapdoor scalar
    HK_i      : ECPoint    — public hash key
    j_i       : int        — salt
    cred_old  : str/bytes  — original evidence credentials
    zeta_old  : int        — original ζ_i
    cred_new  : str/bytes  — updated evidence credentials

    Returns
    -------
    zeta_new : int — new ζ'_i that produces the same CH_i
    """
    if isinstance(cred_old, str):
        cred_old = cred_old.encode("utf-8")
    if isinstance(cred_new, str):
        cred_new = cred_new.encode("utf-8")

    h_old  = H1(j_i, cred_old, HK_i)
    h_new  = H1(j_i, cred_new, HK_i)
    ck_inv = modinv(ck_i, N)
    zeta_new = (ck_inv * (h_old - h_new) + zeta_old) % N
    return zeta_new


def rand_j() -> int:
    """Generate a fresh random salt j_i for a new evidence entry."""
    return rand_scalar()
