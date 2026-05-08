"""
Persistent storage for BCCA Healthcare system parameters.
Saves/loads params and HA secret to/from JSON files in bcca_data/.
"""

import json
import os
from typing import Optional, Tuple
from .ecc_utils import ECPoint, G, N, INF

DATA_DIR    = os.path.join(os.path.dirname(__file__), "..", "bcca_data")
PARAMS_FILE = os.path.join(DATA_DIR, "params.json")
HA_FILE     = os.path.join(DATA_DIR, "ha_secret.json")
USERS_FILE  = os.path.join(DATA_DIR, "users.json")
EVID_FILE   = os.path.join(DATA_DIR, "evidence.json")


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# ECPoint JSON helpers
# ---------------------------------------------------------------------------

def _point_to_json(pt: ECPoint) -> dict:
    return {"x": pt.x, "y": pt.y}


def _point_from_json(d: dict) -> ECPoint:
    if d is None or d.get("x") is None:
        return INF
    return ECPoint(d["x"], d["y"])


# ---------------------------------------------------------------------------
# Save / Load system params (public)
# ---------------------------------------------------------------------------

def save_params(params: dict):
    """
    params keys: s1, s2, Ppub, Ppub1, Ppub2, dpk (EC points as hex),
                 q (int as string for JSON safety)
    """
    _ensure_dir()
    serialisable = {}
    for k, v in params.items():
        if isinstance(v, ECPoint):
            serialisable[k] = v.to_hex()
        elif isinstance(v, int):
            serialisable[k] = str(v)
        else:
            serialisable[k] = v
    with open(PARAMS_FILE, "w") as f:
        json.dump(serialisable, f, indent=2)


def load_params() -> Optional[dict]:
    if not os.path.exists(PARAMS_FILE):
        return None
    with open(PARAMS_FILE) as f:
        raw = json.load(f)
    params = {}
    for k, v in raw.items():
        if isinstance(v, str):
            # Could be hex ECPoint or int-as-string
            try:
                if len(v) > 20:   # likely a hex point
                    params[k] = ECPoint.from_hex(v)
                else:
                    params[k] = int(v)
            except Exception:
                params[k] = v
        else:
            params[k] = v
    return params


# ---------------------------------------------------------------------------
# Save / Load HA secret (master key + doctor decrypt key)
# ---------------------------------------------------------------------------

def save_ha_secret(s: int, y: int):
    """Save HA master key s and doctor decrypt private key y."""
    _ensure_dir()
    with open(HA_FILE, "w") as f:
        json.dump({"s": str(s), "y": str(y)}, f, indent=2)
    # Restrict permissions on sensitive file
    try:
        os.chmod(HA_FILE, 0o600)
    except Exception:
        pass


def load_ha_secret() -> Tuple[Optional[int], Optional[int]]:
    if not os.path.exists(HA_FILE):
        return None, None
    with open(HA_FILE) as f:
        d = json.load(f)
    return int(d["s"]), int(d["y"])


# ---------------------------------------------------------------------------
# User registry (on-device store; in production this lives on blockchain)
# ---------------------------------------------------------------------------

def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)


def _save_users(users: dict):
    _ensure_dir()
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def register_user(pseudo_id: str, record: dict):
    """Store a user's public registration record keyed by pseudonym ID."""
    users = _load_users()
    users[pseudo_id] = record
    _save_users(users)


def get_user(pseudo_id: str) -> Optional[dict]:
    return _load_users().get(pseudo_id)


def get_all_users() -> dict:
    return _load_users()


def revoke_user(pseudo_id: str):
    users = _load_users()
    if pseudo_id in users:
        users[pseudo_id]["revoked"] = True
        _save_users(users)


def is_revoked(pseudo_id: str) -> bool:
    u = get_user(pseudo_id)
    return u is not None and u.get("revoked", False)


# ---------------------------------------------------------------------------
# Evidence chain (local store; in production this lives on blockchain)
# ---------------------------------------------------------------------------

def _load_evidence() -> list:
    if not os.path.exists(EVID_FILE):
        return []
    with open(EVID_FILE) as f:
        return json.load(f)


def _save_evidence(ev: list):
    _ensure_dir()
    with open(EVID_FILE, "w") as f:
        json.dump(ev, f, indent=2)


def add_evidence_entry(entry: dict):
    ev = _load_evidence()
    ev.append(entry)
    _save_evidence(ev)


def update_evidence_entry(pseudo_id: str, updated: dict):
    ev = _load_evidence()
    for i, e in enumerate(ev):
        if e.get("pseudo_id") == pseudo_id:
            ev[i] = updated
            break
    _save_evidence(ev)


def get_evidence_entries() -> list:
    return _load_evidence()


def get_evidence_by_id(pseudo_id: str) -> Optional[dict]:
    for e in _load_evidence():
        if e.get("pseudo_id") == pseudo_id:
            return e
    return None
