"""
Anonymity Module — Pseudonym Management for Healthcare IIoT CLS Scheme
Paper: Qiao et al., IEEE IoT Journal, July 2025  (Section V)

Pseudonym RID = H(ID_pub || V_i) where V_i is a validity-period timestamp.
RIDs are used in place of real identities in all CLS signatures, ensuring
unlinkability across validity periods.  The KGC can trace RID → real_id on
legal demand because it holds the (real_id, V_i) mapping.
"""

import hashlib
import time
import threading
from typing import Optional

# Default validity period: 30 days
PSEUDONYM_VALIDITY_SECONDS = 86400 * 30

# KGC authority token — in production this would be a hardware-backed secret.
# Here it is set at runtime by the Flask app factory.
_AUTHORITY_TOKEN: Optional[str] = None


def set_authority_token(token: str) -> None:
    """Called once by the Flask app factory to configure the KGC trace token."""
    global _AUTHORITY_TOKEN
    _AUTHORITY_TOKEN = token


def _compute_rid(real_id: str, validity_timestamp: int) -> str:
    """
    Legacy formula: RID = SHA-256("CLS_RID|" || real_id || "|" || V_i)
    truncated to 32 hex chars.

    New pseudonyms use compute_pseudonym_id() from cls_scheme.py:
        ID = SHA-256(real_id)[:16] XOR H0(r·P_pub, v_t)[:16]

    V_i is the Unix timestamp (integer) that anchors the validity window.
    Different V_i values for the same user produce different, unlinkable RIDs.
    """
    h = hashlib.sha256()
    h.update(b"CLS_RID|")
    h.update(real_id.encode("utf-8"))
    h.update(b"|")
    h.update(str(validity_timestamp).encode("utf-8"))
    return h.hexdigest()[:32]


class PseudonymManager:
    """
    Thread-safe manager for pseudonym lifecycle:
      generate → (use in signatures) → rotate / expire → revoke (if needed)

    Internal state:
        _store    : RID → {real_id, validity_start, validity_expiry, active, revoked, reason}
        _user_map : real_id → [RID, ...]   (most recent last)
        _revoked  : set of revoked RIDs
        _trace_log: list of tracing events for audit
        _counter  : monotonic counter added to timestamps to guarantee unique RIDs
                    even when generate_pseudonym() is called multiple times per second
    """

    def __init__(self):
        self._store: dict = {}
        self._user_map: dict = {}
        self._revoked: set = set()
        self._trace_log: list = []
        self._lock = threading.Lock()
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_pseudonym(self, real_id: str,
                           validity_seconds: int = PSEUDONYM_VALIDITY_SECONDS) -> dict:
        """
        Generate a new active pseudonym for real_id.

        Returns:
            {"RID": str, "validity_start": int, "validity_expiry": int}
        """
        now = int(time.time())
        expiry = now + validity_seconds
        # Add counter to guarantee uniqueness within the same second
        unique_ts = now * 1000000 + self._counter
        self._counter += 1
        rid = _compute_rid(real_id, unique_ts)

        with self._lock:
            # Deactivate any existing active pseudonym
            for old_rid in self._user_map.get(real_id, []):
                if self._store[old_rid]["active"]:
                    self._store[old_rid]["active"] = False

            self._store[rid] = {
                "real_id": real_id,
                "validity_start": now,
                "validity_expiry": expiry,
                "active": True,
                "revoked": False,
                "revoke_reason": None,
            }
            self._user_map.setdefault(real_id, []).append(rid)

        return {"RID": rid, "validity_start": now, "validity_expiry": expiry}

    def rotate_pseudonym(self, real_id: str,
                         validity_seconds: int = PSEUDONYM_VALIDITY_SECONDS) -> dict:
        """
        Invalidate the current pseudonym and issue a new one.
        Old RID is kept in _store (inactive) so KGC can still trace it.
        """
        return self.generate_pseudonym(real_id, validity_seconds)

    def is_valid(self, rid: str) -> bool:
        """
        Return True iff the RID exists, is active, not expired, and not revoked.
        """
        with self._lock:
            rec = self._store.get(rid)
            if rec is None:
                return False
            if rec["revoked"]:
                return False
            if not rec["active"]:
                return False
            if int(time.time()) > rec["validity_expiry"]:
                rec["active"] = False   # lazy expiry
                return False
            return True

    def get_current_pseudonym(self, real_id: str) -> Optional[str]:
        """Return the active RID for real_id, or None if none exists / all expired."""
        with self._lock:
            for rid in reversed(self._user_map.get(real_id, [])):
                rec = self._store.get(rid, {})
                if rec.get("active") and not rec.get("revoked"):
                    if int(time.time()) <= rec["validity_expiry"]:
                        return rid
        return None

    def get_pseudonym_info(self, rid: str) -> Optional[dict]:
        """Return the metadata record for a RID (without the real_id field)."""
        with self._lock:
            rec = self._store.get(rid)
            if rec is None:
                return None
            return {
                "validity_start":  rec["validity_start"],
                "validity_expiry": rec["validity_expiry"],
                "active":          rec["active"],
                "revoked":         rec["revoked"],
                "revoke_reason":   rec["revoke_reason"],
            }

    def revoke_pseudonym(self, rid: str, reason: str = "") -> bool:
        """
        Revoke a pseudonym (e.g., on patient request or legal order).
        Returns True if the RID was found and revoked.
        """
        with self._lock:
            rec = self._store.get(rid)
            if rec is None:
                return False
            rec["revoked"] = True
            rec["active"] = False
            rec["revoke_reason"] = reason
            self._revoked.add(rid)
        return True

    def get_revocation_list(self) -> list:
        """Return list of all revoked RIDs with reasons."""
        with self._lock:
            return [
                {"RID": rid,
                 "reason": self._store[rid]["revoke_reason"],
                 "validity_expiry": self._store[rid]["validity_expiry"]}
                for rid in self._revoked
            ]

    def trace_identity(self, rid: str, authority_token: str) -> Optional[str]:
        """
        KGC-only: reveal the real identity behind a RID.

        authority_token must match the configured KGC secret.
        Every trace attempt is recorded in _trace_log regardless of success.

        Returns the real_id string, or None on failure.
        """
        event = {
            "rid": rid,
            "timestamp": int(time.time()),
            "success": False,
            "real_id": None,
        }
        try:
            if authority_token != _AUTHORITY_TOKEN:
                return None
            with self._lock:
                rec = self._store.get(rid)
                if rec is None:
                    return None
                event["success"] = True
                event["real_id"] = rec["real_id"]
                return rec["real_id"]
        finally:
            self._trace_log.append(event)

    def get_trace_log(self) -> list:
        """Return all identity-tracing audit events."""
        with self._lock:
            return list(self._trace_log)

    def register_pseudonym(self, rid: str, real_id: str,
                           validity_start: int, validity_expiry: int) -> None:
        """
        Register an externally-computed pseudonym (e.g., from compute_pseudonym_id).
        Used when partial_priv_key_gen generates the RID so the manager can track it.
        """
        with self._lock:
            # Deactivate any existing active pseudonym for this user
            for old_rid in self._user_map.get(real_id, []):
                if self._store.get(old_rid, {}).get("active"):
                    self._store[old_rid]["active"] = False

            self._store[rid] = {
                "real_id": real_id,
                "validity_start": validity_start,
                "validity_expiry": validity_expiry,
                "active": True,
                "revoked": False,
                "revoke_reason": None,
            }
            self._user_map.setdefault(real_id, []).append(rid)

    def load_from_db_rows(self, rows: list) -> None:
        """
        Restore in-memory state from SQLAlchemy Pseudonym model rows.
        Called once at startup to rehydrate the manager after a restart.

        rows: list of objects with attributes:
            RID, user.username, validity_start, validity_expiry, active, revoked, revoke_reason
        """
        with self._lock:
            for row in rows:
                rid = row.RID
                real_id = row.user.username
                self._store[rid] = {
                    "real_id": real_id,
                    "validity_start": row.validity_start,
                    "validity_expiry": row.validity_expiry,
                    "active": row.active,
                    "revoked": row.revoked,
                    "revoke_reason": row.revoke_reason,
                }
                self._user_map.setdefault(real_id, []).append(rid)
                if row.revoked:
                    self._revoked.add(rid)
