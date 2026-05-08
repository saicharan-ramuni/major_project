"""
SQLAlchemy ORM models for the CLS Healthcare IIoT system.

Public key components (PK, R) are stored in the database.
Private keys (x, d) are NEVER persisted — they live only in Flask session.
Session keys K_ab are NEVER stored — only SHA-256(K_ab) for audit.
"""

from datetime import datetime
from . import db


class User(db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)  # real ID
    password_hash = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(16), nullable=False)               # patient/doctor/kgc
    email         = db.Column(db.String(120))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    cls_key       = db.relationship("CLSKeyRecord", back_populates="user",
                                    uselist=False, cascade="all, delete-orphan")
    pseudonyms    = db.relationship("Pseudonym", back_populates="user",
                                    cascade="all, delete-orphan")
    health_records = db.relationship("HealthRecord", back_populates="patient",
                                     foreign_keys="HealthRecord.patient_id",
                                     cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class CLSKeyRecord(db.Model):
    """Stores the PUBLIC components of a user's CLS key pair."""
    __tablename__ = "cls_key_records"

    id       = db.Column(db.Integer, primary_key=True)
    user_id  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    PK_hex   = db.Column(db.String(128), nullable=False)   # x·G encoded as 128-char hex
    R_hex    = db.Column(db.String(128), nullable=False)    # r·G from KGC, 128-char hex
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="cls_key")

    def __repr__(self):
        return f"<CLSKeyRecord user_id={self.user_id}>"


class Pseudonym(db.Model):
    """Maps RIDs to real users.  Only the KGC role may query this table directly."""
    __tablename__ = "pseudonyms"

    id              = db.Column(db.Integer, primary_key=True)
    RID             = db.Column(db.String(32), unique=True, nullable=False)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    validity_start  = db.Column(db.Integer, nullable=False)    # Unix timestamp
    validity_expiry = db.Column(db.Integer, nullable=False)    # Unix timestamp
    active          = db.Column(db.Boolean, default=True)
    revoked         = db.Column(db.Boolean, default=False)
    revoke_reason   = db.Column(db.Text)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="pseudonyms")

    def __repr__(self):
        return f"<Pseudonym {self.RID[:8]}... user_id={self.user_id}>"


class AuthSession(db.Model):
    """Tracks completed mutual-authentication sessions."""
    __tablename__ = "auth_sessions"

    id               = db.Column(db.Integer, primary_key=True)
    initiator_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    responder_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_key_hash = db.Column(db.String(64), nullable=False)  # SHA-256 of K_ab
    W_a_hex          = db.Column(db.String(128))
    W_b_hex          = db.Column(db.String(128))
    T_a              = db.Column(db.Integer)
    T_b              = db.Column(db.Integer)
    established_at   = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at       = db.Column(db.DateTime)

    initiator = db.relationship("User", foreign_keys=[initiator_id])
    responder  = db.relationship("User", foreign_keys=[responder_id])


class HealthRecord(db.Model):
    """Patient health data — AES-256-GCM encrypted, CLS-signed."""
    __tablename__ = "health_records"

    id               = db.Column(db.Integer, primary_key=True)
    patient_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    RID              = db.Column(db.String(32), nullable=False)    # pseudonym used when signing
    data_encrypted   = db.Column(db.LargeBinary, nullable=False)
    nonce            = db.Column(db.LargeBinary, nullable=False)
    data_type        = db.Column(db.String(32))                    # lab_result/prescription/imaging
    filename         = db.Column(db.String(256))
    T_hex            = db.Column(db.String(128), nullable=False)   # Signature component T
    sigma            = db.Column(db.String(80), nullable=False)    # Signature scalar σ (as decimal str)
    message_signed   = db.Column(db.Text, nullable=False)          # Exact string that was signed
    signer_PK_hex    = db.Column(db.String(128))                   # PK (x·G) used when signing
    signer_R_hex     = db.Column(db.String(128))                   # R from partial key used when signing
    hospitals_shared = db.Column(db.Text)                          # Comma-separated
    signed_at        = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("User", back_populates="health_records",
                              foreign_keys=[patient_id])

    def __repr__(self):
        return f"<HealthRecord id={self.id} patient_id={self.patient_id}>"


class AuditLog(db.Model):
    """Non-repudiable access events, each CLS-signed by the accessor."""
    __tablename__ = "audit_log"

    id           = db.Column(db.Integer, primary_key=True)
    patient_id   = db.Column(db.Integer, db.ForeignKey("users.id"))
    accessor_RID = db.Column(db.String(32), nullable=False)
    record_id    = db.Column(db.Integer, db.ForeignKey("health_records.id"))
    T_hex        = db.Column(db.String(128))
    sigma        = db.Column(db.String(80))
    action       = db.Column(db.String(32))   # view / download / batch_verify
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow)


class BatchVerifyLog(db.Model):
    """Records batch-verification requests (IoT telemetry scenario)."""
    __tablename__ = "batch_verify_log"

    id           = db.Column(db.Integer, primary_key=True)
    submitted_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    item_count   = db.Column(db.Integer)
    passed       = db.Column(db.Integer)
    failed       = db.Column(db.Integer)
    all_valid    = db.Column(db.Boolean)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
