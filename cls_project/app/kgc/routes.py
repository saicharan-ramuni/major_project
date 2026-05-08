"""
KGC (Key Generation Center) Blueprint
Endpoints: /kgc/*

Privileged operations:
  - Issue partial private keys to registered users
  - Trace a pseudonym RID back to its real identity
  - Revoke pseudonyms
  - View audit log and revocation list
  - Display system parameters

Access: role == 'kgc' is required for all routes.
"""

import hashlib
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app, jsonify)
from app import db
from app.models import User, CLSKeyRecord, Pseudonym, AuditLog, HealthRecord, AuthSession
from crypto.cls_scheme import (
    partial_priv_key_gen, secret_value_gen, key_gen,
    serialize_pk_record, serialize_point, deserialize_pk_record
)

kgc_bp = Blueprint("kgc", __name__)


# ---------------------------------------------------------------------------
# Auth guard
# ---------------------------------------------------------------------------

def _require_kgc():
    if session.get("role") != "kgc":
        flash("KGC access required.", "danger")
        return redirect(url_for("index_page"))
    return None


# ---------------------------------------------------------------------------
# KGC Login (simple — production would use hardware token)
# ---------------------------------------------------------------------------

@kgc_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, role="kgc").first()
        if user and _check_password(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = "kgc"
            return redirect(url_for("kgc.dashboard"))
        flash("Invalid KGC credentials.", "danger")
    return render_template("kgc/login.html")


@kgc_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index_page"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@kgc_bp.route("/")
@kgc_bp.route("/dashboard")
def dashboard():
    guard = _require_kgc()
    if guard:
        return guard
    params = current_app.cls_params
    patient_count = User.query.filter_by(role="patient").count()
    doctor_count  = User.query.filter_by(role="doctor").count()
    active_pseudonyms = Pseudonym.query.filter_by(active=True, revoked=False).count()
    revoked_count = Pseudonym.query.filter_by(revoked=True).count()
    auth_session_count = AuthSession.query.count()
    return render_template(
        "kgc/dashboard.html",
        P_pub_hex=serialize_point(params.P_pub),
        curve="secp256r1 (NIST P-256)",
        patient_count=patient_count,
        doctor_count=doctor_count,
        active_pseudonyms=active_pseudonyms,
        revoked_count=revoked_count,
        auth_session_count=auth_session_count,
    )


# ---------------------------------------------------------------------------
# Issue partial private key
# ---------------------------------------------------------------------------

@kgc_bp.route("/issue_key/<int:user_id>", methods=["POST"])
def issue_key(user_id):
    guard = _require_kgc()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    params = current_app.cls_params
    msk    = current_app.cls_msk

    # Generate partial private key D = (R, d)
    D = partial_priv_key_gen(params, msk, user.username)

    # Generate user's secret value and full key pair
    x = secret_value_gen(params)
    pk_record, SK = key_gen(params, user.username, D, x)

    # Persist public key components only
    existing = CLSKeyRecord.query.filter_by(user_id=user.id).first()
    if existing:
        existing.PK_hex = serialize_point(pk_record["PK"])
        existing.R_hex  = serialize_point(pk_record["R"])
    else:
        record = CLSKeyRecord(
            user_id=user.id,
            PK_hex=serialize_point(pk_record["PK"]),
            R_hex=serialize_point(pk_record["R"]),
        )
        db.session.add(record)
    db.session.commit()

    # Return SK to the caller (only available at this moment)
    flash(f"Keys issued to {user.username}. Private key shown once — copy it securely.", "success")
    return render_template(
        "kgc/key_issued.html",
        user=user,
        SK_x=SK["x"],
        SK_d=D["d"],
        SK_R=serialize_point(D["R"]),
        PK_hex=serialize_point(pk_record["PK"]),
        R_hex=serialize_point(pk_record["R"]),
    )


# ---------------------------------------------------------------------------
# Manage users — list all for key issuance
# ---------------------------------------------------------------------------

@kgc_bp.route("/users")
def users():
    guard = _require_kgc()
    if guard:
        return guard
    patients = User.query.filter_by(role="patient").all()
    doctors  = User.query.filter_by(role="doctor").all()
    return render_template("kgc/users.html", patients=patients, doctors=doctors)


# ---------------------------------------------------------------------------
# Trace identity
# ---------------------------------------------------------------------------

@kgc_bp.route("/trace_identity", methods=["GET", "POST"])
def trace_identity():
    guard = _require_kgc()
    if guard:
        return guard

    real_id = None
    rid_queried = None
    if request.method == "POST":
        rid = request.form.get("rid", "").strip()
        token = current_app.config["KGC_AUTHORITY_TOKEN"]
        rid_queried = rid
        real_id = current_app.pseudonym_manager.trace_identity(rid, token)
        if real_id is None:
            flash(f"RID '{rid}' not found or authority check failed.", "warning")
        else:
            flash(f"Traced: {rid} → {real_id}", "success")

    trace_log = current_app.pseudonym_manager.get_trace_log()
    return render_template(
        "kgc/trace_identity.html",
        real_id=real_id,
        rid_queried=rid_queried,
        trace_log=trace_log,
    )


# ---------------------------------------------------------------------------
# Revoke pseudonym
# ---------------------------------------------------------------------------

@kgc_bp.route("/revoke/<rid>", methods=["POST"])
def revoke(rid):
    guard = _require_kgc()
    if guard:
        return guard

    reason = request.form.get("reason", "KGC order")
    ok = current_app.pseudonym_manager.revoke_pseudonym(rid, reason)
    if ok:
        # Persist revocation in DB
        row = Pseudonym.query.filter_by(RID=rid).first()
        if row:
            row.revoked = True
            row.active  = False
            row.revoke_reason = reason
            db.session.commit()
        flash(f"Pseudonym {rid} revoked.", "success")
    else:
        flash(f"Pseudonym {rid} not found.", "danger")
    return redirect(url_for("kgc.revocation_list"))


# ---------------------------------------------------------------------------
# Revocation list
# ---------------------------------------------------------------------------

@kgc_bp.route("/revocation_list")
def revocation_list():
    guard = _require_kgc()
    if guard:
        return guard
    revoked = current_app.pseudonym_manager.get_revocation_list()
    return render_template("kgc/revocation_list.html", revoked=revoked)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@kgc_bp.route("/audit_log")
def audit_log():
    guard = _require_kgc()
    if guard:
        return guard
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template("kgc/audit_log.html", logs=logs)


# ---------------------------------------------------------------------------
# Auth sessions — completed mutual authentication sessions
# ---------------------------------------------------------------------------

@kgc_bp.route("/auth_sessions")
def auth_sessions():
    guard = _require_kgc()
    if guard:
        return guard
    sessions = AuthSession.query.order_by(AuthSession.established_at.desc()).limit(100).all()
    # Resolve RIDs for display
    session_rows = []
    for s in sessions:
        initiator = User.query.get(s.initiator_id)
        responder = User.query.get(s.responder_id)
        # Find RIDs associated with each user
        init_pseudo = Pseudonym.query.filter_by(user_id=s.initiator_id, active=True).first()
        resp_pseudo = Pseudonym.query.filter_by(user_id=s.responder_id, active=True).first()
        session_rows.append({
            "session": s,
            "initiator_name": initiator.username if initiator else "—",
            "responder_name": responder.username if responder else "—",
            "initiator_rid": init_pseudo.RID if init_pseudo else "—",
            "responder_rid": resp_pseudo.RID if resp_pseudo else "—",
        })
    return render_template("kgc/auth_sessions.html", session_rows=session_rows)


# ---------------------------------------------------------------------------
# System parameters (public — no auth required)
# ---------------------------------------------------------------------------

@kgc_bp.route("/system_params")
def system_params():
    params = current_app.cls_params
    return render_template(
        "kgc/system_params.html",
        P_pub_hex=serialize_point(params.P_pub),
        curve="secp256r1 (NIST P-256)",
        group_order_hex=hex(params.q),
        hash_functions=[
            ("H1", "SHA-256(\"CLS_H1|\" || P_pub || ID || R)"),
            ("H2", "SHA-256(\"CLS_H2|\" || P_pub || ID || PK || m || T)"),
            ("H3", "SHA-256(\"CLS_H3|\" || P_pub || ID || PK || m || T || h2)  [chained on h2]"),
            ("H4", "SHA-256(\"CLS_H4|\" || P_pub || ID || m || PK || T)"),
        ],
        sign_formula="σ = k + h3·(d + x·h2) + h4·x  mod q",
        verify_equation="σ·P = T + h3·(R + H1(P_pub,ID,R)·P_pub + h2·PK) + h4·PK",
    )


# ---------------------------------------------------------------------------
# Register a new KGC admin (first-run only — only if no KGC user exists)
# ---------------------------------------------------------------------------

@kgc_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if User.query.filter_by(role="kgc").count() > 0:
        flash("KGC admin already exists.", "info")
        return redirect(url_for("kgc.login"))
    if request.method == "POST":
        username = request.form.get("username", "admin").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required.", "danger")
        else:
            user = User(
                username=username,
                password_hash=_hash_password(password),
                role="kgc",
            )
            db.session.add(user)
            db.session.commit()
            flash("KGC admin created. Please log in.", "success")
            return redirect(url_for("kgc.login"))
    return render_template("kgc/setup.html")


# ---------------------------------------------------------------------------
# Password helpers (bcrypt)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(stored_hash: str, password: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        return False
