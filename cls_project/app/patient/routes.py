"""
Patient Blueprint — /patient/*

Handles:
  - Registration (creates user + requests KGC to issue partial key)
  - Login (loads SK into Flask session)
  - Pseudonym management (view current RID, rotate)
  - Health record upload (encrypt + CLS sign)
  - Mutual authentication initiation (Step 1)
"""

import hashlib
import json
import secrets as _secrets
import time
from datetime import datetime

import bcrypt
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app, jsonify)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import db
from app.models import User, CLSKeyRecord, Pseudonym, HealthRecord, AuditLog
from crypto.cls_scheme import (
    partial_priv_key_gen, secret_value_gen, key_gen,
    sign, serialize_point, deserialize_point,
    compress_point, decompress_point,
    precompute_sid_kid,
    serialize_pk_record, serialize_signature, deserialize_pk_record
)

patient_bp = Blueprint("patient", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_patient():
    if session.get("role") != "patient":
        flash("Please log in as a patient.", "warning")
        return redirect(url_for("patient.login"))
    return None


def _record_key() -> bytes:
    """AES-256 key derived from app secret — used for health record encryption."""
    return hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()


def _load_sk():  # returns Optional[dict]
    """Load SK from Flask session (stored as JSON after login)."""
    sk_json = session.get("SK")
    if not sk_json:
        return None
    raw = json.loads(sk_json)
    return {
        "x": int(raw["x"]),
        "d": int(raw["d"]),
    }


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@patient_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("patient/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("patient/register.html")

        # Create user
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User(username=username, password_hash=pw_hash, role="patient", email=email)
        db.session.add(user)
        db.session.flush()  # get user.id

        params = current_app.cls_params
        msk    = current_app.cls_msk
        pman   = current_app.pseudonym_manager

        # User generates secret value first so X = x·P can be passed to KGC
        from crypto.cls_scheme import _point_mul
        import time as _time
        x   = secret_value_gen(params)
        X   = _point_mul(x, params.G)
        v_t = int(_time.time())

        # KGC generates partial key and derives anonymous pseudonym
        D = partial_priv_key_gen(params, msk, username, X, v_t)
        rid_for_key = D["pseudo_id"]
        validity_expiry = v_t + 86400 * 30  # 30 days

        pk_record, SK = key_gen(params, rid_for_key, D, x)

        key_rec = CLSKeyRecord(
            user_id=user.id,
            PK_hex=serialize_point(pk_record["PK"]),
            R_hex=serialize_point(pk_record["R"]),
        )
        db.session.add(key_rec)

        pseudo = Pseudonym(
            RID=rid_for_key,
            user_id=user.id,
            validity_start=v_t,
            validity_expiry=validity_expiry,
            active=True,
        )
        db.session.add(pseudo)

        # Register in pseudonym manager (externally computed RID)
        pman.register_pseudonym(rid_for_key, username, v_t, validity_expiry)

        db.session.commit()

        print("\n" + "=" * 62)
        print("  CLS REGISTRATION — PATIENT")
        print("=" * 62)
        print(f"  Username            : {username}")
        print(f"  Pseudonym (RID)     : {rid_for_key}")
        print(f"  Valid until         : {validity_expiry}  (Unix ts, 30 days)")
        print("-" * 62)
        print("  — Public Parameters (params) —")
        print(f"  G  (base point)     : {serialize_point(params.G)[:48]}...")
        print(f"  P_pub = s·G         : {serialize_point(params.P_pub)[:48]}...")
        print(f"  q  (curve order)    : {hex(params.q)[:48]}...")
        print("-" * 62)
        print("  — Per-User Public Keys (stored in DB) —")
        print(f"  R  = r·G            : {serialize_point(pk_record['R'])[:48]}...")
        print(f"  X  = x·G            : {serialize_point(pk_record['PK'])[:48]}...")
        print(f"  PK = R + X          : {serialize_point(pk_record['PK'])[:48]}...")
        print("-" * 62)
        print("  — Private Keys (session only, never persisted) —")
        print(f"  x  (secret value)   : {str(SK['x'])[:48]}...")
        print(f"  d  (partial priv)   : {str(SK['d'])[:48]}...")
        print("=" * 62 + "\n")

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("patient.login"))

    return render_template("patient/register.html")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@patient_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username, role="patient").first()
        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            flash("Invalid credentials.", "danger")
            return render_template("patient/login.html")

        params = current_app.cls_params
        msk    = current_app.cls_msk
        pman2  = current_app.pseudonym_manager
        active_rid = pman2.get_current_pseudonym(username)
        if not active_rid:
            flash("No active pseudonym found. Please contact KGC.", "danger")
            return render_template("patient/login.html")

        from crypto.cls_scheme import _point_mul
        x   = secret_value_gen(params)
        X   = _point_mul(x, params.G)
        D   = partial_priv_key_gen(params, msk, active_rid, X)
        pk_record, SK = key_gen(params, active_rid, D, x)

        key_rec = CLSKeyRecord.query.filter_by(user_id=user.id).first()
        if key_rec:
            key_rec.PK_hex = serialize_point(pk_record["PK"])
            key_rec.R_hex  = serialize_point(pk_record["R"])
            db.session.commit()

        session.clear()
        session["user_id"]  = user.id
        session["username"] = username
        session["role"]     = "patient"
        session["SK"] = json.dumps({
            "x": str(SK["x"]),
            "d": str(SK["d"]),
        })
        session["signer_R_hex"] = serialize_point(pk_record["R"])

        # Precompute SID/KID pairs for zero-EC-mult signing
        SID_list, KID_list = precompute_sid_kid(
            params, active_rid, SK, pk_record, n=20
        )
        session["SID_list"]  = [str(s) for s in SID_list]
        session["KID_list"]  = [compress_point(k) for k in KID_list]
        session["sid_index"] = 0

        return redirect(url_for("patient.dashboard"))

    return render_template("patient/login.html")


@patient_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index_page"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@patient_bp.route("/dashboard")
def dashboard():
    guard = _require_patient()
    if guard:
        return guard

    username = session["username"]
    pman = current_app.pseudonym_manager
    rid  = pman.get_current_pseudonym(username)
    rid_info = pman.get_pseudonym_info(rid) if rid else None

    records = HealthRecord.query.filter_by(
        patient_id=session["user_id"]
    ).order_by(HealthRecord.signed_at.desc()).limit(10).all()

    return render_template(
        "patient/dashboard.html",
        username=username,
        rid=rid,
        rid_info=rid_info,
        records=records,
    )


# ---------------------------------------------------------------------------
# Pseudonym management
# ---------------------------------------------------------------------------

@patient_bp.route("/pseudonym")
def pseudonym():
    guard = _require_patient()
    if guard:
        return guard

    username = session["username"]
    pman = current_app.pseudonym_manager
    rid  = pman.get_current_pseudonym(username)
    rid_info = pman.get_pseudonym_info(rid) if rid else None
    return render_template("patient/pseudonym.html", rid=rid, rid_info=rid_info)


@patient_bp.route("/pseudonym/rotate", methods=["POST"])
def rotate_pseudonym():
    guard = _require_patient()
    if guard:
        return guard

    username = session["username"]
    user_id  = session["user_id"]
    pman = current_app.pseudonym_manager

    # Deactivate old pseudonym in DB
    old_rid = pman.get_current_pseudonym(username)
    if old_rid:
        old_row = Pseudonym.query.filter_by(RID=old_rid).first()
        if old_row:
            old_row.active = False

    # Generate new pseudonym
    rid_info = pman.rotate_pseudonym(username)
    new_row = Pseudonym(
        RID=rid_info["RID"],
        user_id=user_id,
        validity_start=rid_info["validity_start"],
        validity_expiry=rid_info["validity_expiry"],
        active=True,
    )
    db.session.add(new_row)
    db.session.commit()

    flash(f"New pseudonym generated: {rid_info['RID']}", "success")
    return redirect(url_for("patient.pseudonym"))


# ---------------------------------------------------------------------------
# Health records — list
# ---------------------------------------------------------------------------

@patient_bp.route("/health_records")
def health_records():
    guard = _require_patient()
    if guard:
        return guard

    records = HealthRecord.query.filter_by(
        patient_id=session["user_id"]
    ).order_by(HealthRecord.signed_at.desc()).all()

    # Verify each record's CLS signature using the key stored at signing time
    params = current_app.cls_params
    from crypto.cls_scheme import verify, deserialize_point
    verified_records = []
    for rec in records:
        valid = False
        if rec.signer_PK_hex and rec.signer_R_hex:
            pk_record = {
                "PK": deserialize_point(rec.signer_PK_hex),
                "R":  deserialize_point(rec.signer_R_hex),
            }
            sig = {"KID_k": deserialize_point(rec.T_hex), "sigma": int(rec.sigma)}
            try:
                valid = verify(params, rec.RID, pk_record, rec.message_signed, sig)
            except Exception:
                valid = False
        verified_records.append((rec, valid))

    return render_template("patient/health_records.html", records=verified_records)


# ---------------------------------------------------------------------------
# Health records — upload & sign
# ---------------------------------------------------------------------------

@patient_bp.route("/health_records/upload", methods=["GET", "POST"])
def upload_health_record():
    guard = _require_patient()
    if guard:
        return guard

    if request.method == "POST":
        SK = _load_sk()
        if not SK:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("patient.login"))

        username = session["username"]
        pman = current_app.pseudonym_manager
        rid  = pman.get_current_pseudonym(username)
        if not rid:
            flash("No valid pseudonym. Please rotate your pseudonym first.", "warning")
            return redirect(url_for("patient.pseudonym"))

        file       = request.files.get("file")
        data_type  = request.form.get("data_type", "general")
        hospitals  = request.form.get("hospitals", "")

        if not file or file.filename == "":
            flash("No file selected.", "danger")
            return render_template("patient/upload.html")

        plaintext = file.read()
        filename  = file.filename

        # Encrypt with AES-256-GCM
        key   = _record_key()
        nonce = _secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Build the message string that will be signed
        content_hash = hashlib.sha256(plaintext).hexdigest()
        timestamp_str = str(int(time.time()))
        message = f"{rid}|{data_type}|{timestamp_str}|{content_hash}"

        # CLS Sign — use precomputed SID_k/KID_k (zero EC scalar mult)
        params = current_app.cls_params
        R_point = deserialize_point(session.get("signer_R_hex", ""))

        # Retrieve next precomputed SID_k / KID_k pair
        sid_idx  = session.get("sid_index", 0)
        SID_list = session.get("SID_list", [])
        KID_list = session.get("KID_list", [])
        if sid_idx >= len(SID_list):
            # Exhausted — regenerate
            key_rec_tmp = CLSKeyRecord.query.filter_by(user_id=session["user_id"]).first()
            tmp_pk = {
                "PK": deserialize_point(key_rec_tmp.PK_hex),
                "R":  deserialize_point(key_rec_tmp.R_hex),
            }
            new_SID, new_KID = precompute_sid_kid(params, rid, SK, tmp_pk, n=20)
            SID_list = [str(s) for s in new_SID]
            KID_list = [compress_point(k) for k in new_KID]
            sid_idx  = 0
            session["SID_list"] = SID_list
            session["KID_list"] = KID_list

        SID_k = int(SID_list[sid_idx])
        KID_k = deserialize_point(KID_list[sid_idx])
        session["sid_index"] = sid_idx + 1

        _t_sign_start = time.perf_counter()
        sig = sign(params, SK, rid, message, R=R_point, SID_k=SID_k, KID_k=KID_k)
        _t_sign_ms = (time.perf_counter() - _t_sign_start) * 1000

        # Signature size: T compressed (33 bytes) + sigma (32 bytes) = 65 bytes
        _T_compressed = compress_point(sig["KID_k"])          # 66-char hex = 33 bytes
        _T_bytes      = len(bytes.fromhex(_T_compressed)) # 33
        _sig_bytes    = (sig["sigma"].bit_length() + 7) // 8
        _total_bytes  = _T_bytes + _sig_bytes
        _total_bits   = _total_bytes * 8
        print(
            f"\n{'='*60}\n"
            f"[CLS SIGN]  user={session['username']}  rid={rid[:12]}...\n"
            f"  Sign time            : {_t_sign_ms:.2f} ms\n"
            f"  T (compressed point) : {_T_bytes} bytes  (was 64 uncompressed)\n"
            f"  σ (scalar)           : {_sig_bytes} bytes\n"
            f"  Signature total      : {_total_bytes} bytes  ({_total_bits} bits)\n"
            f"  Saving vs uncompressed: {64 - _T_bytes} bytes\n"
            f"{'='*60}", flush=True
        )

        from crypto.cls_scheme import _point_mul
        signer_X = _point_mul(SK["x"], params.G)   # X = x·P

        # Get R from session (stored at login) or fall back to CLSKeyRecord
        signer_R_hex_val = session.get("signer_R_hex")
        if not signer_R_hex_val:
            key_rec_r = CLSKeyRecord.query.filter_by(user_id=session["user_id"]).first()
            signer_R_hex_val = key_rec_r.R_hex if key_rec_r else None

        rec = HealthRecord(
            patient_id=session["user_id"],
            RID=rid,
            data_encrypted=ciphertext,
            nonce=nonce,
            data_type=data_type,
            filename=filename,
            T_hex=compress_point(sig["KID_k"]),   # KID_k stored in T_hex column
            sigma=str(sig["sigma"]),
            message_signed=message,
            signer_PK_hex=serialize_point(signer_X),
            signer_R_hex=signer_R_hex_val,
            hospitals_shared=hospitals,
        )
        db.session.add(rec)
        db.session.commit()

        flash("Health record uploaded and signed successfully.", "success")
        return render_template(
            "patient/upload_success.html",
            record=rec,
            sig_T=serialize_point(sig["KID_k"])[:32] + "…",
            sig_sigma=str(sig["sigma"])[:20] + "…",
        )

    return render_template("patient/upload.html")


# ---------------------------------------------------------------------------
# Mutual authentication — Step 1
# ---------------------------------------------------------------------------

@patient_bp.route("/authenticate/<doctor_username>", methods=["GET"])
def auth_initiate(doctor_username):
    guard = _require_patient()
    if guard:
        return guard
    return render_template(
        "patient/auth_session.html",
        doctor_username=doctor_username,
        step=1,
    )


@patient_bp.route("/authenticate/step1", methods=["POST"])
def auth_step1():
    guard = _require_patient()
    if guard:
        return guard

    SK = _load_sk()
    if not SK:
        return jsonify({"error": "Session expired"}), 401

    username = session["username"]
    pman = current_app.pseudonym_manager
    rid  = pman.get_current_pseudonym(username)
    if not rid:
        return jsonify({"error": "No valid pseudonym"}), 400

    auth_protocol = current_app.auth_protocol
    R_a = deserialize_point(session.get("signer_R_hex", ""))
    msg1, auth_session = auth_protocol.initiator_step1(SK, rid, R_a)

    # Store ephemeral state in Flask session
    session["auth_w"]     = str(auth_session.w)
    session["auth_W_hex"] = auth_session.W_hex
    session["auth_T"]     = auth_session.T
    session["auth_RID_a"] = rid

    return jsonify(msg1)


# ---------------------------------------------------------------------------
# Mutual authentication — Step 3 (patient verifies doctor's response)
# ---------------------------------------------------------------------------

@patient_bp.route("/authenticate/step3", methods=["POST"])
def auth_step3():
    guard = _require_patient()
    if guard:
        return jsonify({"error": "Unauthorized"}), 401

    # Recover ephemeral state saved during step 1
    w_a_str  = session.get("auth_w")
    W_a_hex  = session.get("auth_W_hex")
    T_a      = session.get("auth_T")
    RID_a    = session.get("auth_RID_a")
    if not all([w_a_str, W_a_hex, T_a, RID_a]):
        return jsonify({"error": "No active auth session. Run step 1 first."}), 400

    msg2 = request.get_json(force=True)
    RID_b = msg2.get("RID_b", "")

    # Look up doctor's current public key by RID_b
    pseudo_row = Pseudonym.query.filter_by(RID=RID_b).first()
    if not pseudo_row:
        return jsonify({"error": "Unknown doctor pseudonym"}), 400
    key_rec = CLSKeyRecord.query.filter_by(user_id=pseudo_row.user_id).first()
    if not key_rec:
        return jsonify({"error": "Doctor has no registered key"}), 400

    pk_b = {
        "PK": deserialize_point(key_rec.PK_hex),
        "R":  deserialize_point(key_rec.R_hex),
    }

    # Reconstruct initiator AuthSession from saved state
    from crypto.auth_protocol import AuthSession as _AuthSession
    session_a = _AuthSession(
        w=int(w_a_str),
        W_hex=W_a_hex,
        T=T_a,
        RID_a=RID_a,
    )

    try:
        from datetime import timedelta
        from app.models import AuthSession as AuthSessionModel
        auth_protocol = current_app.auth_protocol
        K_ab = auth_protocol.initiator_step3(msg2, pk_b, session_a)

        K_hash = hashlib.sha256(K_ab).hexdigest()

        auth_sess = AuthSessionModel(
            initiator_id=session["user_id"],
            responder_id=pseudo_row.user_id,
            session_key_hash=K_hash,
            W_a_hex=W_a_hex,
            W_b_hex=msg2.get("W_b", ""),
            T_a=T_a,
            T_b=msg2.get("T_b"),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db.session.add(auth_sess)
        db.session.commit()

        # Clear ephemeral state — session is now complete
        for k in ("auth_w", "auth_W_hex", "auth_T", "auth_RID_a"):
            session.pop(k, None)

        return jsonify({
            "status": "authenticated",
            "session_key_hash": K_hash,
            "message": "Mutual authentication complete. Shared session key established."
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400
