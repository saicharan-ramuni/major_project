"""
Doctor Blueprint — /doctor/*

Handles:
  - Doctor registration and login
  - View and verify patient health records (CLS signature check + green/red badge)
  - Single signature verify (AJAX)
  - Batch verification of multiple records
  - Mutual authentication response (Step 2)
"""

import hashlib
import json
import time
from datetime import datetime, timedelta

import bcrypt
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app, jsonify,
                   send_file, abort)
import io

from app import db
from app.models import (User, CLSKeyRecord, Pseudonym, HealthRecord,
                        AuditLog, BatchVerifyLog, AuthSession)
from crypto.cls_scheme import (
    partial_priv_key_gen, secret_value_gen, key_gen,
    sign, verify, batch_verify,
    serialize_point, deserialize_point, compress_point,
    precompute_sid_kid,
    serialize_pk_record, serialize_signature, deserialize_signature,
    deserialize_pk_record
)

doctor_bp = Blueprint("doctor", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_doctor():
    if session.get("role") != "doctor":
        flash("Please log in as a doctor.", "warning")
        return redirect(url_for("doctor.login"))
    return None


def _load_sk():  # returns Optional[dict]
    sk_json = session.get("SK")
    if not sk_json:
        return None
    raw = json.loads(sk_json)
    return {
        "x": int(raw["x"]),
        "d": int(raw["d"]),
    }


def _log_access(patient_id, accessor_rid, record_id, action, SK=None, R=None):
    """Write a CLS-signed audit log entry."""
    log = AuditLog(
        patient_id=patient_id,
        accessor_RID=accessor_rid,
        record_id=record_id,
        action=action,
    )
    if SK:
        try:
            params = current_app.cls_params
            message = f"audit|{action}|{record_id}|{int(time.time())}"
            R_point = deserialize_point(session.get("signer_R_hex", "")) if R is None else R
            sig = sign(params, SK, accessor_rid, message, R=R_point)
            log.T_hex = compress_point(sig["KID_k"])   # KID_k stored in T_hex column
            log.sigma  = str(sig["sigma"])
        except Exception:
            pass
    db.session.add(log)


# ---------------------------------------------------------------------------
# Register (done via KGC in production; here admin creates via form)
# ---------------------------------------------------------------------------

@doctor_bp.route("/register", methods=["GET", "POST"])
def register():
    # Any logged-in KGC admin can register doctors, or allow self-registration
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        if not username or not password:
            flash("Username and password required.", "danger")
            return render_template("doctor/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("doctor/register.html")

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User(username=username, password_hash=pw_hash, role="doctor", email=email)
        db.session.add(user)
        db.session.flush()

        params = current_app.cls_params
        msk    = current_app.cls_msk
        pman   = current_app.pseudonym_manager

        from crypto.cls_scheme import _point_mul
        import time as _time_d
        x   = secret_value_gen(params)
        X   = _point_mul(x, params.G)
        v_t = int(_time_d.time())

        D = partial_priv_key_gen(params, msk, username, X, v_t)
        rid_for_key = D["pseudo_id"]
        validity_expiry = v_t + 86400 * 30

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
        pman.register_pseudonym(rid_for_key, username, v_t, validity_expiry)
        db.session.commit()

        print("\n" + "=" * 62)
        print("  CLS REGISTRATION — DOCTOR")
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

        flash("Doctor registered. Please log in.", "success")
        return redirect(url_for("doctor.login"))

    return render_template("doctor/register.html")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@doctor_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username, role="doctor").first()
        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            flash("Invalid credentials.", "danger")
            return render_template("doctor/login.html")

        params = current_app.cls_params
        msk    = current_app.cls_msk
        pman2  = current_app.pseudonym_manager
        active_rid_d = pman2.get_current_pseudonym(username)
        if not active_rid_d:
            flash("No active pseudonym. Please contact KGC.", "danger")
            return render_template("doctor/login.html")

        from crypto.cls_scheme import _point_mul
        x   = secret_value_gen(params)
        X   = _point_mul(x, params.G)
        D   = partial_priv_key_gen(params, msk, active_rid_d, X)
        pk_record, SK = key_gen(params, active_rid_d, D, x)

        key_rec = CLSKeyRecord.query.filter_by(user_id=user.id).first()
        if key_rec:
            key_rec.PK_hex = serialize_point(pk_record["PK"])
            key_rec.R_hex  = serialize_point(pk_record["R"])
            db.session.commit()

        session.clear()
        session["user_id"]  = user.id
        session["username"] = username
        session["role"]     = "doctor"
        session["SK"] = json.dumps({
            "x": str(SK["x"]),
            "d": str(SK["d"]),
        })
        session["signer_R_hex"] = serialize_point(pk_record["R"])

        # Precompute SID/KID pairs for zero-EC-mult signing (used in audit log)
        SID_list, KID_list = precompute_sid_kid(
            params, active_rid_d, SK, pk_record, n=20
        )
        session["SID_list"]  = [str(s) for s in SID_list]
        session["KID_list"]  = [compress_point(k) for k in KID_list]
        session["sid_index"] = 0

        return redirect(url_for("doctor.dashboard"))

    return render_template("doctor/login.html")


@doctor_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index_page"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@doctor_bp.route("/dashboard")
@doctor_bp.route("/")
def dashboard():
    guard = _require_doctor()
    if guard:
        return guard

    # Show distinct patients (by RID) who have records
    records = HealthRecord.query.order_by(HealthRecord.signed_at.desc()).limit(5).all()
    batch_logs = BatchVerifyLog.query.filter_by(
        submitted_by=session["user_id"]
    ).order_by(BatchVerifyLog.submitted_at.desc()).limit(5).all()

    return render_template(
        "doctor/dashboard.html",
        username=session["username"],
        recent_records=records,
        batch_logs=batch_logs,
    )


# ---------------------------------------------------------------------------
# View and verify a patient's records by RID
# ---------------------------------------------------------------------------

@doctor_bp.route("/records")
def records_search():
    guard = _require_doctor()
    if guard:
        return guard
    return render_template("doctor/records_search.html")


@doctor_bp.route("/records/<rid>")
def view_records(rid):
    guard = _require_doctor()
    if guard:
        return guard

    # Check revocation
    if not current_app.pseudonym_manager.is_valid(rid):
        flash(f"Pseudonym {rid} is invalid, expired, or revoked.", "danger")
        return redirect(url_for("doctor.records_search"))

    records = HealthRecord.query.filter_by(RID=rid).order_by(
        HealthRecord.signed_at.desc()
    ).all()

    # Verify each record's signature
    params = current_app.cls_params
    SK = _load_sk()
    doctor_rid = None
    if SK:
        username = session["username"]
        pman = current_app.pseudonym_manager
        doctor_rid = pman.get_current_pseudonym(username)

    verified_records = []
    _verify_stats = []   # collect per-record timing for summary print

    for rec in records:
        # Use the PK and R stored at signing time — not the current key in
        # CLSKeyRecord, which may have been rotated since the record was signed.
        valid = False
        _elapsed_ms = 0.0
        if rec.signer_PK_hex and rec.signer_R_hex:
            pk_record = {
                "PK": deserialize_point(rec.signer_PK_hex),
                "R":  deserialize_point(rec.signer_R_hex),
            }
            sig = {"KID_k": deserialize_point(rec.T_hex), "sigma": int(rec.sigma)}
            try:
                import time as _time_mod
                _t0 = _time_mod.perf_counter()
                valid = verify(params, rec.RID, pk_record, rec.message_signed, sig)
                _elapsed_ms = (_time_mod.perf_counter() - _t0) * 1000
            except Exception:
                valid = False

        # Signature size: T stored as compressed (33 bytes) + sigma (32 bytes)
        _T_bytes   = len(bytes.fromhex(rec.T_hex)) if rec.T_hex else 0  # 33 if compressed
        _sig_bytes = (int(rec.sigma).bit_length() + 7) // 8 if rec.sigma else 0
        _verify_stats.append({
            "record_id": rec.id,
            "valid":     valid,
            "ms":        _elapsed_ms,
            "sig_bytes": _T_bytes + _sig_bytes,
        })

        pseudo_row = Pseudonym.query.filter_by(RID=rec.RID).first()

        # Log access (CLS-signed if doctor has SK)
        if doctor_rid:
            R_for_log = deserialize_point(session.get("signer_R_hex", ""))
            _log_access(pseudo_row.user_id if pseudo_row else None,
                        doctor_rid, rec.id, "view", SK, R=R_for_log)

        verified_records.append({"record": rec, "valid": valid})

    # Print verification summary to terminal
    if _verify_stats:
        _total_ms  = sum(s["ms"] for s in _verify_stats)
        _avg_ms    = _total_ms / len(_verify_stats)
        _all_valid = all(s["valid"] for s in _verify_stats)
        print(
            f"\n{'='*60}\n"
            f"[CLS VERIFY]  doctor={session.get('username')}  rid={rid[:12]}...\n"
            f"  Records checked : {len(_verify_stats)}\n"
            f"  All valid       : {_all_valid}\n"
            f"  Avg verify time : {_avg_ms:.2f} ms\n"
            f"  Total time      : {_total_ms:.2f} ms",
            flush=True
        )
        for s in _verify_stats:
            status = "VALID  " if s["valid"] else "INVALID"
            print(
                f"    record #{s['record_id']:>4}  [{status}]"
                f"  verify={s['ms']:.2f} ms"
                f"  sig={s['sig_bytes']} bytes ({s['sig_bytes']*8} bits)",
                flush=True
            )
        print(f"{'='*60}", flush=True)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template(
        "doctor/view_records.html",
        rid=rid,
        verified_records=verified_records,
    )


# ---------------------------------------------------------------------------
# Single signature verify (AJAX)
# ---------------------------------------------------------------------------

@doctor_bp.route("/verify_signature", methods=["POST"])
def verify_signature():
    guard = _require_doctor()
    if guard:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    rid     = data.get("rid", "")
    PK_hex  = data.get("PK_hex", "")
    R_hex   = data.get("R_hex", "")
    message = data.get("message", "")
    T_hex   = data.get("T_hex", "")
    sigma   = data.get("sigma")

    try:
        params = current_app.cls_params
        pk_record = {
            "PK": deserialize_point(PK_hex),
            "R":  deserialize_point(R_hex),
        }
        sig = {"KID_k": deserialize_point(T_hex), "sigma": int(sigma)}
        valid = verify(params, rid, pk_record, message, sig)
        return jsonify({"valid": valid})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


# ---------------------------------------------------------------------------
# Batch verification
# ---------------------------------------------------------------------------

@doctor_bp.route("/batch_verify", methods=["GET", "POST"])
def batch_verify_view():
    guard = _require_doctor()
    if guard:
        return guard

    if request.method == "GET":
        return render_template("doctor/batch_verify.html")

    # POST: accept JSON array or uploaded file
    items_raw = None
    if request.files.get("json_file"):
        items_raw = json.loads(request.files["json_file"].read())
    elif request.is_json:
        items_raw = request.get_json()
    else:
        try:
            items_raw = json.loads(request.form.get("json_data", "[]"))
        except Exception:
            flash("Invalid JSON.", "danger")
            return render_template("doctor/batch_verify.html")

    params = current_app.cls_params
    items = []
    for raw in items_raw:
        try:
            item = {
                "identity":  raw["identity"],
                "pk_record": deserialize_pk_record(raw["pk_record"]),
                "message":   raw["message"],
                "signature": deserialize_signature(raw["signature"]),
            }
            items.append(item)
        except Exception:
            continue

    start = time.time()
    all_valid, passed, failed = batch_verify(params, items)
    elapsed_ms = round((time.time() - start) * 1000, 2)

    # Per-signature size stats
    _sig_sizes = []
    for item in items:
        _kid_point = item["signature"].get("KID_k") or item["signature"].get("T")
        _T_b   = len(bytes.fromhex(serialize_point(_kid_point)))
        _sig_b = (item["signature"]["sigma"].bit_length() + 7) // 8
        _sig_sizes.append(_T_b + _sig_b)
    _avg_sig = sum(_sig_sizes) / len(_sig_sizes) if _sig_sizes else 0

    print(
        f"\n{'='*60}\n"
        f"[CLS BATCH VERIFY]  doctor={session.get('username')}\n"
        f"  Items submitted : {len(items)}\n"
        f"  Passed          : {passed}\n"
        f"  Failed          : {failed}\n"
        f"  All valid       : {all_valid}\n"
        f"  Total time      : {elapsed_ms} ms\n"
        f"  Avg per sig     : {elapsed_ms/len(items):.2f} ms  (batch)\n"
        f"  Avg sig size    : {_avg_sig:.0f} bytes ({_avg_sig*8:.0f} bits)\n"
        f"{'='*60}", flush=True
    )

    # Log
    log = BatchVerifyLog(
        submitted_by=session["user_id"],
        item_count=len(items),
        passed=passed,
        failed=failed,
        all_valid=all_valid,
    )
    db.session.add(log)
    db.session.commit()

    return render_template(
        "doctor/batch_verify_result.html",
        all_valid=all_valid,
        passed=passed,
        failed=failed,
        total=len(items),
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Download a patient's health record file (doctor side)
# ---------------------------------------------------------------------------

@doctor_bp.route("/download/<int:record_id>")
def download_record(record_id):
    guard = _require_doctor()
    if guard:
        return guard

    rec = HealthRecord.query.get_or_404(record_id)

    # Verify the RID is still valid before allowing download
    if not current_app.pseudonym_manager.is_valid(rec.RID):
        flash("This pseudonym is revoked or expired.", "danger")
        return redirect(url_for("doctor.records_search"))

    # Decrypt the file using the app's AES-256-GCM record key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(rec.nonce, rec.data_encrypted, None)
    except Exception:
        flash("File decryption failed.", "danger")
        return redirect(url_for("doctor.view_records", rid=rec.RID))

    # Log the download
    SK = _load_sk()
    pman = current_app.pseudonym_manager
    doctor_rid = pman.get_current_pseudonym(session["username"])
    if doctor_rid:
        R_for_log = deserialize_point(session.get("signer_R_hex", ""))
        _log_access(None, doctor_rid, rec.id, "download", SK, R=R_for_log)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return send_file(
        io.BytesIO(plaintext),
        download_name=rec.filename or f"record_{rec.id}.bin",
        as_attachment=True,
    )


# ---------------------------------------------------------------------------
# Mutual authentication — Step 2
# ---------------------------------------------------------------------------

@doctor_bp.route("/authenticate/step2", methods=["POST"])
def auth_step2():
    guard = _require_doctor()
    if guard:
        return jsonify({"error": "Unauthorized"}), 401

    SK = _load_sk()
    if not SK:
        return jsonify({"error": "Session expired"}), 401

    msg1 = request.get_json(force=True)
    RID_a = msg1.get("RID_a", "")

    # Look up patient's public key by RID
    pseudo_row = Pseudonym.query.filter_by(RID=RID_a).first()
    if not pseudo_row:
        return jsonify({"error": "Unknown patient pseudonym"}), 400

    key_rec = CLSKeyRecord.query.filter_by(user_id=pseudo_row.user_id).first()
    if not key_rec:
        return jsonify({"error": "Patient has no registered key"}), 400

    pk_a = {
        "PK": deserialize_point(key_rec.PK_hex),
        "R":  deserialize_point(key_rec.R_hex),
    }

    username = session["username"]
    pman = current_app.pseudonym_manager
    rid_b = pman.get_current_pseudonym(username)
    if not rid_b:
        return jsonify({"error": "Doctor has no valid pseudonym"}), 400

    try:
        auth_protocol = current_app.auth_protocol
        R_b = deserialize_point(session.get("signer_R_hex", ""))
        msg2, session_b = auth_protocol.responder_step2(msg1, pk_a, SK, rid_b, R_b)

        # Store completed session
        K_hash = hashlib.sha256(session_b.session_key).hexdigest()
        auth_sess = AuthSession(
            initiator_id=pseudo_row.user_id,
            responder_id=session["user_id"],
            session_key_hash=K_hash,
            W_a_hex=msg1.get("W_a", ""),
            W_b_hex=session_b.W_hex,
            T_a=msg1.get("T_a"),
            T_b=session_b.T,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db.session.add(auth_sess)
        db.session.commit()

        return jsonify(msg2)

    except Exception as e:
        return jsonify({"error": str(e)}), 400
