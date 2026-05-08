"""
Healthcare BCCA Flask Application
===================================
Blockchain-Based Certificateless Conditional Anonymous Authentication
for Healthcare EHR Sharing.

Implements all 10 algorithms from healthcare_ehr_scheme.md as REST
endpoints, plus a full HTML UI for patients, doctors, and the Hospital
Admin (HA).

Roles
-----
  Hospital Admin (HA)  → /ha/...
  Patient              → /patient/...
  Doctor               → /doctor/...
  Blockchain Node      → /node/...  (consensus server endpoints)
"""

import os, json, time, io, hashlib, base64
from typing import Dict, List, Optional
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_file)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from web3 import Web3, HTTPProvider

# ---------- BCCA modules ----------
from bcca.pkg        import setup as ha_setup, extract_partial_key
from bcca.user       import (register as bcca_register, generate_keys,
                              login as bcca_login, sign_ehr, decrypt_ehr,
                              PRECOMPUTE_N)
from bcca.verify     import verify_ehr, batch_verify_ehr
from bcca.mutual_auth import (patient_auth_request, doctor_verify_and_respond,
                               patient_verify_and_key, doctor_compute_session_key)
from bcca.revocation import revoke_user_access, modify_evidence
from bcca.params_store import (load_params, get_user, get_all_users,
                                get_evidence_entries, is_revoked)
from bcca.ecc_utils  import ECPoint

# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)          # session encryption key

UPLOAD_FOLDER   = os.path.join("static", "ehr_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Keys stored in-memory per session (in production: secure device storage)
# key: session_id → full_key dict
_KEY_STORE: Dict[str, dict] = {}

# In-memory EHR message store (mirrors what is submitted to blockchain)
_EHR_MSGS: List[dict] = []

# Pending registration packets waiting for HA to extract partial key (manual flow)
# key: RID → {upk, RID, UPW, alpha, role}
_PENDING_REG: Dict[str, dict] = {}

# HA-issued partial keys waiting for user to run key generation (manual flow)
# key: RID → partial key dict
_PENDING_PARTIAL: Dict[str, dict] = {}

# RID → pseudo_id mapping for login without pseudonym (one-step registration)
_RID_TO_PSEUDO: Dict[str, str] = {}

# ──────────────────────────────────────────────────────────────────────────────
# Persistent store helpers  (survive server restart)
# ──────────────────────────────────────────────────────────────────────────────

_DATA_DIR       = "bcca_data"
_RID_MAP_FILE   = os.path.join(_DATA_DIR, "rid_map.json")
_KEY_STORE_FILE = os.path.join(_DATA_DIR, "key_store.json")

os.makedirs(_DATA_DIR, exist_ok=True)

def _load_persistent_stores():
    """Load RID→pseudo map and key store from disk on startup."""
    global _RID_TO_PSEUDO, _KEY_STORE
    if os.path.exists(_RID_MAP_FILE):
        try:
            with open(_RID_MAP_FILE, encoding="utf-8") as f:
                _RID_TO_PSEUDO = json.load(f)
        except Exception:
            pass
    if os.path.exists(_KEY_STORE_FILE):
        try:
            with open(_KEY_STORE_FILE, encoding="utf-8") as f:
                _KEY_STORE = json.load(f)
        except Exception:
            pass

def _save_persistent_stores():
    """Persist RID→pseudo map and key store to disk."""
    with open(_RID_MAP_FILE,   "w", encoding="utf-8") as f:
        json.dump(_RID_TO_PSEUDO, f)
    with open(_KEY_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(_KEY_STORE, f)

# Load on import
_load_persistent_stores()

# ──────────────────────────────────────────────────────────────────────────────
# Audit log helpers
# ──────────────────────────────────────────────────────────────────────────────

_AUDIT_FILE = os.path.join(_DATA_DIR, "audit_log.json")

def _append_audit(actor: str, action: str, target: str = "", role: str = ""):
    """Append one entry to the local audit log file."""
    entry = {
        "actor"    : actor,
        "action"   : action,
        "target"   : target,
        "role"     : role,
        "timestamp": int(time.time()),
    }
    logs = []
    if os.path.exists(_AUDIT_FILE):
        try:
            with open(_AUDIT_FILE, encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            pass
    logs.append(entry)
    with open(_AUDIT_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f)

def _load_audit() -> list:
    if not os.path.exists(_AUDIT_FILE):
        return []
    try:
        with open(_AUDIT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

# ──────────────────────────────────────────────────────────────────────────────
# Blockchain helpers
# ──────────────────────────────────────────────────────────────────────────────

BLOCKCHAIN_ADDR    = "http://127.0.0.1:8545"
TRUFFLE_ARTIFACT   = os.path.join("build", "contracts", "BCCA_Healthcare.json")
ADDR_FILE          = os.path.join("bcca_data", "contract_address.txt")

_w3        = None
_contract  = None

def _get_web3():
    global _w3
    if _w3 is None:
        w3 = Web3(HTTPProvider(BLOCKCHAIN_ADDR))
        # Support both Web3.py v4 (isConnected) and v5/v6 (is_connected)
        connected = w3.isConnected() if hasattr(w3, 'isConnected') else w3.is_connected()
        if not connected:
            return None
        # Support both v4 (defaultAccount) and v5/v6 (default_account)
        if hasattr(w3.eth, 'defaultAccount'):
            w3.eth.defaultAccount = w3.eth.accounts[0]
        else:
            w3.eth.default_account = w3.eth.accounts[0]
        _w3 = w3
    return _w3

def _get_contract():
    """Auto-load contract from Truffle artifact (address + ABI in one file)."""
    global _contract
    if _contract is not None:
        return _contract
    w3 = _get_web3()
    if w3 is None:
        return None
    # Load Truffle build artifact — contains both ABI and deployed address
    if not os.path.exists(TRUFFLE_ARTIFACT):
        return None
    with open(TRUFFLE_ARTIFACT, encoding='utf-8') as f:
        artifact = json.load(f)
    abi = artifact.get("abi")
    if not abi:
        return None
    # Find deployed address — try networks dict first, then saved file
    address = None
    networks = artifact.get("networks", {})
    if networks:
        # Use the most recently deployed network entry
        latest = sorted(networks.keys())[-1]
        address = networks[latest].get("address")
    if not address and os.path.exists(ADDR_FILE):
        with open(ADDR_FILE) as f:
            address = f.read().strip()
    if not address:
        return None
    # Save address for reference
    os.makedirs("bcca_data", exist_ok=True)
    with open(ADDR_FILE, "w") as f:
        f.write(address)
    _contract = w3.eth.contract(address=address, abi=abi)
    app.logger.info(f"[Blockchain] Contract loaded at {address}")
    return _contract

def _wait_for_receipt(w3, tx):
    """Compatible wait for receipt across Web3.py v4/v5/v6."""
    if hasattr(w3.eth, 'waitForTransactionReceipt'):
        return w3.eth.waitForTransactionReceipt(tx)
    return w3.eth.wait_for_transaction_receipt(tx)

def _block_number(w3):
    """Compatible block number across Web3.py v4/v5/v6."""
    if hasattr(w3.eth, 'blockNumber'):
        return w3.eth.blockNumber
    return w3.eth.block_number

def _blockchain_status():
    """Return dict with connection status for UI display."""
    w3 = _get_web3()
    if w3 is None:
        return {"connected": False, "address": None, "block": None}
    c = _get_contract()
    return {
        "connected": True,
        "address"  : c.address if c else None,
        "block"    : _block_number(w3),
        "accounts" : len(w3.eth.accounts),
    }

def _blockchain_register(pseudo_id, gpk, upk, E_i, h1_i, role_int):
    """Call registerUser on BCCA smart contract."""
    try:
        c = _get_contract()
        if c is None:
            return
        tx = c.functions.registerUser(pseudo_id, gpk, upk, E_i, h1_i, role_int).transact()
        _wait_for_receipt(_get_web3(), tx)
    except Exception as e:
        app.logger.warning(f"Blockchain registration skipped: {e}")

def _blockchain_store_ehr(msg: dict) -> str:
    """Call storeEHRRecord on BCCA smart contract. Returns blockHash hex."""
    try:
        c = _get_contract()
        if c is None:
            return ""
        tx = c.functions.storeEHRRecord(
            msg["ID_i"], msg["sigma_i"], msg["KID_k"],
            msg["c_i"], msg["Q_k"], int(msg["T_i"])
        ).transact()
        receipt = _wait_for_receipt(_get_web3(), tx)
        # Parse EHRUploaded event to get blockHash
        logs = c.events.EHRUploaded().process_receipt(receipt)
        if logs:
            return logs[0]["args"]["blockHash"].hex()
    except Exception as e:
        app.logger.warning(f"Blockchain EHR store skipped: {e}")
    return ""

# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _session_keys() -> Optional[dict]:
    sid = session.get("user_id")
    return _KEY_STORE.get(sid)

def _save_session_keys(keys: dict):
    sid = session.get("user_id")
    if sid:
        _KEY_STORE[sid] = keys

def _require_role(*roles):
    """Return user keys if logged in with correct role, else None."""
    keys = _session_keys()
    if keys is None:
        return None
    if keys.get("role") not in roles:
        return None
    return keys

# ──────────────────────────────────────────────────────────────────────────────
# Home
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    params_ready = load_params() is not None
    return render_template("bcca_index.html", params_ready=params_ready)

# ──────────────────────────────────────────────────────────────────────────────
# HOSPITAL ADMIN (HA) — Algorithm 1 & 3
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/ha/login", methods=["GET", "POST"])
def ha_login():
    if request.method == "POST":
        if (request.form.get("username") == "admin" and
                request.form.get("password") == "admin"):
            session["user_id"] = "ha_admin"
            session["role"]    = "HA"
            return redirect(url_for("ha_dashboard"))
        return render_template("bcca_ha_login.html",
                               error="Invalid credentials")
    return render_template("bcca_ha_login.html")

@app.route("/ha/dashboard")
def ha_dashboard():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    params  = load_params()
    users   = get_all_users()
    evid    = get_evidence_entries()
    ehrs    = _EHR_MSGS
    return render_template("bcca_ha_dashboard.html",
                           params=params, users=users,
                           evidence=evid, ehr_count=len(ehrs))

@app.route("/ha/setup", methods=["POST"])
def ha_setup_action():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    try:
        params = ha_setup()
        return render_template("bcca_ha_dashboard.html",
                               params=params, users=get_all_users(),
                               evidence=get_evidence_entries(),
                               ehr_count=len(_EHR_MSGS),
                               msg="System parameters generated successfully.")
    except Exception as e:
        return render_template("bcca_ha_dashboard.html",
                               params=None, users={},
                               evidence=[], ehr_count=0,
                               error=str(e))

@app.route("/ha/extract_key", methods=["GET", "POST"])
def ha_extract_key():
    """HA processes a pending registration request and issues partial key."""
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    if request.method == "POST":
        try:
            reg = {
                "upk"  : request.form["upk"],
                "RID"  : request.form["rid"],
                "UPW"  : request.form["upw"],
                "alpha": request.form["alpha"],
                "role" : request.form["role"].upper(),
            }
            partial = extract_partial_key(reg)
            # Register on blockchain
            role_int = 0 if reg["role"] == "PATIENT" else 1
            _blockchain_register(partial["ID_i"], partial["gpk_i"],
                                  reg["upk"], partial["E_i"],
                                  partial["h1_i"], role_int)
            # Store partial key for user to auto-retrieve (no copy-paste needed)
            _PENDING_PARTIAL[reg["RID"]] = partial
            # Remove from pending queue
            _PENDING_REG.pop(reg["RID"], None)
            return render_template("bcca_ha_keygen_result.html",
                                   partial=partial)
        except Exception as e:
            return render_template("bcca_ha_extract.html",
                                   error=str(e),
                                   pending=list(_PENDING_REG.values()))
    return render_template("bcca_ha_extract.html",
                           pending=list(_PENDING_REG.values()))

@app.route("/ha/revoke", methods=["GET", "POST"])
def ha_revoke():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    users    = get_all_users()
    evidence = get_evidence_entries()
    revoked  = [e for e in evidence]
    if request.method == "POST":
        try:
            pseudo_id  = request.form["pseudo_id"]
            ev_reason  = request.form["evidence"]
            user_rec   = get_user(pseudo_id)
            if not user_rec:
                raise ValueError("User not found in registry.")
            entry = revoke_user_access(pseudo_id, ev_reason, user_rec["E_i"])
            try:
                c = _get_contract()
                if c:
                    tx = c.functions.addEvidenceEntry(
                        pseudo_id, entry["HK_i"], entry["CH_i"],
                        entry["j_i"], entry["cred_i"]
                    ).transact()
                    _wait_for_receipt(_get_web3(), tx)
            except Exception as be:
                app.logger.warning(f"Blockchain revoke skipped: {be}")
            return render_template("bcca_ha_revoke.html",
                                   users=get_all_users(),
                                   revoked_list=get_evidence_entries(),
                                   msg=f"User {pseudo_id[:20]}... revoked successfully.")
        except Exception as e:
            return render_template("bcca_ha_revoke.html",
                                   users=users, revoked_list=revoked, error=str(e))
    return render_template("bcca_ha_revoke.html", users=users, revoked_list=revoked)

@app.route("/ha/modify", methods=["GET"])
def ha_modify():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    return render_template("bcca_ha_modify.html", evidence=get_evidence_entries())

@app.route("/ha/modify_evidence", methods=["POST"])
def ha_modify_evidence():
    if session.get("role") != "HA":
        return redirect(url_for("ha_login"))
    try:
        pseudo_id    = request.form["pseudo_id"]
        new_evidence = request.form["new_evidence"]
        updated = modify_evidence(pseudo_id, new_evidence)
        try:
            c = _get_contract()
            if c:
                tx = c.functions.modifyEvidenceEntry(
                    pseudo_id, updated["cred_i"], updated["CH_i"]
                ).transact()
                _wait_for_receipt(_get_web3(), tx)
        except Exception as be:
            app.logger.warning(f"Blockchain modify skipped: {be}")
        msg = f"Evidence for {pseudo_id[:20]}... updated. Block hash UNCHANGED."
        return render_template("bcca_ha_modify.html",
                               evidence=get_evidence_entries(), msg=msg)
    except Exception as e:
        return render_template("bcca_ha_modify.html",
                               evidence=get_evidence_entries(), error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# REGISTRATION — Algorithms 2 + 3 + 4 run automatically in one step
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            role = request.form["role"].upper()
            rid  = request.form["rid"]
            pw   = request.form["password"]
            dob  = request.form["dob"]
            sa   = request.form["security_answer"]
            od   = request.form["other_details"]

            # ── Algorithm 2: User key generation ──────────────────────────────
            reg_pkt, local = bcca_register(rid, pw, dob, sa, od, role)

            # ── Algorithm 3: HA partial key extraction (runs in backend) ──────
            ha_input = {
                "upk"  : reg_pkt["upk"],
                "RID"  : rid,
                "UPW"  : str(reg_pkt["UPW"]),
                "alpha": str(reg_pkt["alpha"]),
                "role" : role,
            }
            partial = extract_partial_key(ha_input)

            # Register on blockchain
            role_int = 0 if role == "PATIENT" else 1
            _blockchain_register(partial["ID_i"], partial["gpk_i"],
                                  reg_pkt["upk"], partial["E_i"],
                                  partial["h1_i"], role_int)

            # ── Algorithm 4: Full key generation (runs in backend) ────────────
            full_key = generate_keys(partial, local)

            # Store full keys in memory keyed by pseudonym ID
            pseudo_id = partial["ID_i"]
            _KEY_STORE[pseudo_id] = full_key
            # Store credentials so login only needs RID + password
            _KEY_STORE[pseudo_id]["od"]  = od
            _KEY_STORE[pseudo_id]["dob"] = dob
            _KEY_STORE[pseudo_id]["sa"]  = sa
            # Map RID → pseudo_id so login only needs RID
            _RID_TO_PSEUDO[rid] = pseudo_id
            # Persist both stores so they survive server restart
            _save_persistent_stores()
            _append_audit(pseudo_id, "REGISTER", "", role)

            # ── Console log keys on successful registration ───────────────────
            print("\n" + "="*60)
            print(f"  REGISTRATION SUCCESSFUL — {role}")
            print("="*60)
            print(f"  RID (Real Identity)  : {rid}")
            print(f"  Pseudonym (ID_i)     : {pseudo_id}")
            print(f"  Role                 : {role}")
            print("-"*60)
            print(f"  upk_i  (user pubkey) : {full_key['upk_i'][:40]}...")
            print(f"  gpk_i  (HA pubkey)   : {full_key['gpk_i'][:40]}...")
            print(f"  E_i    (HA ephemeral): {full_key['E_i'][:40]}...")
            print(f"  h1_i   (binding hash): {full_key['h1_i']}")
            print(f"  psk_i  (partial key) : {str(full_key['psk_i'])[:40]}...")
            print(f"  x_i    (secret key)  : {str(full_key['x_i'])[:40]}...")
            print(f"  A_i    (login cred1) : {str(full_key['A_i'])[:40]}...")
            print(f"  B_i    (login cred2) : {str(full_key['B_i'])[:40]}...")
            print("-"*60)
            print(f"  Precomputed SID/KID pairs : {len(full_key['SID'])} pairs ready")
            print(f"  SID[0] (sample)      : {str(full_key['SID'][0])[:40]}...")
            print(f"  KID[0] (sample)      : {full_key['KID'][0][:40]}...")
            print(f"  Precomputed Q/ek pairs    : {len(full_key['Q'])} pairs ready")
            print(f"  Q[0]   (sample)      : {full_key['Q'][0][:40]}...")
            print(f"  ek[0]  (sample)      : {str(full_key['ek'][0])[:40]}...")
            if role == "DOCTOR":
                print(f"  y (decrypt key)      : {str(full_key.get('y','N/A'))[:40]}...")
            print("="*60 + "\n")

            return render_template("bcca_register_result.html",
                                   pseudo_id=pseudo_id, role=role, rid=rid)
        except Exception as e:
            return render_template("bcca_register.html", error=str(e))
    return render_template("bcca_register.html")

# ──────────────────────────────────────────────────────────────────────────────
# KEY GENERATION — Algorithm 4
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    # Auto-fill: check if HA has already processed this user's registration
    rid = session.get("pending_rid")
    auto_partial = _PENDING_PARTIAL.get(rid) if rid else None

    if request.method == "POST":
        try:
            # Use form values if submitted, else fall back to auto_partial
            partial = {
                "ID_i"  : request.form["id_i"],
                "gpk_i" : request.form["gpk_i"],
                "psk_i" : request.form["psk_i"],
                "E_i"   : request.form["e_i"],
                "d_i"   : request.form.get("d_i", "0"),
                "A_i"   : request.form["a_i"],
                "B_i"   : request.form["b_i"],
                "h1_i"  : request.form["h1_i"],
                "role"  : request.form["role"].upper(),
            }
            if request.form.get("y"):
                partial["y"] = request.form["y"]

            local = session.get("pending_local")
            if not local:
                raise ValueError("No pending registration found. Please register first.")

            full_key = generate_keys(partial, local)

            # Save to key store (keyed by pseudonym ID)
            _KEY_STORE[partial["ID_i"]] = full_key
            session["user_id"]       = partial["ID_i"]
            session["role"]          = partial["role"]
            session["pending_rid"]   = None   # clear
            # Remove from pending partial store
            if rid:
                _PENDING_PARTIAL.pop(rid, None)

            return render_template("bcca_keygen_result.html",
                                   keys=full_key, role=partial["role"])
        except Exception as e:
            return render_template("bcca_keygen.html",
                                   error=str(e), auto_partial=auto_partial)
    return render_template("bcca_keygen.html", auto_partial=auto_partial)

# ──────────────────────────────────────────────────────────────────────────────
# LOGIN — Algorithm 5 (Multi-Factor)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            rid      = request.form["rid"]
            password = request.form["password"]
            dob      = request.form.get("dob", "")
            sa       = request.form.get("security_answer", "")
            od       = request.form.get("other_details", "")

            # Look up pseudonym by RID (set during registration)
            pseudo_id = _RID_TO_PSEUDO.get(rid)
            if pseudo_id is None:
                raise ValueError("No account found for this ID. Please register first.")

            if is_revoked(pseudo_id):
                raise ValueError("Your account has been revoked by the Hospital Admin. Access denied.")

            stored = _KEY_STORE.get(pseudo_id)
            if stored is None:
                # Try reloading from disk (in case in-memory store was cleared)
                _load_persistent_stores()
                stored = _KEY_STORE.get(pseudo_id)
            if stored is None:
                raise ValueError("Keys not found. Please register again.")

            ok = bcca_login(stored, rid, password, dob, sa, od)
            if ok:
                session["user_id"] = pseudo_id
                session["role"]    = stored["role"]
                _append_audit(pseudo_id, "LOGIN", "", stored["role"])
                if stored["role"] == "PATIENT":
                    return redirect(url_for("patient_dashboard"))
                else:
                    return redirect(url_for("doctor_dashboard"))
            else:
                return render_template("bcca_login.html",
                                       error="Invalid credentials. Please try again.")
        except Exception as e:
            return render_template("bcca_login.html", error=str(e))
    return render_template("bcca_login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ──────────────────────────────────────────────────────────────────────────────
# PATIENT DASHBOARD & EHR UPLOAD — Algorithm 6
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/patient/dashboard")
def patient_dashboard():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    # Collect this patient's EHR records
    pid  = session["user_id"]
    ehrs = [m for m in _EHR_MSGS if m.get("ID_i") == pid]
    return render_template("bcca_patient_dashboard.html",
                           keys=keys, ehrs=ehrs)

@app.route("/patient/upload_ehr", methods=["GET", "POST"])
def upload_ehr():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        try:
            # Collect EHR data from form fields (vital signs, notes, etc.)
            vitals  = request.form.get("vitals", "")
            notes   = request.form.get("notes", "")
            report_file = request.files.get("report_file")

            ehr_payload = {
                "vitals"   : vitals,
                "notes"    : notes,
                "patient"  : session["user_id"],
                "timestamp": int(time.time()),
            }
            if report_file and report_file.filename:
                fname     = secure_filename(report_file.filename)
                file_bytes = report_file.read()
                ehr_payload["file_name"] = fname
                ehr_payload["file_data"] = base64.b64encode(file_bytes).decode()

            ehr_bytes = json.dumps(ehr_payload).encode("utf-8")

            # Algorithm 6: Sign & Encrypt
            ehr_msg = sign_ehr(ehr_bytes, keys)
            _save_session_keys(keys)          # save updated SID index

            # Algorithm 7: Verify before storing on chain
            valid, reason = verify_ehr(ehr_msg)
            if not valid:
                return render_template("bcca_upload_ehr.html",
                                       error=f"Signature verification failed: {reason}")

            # Store on blockchain
            block_hash = _blockchain_store_ehr(ehr_msg)
            ehr_msg["block_hash"]   = block_hash
            ehr_msg["verified"]     = True
            ehr_msg["ehr_preview"]  = vitals[:60] + ("..." if len(vitals) > 60 else "")
            _EHR_MSGS.append(ehr_msg)
            _append_audit(session["user_id"], "EHR_UPLOAD", "", "PATIENT")

            return render_template("bcca_upload_ehr.html",
                                   success=True, ehr_msg=ehr_msg,
                                   block_hash=block_hash)
        except Exception as e:
            return render_template("bcca_upload_ehr.html", error=str(e))
    return render_template("bcca_upload_ehr.html")

# ──────────────────────────────────────────────────────────────────────────────
# DOCTOR DASHBOARD, EHR ACCESS & DECRYPTION — Algorithm 7 Part B
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/doctor/dashboard")
def doctor_dashboard():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    # All EHR records visible to the doctor
    return render_template("bcca_doctor_dashboard.html",
                           keys=keys, ehrs=_EHR_MSGS)

@app.route("/doctor/decrypt_ehr", methods=["POST"])
def doctor_decrypt_ehr():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    try:
        c_i_hex = request.form["c_i"]
        Q_k_hex = request.form["Q_k"]
        plaintext_bytes = decrypt_ehr(c_i_hex, Q_k_hex, keys)
        plaintext = plaintext_bytes.decode("utf-8")
        ehr_data  = json.loads(plaintext)

        patient_pid = request.form.get("patient_pid", "")
        # Log access locally
        _append_audit(session["user_id"], "EHR_ACCESS", patient_pid, "DOCTOR")

        # Log access on blockchain
        try:
            c = _get_contract()
            if c:
                block_hash_hex = request.form.get("block_hash", "0" * 64)
                tx = c.functions.logEHRAccess(
                    session["user_id"], patient_pid, block_hash_hex
                ).transact()
                _wait_for_receipt(_get_web3(), tx)
        except Exception as be:
            app.logger.warning(f"Blockchain access log skipped: {be}")

        return render_template("bcca_ehr_view.html",
                               ehr=ehr_data, decrypted=True)
    except Exception as e:
        return render_template("bcca_doctor_dashboard.html",
                               keys=keys, ehrs=_EHR_MSGS,
                               error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# MUTUAL AUTHENTICATION — Algorithm 8
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/auth/patient_request", methods=["GET", "POST"])
def patient_auth_req():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        try:
            doctor_pseudo = request.form["doctor_pseudo_id"]
            doc_pub       = get_user(doctor_pseudo)
            if not doc_pub:
                raise ValueError("Doctor not found in registry.")
            if doc_pub.get("role") != "DOCTOR":
                raise ValueError("Target is not a DOCTOR.")

            auth_req, ephemeral = patient_auth_request(keys, doc_pub)
            _save_session_keys(keys)

            # Store ephemeral in session for session key step
            session["ephemeral_a"]    = ephemeral
            session["target_doctor"]  = doctor_pseudo
            # In a real system, C_a would be sent to cloud server → doctor
            # Here we store it for demonstration
            session["pending_auth_req"] = auth_req

            return render_template("bcca_mutual_auth.html",
                                   step="sent", auth_req=auth_req,
                                   doctor_id=doctor_pseudo[:20])
        except Exception as e:
            return render_template("bcca_mutual_auth.html",
                                   step="request", error=str(e))
    return render_template("bcca_mutual_auth.html", step="request",
                           users=get_all_users())

@app.route("/auth/doctor_verify", methods=["POST"])
def doctor_auth_verify():
    keys = _require_role("DOCTOR")
    if keys is None:
        return redirect(url_for("login"))
    try:
        auth_req_json = request.form["auth_request"]
        auth_req = json.loads(auth_req_json)

        patient_pub = get_user(auth_req["ID_a"])
        if not patient_pub:
            raise ValueError("Patient not found in registry.")

        auth_resp, ephemeral_b = doctor_verify_and_respond(auth_req, keys, patient_pub)
        _save_session_keys(keys)

        # Compute session key (doctor side)
        # Ephemeral Z_a from auth_req
        import json as _json
        ephemeral_b["Z_a"]  = auth_req["Z_a"]
        ephemeral_b["ID_a"] = auth_req["ID_a"]
        ephemeral_b["ID_b"] = keys["ID_i"]

        K_ab = doctor_compute_session_key(ephemeral_b, auth_req)
        session["session_key_b64"] = base64.b64encode(K_ab).decode()

        return render_template("bcca_mutual_auth_doctor.html",
                               auth_resp=auth_resp,
                               session_key=base64.b64encode(K_ab).decode()[:16] + "...")
    except Exception as e:
        return render_template("bcca_doctor_dashboard.html",
                               keys=keys, ehrs=_EHR_MSGS, error=str(e))

@app.route("/auth/patient_finalize", methods=["POST"])
def patient_auth_finalize():
    keys = _require_role("PATIENT")
    if keys is None:
        return redirect(url_for("login"))
    try:
        auth_resp_json = request.form["auth_response"]
        auth_resp  = json.loads(auth_resp_json)
        ephemeral_a = session.get("ephemeral_a")
        if not ephemeral_a:
            raise ValueError("No pending authentication request.")

        doctor_pub = get_user(auth_resp["ID_b"])
        K_ab = patient_verify_and_key(auth_resp, keys, doctor_pub, ephemeral_a)
        session["session_key_b64"] = base64.b64encode(K_ab).decode()
        session.pop("ephemeral_a", None)
        session.pop("pending_auth_req", None)

        return render_template("bcca_mutual_auth.html",
                               step="complete",
                               session_key=base64.b64encode(K_ab).decode()[:16] + "...",
                               doctor_id=auth_resp["ID_b"][:20])
    except Exception as e:
        return render_template("bcca_mutual_auth.html",
                               step="finalize", error=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# BATCH VERIFICATION API — Algorithm 7 Part C
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/node/blockchain_status")
def api_blockchain_status():
    """Return live blockchain connection status as JSON."""
    return jsonify(_blockchain_status())

@app.route("/node/batch_verify", methods=["POST"])
def api_batch_verify():
    """Blockchain node batch-verifies all pending EHR messages."""
    data = request.get_json()
    msgs = data.get("messages", _EHR_MSGS)
    if not msgs:
        return jsonify({"valid": False, "reason": "No messages to verify."})
    valid, reason = batch_verify_ehr(msgs)
    return jsonify({"valid": valid, "reason": reason, "count": len(msgs)})

@app.route("/node/verify_one", methods=["POST"])
def api_verify_one():
    """Blockchain node verifies a single EHR message."""
    msg = request.get_json()
    valid, reason = verify_ehr(msg)
    return jsonify({"valid": valid, "reason": reason})

# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC REGISTRY VIEW
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/registry")
def registry():
    users = get_all_users()
    return render_template("bcca_registry.html", users=users)

@app.route("/audit_log")
def audit_log():
    """View audit log filtered by the caller's role."""
    all_logs = _load_audit()
    uid  = session.get("user_id")
    role = session.get("role", "")

    if uid == "ha_admin":
        # HA sees everything
        logs = all_logs
    elif role == "DOCTOR":
        # Doctor sees only their own actions
        logs = [e for e in all_logs if e.get("actor") == uid]
    elif role == "PATIENT":
        # Patient sees their own events + any doctor's EHR_ACCESS targeting them
        logs = [e for e in all_logs
                if e.get("actor") == uid
                or (e.get("action") == "EHR_ACCESS" and e.get("target") == uid)]
    else:
        logs = []

    return render_template("bcca_audit_log.html", logs=logs, role=role)

# ──────────────────────────────────────────────────────────────────────────────
# EVIDENCE CHAIN VIEW
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/evidence_chain")
def evidence_chain():
    entries = get_evidence_entries()
    return render_template("bcca_evidence_chain.html", entries=entries)

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5001)
