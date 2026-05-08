"""
Flask application factory for the CLS Healthcare IIoT system.

On startup:
  1. Loads (or generates on first run) CLS system parameters and KGC master
     secret key from instance/cls_params.json so they survive server restarts
     and Flask auto-reloads.  Without persistence every reload produces a new
     P_pub, making all previously stored signatures unverifiable.
  2. Initialises PseudonymManager and MutualAuthProtocol.
  3. Rehydrates in-memory pseudonym state from the SQLite DB.

The KGC master secret key (msk) is stored in instance/cls_params.json.
In production this file must be protected at the OS level (chmod 600).
"""

import hashlib
import json
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Path to the persisted params file (relative to project root)
_PARAMS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance", "cls_params.json")


def _load_or_create_cls_params():
    """
    Load CLS params + msk from disk if they exist, otherwise run Setup()
    and save them.  This guarantees P_pub is stable across restarts.
    """
    from crypto.cls_scheme import setup, CLSParams, deserialize_point, serialize_point
    from crypto.cls_scheme import _G, _N

    if os.path.exists(_PARAMS_FILE):
        with open(_PARAMS_FILE, "r") as f:
            data = json.load(f)
        msk    = int(data["msk"])
        P_pub  = deserialize_point(data["P_pub_hex"])
        params = CLSParams(G=_G, q=_N, P_pub=P_pub)
        return params, msk

    # First run — generate and persist
    params, msk = setup(256)
    os.makedirs(os.path.dirname(_PARAMS_FILE), exist_ok=True)
    with open(_PARAMS_FILE, "w") as f:
        json.dump({
            "msk":     str(msk),
            "P_pub_hex": serialize_point(params.P_pub),
        }, f, indent=2)
    return params, msk


def create_app(config_object: str = "config.DevelopmentConfig") -> Flask:
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
        instance_path=None,          # use Flask default (instance/ sibling to app/)
    )
    app.config.from_object(config_object)

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)

    # ------------------------------------------------------------------
    # CLS Cryptographic Setup  (stable across restarts)
    # ------------------------------------------------------------------
    from crypto.anonymity import PseudonymManager, set_authority_token
    from crypto.auth_protocol import MutualAuthProtocol

    params, msk = _load_or_create_cls_params()
    app.cls_params = params       # public — shared with all blueprints
    app.cls_msk    = msk          # secret — KGC only; never sent over network
    app.pseudonym_manager = PseudonymManager()
    app.auth_protocol = MutualAuthProtocol(params)

    # Set the authority token that gates identity-tracing calls
    set_authority_token(app.config["KGC_AUTHORITY_TOKEN"])

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from app.kgc.routes     import kgc_bp
    from app.patient.routes import patient_bp
    from app.doctor.routes  import doctor_bp

    app.register_blueprint(kgc_bp,     url_prefix="/kgc")
    app.register_blueprint(patient_bp, url_prefix="/patient")
    app.register_blueprint(doctor_bp,  url_prefix="/doctor")

    # ------------------------------------------------------------------
    # Root redirect
    # ------------------------------------------------------------------
    from flask import redirect, url_for

    @app.route("/")
    def index():
        return redirect(url_for("index_page"))

    @app.route("/home")
    def index_page():
        from flask import render_template
        return render_template("index.html")

    # ------------------------------------------------------------------
    # DB init + pseudonym rehydration
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()
        _rehydrate_pseudonyms(app)

    return app


def _rehydrate_pseudonyms(app: Flask) -> None:
    """
    Restore PseudonymManager in-memory state from persisted DB rows
    so the manager survives app restarts.
    """
    try:
        from app.models import Pseudonym
        rows = Pseudonym.query.all()
        app.pseudonym_manager.load_from_db_rows(rows)
    except Exception:
        pass  # DB may not exist yet on first run


# ---------------------------------------------------------------------------
# Shared utility: encrypt/decrypt health record data with AES-256-GCM
# ---------------------------------------------------------------------------

import secrets as _secrets

def _get_record_key(app: Flask) -> bytes:
    """
    Derive a stable AES-256 key for health record encryption from the app
    secret key.  In production this should be an HSM-backed key.
    """
    return hashlib.sha256(app.config["SECRET_KEY"].encode()).digest()
