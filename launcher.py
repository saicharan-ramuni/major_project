"""
Unified Launcher — Healthcare Authentication System
====================================================
Runs on port 5000. Starts the chosen sub-app on demand and
redirects the browser to it.

  Standard (CLS)   → port 5002   cls_project/run.py
  Blockchain (BCCA)→ port 5001   bcca_app.py
"""

import os
import sys
import socket
import subprocess
import time
from flask import Flask, redirect, jsonify

app = Flask(__name__, template_folder="launcher_templates")

# ── Paths ────────────────────────────────────────────────────────────────────
BCCA_DIR = os.path.dirname(os.path.abspath(__file__))
CLS_DIR  = os.path.join(BCCA_DIR, "cls_project")

BCCA_PORT = 5001
CLS_PORT  = 5002

# Track subprocesses we started (key: 'blockchain' | 'cls')
_procs: dict = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _port_open(port: int) -> bool:
    """Return True if something is already listening on the port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _alive(key: str) -> bool:
    """Return True if the subprocess we launched is still running."""
    proc = _procs.get(key)
    return proc is not None and proc.poll() is None


def _start(key: str, cmd: list, cwd: str, port: int):
    """Start sub-app if not already running."""
    if _port_open(port):
        return  # already listening — don't double-start
    if _alive(key):
        return  # our subprocess is still alive
    _procs[key] = subprocess.Popen(cmd, cwd=cwd)


def _wait_for_port(port: int, timeout: float = 15.0) -> bool:
    """Block until the port is open or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.3)
    return False


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    from flask import render_template
    return render_template("index.html")


@app.route("/launch/blockchain")
def launch_blockchain():
    cmd = [sys.executable, "-X", "utf8", "bcca_app.py"]
    _start("blockchain", cmd, BCCA_DIR, BCCA_PORT)
    _wait_for_port(BCCA_PORT)
    return redirect(f"http://localhost:{BCCA_PORT}")


@app.route("/launch/cls")
def launch_cls():
    cmd = [sys.executable, "run.py"]
    _start("cls", cmd, CLS_DIR, CLS_PORT)
    _wait_for_port(CLS_PORT)
    return redirect(f"http://localhost:{CLS_PORT}")


@app.route("/status")
def status():
    return jsonify({
        "blockchain": _port_open(BCCA_PORT),
        "cls"       : _port_open(CLS_PORT),
    })


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Healthcare Authentication Launcher")
    print("  Open: http://localhost:5000")
    print("=" * 55)
    app.run(port=5000, debug=False)
