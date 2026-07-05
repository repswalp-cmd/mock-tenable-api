"""
Mock Tenable Vulnerability Management API — Flask application.

Implements the V2 asset export flow used by the Infoblox Universal Asset
Insights Tenable connector, plus stub endpoints for all discovery scope groups:

  ASSETS (full data):
    POST /assets/v2/export
    POST /assets/export
    GET  /assets/export/{uuid}/status
    GET  /assets/export/{uuid}/chunks/{n}
    GET  /assets
    GET  /assets/{uuid}

  VULNERABILITIES (empty export):
    POST /vulns/export
    GET  /vulns/export/{uuid}/status
    GET  /vulns/export/status

  COMPLIANCES (empty export):
    POST /compliance/export
    GET  /compliance/export/{uuid}/status
    GET  /compliance/export/status

  PLATFORM & SETTINGS stubs:
    GET  /scanners
    GET  /scans
    GET  /exclusions
    GET  /networks
    GET  /users
    GET  /user-groups
    GET  /user-groups/{id}/members

  WAS stubs:
    GET  /was/v2/vulnerabilities

  HEALTH & DIAG:
    GET  /
    GET  /debug/requests

Auth: X-ApiKeys header (accessKey=xxx; secretKey=yyy). Permissive unless
TIO_ACCESS_KEY / TIO_SECRET_KEY env vars are set.
"""

import hashlib
import json
import math
import os
import secrets
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
ACCESS_KEY = os.environ.get("TIO_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TIO_SECRET_KEY", "")
DATA_DIR   = Path(__file__).parent / "seed_data" / "raw"

DYNAMIC_LASTSEEN = os.environ.get("TIO_DYNAMIC_LASTSEEN", "1") not in (
    "0", "false", "False", ""
)

# Static export UUIDs — deterministic, no state needed
def _make_uuid(seed):
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

ASSET_EXPORT_UUID  = _make_uuid("luminary-tenable-export")
VULN_EXPORT_UUID   = _make_uuid("luminary-tenable-vulns-export")
COMPL_EXPORT_UUID  = _make_uuid("luminary-tenable-compl-export")

# ── Load asset data ───────────────────────────────────────────────────────────
_data_path = DATA_DIR / "assets.json"
if _data_path.exists():
    _raw       = json.loads(_data_path.read_text())
    ASSETS     = _raw.get("assets", [])
    CHUNK_SIZE = _raw.get("chunk_size", 1000)
    N_CHUNKS   = _raw.get("chunks", max(1, math.ceil(len(ASSETS) / 1000)))
else:
    ASSETS, CHUNK_SIZE, N_CHUNKS = [], 1000, 0

ASSET_BY_ID      = {a["id"]: a for a in ASSETS}
CHUNKS_AVAILABLE = list(range(1, N_CHUNKS + 1))

print(f"[startup] Loaded {len(ASSETS)} assets, {N_CHUNKS} chunks")
print(f"[startup] Asset export UUID: {ASSET_EXPORT_UUID}")

# ── Diagnostics ───────────────────────────────────────────────────────────────
REQUEST_LOG = deque(maxlen=8000)


def _log(status, note=None):
    REQUEST_LOG.append({
        "ts":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": request.method,
        "path":   request.path,
        "status": status,
        "note":   note,
        "query":  {k: v for k, v in request.args.items()},
    })


# ── Auth ──────────────────────────────────────────────────────────────────────
def require_api_keys():
    """X-ApiKeys: accessKey=xxx; secretKey=yyy — permissive unless env set."""
    hdr = request.headers.get("X-ApiKeys", "")
    if not hdr:
        return False
    parts = dict(p.strip().split("=", 1) for p in hdr.split(";") if "=" in p)
    ak = parts.get("accessKey", "").strip()
    sk = parts.get("secretKey", "").strip()
    if not ak or not sk:
        return False
    if ACCESS_KEY and ak != ACCESS_KEY:
        return False
    if SECRET_KEY and sk != SECRET_KEY:
        return False
    return True


def err_401(msg="Invalid credentials."):
    _log(401, msg)
    return jsonify({"statusCode": 401, "error": "Unauthorized", "message": msg}), 401


def err_404(msg="Resource not found."):
    _log(404, msg)
    return jsonify({"statusCode": 404, "error": "Not Found", "message": msg}), 404


# ── Dynamic last_seen ─────────────────────────────────────────────────────────
def fresh_asset(a):
    if not DYNAMIC_LASTSEEN:
        return a
    d = dict(a)
    now    = datetime.now(timezone.utc)
    jitter = timedelta(minutes=secrets.randbelow(20), seconds=secrets.randbelow(60))
    seen   = now - jitter
    ts     = seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    d["last_seen"]  = ts
    d["updated_at"] = ts
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# ASSETS — full data
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/assets/v2/export", methods=["POST"])
@app.route("/assets/export", methods=["POST"])
def export_assets():
    if not require_api_keys():
        return err_401()
    _log(200, f"asset export → {ASSET_EXPORT_UUID}")
    return jsonify({"export_uuid": ASSET_EXPORT_UUID})


@app.route("/assets/export/<export_uuid>/status", methods=["GET"])
def export_assets_status(export_uuid):
    if not require_api_keys():
        return err_401()
    _log(200, f"asset export status {export_uuid}")
    return jsonify({
        "status": "FINISHED",
        "chunks_available": CHUNKS_AVAILABLE,
    })


@app.route("/assets/export/status", methods=["GET"])
def export_assets_status_list():
    if not require_api_keys():
        return err_401()
    _log(200, "asset export status list")
    return jsonify({"exports": [{"export_uuid": ASSET_EXPORT_UUID, "status": "FINISHED"}]})


@app.route("/assets/export/<export_uuid>/chunks/<int:chunk_id>", methods=["GET"])
def export_assets_chunk(export_uuid, chunk_id):
    if not require_api_keys():
        return err_401()
    if chunk_id < 1 or chunk_id > N_CHUNKS:
        return err_404(f"Chunk {chunk_id} not available (export has {N_CHUNKS} chunks)")
    start = (chunk_id - 1) * CHUNK_SIZE
    end   = start + CHUNK_SIZE
    page  = [fresh_asset(a) for a in ASSETS[start:end]]
    _log(200, f"asset chunk {chunk_id}: {len(page)} assets")
    return jsonify(page)


@app.route("/assets", methods=["GET"])
def assets_list():
    if not require_api_keys():
        return err_401()
    page = [fresh_asset(a) for a in ASSETS[:5000]]
    _log(200, f"assets list {len(page)}")
    return jsonify({"assets": page, "total": len(ASSETS)})


@app.route("/assets/<asset_uuid>", methods=["GET"])
def asset_detail(asset_uuid):
    if not require_api_keys():
        return err_401()
    a = ASSET_BY_ID.get(asset_uuid)
    if not a:
        return err_404(f"Asset {asset_uuid} not found")
    _log(200, f"asset detail {asset_uuid}")
    return jsonify(fresh_asset(a))


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITIES — empty export (no vuln data in demo)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/vulns/export", methods=["POST"])
def export_vulns():
    if not require_api_keys():
        return err_401()
    _log(200, f"vuln export → {VULN_EXPORT_UUID}")
    return jsonify({"export_uuid": VULN_EXPORT_UUID})


@app.route("/vulns/export/<export_uuid>/status", methods=["GET"])
def export_vulns_status(export_uuid):
    if not require_api_keys():
        return err_401()
    _log(200, f"vuln export status {export_uuid}")
    return jsonify({"status": "FINISHED", "chunks_available": []})


@app.route("/vulns/export/status", methods=["GET"])
def export_vulns_status_list():
    if not require_api_keys():
        return err_401()
    _log(200, "vuln export status list")
    return jsonify({"exports": [{"export_uuid": VULN_EXPORT_UUID, "status": "FINISHED"}]})


@app.route("/vulns/export/<export_uuid>/chunks/<int:chunk_id>", methods=["GET"])
def export_vulns_chunk(export_uuid, chunk_id):
    if not require_api_keys():
        return err_401()
    _log(404, f"vuln chunk {chunk_id} not found (empty export)")
    return err_404("No vulnerability chunks — export is empty")


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE — empty export
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/compliance/export", methods=["POST"])
def export_compliance():
    if not require_api_keys():
        return err_401()
    _log(200, f"compliance export → {COMPL_EXPORT_UUID}")
    return jsonify({"export_uuid": COMPL_EXPORT_UUID})


@app.route("/compliance/export/<export_uuid>/status", methods=["GET"])
def export_compliance_status(export_uuid):
    if not require_api_keys():
        return err_401()
    _log(200, f"compliance export status {export_uuid}")
    return jsonify({"status": "FINISHED", "chunks_available": []})


@app.route("/compliance/export/status", methods=["GET"])
def export_compliance_status_list():
    if not require_api_keys():
        return err_401()
    _log(200, "compliance export status list")
    return jsonify({"exports": [{"export_uuid": COMPL_EXPORT_UUID, "status": "FINISHED"}]})


@app.route("/compliance/export/<export_uuid>/chunks/<int:chunk_id>", methods=["GET"])
def export_compliance_chunk(export_uuid, chunk_id):
    if not require_api_keys():
        return err_401()
    return err_404("No compliance chunks — export is empty")


# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM & SETTINGS stubs
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/networks", methods=["GET"])
def networks():
    if not require_api_keys():
        return err_401()
    _log(200, "networks")
    return jsonify({
        "networks": [{
            "uuid":        "00000000-0000-0000-0000-000000000000",
            "name":        "Default Network",
            "description": "The default network",
            "is_default":  True,
            "created_at":  1609459200,
            "modified_at": 1609459200,
        }],
        "pagination": {"total": 1, "offset": 0, "limit": 100, "sort": []},
    })


@app.route("/scanners", methods=["GET"])
def scanners():
    if not require_api_keys():
        return err_401()
    _log(200, "scanners")
    return jsonify({
        "scanners": [{
            "id":           1,
            "uuid":         _make_uuid("luminary-scanner-1"),
            "name":         "Luminary Systems Scanner",
            "status":       "on",
            "type":         "managed",
            "network_name": "Default",
            "owner":        "admin@luminarysystems.com",
            "platform":     "LINUX",
            "distro":       "es7-x86-64",
        }]
    })


@app.route("/scans", methods=["GET"])
def scans():
    if not require_api_keys():
        return err_401()
    _log(200, "scans")
    return jsonify({
        "folders":   [],
        "scans":     None,
        "timestamp": int(time.time()),
    })


@app.route("/exclusions", methods=["GET"])
def exclusions():
    if not require_api_keys():
        return err_401()
    _log(200, "exclusions")
    return jsonify([])


@app.route("/users", methods=["GET"])
def users():
    if not require_api_keys():
        return err_401()
    _log(200, "users")
    return jsonify({
        "users": [{
            "id":          1,
            "uuid":        _make_uuid("luminary-admin-user"),
            "username":    "admin@luminarysystems.com",
            "name":        "Luminary Admin",
            "email":       "admin@luminarysystems.com",
            "type":        "local",
            "permissions": 64,
            "enabled":     True,
        }]
    })


@app.route("/user-groups", methods=["GET"])
def user_groups():
    if not require_api_keys():
        return err_401()
    _log(200, "user-groups")
    return jsonify({"groups": []})


@app.route("/user-groups/<int:group_id>/members", methods=["GET"])
def user_group_members(group_id):
    if not require_api_keys():
        return err_401()
    _log(200, f"user-group {group_id} members")
    return jsonify({"members": []})


# ── API v3 attributes (rules) ─────────────────────────────────────────────────
@app.route("/api/v3/assets/attributes", methods=["GET"])
def asset_attributes():
    if not require_api_keys():
        return err_401()
    _log(200, "asset attributes")
    return jsonify({"attributes": [], "pagination": {"total": 0, "offset": 0, "limit": 100}})


# ═══════════════════════════════════════════════════════════════════════════════
# WAS — Web App Scanning stubs
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/was/v2/vulnerabilities", methods=["GET"])
def was_vulnerabilities():
    if not require_api_keys():
        return err_401()
    _log(200, "was vulnerabilities")
    return jsonify({
        "vulnerabilities": [],
        "pagination": {"total": 0, "offset": 0, "limit": 100, "sort": []},
    })


@app.route("/was/v2/configs", methods=["GET"])
def was_configs():
    if not require_api_keys():
        return err_401()
    _log(200, "was configs")
    return jsonify({"configs": [], "pagination": {"total": 0}})


@app.route("/was/v2/scans", methods=["GET"])
def was_scans():
    if not require_api_keys():
        return err_401()
    _log(200, "was scans")
    return jsonify({"scans": [], "pagination": {"total": 0}})


# ── Filters (referenced in connector flow) ────────────────────────────────────
@app.route("/filters/workbenches/assets", methods=["GET"])
def filters_assets():
    if not require_api_keys():
        return err_401()
    _log(200, "filters/workbenches/assets")
    return jsonify({"filters": []})


@app.route("/filters/workbenches/vulnerabilities", methods=["GET"])
def filters_vulnerabilities():
    if not require_api_keys():
        return err_401()
    _log(200, "filters/workbenches/vulnerabilities")
    return jsonify({"filters": []})


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH & DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok",
        "name":         "Mock Tenable Vulnerability Management API",
        "assets":       len(ASSETS),
        "chunks":       N_CHUNKS,
        "chunk_size":   CHUNK_SIZE,
        "export_uuid":  ASSET_EXPORT_UUID,
        "endpoints": [
            "POST /assets/v2/export",
            "GET  /assets/export/{uuid}/status",
            "GET  /assets/export/{uuid}/chunks/{n}",
            "GET  /assets",
            "GET  /assets/{uuid}",
            "POST /vulns/export  (empty)",
            "POST /compliance/export  (empty)",
            "GET  /networks",
            "GET  /scanners",
            "GET  /scans",
            "GET  /users",
            "GET  /user-groups",
            "GET  /was/v2/vulnerabilities",
        ],
    })


@app.route("/debug/requests", methods=["GET"])
def debug_requests():
    if request.args.get("clear"):
        REQUEST_LOG.clear()
        return jsonify({"cleared": True})
    log = list(REQUEST_LOG)
    summary = {}
    for e in log:
        key = f"{e['method']} {e['path']}"
        s = summary.setdefault(key, {"count": 0, "statuses": {}})
        s["count"] += 1
        s["statuses"][str(e["status"])] = s["statuses"].get(str(e["status"]), 0) + 1
    return jsonify({
        "total_logged": len(log),
        "summary":      summary,
        "recent":       log[-200:][::-1],
    })


@app.errorhandler(404)
def not_found(e):
    _log(404, "unmatched path")
    return jsonify({"statusCode": 404, "error": "Not Found",
                    "message": f"path not found: {request.path}"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
