#!/usr/bin/env python3
"""
generate_tenable_data.py — build the Luminary Systems Tenable dataset from
assets_luminary.xlsx.

Reads all rows where seen_by includes 'tenable' and emits
seed_data/raw/assets.json in the Tenable Vulnerability Management v2 export
chunk schema.

Source of truth: luminary-demo-docs/master-sheet/assets_luminary.xlsx
Falls back to seed_data/source/assets_luminary.xlsx if the central repo
is not present.

Deterministic: all values derived from hostname via md5.
Expected output: ~1587 assets in 2 chunks (1000 + 587).
"""
import json, hashlib, zipfile, re
import xml.etree.ElementTree as ET
import datetime as dt
from pathlib import Path
from collections import Counter

ROOT     = Path(__file__).resolve().parent.parent
RAW      = ROOT / "seed_data" / "raw"
_CENTRAL = ROOT.parent / "luminary-demo-docs" / "master-sheet" / "assets_luminary.xlsx"
_LOCAL   = ROOT / "seed_data" / "source" / "assets_luminary.xlsx"
SRC      = _CENTRAL if _CENTRAL.exists() else _LOCAL
RAW.mkdir(exist_ok=True)

NOW        = dt.datetime(2026, 7, 1, 18, 0, 0)
DOMAIN     = "luminarysystems.com"
CHUNK_SIZE = 1000

# Network/infrastructure categories: scanned via Nessus, never have an agent
NETWORK_CATEGORIES = {
    "switch", "router", "wap", "iot", "printer",
    "security", "clinic", "esx_server",
}
# Windows categories: have a NetBIOS name
WINDOWS_CATEGORIES = {"win_laptop", "win_vm", "win_server", "vdi"}


# ── xlsx reader (no openpyxl) ─────────────────────────────────────────────────
def read_xlsx(path):
    z = zipfile.ZipFile(path)
    ns = {'a': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        r = ET.fromstring(z.read('xl/sharedStrings.xml'))
        for si in r.findall('a:si', ns):
            shared.append("".join(t.text or "" for t in si.iter(
                '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')))

    def colnum(ref):
        m = re.match(r'([A-Z]+)(\d+)', ref)
        col = 0
        for c in m.group(1):
            col = col * 26 + (ord(c) - 64)
        return col - 1, int(m.group(2))

    root = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
    rows = {}
    for c in root.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c'):
        ref = c.get('r'); t = c.get('t')
        v = c.find('a:v', ns); isv = c.find('a:is', ns)
        if v is not None:
            val = v.text
            if t == 's' and val is not None:
                val = shared[int(val)]
        elif isv is not None:
            val = "".join(x.text or "" for x in isv.iter(
                '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t'))
        else:
            val = None
        ci, ri = colnum(ref)
        rows.setdefault(ri, {})[ci] = val

    hdr = [rows[1].get(i) for i in range(len(rows[1]))]
    out = []
    for ri in sorted(rows):
        if ri == 1:
            continue
        out.append({hdr[i]: rows[ri].get(i) for i in range(len(hdr))})
    return out


# ── helpers ───────────────────────────────────────────────────────────────────
def _h(s):
    return hashlib.md5(s.encode()).hexdigest()

def _h_int(s, lo, hi):
    return lo + int(_h(s)[:4], 16) % (hi - lo + 1)

def to_uuid(hex32):
    h = hex32.ljust(32, '0')[:32]
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def mac_upper(raw):
    if not raw:
        return None
    return raw.upper().replace("-", ":").strip()

def system_type(category):
    c = (category or "").lower()
    if c in ("win_server", "linux_server", "esx_server"):
        return "scan-host"
    if c in ("switch", "router", "wap"):
        return "embedded"
    return "general-purpose"


# ── read and filter ───────────────────────────────────────────────────────────
print(f"Reading xlsx: {'CENTRAL' if SRC == _CENTRAL else 'LOCAL'} → {SRC}")
all_assets = read_xlsx(SRC)
seeds = [a for a in all_assets if 'tenable' in (a.get('seen_by') or '').lower()]
print(f"Tenable rows found: {len(seeds)}")


# ── build asset records ───────────────────────────────────────────────────────
def make_asset(row):
    host = (row.get('hostname') or '').strip()
    if not host:
        return None

    hx = _h("tio:" + host)
    asset_id = to_uuid(hx)
    category = (row.get('category') or '').strip().lower()
    is_network = category in NETWORK_CATEGORIES
    is_windows = category in WINDOWS_CATEGORIES

    # timestamps (deterministic)
    days_ago_first = _h_int("first:" + host, 90, 365)
    days_ago_last  = _h_int("last:" + host, 0, 30)
    days_ago_scan  = _h_int("scan:" + host, 0, 14)

    first_seen = NOW - dt.timedelta(days=days_ago_first)
    last_seen  = NOW - dt.timedelta(days=days_ago_last, hours=_h_int("lh:"+host, 0, 23))
    last_scan  = NOW - dt.timedelta(days=days_ago_scan, hours=_h_int("sh:"+host, 0, 23))
    created_at = first_seen - dt.timedelta(hours=_h_int("ca:"+host, 1, 12))
    updated_at = last_seen  + dt.timedelta(minutes=_h_int("ua:"+host, 1, 60))

    # Network devices never have an agent; ~62.5% of endpoints do (first hex nibble < 10)
    if is_network:
        has_agent = False
    else:
        has_agent = int(hx[0], 16) < 10

    ip      = (row.get('ip_address') or '').strip() or None
    mac_raw = (row.get('mac_address') or '').strip()
    mac     = mac_upper(mac_raw) if mac_raw else None
    os_str  = (row.get('os') or '').strip() or None

    acr      = _h_int("acr:"+host, 1, 10)
    exposure = _h_int("exp:"+host, 100, 900)

    sources = [{"name": "NESSUS_SCAN",
                "first_seen": iso(first_seen),
                "last_seen": iso(last_scan)}]
    if has_agent:
        sources.append({"name": "NESSUS_AGENT",
                        "first_seen": iso(first_seen + dt.timedelta(hours=2)),
                        "last_seen": iso(last_seen)})

    iface = {
        "name": "eth0",
        "mac_addresses": [mac] if mac else [],
        "ipv4s": [ip] if ip else [],
        "ipv6s": [],
        "fqdns": [host],
        "virtual": False,
        "aliased": False,
    }

    return {
        # Identity
        "id": asset_id,
        "has_agent": has_agent,
        "has_plugin_results": True,
        "agent_uuid": None,
        "types": ["host"],

        # Timestamps (top-level, same in V1 and V2)
        "created_at": iso(created_at),
        "updated_at": iso(updated_at),
        "terminated_at": None,
        "deleted_at": None,
        "first_seen": iso(first_seen),
        "last_seen": iso(last_seen),

        # Scan sub-object (V2 model)
        "scan": {
            "first_scan_time": iso(first_seen),
            "last_scan_time": iso(last_scan),
            "last_authenticated_scan_date": iso(last_scan),
            "last_licensed_scan_date": iso(last_scan),
            "last_scan_id": to_uuid(_h("scanid:"+host)),
            "last_schedule_id": None,
        },

        # Network sub-object (V2 model — ipv4s/hostnames/fqdns live here)
        "network": {
            "network_id": "00000000-0000-0000-0000-000000000000",
            "network_name": "Default",
            "ipv4s": [ip] if ip else [],
            "ipv6s": [],
            "fqdns": [host],
            "mac_addresses": [mac] if mac else [],
            "netbios_names": [host.upper()] if is_windows else [],
            "hostnames": [host],
            "ssh_fingerprints": [],
            "network_interfaces": [iface],
            "open_ports": [],
        },

        # Top-level identity attributes (V2 model)
        "agent_names": [host] if has_agent else [],
        "operating_systems": [os_str] if os_str else [],
        "system_types": [system_type(category)],
        "installed_software": [],
        "sources": sources,
        "tags": [],
        "acr_score": str(acr),
        "exposure_score": str(exposure),
        "acr_drivers": [
            {"driver_name": "device_type",      "driver_value": ["general_purpose"]},
            {"driver_name": "internet_exposure", "driver_value": ["internal"]},
        ],
        "security_protection_level": None,
        "security_protections": [],
        "exposure_confidence_value": None,
    }


assets = []
for row in seeds:
    a = make_asset(row)
    if a:
        assets.append(a)

n_chunks = max(1, (len(assets) + CHUNK_SIZE - 1) // CHUNK_SIZE)

output = {
    "assets": assets,
    "total": len(assets),
    "chunk_size": CHUNK_SIZE,
    "chunks": n_chunks,
}
(RAW / "assets.json").write_text(json.dumps(output, indent=2))

# ── summary ───────────────────────────────────────────────────────────────────
sites = Counter(row.get('location') or 'Unknown' for row in seeds if row.get('hostname'))
cats  = Counter(row.get('category') or 'unknown' for row in seeds if row.get('hostname'))

print(f"Total assets: {len(assets)}")
print(f"Chunks: {n_chunks} (chunk_size={CHUNK_SIZE})")
print("By site:")
for site, count in sorted(sites.items(), key=lambda x: -x[1]):
    print(f"  {site}: {count}")
print("By category:")
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count}")
print(f"Output: {RAW / 'assets.json'}")
