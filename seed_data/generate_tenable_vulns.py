#!/usr/bin/env python3
"""
Generate Tenable vulnerability findings for 100 laptop / VM / server assets.

Writes seed_data/raw/vulns.json — served by app.py via /vulns/export chunks.
Does NOT touch assets.json or change any asset counts.

Usage:
    python3 seed_data/generate_tenable_vulns.py
"""
import hashlib
import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT        = Path(__file__).parent
ASSETS_FILE = ROOT / "raw" / "assets.json"
VULNS_FILE  = ROOT / "raw" / "vulns.json"

# ── CVE library ───────────────────────────────────────────────────────────────
# (severity, plugin_id, cve, name, cvss3, family, exploit_available, port, protocol, os_filter)
# os_filter: "windows" | "linux" | "any"
CVE_POOL = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    ("critical", 155999, "CVE-2021-44228",
     "Apache Log4j2 Remote Code Execution (Log4Shell)",
     10.0, "Web Servers", True, 8080, "TCP",
     "Successful exploitation allows an unauthenticated remote attacker to execute "
     "arbitrary code by sending a specially crafted request containing a JNDI lookup.",
     "Upgrade Apache Log4j2 to version 2.15.0 or later.",
     "any"),

    ("critical", 148154, "CVE-2021-26855",
     "Microsoft Exchange Server SSRF (ProxyLogon)",
     9.8, "Windows", True, 443, "TCP",
     "A server-side request forgery vulnerability in Microsoft Exchange allows an "
     "unauthenticated attacker to send arbitrary HTTP requests and authenticate as the Exchange server.",
     "Apply the Microsoft Exchange cumulative update (CU) for March 2021 or later.",
     "windows"),

    ("critical", 173111, "CVE-2023-23397",
     "Microsoft Outlook Elevation of Privilege Vulnerability",
     9.8, "Windows", True, 0, "NONE",
     "A critical privilege escalation flaw in Microsoft Outlook allows a remote, unauthenticated "
     "attacker to steal Net-NTLMv2 hashes by sending a specially crafted email.",
     "Apply the Microsoft security update for March 2023 (KB5002375).",
     "windows"),

    ("critical", 166062, "CVE-2022-22965",
     "Spring Framework Remote Code Execution (Spring4Shell)",
     9.8, "Web Servers", True, 8080, "TCP",
     "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to "
     "remote code execution via data binding.",
     "Upgrade Spring Framework to version 5.3.18 or 5.2.20, or apply vendor patch.",
     "any"),

    ("critical", 168939, "CVE-2022-42889",
     "Apache Commons Text Remote Code Execution (Text4Shell)",
     9.8, "Web Servers", False, 8080, "TCP",
     "Apache Commons Text performs variable interpolation that can be exploited to execute "
     "arbitrary code or contact remote servers via DNS/LDAP lookups.",
     "Upgrade Apache Commons Text to version 1.10.0 or later.",
     "any"),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    ("high", 151074, "CVE-2021-34527",
     "Windows Print Spooler Remote Code Execution (PrintNightmare)",
     8.8, "Windows", True, 445, "TCP",
     "A remote code execution vulnerability exists in the Windows Print Spooler service. "
     "An authenticated attacker could exploit this to run code with SYSTEM privileges.",
     "Apply the out-of-band update KB5004945 or later from Microsoft.",
     "windows"),

    ("high", 160890, "CVE-2022-30190",
     "Microsoft Windows MSDT Remote Code Execution (Follina)",
     7.8, "Windows", True, 0, "NONE",
     "A remote code execution vulnerability exists when MSDT is called using the URL protocol "
     "from a calling application such as Word. Exploitable via malicious Office documents.",
     "Apply Microsoft security update KB5014699 or disable the ms-msdt URI protocol.",
     "windows"),

    ("high", 150946, "CVE-2021-3156",
     "Sudo Heap-Based Buffer Overflow Privilege Escalation (Baron Samedit)",
     7.8, "General", True, 0, "NONE",
     "A heap-based buffer overflow in sudo allows any local user to gain root privileges "
     "without authentication, even if the user is not listed in the sudoers file.",
     "Update sudo to version 1.9.5p2 or later.",
     "linux"),

    ("high", 157288, "CVE-2021-4034",
     "Polkit pkexec Local Privilege Escalation (PwnKit)",
     7.8, "General", True, 0, "NONE",
     "A local privilege escalation vulnerability in polkit's pkexec allows any unprivileged "
     "local user to become root on the vulnerable host.",
     "Update polkit to the patched version provided by your Linux distribution.",
     "linux"),

    ("high", 159461, "CVE-2022-0847",
     "Linux Kernel Privilege Escalation via Pipe (Dirty Pipe)",
     7.8, "General", True, 0, "NONE",
     "A flaw in the way the Linux kernel's pipe page cache flags are managed allows an "
     "unprivileged local attacker to overwrite data in read-only files and escalate privileges.",
     "Update the Linux kernel to version 5.16.11, 5.15.25, or 5.10.102 or later.",
     "linux"),

    ("high", 177785, "CVE-2023-32049",
     "Windows SmartScreen Security Feature Bypass",
     8.8, "Windows", False, 0, "NONE",
     "A security feature bypass vulnerability exists in Windows SmartScreen. An attacker who "
     "convinces a user to open a specially crafted file can bypass SmartScreen protections.",
     "Apply the Microsoft security update for June 2023.",
     "windows"),

    ("high", 177551, "CVE-2023-28252",
     "Windows Common Log File System Driver Elevation of Privilege",
     7.8, "Windows", True, 0, "NONE",
     "An elevation of privilege vulnerability in the Windows CLFS driver allows a local "
     "attacker to gain SYSTEM privileges. Exploited in ransomware campaigns.",
     "Apply the Microsoft security update for April 2023.",
     "windows"),

    ("high", 153953, "CVE-2021-45105",
     "Apache Log4j2 Infinite Recursion Denial of Service",
     7.5, "Web Servers", False, 8080, "TCP",
     "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled "
     "recursion in lookup evaluation, allowing a denial of service attack.",
     "Upgrade Apache Log4j2 to version 2.17.0 or later.",
     "any"),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    ("medium", 156327, "CVE-2021-45046",
     "Apache Log4j2 Incomplete Fix for Log4Shell",
     3.7, "Web Servers", False, 8080, "TCP",
     "The fix for CVE-2021-44228 in Apache Log4j2 versions 2.15.0 was incomplete. Certain "
     "non-default configurations could still allow attackers to craft malicious input data "
     "using a JNDI lookup pattern.",
     "Upgrade Apache Log4j2 to version 2.16.0 or later.",
     "any"),

    ("medium", 156582, "CVE-2021-44832",
     "Apache Log4j2 Arbitrary Code Execution via JDBC Appender",
     6.6, "Web Servers", False, 8080, "TCP",
     "Apache Log4j2 versions 2.0-beta7 through 2.17.0 are vulnerable to a remote code "
     "execution attack where an attacker with permission to modify the logging configuration "
     "can construct a malicious JDBC Appender configuration.",
     "Upgrade Apache Log4j2 to version 2.17.1 or later.",
     "any"),

    ("medium", 170960, "CVE-2023-24880",
     "Windows SmartScreen Security Feature Bypass (Mark of the Web)",
     4.4, "Windows", False, 0, "NONE",
     "A security feature bypass vulnerability exists in Windows SmartScreen that allows an "
     "attacker to craft a file that bypasses the Mark of the Web security feature.",
     "Apply the Microsoft security update for March 2023.",
     "windows"),

    ("medium", 155597, "CVE-2021-41379",
     "Windows Installer Elevation of Privilege",
     5.5, "Windows", False, 0, "NONE",
     "An elevation of privilege vulnerability exists in the Windows Installer service. "
     "A local attacker can exploit this to gain elevated privileges.",
     "Apply the Microsoft security update for November 2021.",
     "windows"),

    ("medium", 161082, "CVE-2021-33764",
     "Windows Key Distribution Center Information Disclosure",
     5.3, "Windows", False, 0, "NONE",
     "An information disclosure vulnerability exists in Windows Key Distribution Center. "
     "An attacker could exploit this to obtain sensitive information from the KDC.",
     "Apply the Microsoft security update for July 2021.",
     "windows"),

    ("medium", 163562, "CVE-2022-34691",
     "Active Directory Domain Services Elevation of Privilege",
     8.8, "Windows", False, 389, "TCP",
     "An elevation of privilege vulnerability in Active Directory Domain Services could allow "
     "an authenticated attacker to manipulate attributes on computer accounts and acquire a "
     "certificate that enables privilege escalation to SYSTEM.",
     "Apply the Microsoft security update for August 2022 (KB5016616).",
     "windows"),

    ("medium", 158374, "CVE-2021-36934",
     "Windows SAM Database Insecure NTFS Permissions (HiveNightmare)",
     7.0, "Windows", False, 0, "NONE",
     "Overly permissive access control lists on the Security Account Manager (SAM) database "
     "and other files in Windows 10 and 11 allow a standard user to read the SAM, SYSTEM, and "
     "SECURITY registry hives, potentially enabling credential harvesting.",
     "Apply the Microsoft security update for July 2021 and delete Volume Shadow Copies.",
     "windows"),
]

SEVERITY_IDS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
RISK_LABELS  = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

SCAN_UUID  = "aa84617e-161d-f4d0-6a7c-b53a72675851"
SCAN_START = "2026-06-28T09:00:00Z"
SCAN_END   = "2026-06-28T12:00:00Z"


def _hash(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16)


def _seed_rng(asset_id: str) -> random.Random:
    return random.Random(_hash(asset_id))


def pick_vulns(asset_id: str, hostname: str, os_str: str) -> list:
    rng = _seed_rng(asset_id)
    is_windows = "windows" in os_str.lower() or "server 2" in os_str.lower()
    is_linux   = "linux" in os_str.lower() or "ubuntu" in os_str.lower() or "debian" in os_str.lower()

    candidates = [
        v for v in CVE_POOL
        if v[11] == "any"
        or (v[11] == "windows" and is_windows)
        or (v[11] == "linux"   and is_linux)
    ]
    if not candidates:
        candidates = [v for v in CVE_POOL if v[11] == "any"]

    # 2-5 distinct vulns per asset, weighted toward higher severity
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    weighted = []
    for v in candidates:
        weighted.extend([v] * weights.get(v[0], 1))

    n = rng.randint(2, min(5, len(candidates)))
    seen_plugins = set()
    chosen = []
    pool   = list(weighted)
    rng.shuffle(pool)
    for v in pool:
        if v[1] not in seen_plugins:
            chosen.append(v)
            seen_plugins.add(v[1])
        if len(chosen) >= n:
            break
    return chosen


def make_finding(asset: dict, vuln: tuple) -> dict:
    sev, plugin_id, cve, name, cvss3, family, exploit, port, protocol, desc, solution, _ = vuln
    network  = asset.get("network", {})
    fqdn     = (network.get("fqdns")        or ["unknown"])[0]
    hostname = (network.get("hostnames")    or [fqdn])[0]
    ipv4     = (network.get("ipv4s")        or ["0.0.0.0"])[0]
    os_str   = (asset.get("operating_systems") or ["Unknown"])[0]

    rng = _seed_rng(asset["id"] + cve)
    days_since_first = rng.randint(30, 180)
    first_found = (datetime.now(timezone.utc) - timedelta(days=days_since_first)).strftime("%Y-%m-%dT%H:%M:%SZ")
    last_found  = "2026-06-28T10:00:00Z"

    return {
        "asset": {
            "device_type": (asset.get("system_types") or ["general-purpose"])[0],
            "fqdn": fqdn,
            "hostname": hostname,
            "id": asset["id"],
            "ipv4": ipv4,
            "last_unauthenticated_results": None,
            "operating_system": os_str,
            "tracked": True,
        },
        "output": f"The remote host is affected by {cve} ({name}). Version/instance detected on this host.",
        "plugin": {
            "bid": [],
            "checks_for_default_account": False,
            "checks_for_malware": False,
            "cvss3_base_score": cvss3,
            "cvss3_vector": {"raw": f"CVSS:3.0/AV:{'N' if port else 'L'}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "cvss_base_score": round(cvss3 * 0.9, 1),
            "description": desc,
            "exploit_available": exploit,
            "exploitability_ease": "Exploits are available" if exploit else "No known exploits are available",
            "exploited_by_nessus": False,
            "family": family,
            "family_id": abs(_hash(family)) % 50 + 1,
            "has_patch": True,
            "id": plugin_id,
            "name": name,
            "risk_factor": RISK_LABELS[sev],
            "see_also": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
            "solution": solution,
            "synopsis": f"The remote host is vulnerable to {cve}.",
            "type": "remote" if port else "local",
            "version": "$Revision: 1.0 $",
            "vuln_publication_date": "2023-01-01T00:00:00Z",
            "cve": [cve],
        },
        "port": {
            "port": port,
            "protocol": protocol,
            "service": "www" if port in (80, 8080, 443, 8090) else ("smb" if port == 445 else "unknown"),
        },
        "scan": {
            "completed_at": SCAN_END,
            "schedule_uuid": "00000000-0000-0000-0000-000000000000",
            "started_at": SCAN_START,
            "uuid": SCAN_UUID,
        },
        "severity": sev,
        "severity_id": SEVERITY_IDS[sev],
        "severity_default_id": SEVERITY_IDS[sev],
        "severity_modification_type": "NONE",
        "first_found": first_found,
        "last_found": last_found,
        "last_fixed": None,
        "state": "open",
        "indexed": "2026-06-28T11:00:00Z",
    }


def main():
    raw       = json.loads(ASSETS_FILE.read_text())
    all_assets = raw["assets"]

    # Filter to laptops, VMs, workstations, VDI, ESX — by hostname pattern
    TARGET_PATTERNS = ("lap", "vm", "vdi", "esx", "lws")
    eligible = [
        a for a in all_assets
        if any(
            pat in (a.get("network", {}).get("fqdns") or [""])[0].lower()
            for pat in TARGET_PATTERNS
        )
    ]

    # Deterministic selection: sort by ID, pick first 100
    eligible.sort(key=lambda a: a["id"])
    target = eligible[:100]

    print(f"Eligible assets (laptop/VM/server): {len(eligible)}")
    print(f"Selecting first 100 deterministically by asset ID")

    findings = []
    counts   = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for asset in target:
        os_str = (asset.get("operating_systems") or [""])[0]
        vulns  = pick_vulns(asset["id"], "", os_str)
        for v in vulns:
            findings.append(make_finding(asset, v))
            counts[v[0]] += 1

    print(f"\nGenerated {len(findings)} findings across {len(target)} assets")
    print(f"  Critical: {counts['critical']}")
    print(f"  High:     {counts['high']}")
    print(f"  Medium:   {counts['medium']}")
    print(f"  Low:      {counts['low']}")

    # Wrap in a minimal envelope so app.py can detect chunk count
    output = {
        "findings": findings,
        "total": len(findings),
        "chunk_size": 500,
        "chunks": max(1, -(-len(findings) // 500)),  # ceiling division
    }
    VULNS_FILE.write_text(json.dumps(output, indent=2))
    print(f"\nWrote {VULNS_FILE}")
    print(f"Chunks: {output['chunks']}  (chunk_size={output['chunk_size']})")


if __name__ == "__main__":
    main()
