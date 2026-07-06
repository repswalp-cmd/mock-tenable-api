# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What this is

A mock **Tenable Vulnerability Management** API (Flask) serving **1,587 assets** for the
**Luminary Systems** demo tenant, so the Infoblox Universal Asset Insights Tenable
connector can discover assets without a real Tenable subscription.

Sibling project to the other mock vendor APIs (CrowdStrike, ServiceNow, Jamf, etc.).
Same Flask-on-App-Runner pattern.

## API contract

The UAI connector uses the **V2 asset export flow**:
1. `POST /assets/v2/export` → `{"export_uuid": "<static-uuid>"}` — same UUID every call
2. `GET /assets/export/{uuid}/status` → `{"status": "FINISHED", "chunks_available": [1, 2]}`
3. `GET /assets/export/{uuid}/chunks/1` → JSON array of 1000 assets (not wrapped)
4. `GET /assets/export/{uuid}/chunks/2` → JSON array of 587 assets

**V2 chunk schema** — network identity fields are nested under `network`:
```json
{
  "id": "...",
  "has_agent": true,
  "network": {
    "network_id": "00000000-0000-0000-0000-000000000000",
    "network_name": "Default",
    "ipv4s": ["10.x.x.x"],
    "fqdns": ["lsys-blr-lap-0001"],
    "hostnames": ["lsys-blr-lap-0001"],
    "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
    "netbios_names": [],
    "network_interfaces": [{"name": "eth0", "ipv4s": [...], "mac_addresses": [...], ...}]
  },
  "scan": {"last_scan_time": "...", "first_scan_time": "..."},
  "operating_systems": ["Windows 11 Enterprise"],
  "system_types": ["general-purpose"],
  "agent_names": ["lsys-blr-lap-0001"],
  "sources": [{"name": "NESSUS_SCAN", ...}]
}
```

**Note:** `network.fqdns[0]` is read by the connector as the asset display name — keep it
as the short hostname (no domain suffix) so the portal shows clean names.

### Full endpoint list

**Assets (full data):**
- `POST /assets/v2/export` — start V2 asset export (static UUID)
- `POST /assets/export` — start V1 asset export (same static UUID)
- `GET  /assets/export/{uuid}/status` — export status → FINISHED
- `GET  /assets/export/status` — bare status (no UUID)
- `GET  /assets/export/{uuid}/chunks/{n}` — download chunk
- `GET  /assets` — full asset list
- `GET  /assets/{uuid}` — single asset

**Vulnerabilities (empty export):**
- `POST /vulns/export`
- `GET  /vulns/export/{uuid}/status` → FINISHED, 0 chunks
- `GET  /vulns/export/status`
- `GET  /vulns/export/{uuid}/chunks/{n}` → empty array

**Compliance (empty export):**
- `POST /compliance/export`
- `GET  /compliance/export/{uuid}/status` → FINISHED, 0 chunks
- `GET  /compliance/export/status`
- `GET  /compliance/export/{uuid}/chunks/{n}` → empty array

**Platform & Settings stubs:**
- `GET  /networks` — default network record (UUID 00000000-…)
- `GET  /scanners` — single scanner record
- `GET  /scans` — empty list
- `GET  /exclusions` — empty list
- `GET  /users` — single admin user
- `GET  /groups` — empty groups list
- `GET  /user-groups` — empty user-groups list
- `GET  /user-groups/{id}/members` — empty members list
- `GET  /scanners/null/agents` — empty agents (null = default scanner)
- `GET  /scanners/{id}/agents` — empty agents
- `GET  /server/properties` — realistic server properties dict
- `GET  /api/v3/assets/attributes` — empty attributes list

**Recast / Rules:**
- `GET+POST /v1/recast/rules/search` — empty rules list

**WAS (Web App Scanning) stubs:**
- `GET      /was/v2/vulnerabilities` — empty
- `GET+POST /was/v2/vulnerabilities/search` — empty pagination response
- `GET      /was/v2/configs` — empty
- `GET      /was/v2/scans` — empty

**Filters stubs:**
- `GET /filters/workbenches/assets` — empty filter list
- `GET /filters/workbenches/vulnerabilities` — empty filter list

**Health & Diagnostics:**
- `GET /` — health check + loaded asset count + all endpoints
- `GET /debug/requests` — last 200 connector requests (add `?clear=1` to reset)

**Auth:** `X-ApiKeys: accessKey=<key>; secretKey=<secret>` header.
Permissive unless `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` env vars are set.

## Architecture

Single Flask app (`app.py`) loads `seed_data/raw/assets.json` into memory at
startup and serves the Tenable API. Deployed via Dockerfile (gunicorn).

`last_seen` is overridden dynamically at serve time (per-asset jitter) so assets
always appear recently seen. Controlled by `TIO_DYNAMIC_LASTSEEN` env var (default: on).

## Data generation

```bash
python3 seed_data/generate_tenable_data.py
```

Reads from `{API root}/luminary-demo-docs/master-sheet/assets_luminary.xlsx` (CENTRAL)
or falls back to `seed_data/source/assets_luminary.xlsx` (LOCAL).
Prints CENTRAL or LOCAL to confirm which xlsx it's reading.

`seed_data/raw/assets.json` IS committed — do not gitignore it.

## No user/email fields

Tenable is a vulnerability scanner. The asset records do NOT contain assigned_to /
user / email fields. Only network identity fields: hostname, IP, MAC, OS, FQDN.

## Deployment

ECR repo: `mock-tenable-api`
App Runner service: `mock-tenable-api` at `https://9rdis2evgu.us-east-1.awsapprunner.com`
Auto-deploy: **disabled** — requires `aws apprunner start-deployment` after ECR push.

## Diagnostics

`GET /debug/requests` shows what the connector requested — use it to diagnose
any integration issues. `GET /` shows loaded asset count and all endpoints.
