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

Additional endpoints implemented (stubs for connector discovery scope):
- Vulnerabilities export (POST/GET /vulns/export/...) — empty, FINISHED
- Compliance export (POST/GET /compliance/export/...) — empty, FINISHED
- GET /networks — default network record (UUID 00000000-...) required by asset records
- GET /scanners — single scanner record
- GET /scans — empty
- GET /users — single admin user
- GET /user-groups — empty
- GET /was/v2/vulnerabilities — empty WAS vulns
- GET /filters/workbenches/... — empty filter lists

**Auth:** `X-ApiKeys: accessKey=<key>; secretKey=<secret>` header.
Permissive unless `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` env vars are set.

## Architecture

Single Flask app (`app.py`) loads `seed_data/raw/assets.json` into memory at
startup and serves the Tenable API. Deployed via Dockerfile (gunicorn).

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
