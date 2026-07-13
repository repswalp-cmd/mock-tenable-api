# Mock Tenable Vulnerability Management API

A mock **Tenable Vulnerability Management** API (Flask) serving **1,425 assets** for the
**Luminary Systems** demo tenant, so the Infoblox Universal Asset Insights Tenable
connector can discover assets without a real Tenable subscription.

Deployed on AWS App Runner: **https://9rdis2evgu.us-east-1.awsapprunner.com**

---

## API Contract

The UAI connector uses the **V2 asset export flow**:

```
POST /assets/v2/export
  → {"export_uuid": "<static-uuid>"}

GET  /assets/export/{export_uuid}/status
  → {"status": "FINISHED", "chunks_available": [1, 2]}

GET  /assets/export/{export_uuid}/chunks/1   → JSON array, 1000 assets
GET  /assets/export/{export_uuid}/chunks/2   → JSON array, 425 assets
```

Asset records use the **V2 chunk schema** — network identity fields nested under `network`:
- `network.ipv4s`, `network.fqdns`, `network.hostnames`, `network.mac_addresses`
- `network.fqdns[0]` is used by the connector as the display name (short hostname, no domain)
- Scan timestamps nested under `scan.last_scan_time` etc.

**Full discovery scope endpoints also implemented:**

| Group | Endpoints |
|---|---|
| Assets | `POST/GET /assets/v2/export`, `/assets/export`, status, chunks, `GET /assets`, `GET /assets/{uuid}` |
| Vulnerabilities | `POST /vulns/export`, status, chunks (empty) |
| Compliance | `POST /compliance/export`, status, chunks (empty) |
| Platform | `GET /networks`, `/scanners`, `/scans`, `/exclusions`, `/server/properties` |
| Users | `GET /users`, `/groups`, `/user-groups`, `/user-groups/{id}/members` |
| Agents | `GET /scanners/null/agents`, `/scanners/{id}/agents` |
| Rules | `GET+POST /v1/recast/rules/search` |
| WAS | `GET+POST /was/v2/vulnerabilities/search`, `/was/v2/configs`, `/was/v2/scans` |
| Filters | `GET /filters/workbenches/assets`, `/filters/workbenches/vulnerabilities` |
| Attributes | `GET /api/v3/assets/attributes` |
| Diagnostics | `GET /`, `GET /debug/requests` |

**Auth:** `X-ApiKeys: accessKey=<key>; secretKey=<secret>`  
The mock is permissive — any non-empty keys are accepted unless `TIO_ACCESS_KEY` /
`TIO_SECRET_KEY` env vars are set.

---

## Dataset

**1,425 Luminary Systems assets** — 2 export chunks (1,000 + 425)

Source: [luminary-demo-docs master sheet](https://github.com/repswalp-cmd/luminary-demo-docs)

### By site

| Site          | Assets |
|---------------|--------|
| San Francisco | 453    |
| Bangalore     | 266    |
| London        | 215    |
| New York      | 204    |
| Amsterdam     | 165    |
| Singapore     | 122    |

### By category

| Category     | Count | Notes                              |
|--------------|-------|------------------------------------|
| win_laptop   | 550   | Windows endpoints, ~62% with agent |
| mac_laptop   | 299   | Mac endpoints, ~62% with agent     |
| iot          | 155   | Network scan only, no agent        |
| wap          | 130   | Wireless APs, network scan only    |
| win_vm       | 126   | Windows VMs                        |
| linux_vm     | 105   | Linux VMs                          |
| switch       | 64    | Network scan only                  |
| linux_ws     | 37    | Linux workstations                 |
| vdi          | 36    | VDI endpoints                      |
| printer      | 33    | Network scan only                  |
| win_server   | 12    | Windows servers                    |
| router       | 10    | Network scan only                  |
| linux_server | 9     | Linux servers                      |
| security     | 9     | Security appliances, no agent      |
| clinic       | 7     | Medical devices, no agent          |
| esx_server   | 5     | ESXi hosts, no agent               |
| **Total**    | **1,425** | |

**No user/email fields** — vulnerability scanner data only.

---

## Data Generation

```bash
python3 seed_data/generate_tenable_data.py
```

Reads from central master sheet (or falls back to `seed_data/source/assets_luminary.xlsx`).
Prints `CENTRAL` or `LOCAL` to confirm which xlsx it's reading.

The generated `seed_data/raw/assets.json` is committed so the deployed app serves data.

---

## Local Development

```bash
pip install flask gunicorn
python app.py
# test: curl -H "X-ApiKeys: accessKey=demo; secretKey=demo" http://localhost:5000/
```

---

## Deployment

```bash
# Authenticate
aws ecr get-login-password --profile okta-sso --region us-east-1 \
  | docker login --username AWS --password-stdin 905418046272.dkr.ecr.us-east-1.amazonaws.com

# Build & push
docker build --no-cache --platform linux/amd64 \
  -t 905418046272.dkr.ecr.us-east-1.amazonaws.com/mock-tenable-api:latest .
docker push 905418046272.dkr.ecr.us-east-1.amazonaws.com/mock-tenable-api:latest

# Trigger App Runner deploy (auto-deploy is disabled)
aws apprunner start-deployment --profile okta-sso --region us-east-1 \
  --service-arn <ARN>
```

---

## Contact

Built for Infoblox Universal Asset Insights Simulator. Contact: TME Team or Rajkumar Repswal for any questions.

---

*Mock API for testing purposes. Not affiliated with or endorsed by Tenable or Infoblox.*
