# Webhook Test Server

Configurable webhook test server. Logs incoming headers and payloads, returns a configurable status. All settings can be changed at runtime via admin API — no restart needed.

## Setup

```bash
npm install
cp .env.example .env   # edit credentials as needed
npm start
```

## Environment Variables

| Variable         | Default    | Description                             |
| ---------------- | ---------- | --------------------------------------- |
| `ADMIN_USERNAME` | `admin`    | Basic auth username for admin endpoints |
| `ADMIN_PASSWORD` | `changeme` | Basic auth password for admin endpoints |
| `PORT`           | `3000`     | Server port                             |

## Endpoints

### Webhook

| Method | Path       | Auth         | Description                                                       |
| ------ | ---------- | ------------ | ----------------------------------------------------------------- |
| Any    | `/webhook` | Configurable | Receives webhooks, logs headers + body, returns configured status |

### Admin (all require Basic auth from `.env`)

| Method | Path            | Description                     |
| ------ | --------------- | ------------------------------- |
| GET    | `/admin/config` | View current configuration      |
| PATCH  | `/admin/config` | Update configuration at runtime |
| GET    | `/admin/logs`   | View captured request logs      |
| DELETE | `/admin/logs`   | Clear all captured logs         |

## Configuration

Send a `PATCH` to `/admin/config` with any of the following fields (all optional):

```json
{
  "authMode": "none|basic|token|both",
  "webhookBasicUser": "user",
  "webhookBasicPass": "pass",
  "webhookToken": "my-secret-token",
  "responseStatus": 200,
  "responseBody": { "ok": true },
  "allowedIPs": ["192.30.252.0/22", "::1"],
  "requiredHeaders": [{ "name": "x-webhook-secret", "value": "mysecret" }],
  "rateLimitPerIp": 10,
  "rateLimitGlobal": 30
}
```

### Auth Modes

| Mode    | Behavior                                                             |
| ------- | -------------------------------------------------------------------- |
| `none`  | No authentication required (default)                                 |
| `basic` | Requires Basic auth matching `webhookBasicUser` / `webhookBasicPass` |
| `token` | Requires `Authorization: Bearer <webhookToken>` header               |
| `both`  | Accepts either basic or token authentication                         |

### Whitelist

| Field             | Type                | Default               | Description                                                             |
| ----------------- | ------------------- | --------------------- | ----------------------------------------------------------------------- |
| `allowedIPs`      | `string[]`          | `[]` (allow all)      | IP addresses or CIDR ranges to accept. Empty = no restriction.          |
| `requiredHeaders` | `{ name, value }[]` | `[]` (no requirement) | Headers that **all** must be present and match. Empty = no restriction. |

### Rate Limiting

| Field             | Type     | Default | Description                                                   |
| ----------------- | -------- | ------- | ------------------------------------------------------------- |
| `rateLimitPerIp`  | `number` | `10`    | Max requests per IP per minute. `0` = disabled.               |
| `rateLimitGlobal` | `number` | `30`    | Max total requests per minute across all IPs. `0` = disabled. |

## Security

- **Helmet** — Sets security headers on all responses (CSP, HSTS, X-Frame-Options, etc.)
- **Rate limiting** — `/webhook` is capped at 10 req/min per IP and 30 req/min globally by default. Both are configurable at runtime. Returns `429` when exceeded.
- **IP whitelist** — Optionally restrict `/webhook` to specific IPs or CIDR ranges.
- **Header whitelist** — Optionally require specific headers to be present with exact values.
- **Body size limit** — All request bodies are limited to 256KB.

## Examples

### Sending test webhooks

```bash
# No auth (default config)
curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -d '{"event":"test","data":"hello"}'
```

### Configuring token auth

```bash
# Enable token auth and 202 response
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{"authMode":"token","webhookToken":"secret123","responseStatus":202}'

# Send with token
curl -X POST http://localhost:3000/webhook \
  -H "Authorization: Bearer secret123" \
  -H "Content-Type: application/json" \
  -d '{"event":"deploy","status":"success"}'
```

### Configuring basic auth

```bash
# Enable basic auth
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{"authMode":"basic","webhookBasicUser":"hook","webhookBasicPass":"pass123"}'

# Send with basic auth
curl -u hook:pass123 -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -d '{"event":"test"}'
```

### Configuring whitelist and rate limits

```bash
# Only allow GitHub webhook IPs and require a secret header
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{
    "allowedIPs": ["192.30.252.0/22", "185.199.108.0/22"],
    "requiredHeaders": [{"name": "x-webhook-secret", "value": "mysecret"}]
  }'

# Tighten rate limits
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{"rateLimitPerIp": 5, "rateLimitGlobal": 20}'

# Disable rate limiting entirely
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{"rateLimitPerIp": 0, "rateLimitGlobal": 0}'

# Clear whitelist (allow all IPs and headers again)
curl -u admin:changeme -X PATCH http://localhost:3000/admin/config \
  -H "Content-Type: application/json" \
  -d '{"allowedIPs": [], "requiredHeaders": []}'
```

### Managing logs

```bash
# View captured requests
curl -u admin:changeme http://localhost:3000/admin/logs

# Clear logs
curl -u admin:changeme -X DELETE http://localhost:3000/admin/logs

# Check current config
curl -u admin:changeme http://localhost:3000/admin/config
```
