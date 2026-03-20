# Wicketgate

A Cloudflare Worker that generates opaque, shareable links to services behind Cloudflare Tunnels. Clients get a single URL that just works — no tokens to configure, no headers to set, no knowledge of your infrastructure required.

```
https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

That URL is the entire client configuration. It encodes which service to reach and how to authenticate with Cloudflare Access. The person using it doesn't know — or need to know — anything else.

---

## Table of contents

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Use cases](#use-cases)
- [Installation](#installation)
- [Configuration](#configuration)
- [Dashboard usage](#dashboard-usage)
- [Client examples](#client-examples)
- [API reference](#api-reference)
- [Auth modes](#auth-modes)
- [Security](#security)
- [Rate limiting](#rate-limiting)
- [Local development](#local-development)
- [Cost](#cost)
- [License](#license)

---

## The problem

You self-host services behind Cloudflare Tunnels with Access policies. Browser access works — you log in once and get a session cookie. But native apps and mobile clients don't speak Cloudflare Access:

- **Media apps** (Jellyfin, Plex, Navidrome clients) can't send service token headers
- **Game library apps** (Daijishō, Lemuroid, RomM clients) just see a 403
- **Home automation apps** can't reach Home Assistant behind Access
- **Git clients** can't push to Gitea/Forgejo behind a tunnel
- **RSS readers** can't fetch from Miniflux or FreshRSS
- **Any app** that takes a "server URL" and nothing else

The standard workarounds — running `cloudflared` on every client device, bypassing Access entirely, or hoping the app adds Cloudflare support — are either impractical or insecure.

## How it works

```
┌──────────────┐        ┌───────────────────────┐        ┌──────────────────┐        ┌──────────────┐
│    Client     │──────▶ │   Wicketgate │──────▶ │ Cloudflare Access │──────▶ │ Your service │
│ (any app)     │        │   (this Worker)        │        │ (validates svc   │        │ (behind      │
│               │        │                        │        │  token headers)  │        │  tunnel)     │
│ Only knows:   │        │ 1. Looks up key in KV  │        │                  │        │              │
│ /s/{key}/     │        │ 2. Finds origin config │        │                  │        │              │
│               │        │ 3. Injects CF headers  │        │                  │        │              │
│               │◀────── │ 4. Proxies response    │◀────── │                  │◀────── │              │
└──────────────┘        └───────────────────────┘        └──────────────────┘        └──────────────┘
```

1. You configure an **origin** — a hostname behind a tunnel, plus its Cloudflare Access service token credentials
2. You generate an **access key** — a random opaque string tied to that origin
3. You give the client the URL `https://wicketgate.yourdomain.com/s/{key}/`
4. The Worker looks up the key, finds the origin, injects the service token headers, and proxies the request
5. The client gets a normal response. It has no idea Cloudflare Access exists.

The key reveals nothing. Not the service name, not the hostname, not the auth mechanism, not anything about your infrastructure.

## Use cases

### Media streaming

You run Jellyfin behind a tunnel. Your family needs access from their phones.

1. Add Jellyfin as an origin with its service token
2. Generate a key for "Mom's iPad"
3. Give her `https://wicketgate.yourdomain.com/s/xK9mQ2v.../` as the server URL in the Jellyfin app
4. She streams. You can revoke access any time.

### Game library

You run RomM and want to access your ROM library from Daijishō on your phone while traveling.

1. Add RomM as an origin
2. Generate a key for "my phone"
3. Plug the URL into Daijishō as the server
4. Browse your game library from anywhere

### Home automation

Home Assistant is behind a tunnel. You want the companion app to work remotely without exposing HA to the internet unprotected.

1. Add Home Assistant as an origin
2. Generate a key for each family member's phone
3. Each person gets their own URL. Revoke individually if a phone is lost.

### Git hosting

Gitea or Forgejo behind a tunnel. You want to `git push` from your laptop without running `cloudflared` locally.

```bash
# Instead of:
git remote set-url origin https://gitea.yourdomain.com/you/repo.git

# Use:
git remote set-url origin https://wicketgate.yourdomain.com/s/xK9mQ2v.../you/repo.git
```

Git just sees a URL. It works over HTTPS as normal.

### RSS feeds

Your self-hosted Miniflux or FreshRSS is behind a tunnel. Feed reader apps (NetNewsWire, Reeder, etc.) just need a server URL:

```
https://wicketgate.yourdomain.com/s/xK9mQ2v.../
```

### Sharing with non-technical people

The real power: you can give someone access to a service without explaining anything about Cloudflare, tunnels, tokens, or headers. "Here's the URL, paste it in the app" is the entire conversation.

---

## Installation

### Prerequisites

- A Cloudflare account with at least one tunnel configured
- Services behind those tunnels protected by Cloudflare Access policies
- A Cloudflare Access **service token** for each service (or a shared one)
- [Node.js](https://nodejs.org) 18+ (for the Wrangler CLI)

### Step 1: Clone or download

```bash
git clone https://github.com/youruser/wicketgate.git
cd wicketgate
```

Or just download and unzip the files. The project is four files:

```
wicketgate/
├── src/
│   ├── worker.js        # The Worker logic
│   └── dashboard.html   # Admin dashboard UI
├── wrangler.toml        # Deployment config
├── package.json
├── LICENSE
└── README.md
```

### Step 2: Install Wrangler

```bash
npm install
```

Or if you have Wrangler installed globally, skip this.

### Step 3: Create a KV namespace

```bash
npx wrangler kv namespace create WICKETGATE_KV
```

You'll see output like:

```
🌀 Creating namespace with title "wicketgate-WICKETGATE_KV"
✨ Success!
Add the following to your configuration file in your kv_namespaces array:
[[kv_namespaces]]
binding = "WICKETGATE_KV"
id = "abc123def456..."
```

Open `wrangler.toml` and uncomment/update the KV section:

```toml
[[kv_namespaces]]
binding = "WICKETGATE_KV"
id = "abc123def456..."    # ← paste your actual ID
```

### Step 4: Set secrets

```bash
# Required if you want built-in dashboard auth (recommended for workers.dev):
npx wrangler secret put ADMIN_SECRET
# Paste a strong random string, e.g.: openssl rand -base64 32

# Optional — for auto-discovering tunnel hostnames:
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put CF_ACCOUNT_ID
```

**Generating an ADMIN_SECRET:**

```bash
# macOS / Linux
openssl rand -base64 32

# Or use Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**CF_API_TOKEN** needs the permission `Account > Cloudflare Tunnel > Read`. Create one at https://dash.cloudflare.com/profile/api-tokens. This is optional — you can add origins manually without it.

**CF_ACCOUNT_ID** is on your Cloudflare dashboard home page, right sidebar.

### Step 5: Deploy

```bash
npx wrangler deploy
```

Your Worker is now live at `wicketgate.YOUR_SUBDOMAIN.workers.dev`.

### Step 6: Custom domain (recommended)

A custom domain lets you put the admin dashboard behind Cloudflare Access, and gives you a cleaner URL to share.

**Via the Cloudflare dashboard:**

1. Go to Workers & Pages → your worker → Settings → Domains & Routes
2. Click "Add" → Custom Domain
3. Enter your desired subdomain, e.g. `wicketgate.yourdomain.com`
4. Cloudflare creates the DNS record automatically

**Via DNS + wrangler route:**

1. Add a DNS `AAAA` record: `wicketgate` → `100::` (proxied / orange cloud)
2. Uncomment the `[[routes]]` block in `wrangler.toml`:

```toml
[[routes]]
pattern = "wicketgate.yourdomain.com/*"
zone_name = "yourdomain.com"
```

3. Redeploy: `npx wrangler deploy`

### Step 7: Protect the dashboard

The dashboard requires authentication. There are two options:

**Option A — ADMIN_SECRET (always required unless using Option B):**

Set an `ADMIN_SECRET` (see [Step 5](#step-5-set-secrets)):

```bash
npx wrangler secret put ADMIN_SECRET
```

**Option B — Cloudflare Access (external gate) instead of ADMIN_SECRET:**

If you're using a custom domain, you can put the dashboard behind Cloudflare Access and skip the built-in secret by setting `ALLOW_UNAUTH_ADMIN=true`:

1. Go to Zero Trust → Access → Applications → Add an application
2. Choose **Self-hosted**
3. Configure:
   - **Application name**: Wicketgate Admin
   - **Subdomain**: `broker` | **Domain**: `yourdomain.com`
   - **Path**: `admin`
4. Add a policy:
   - **Action**: Allow
   - **Include**: Emails — `your@email.com`
5. Save
6. Set `ALLOW_UNAUTH_ADMIN=true` in your `wrangler.toml` under `[vars]`.

Now `/admin` and `/admin/*` require your Cloudflare login, while `/s/*` stays open for clients.

**Important**: Do NOT put an Access policy on the root domain or `/s/*` — that would block client requests.

### Step 8: Create a service token

If you don't already have one:

1. Go to Zero Trust → Access → Service Auth → Create Service Token
2. **Save both the Client ID and Client Secret immediately** — the secret is only shown once
3. Go to the Access Application for your service's hostname
4. Add a policy:
   - **Action**: Service Auth
   - **Include**: Service Token — select the one you just created

You need one service token per Access application. If multiple hostnames share an Access app, they can share a token.

---

## Configuration

### Environment variables / secrets

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_SECRET` | Yes* | Password for the admin dashboard and API. Required unless `ALLOW_UNAUTH_ADMIN=true` is set. |
| `ALLOW_UNAUTH_ADMIN` | No | Set to `"true"` to bypass built-in admin auth. **Only use when `/admin*` is protected by an external gate** (e.g., Cloudflare Access). |
| `CF_API_TOKEN` | No | Cloudflare API token for tunnel discovery. Needs `Account > Cloudflare Tunnel > Read`. |
| `CF_ACCOUNT_ID` | No | Your Cloudflare account ID. Required alongside `CF_API_TOKEN`. |

\* Required unless `ALLOW_UNAUTH_ADMIN=true` is explicitly set (external-gate mode only).

### KV namespace

| Binding | Description |
|---------|-------------|
| `WICKETGATE_KV` | Stores all origins and access keys. Required. |

### KV data schema

| Key pattern | Value | Description |
|-------------|-------|-------------|
| `origin:{slug}` | `{ hostname, serviceTokenId, serviceTokenSecret, label, created }` | A configured origin/service |
| `key:{opaque_key}` | `{ name, origin, created }` | An access key mapped to an origin |

---

## Dashboard usage

Go to `https://wicketgate.yourdomain.com/admin`.

The dashboard has three tabs:

### Access Keys tab

This is the primary view. To create a new access link:

1. Enter a name — who or what this is for ("Dad's phone", "bedroom Roku", "CI server")
2. Select the service from the dropdown
3. Click **Generate link**
4. Copy the link and send it to the person

The link looks like: `https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/`

Active keys are listed below with their name, creation date, associated service, and a copy button. Click **Revoke** to immediately kill a key.

### Origins tab

Configure services wicketgate can proxy to:

1. **Slug** — a short identifier (`jellyfin`, `romm`, `ha`). Only used internally.
2. **Label** — a friendly name shown in the dashboard ("Media server", "Game library")
3. **Hostname** — the tunnel hostname (`jellyfin.yourdomain.com`)
4. **Service token ID** — the `CF-Access-Client-Id` for this hostname's Access application
5. **Service token secret** — the `CF-Access-Client-Secret`

### Discover tab

If you've set `CF_API_TOKEN` and `CF_ACCOUNT_ID`, this tab pulls all hostnames from your Cloudflare Tunnels. For each hostname:

- If it's already configured as an origin, it shows a "configured" badge
- If not, click **Add as origin** to prefill the origin form — you just need to add the service token credentials

---

## Client examples

In every example below, the base URL is:

```
https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

The client appends its API paths after the trailing slash. The Worker strips `/s/{key}` and forwards the rest.

### Jellyfin / Emby

In the Jellyfin app connection screen:

```
Server address: https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

The app discovers the API at `/System/Info` and everything works normally.

### RomM + Daijishō

In Daijishō's server settings:

```
Server URL: https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

### Home Assistant companion app

In the companion app setup:

```
External URL: https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

### Navidrome / Subsonic clients

In a Subsonic-compatible app (play:Sub, Symfonium, etc.):

```
Server: https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

The `/rest/` API paths get forwarded normally.

### Git over HTTPS

```bash
git clone https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/youruser/yourrepo.git

# Or update an existing remote:
git remote set-url origin https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/youruser/yourrepo.git
```

### curl

```bash
# Simple GET
curl https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/api/endpoint

# POST with data
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}' \
  https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/api/endpoint
```

### wget

```bash
wget https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/files/document.pdf
```

### Python (requests)

```python
import requests

BASE = "https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j"

response = requests.get(f"{BASE}/api/items")
print(response.json())
```

### JavaScript (fetch)

```javascript
const BASE = "https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j";

const response = await fetch(`${BASE}/api/items`);
const data = await response.json();
```

### iOS Shortcuts / Scriptable

Use the URL directly in any HTTP action:

```
https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/api/endpoint
```

### Browser bookmark

Note: The proxy strips `Cookie` headers from requests and `Set-Cookie` from responses, so session-based web UIs (apps that require login) will not work through a bookmark. Wicketgate is best suited for API access or services that do not rely on cookies for session state.

For services that do work without cookies, you can bookmark the URL:

```
https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/
```

---

## API reference

All admin endpoints are under `/admin/`. Auth depends on your [auth mode](#auth-modes).

### Origins

#### List origins

```
GET /admin/origins
```

```bash
curl https://wicketgate.yourdomain.com/admin/origins \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Response:

```json
{
  "origins": [
    {
      "slug": "jellyfin",
      "hostname": "jellyfin.yourdomain.com",
      "label": "Media server",
      "created": "2026-03-18T12:00:00.000Z"
    }
  ]
}
```

Note: credential fields (`serviceTokenId`, `serviceTokenSecret`) are omitted from list responses.

#### Create origin

```
POST /admin/origins
Content-Type: application/json
```

```bash
curl -X POST https://wicketgate.yourdomain.com/admin/origins \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "jellyfin",
    "hostname": "jellyfin.yourdomain.com",
    "label": "Media server",
    "serviceTokenId": "your-cf-access-client-id",
    "serviceTokenSecret": "your-cf-access-client-secret"
  }'
```

| Field | Required | Description |
|-------|----------|-------------|
| `slug` | Yes | Lowercase alphanumeric with hyphens. Internal identifier. |
| `hostname` | Yes | The tunnel hostname. |
| `serviceTokenId` | Yes | CF-Access-Client-Id for this hostname's Access application. |
| `serviceTokenSecret` | Yes | CF-Access-Client-Secret. |
| `label` | No | Friendly name for the dashboard. Defaults to the slug. |

#### Update origin (partial)

```
PATCH /admin/origins/{slug}
Content-Type: application/json
```

```bash
curl -X PATCH https://wicketgate.yourdomain.com/admin/origins/jellyfin \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"label": "Jellyfin (new name)"}'
```

Only include fields you want to change. To clear the label, pass `"label": ""`.

#### Replace origin (full)

```
PUT /admin/origins/{slug}
Content-Type: application/json
```

```bash
curl -X PUT https://wicketgate.yourdomain.com/admin/origins/jellyfin \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "jellyfin.example.com", "serviceTokenId": "id", "serviceTokenSecret": "secret", "label": "Jellyfin"}'
```

Replaces the entire origin record. `hostname`, `serviceTokenId`, and `serviceTokenSecret` are all required. `label` is optional (defaults to the slug). The `created` timestamp is preserved.

#### Delete origin

```
DELETE /admin/origins/{slug}
```

```bash
curl -X DELETE https://wicketgate.yourdomain.com/admin/origins/jellyfin \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Warning: existing access keys for this origin will stop working.

### Access keys

#### List keys

```
GET /admin/keys
```

```bash
curl https://wicketgate.yourdomain.com/admin/keys \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Response:

```json
{
  "keys": [
    {
      "key": "xK9mQ2vL8nP4wR7jAb3cDe...",
      "name": "Dad's phone",
      "origin": "jellyfin",
      "created": "2026-03-18T14:30:00.000Z"
    }
  ]
}
```

#### Create key

```
POST /admin/keys
Content-Type: application/json
```

```bash
curl -X POST https://wicketgate.yourdomain.com/admin/keys \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name": "Dad phone", "origin": "jellyfin"}'
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | No | Who/what this is for. Defaults to "unnamed". |
| `origin` | Yes | Slug of the origin this key can access. Must already exist. |

Response:

```json
{
  "key": "xK9mQ2vL8nP4wR7jAb3cDe...",
  "name": "Dad phone",
  "origin": "jellyfin"
}
```

The share URL is: `https://wicketgate.yourdomain.com/s/{key}/`

#### Revoke key

```
DELETE /admin/keys/{key}
```

```bash
curl -X DELETE https://wicketgate.yourdomain.com/admin/keys/xK9mQ2vL8nP4wR7jAb3cDe... \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Takes effect immediately.

### Tunnel discovery

```
GET /admin/discover
```

```bash
curl https://wicketgate.yourdomain.com/admin/discover \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Requires `CF_API_TOKEN` and `CF_ACCOUNT_ID` to be set.

Response:

```json
{
  "hostnames": [
    {
      "hostname": "jellyfin.yourdomain.com",
      "tunnelName": "homelab",
      "suggestedSlug": "jellyfin",
      "configured": false
    },
    {
      "hostname": "ha.yourdomain.com",
      "tunnelName": "homelab",
      "suggestedSlug": "ha",
      "configured": true
    }
  ]
}
```

### Auth mode check

```
GET /admin/auth-mode
```

Returns whether built-in auth is enabled. Used by the dashboard to decide whether to show the login screen. No auth required for this endpoint.

```json
{ "authRequired": true }
```

---

## Auth modes

The dashboard and admin API support two modes:

### Mode 1: Built-in auth (ADMIN_SECRET) — default

`ADMIN_SECRET` **must be set** by default. The dashboard shows a login screen and all API requests must authenticate.

The API accepts two auth methods:

**Bearer token** (used by the dashboard):
```
Authorization: Bearer YOUR_ADMIN_SECRET
```

**HTTP Basic Auth** (for curl, browsers, etc.):
```bash
# Username is ignored, password is the ADMIN_SECRET
curl -u :YOUR_ADMIN_SECRET https://wicketgate.yourdomain.com/admin/keys
```

If a browser hits an API endpoint without credentials, it gets a `401` with `WWW-Authenticate: Basic` header, triggering the browser's native login prompt.

### Mode 2: External gate only (ALLOW_UNAUTH_ADMIN)

If you protect `/admin*` with an external gate (e.g., Cloudflare Access), you can skip the built-in secret by setting `ALLOW_UNAUTH_ADMIN=true`. In this mode, no `ADMIN_SECRET` is needed and the dashboard loads without a login screen.

```toml
# wrangler.toml — only when /admin* is behind Cloudflare Access
[vars]
ALLOW_UNAUTH_ADMIN = "true"
```

> ⚠️ **Warning:** Setting `ALLOW_UNAUTH_ADMIN=true` without an external auth gate makes the admin API fully public. Anyone can create or revoke keys and origins.

**You can use both.** If you put `/admin*` behind Cloudflare Access AND set `ADMIN_SECRET`, a user must pass both gates. This is the most secure option.

---

## Security

### What the client sees

A client using `https://wicketgate.yourdomain.com/s/xK9mQ2vL8nP4wR7j/api/items` knows:

- There's a domain called `wicketgate.yourdomain.com`
- There's a path starting with `/s/` and a random string
- The service returns data

A client does **not** see:

- The real hostname of the service
- That Cloudflare Access is involved
- Any service token credentials
- What other services the broker can reach
- Any other users' keys

### Error messages

Error responses are deliberately vague:

| Situation | Response |
|-----------|----------|
| Invalid key | `403 Access denied.` |
| Origin not configured or fetch error | `502 Service unavailable.` |
| Path traversal attempt | `400 Not found.` |
| Unknown URL pattern | `404 Not found.` |

No internal details, hostnames, or configuration info is ever leaked.

### Where credentials live

| Credential | Stored in | Exposed to |
|------------|-----------|------------|
| CF Access service token ID/secret | KV (per origin) | Never leaves Cloudflare's edge |
| Admin secret | Worker secret | Never sent to clients |
| Client access keys | KV | Only in the share URL |

### Timing-safe comparison

All secret/key validation uses constant-time comparison to prevent timing attacks.

### CORS

The Worker returns `Access-Control-Allow-Origin: *` on proxy responses, allowing browser-based clients. If you know your client origins, restrict this in the `proxyCorsHeaders()` function in `worker.js`.

### Key entropy

Access keys are 32 random bytes (256 bits of entropy), URL-safe base64 encoded. Brute-forcing a key at 1 billion attempts per second would take approximately 3.7×10^60 years.

---

## Rate limiting

Consider adding Cloudflare rate limiting to prevent brute-force key guessing:

1. Go to your domain in the Cloudflare dashboard
2. Security → WAF → Rate limiting rules
3. Create a rule:
   - **If**: URI path starts with `/s/` AND response code is `403`
   - **Then**: Block for 10 minutes
   - **Rate**: 10 requests per minute per IP

This blocks IPs that are rapidly hitting invalid keys without affecting legitimate users.

---

## Local development

```bash
# Local dev server with local KV (starts empty)
npx wrangler dev

# Local dev server using your production KV data
npx wrangler dev --remote
```

The dashboard is at `http://localhost:8787/admin`.

To seed local KV with test data:

```bash
# Create a test origin
curl -X POST http://localhost:8787/admin/origins \
  -H "Authorization: Bearer your-local-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "test",
    "hostname": "httpbin.org",
    "serviceTokenId": "fake-id",
    "serviceTokenSecret": "fake-secret",
    "label": "Test service"
  }'

# Create a test key
curl -X POST http://localhost:8787/admin/keys \
  -H "Authorization: Bearer your-local-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-key", "origin": "test"}'
```

---

## Cost

| Resource | Free tier | Your likely usage |
|----------|-----------|-------------------|
| Worker requests | 100,000/day | A few hundred at most |
| KV reads | 100,000/day | A few hundred at most |
| KV writes | 1,000/day | A few per week |
| KV storage | 1 GB | A few KB |
| Custom domain | Free | — |
| Cloudflare Access | Free (up to 50 users) | 1 user (you) |

For personal/family use, everything is well within free tier limits.

---

## License

This is free and unencumbered software released into the public domain under [The Unlicense](LICENSE).

You can do anything you want with it. No attribution required. No restrictions. Copy it, modify it, sell it, embed it in your own project — whatever you want.