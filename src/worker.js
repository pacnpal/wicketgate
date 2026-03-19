/**
 * Wicketgate
 *
 * Provides opaque access to any service behind a Cloudflare Tunnel + Access
 * policy using a single opaque key in the URL.
 *
 * URL pattern:  /s/{opaque_key}/rest/of/path
 *
 * KV schema (WICKETGATE_KV namespace):
 *   origin:{slug}  → { hostname, serviceTokenId, serviceTokenSecret, label }
 *   key:{key}      → { name, origin, created }
 *
 * Secrets:
 *   ADMIN_SECRET        - Required for admin dashboard / API unless ALLOW_UNAUTH_ADMIN is set
 *   ALLOW_UNAUTH_ADMIN  - Set to "true" to skip built-in auth (only when /admin/* is externally gated)
 *   CF_API_TOKEN        - Cloudflare API token (optional, for tunnel discovery)
 *   CF_ACCOUNT_ID       - Cloudflare account ID (optional, for tunnel discovery)
 */

import DASHBOARD_HTML from './dashboard.html';

// ── Security constants ──
const MAX_SLUG_LENGTH = 48;
const MAX_LABEL_LENGTH = 100;
const MAX_HOSTNAME_LENGTH = 253;
const MAX_NAME_LENGTH = 100;
const MAX_REQUEST_BODY = 8192; // 8KB for admin API bodies
const KEY_BYTES = 32; // 256-bit entropy
const LIST_MAX_ENTRIES = 500; // Max entries returned per list call (origins or keys)
const LIST_BATCH_SIZE = 50;   // KV reads are issued in sequential batches to stay within Worker limits
const DELETE_MAX_PAGES = 20;  // Max KV pages scanned per deleteOrigin call (20 × 500 = 10,000 keys).
                               // Keeps free-tier workers well inside the 30 s wall-clock limit.
                               // Large namespaces are handled via resumeCursor retries.
const TUNNEL_FETCH_CONCURRENCY = 5; // Max parallel Cloudflare API requests during tunnel discovery
const PROXY_TIMEOUT_MS = 25_000;   // Abort upstream proxy fetch after 25 s (Worker CPU limit is 30 s)
const DISCOVER_TIMEOUT_MS = 10_000; // Per-request timeout for Cloudflare API calls during discovery

// Hostnames must be valid DNS: alphanumeric, hyphens, dots, no leading/trailing dots
const HOSTNAME_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;

// Slug format: lowercase alphanumeric with hyphens (length enforced separately via MAX_SLUG_LENGTH)
const SLUG_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

// Security headers applied to all responses
const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'DENY',
	'Referrer-Policy': 'no-referrer',
	'X-Robots-Tag': 'noindex, nofollow',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

// Subset of SECURITY_HEADERS safe to apply to proxied responses.
// X-Frame-Options: DENY and Permissions-Policy are intentionally excluded: they
// can break browser-based services (e.g. media server UIs that embed iframes or
// need camera/microphone access) when applied to proxied content that the origin
// did not intend to restrict.
const PROXY_SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'no-referrer',
	'X-Robots-Tag': 'noindex, nofollow',
};


export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		// ── Block non-standard methods globally ──
		const allowed = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
		if (!allowed.includes(request.method)) {
			return secureJsonError(405, 'Method not allowed.');
		}

		// ── CORS preflight ──
		if (request.method === 'OPTIONS') {
			// Only allow CORS on proxy paths, not admin
			if (url.pathname.startsWith('/s/')) {
				return new Response(null, { headers: { ...proxyCorsHeaders(), ...SECURITY_HEADERS } });
			}
			// Admin CORS: same-origin only (dashboard is served from same origin)
			return new Response(null, {
				status: 204,
				headers: {
					'Access-Control-Allow-Origin': url.origin,
					'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
					'Access-Control-Allow-Headers': 'Authorization, Content-Type',
					'Access-Control-Max-Age': '86400',
					...SECURITY_HEADERS,
				},
			});
		}

		// ── Admin dashboard ──
		if (url.pathname === '/admin' || url.pathname === '/admin/') {
			// Generate a per-request CSP nonce to replace unsafe-inline
			const nonceBytes = new Uint8Array(16);
			crypto.getRandomValues(nonceBytes);
			const nonce = btoa(String.fromCharCode(...nonceBytes));

			// Inject nonce into inline <style> and <script> tags
			const html = DASHBOARD_HTML
				.replace(/(<style)(?=[>\s])/gi, `<style nonce="${nonce}"`)
				.replace(/(<script)(?=[>\s])/gi, `<script nonce="${nonce}"`);

			return new Response(html, {
				headers: {
					'Content-Type': 'text/html;charset=UTF-8',
					// Prevent caching of the admin page: the CSP nonce is per-request, and
					// a cached page with a stale nonce would break inline script execution.
					'Cache-Control': 'no-store',
					// style-src requires 'unsafe-inline' because CSP nonces do not apply to
					// style="" attributes (only to <style> elements), and the dashboard uses
					// both. The nonce still eliminates unsafe-inline for scripts, which is
					// the higher-risk surface.
					'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'none'`,
					...SECURITY_HEADERS,
				},
			});
		}

		// ── Auth mode check ──
		if (url.pathname === '/admin/auth-mode') {
			const authDisabled = env.ALLOW_UNAUTH_ADMIN === 'true';
			// authRequired is true unless explicitly opted out via ALLOW_UNAUTH_ADMIN.
			// Even when ADMIN_SECRET is missing (misconfigured), authRequired=true so the
			// dashboard shows the login screen; admin calls will return 403 until fixed.
			return secureJsonResponse(200, { authRequired: !authDisabled });
		}

		// ── Admin API ──
		if (url.pathname.startsWith('/admin/')) {
			return handleAdmin(request, url, env);
		}

		// ── Client proxy ──
		return handleProxy(request, url, env);
	},
};


// ═══════════════════════════════════════════════════════════════════
// CLIENT PROXY
// ═══════════════════════════════════════════════════════════════════

async function handleProxy(request, url, env) {
	if (!env.WICKETGATE_KV) {
		return secureJsonError(500, 'Service unavailable.');
	}

	// Parse: /s/{key}/rest/of/path
	const match = url.pathname.match(/^\/s\/([A-Za-z0-9_-]+)(\/.*)?$/);
	if (!match) {
		return secureJsonError(404, 'Not found.');
	}

	const [, opaqueKey, restPath] = match;

	// Reject keys that are clearly wrong length (valid keys are 43 chars for 32-byte base64url)
	if (opaqueKey.length < 20 || opaqueKey.length > 64) {
		// Use same error as invalid key to avoid key-length oracle
		return secureJsonError(403, 'Access denied.');
	}

	const path = restPath || '/';

	// ── Block path traversal ──
	// new URL() normalizes /../ but be explicit
	if (path.includes('..') || path.includes('\0')) {
		return secureJsonError(400, 'Not found.');
	}

	// Look up the key
	const keyData = await kvGetJson(env.WICKETGATE_KV, `key:${opaqueKey}`);
	if (!keyData) {
		return secureJsonError(403, 'Access denied.');
	}

	// Look up the origin
	const origin = await kvGetJson(env.WICKETGATE_KV, `origin:${keyData.origin}`);
	if (!origin || !origin.hostname || !origin.serviceTokenId || !origin.serviceTokenSecret) {
		return secureJsonError(502, 'Service unavailable.');
	}

	// ── Build origin URL ──
	const originUrl = new URL(path, `https://${origin.hostname}`);
	originUrl.search = url.search;

	// Verify the constructed URL still points to the expected host (defense against host confusion)
	if (originUrl.hostname !== origin.hostname) {
		return secureJsonError(502, 'Service unavailable.');
	}

	// ── Build headers ──
	const headers = new Headers(request.headers);
	headers.set('CF-Access-Client-Id', origin.serviceTokenId);
	headers.set('CF-Access-Client-Secret', origin.serviceTokenSecret);
	headers.set('Host', origin.hostname);
	// Strip browser cookies — the origin doesn't share a cookie domain with the client
	headers.delete('Cookie');
	// Strip headers that could confuse the origin about the real client
	headers.delete('X-Forwarded-For');
	headers.delete('X-Real-IP');
	headers.delete('CF-Connecting-IP');
	// Strip headers that could leak the access key URL to the origin via Referer/Origin
	headers.delete('Referer');
	headers.delete('Origin');
	// Strip browser fetch metadata headers (could expose key URL or internal routing)
	headers.delete('Sec-Fetch-Site');
	headers.delete('Sec-Fetch-Mode');
	headers.delete('Sec-Fetch-Dest');
	headers.delete('Sec-Fetch-User');

	const originRequest = new Request(originUrl.toString(), {
		method: request.method,
		headers,
		body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
		redirect: 'manual',
	});

	// Abort the upstream fetch if it takes longer than PROXY_TIMEOUT_MS to prevent
	// the Worker from hanging until the 30-second CPU limit is reached.
	const proxyAbort = new AbortController();
	const proxyTimer = setTimeout(() => proxyAbort.abort(), PROXY_TIMEOUT_MS);

	try {
		const response = await fetch(originRequest, { signal: proxyAbort.signal });
		const responseHeaders = new Headers(response.headers);

		// Strip sensitive origin response headers
		responseHeaders.delete('cf-access-authenticated-user-email');
		responseHeaders.delete('cf-ray');
		responseHeaders.delete('server');
		responseHeaders.delete('set-cookie');
		// Strip cache validators: Cache-Control: no-store (set below) is the primary
		// signal, but ETag/Last-Modified can still be used for conditional revalidation
		// requests that would bypass no-store on some clients.
		responseHeaders.delete('etag');
		responseHeaders.delete('last-modified');

		// Rewrite Location header on redirects to prevent origin hostname leakage.
		// The origin hostname must never appear in headers sent to the client.
		// Rewrite or strip Location header regardless of status code to prevent
		// origin hostname from leaking on 201 Created, 202 Accepted, etc.
		const location = responseHeaders.get('location');
		if (location) {
			try {
				// Use origin as base to correctly resolve relative Location URLs
				const locationUrl = new URL(location, `https://${origin.hostname}`);
				if (locationUrl.hostname === origin.hostname) {
					// Same-origin Location: rewrite the path through the proxy
					const proxyBase = `${url.protocol}//${url.host}/s/${opaqueKey}`;
					responseHeaders.set('location', `${proxyBase}${locationUrl.pathname}${locationUrl.search}${locationUrl.hash}`);
				} else {
					// External Location: strip for 2xx, block 3xx to prevent unresolvable redirect
					if (response.status >= 300 && response.status < 400) {
						return secureJsonError(502, 'Service unavailable.');
					}
					responseHeaders.delete('location');
				}
			} catch {
				// Malformed Location: strip for 2xx, block 3xx
				if (response.status >= 300 && response.status < 400) {
					return secureJsonError(502, 'Service unavailable.');
				}
				responseHeaders.delete('location');
			}
		}

		// Add proxy CORS and security headers.
		// Use PROXY_SECURITY_HEADERS (not the full SECURITY_HEADERS) to avoid
		// stamping X-Frame-Options: DENY / Permissions-Policy onto proxied responses
		// that may belong to browser-based services (media UIs, dashboards, etc.).
		// These headers intentionally enforce the proxy's security policy regardless
		// of what the origin sent — Referrer-Policy and X-Robots-Tag are always
		// set to the proxy's values to prevent referrer leakage and indexing of
		// proxy URLs, even if the origin intended different values.
		Object.entries(proxyCorsHeaders()).forEach(([k, v]) => responseHeaders.set(k, v));
		Object.entries(PROXY_SECURITY_HEADERS).forEach(([k, v]) => responseHeaders.set(k, v));
		// Keys can be revoked at any time; prevent caching to avoid stale access
		responseHeaders.set('Cache-Control', 'no-store');

		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: responseHeaders,
		});
	} catch (err) {
		if (err?.name === 'AbortError')
			return secureJsonError(504, 'Gateway timeout.');
		return secureJsonError(502, 'Service unavailable.');
	} finally {
		// Always clear the abort timer regardless of outcome — covers the success path,
		// fetch errors, header-processing exceptions, and early redirect returns.
		clearTimeout(proxyTimer);
	}
}


// ═══════════════════════════════════════════════════════════════════
// ADMIN API
// ═══════════════════════════════════════════════════════════════════

async function handleAdmin(request, url, env) {
	if (!env.WICKETGATE_KV) return secureJsonError(500, 'Service unavailable.');

	// ── Auth ──
	// Auth is required unless ALLOW_UNAUTH_ADMIN is explicitly set to "true".
	// IMPORTANT: Only set ALLOW_UNAUTH_ADMIN=true when the /admin/* routes are
	// externally gated (e.g., behind Cloudflare Access), otherwise admin is public.
	const authDisabled = env.ALLOW_UNAUTH_ADMIN === 'true';
	if (!authDisabled) {
		if (!env.ADMIN_SECRET) {
			// No secret configured and opt-out not set — block all admin access
			return secureJsonError(403, 'Admin access requires ADMIN_SECRET or ALLOW_UNAUTH_ADMIN=true.');
		}
		const authResult = checkAdminAuth(request, env.ADMIN_SECRET);
		if (authResult) return authResult; // Returns a Response on failure, null on success
	}

	const p = url.pathname;

	// ── Origins ──
	if ((p === '/admin/origins' || p === '/admin/origins/') && request.method === 'GET')
		return listOrigins(env);
	if ((p === '/admin/origins' || p === '/admin/origins/') && request.method === 'POST')
		return createOrigin(request, env);
	const oMatch = p.match(/^\/admin\/origins\/([^/]+)$/);
	if (oMatch) {
		const slug = oMatch[1];
		if (slug.length > MAX_SLUG_LENGTH || !SLUG_RE.test(slug))
			return secureJsonError(404, 'Not found.');
		if (request.method === 'DELETE') return deleteOrigin(slug, request, env);
		if (request.method === 'PUT') return updateOrigin(slug, request, env);
	}

	// ── Keys ──
	if ((p === '/admin/keys' || p === '/admin/keys/') && request.method === 'GET')
		return listKeys(env);
	if ((p === '/admin/keys' || p === '/admin/keys/') && request.method === 'POST')
		return createKey(request, env);
	const kMatch = p.match(/^\/admin\/keys\/([A-Za-z0-9_-]+)$/);
	if (kMatch && kMatch[1].length <= 64 && request.method === 'DELETE')
		return deleteKey(kMatch[1], env);

	// ── Discover ──
	if ((p === '/admin/discover' || p === '/admin/discover/') && request.method === 'GET')
		return discoverTunnels(env);

	return secureJsonError(404, 'Not found.');
}

// Max Authorization header length to prevent resource exhaustion via timingSafeEqual
const MAX_AUTH_HEADER_LENGTH = 1024;

function checkAdminAuth(request, secret) {
	const authHeader = request.headers.get('Authorization') || '';

	// Reject excessively long auth headers before any comparison
	if (authHeader.length > MAX_AUTH_HEADER_LENGTH) {
		return secureJsonError(401, 'Unauthorized.');
	}

	// Bearer token (dashboard JS)
	const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
	if (bearerMatch) {
		if (!timingSafeEqual(bearerMatch[1].trim(), secret)) {
			return secureJsonError(401, 'Unauthorized.');
		}
		return null; // Auth passed
	}

	// Basic auth (curl, browsers)
	if (authHeader.startsWith('Basic ')) {
		try {
			const decoded = atob(authHeader.slice(6));
			const password = decoded.includes(':') ? decoded.split(':').slice(1).join(':') : decoded;
			if (!timingSafeEqual(password, secret)) {
				return new Response('Unauthorized', {
					status: 401,
					headers: { 'WWW-Authenticate': 'Basic realm="Wicketgate"', ...SECURITY_HEADERS },
				});
			}
			return null; // Auth passed
		} catch {
			return new Response('Unauthorized', {
				status: 401,
				headers: { 'WWW-Authenticate': 'Basic realm="Wicketgate"', ...SECURITY_HEADERS },
			});
		}
	}

	// No auth header — prompt Basic if browser, JSON error if API client
	const accept = request.headers.get('Accept') || '';
	if (!accept.includes('application/json')) {
		return new Response('Unauthorized', {
			status: 401,
			headers: { 'WWW-Authenticate': 'Basic realm="Wicketgate"', ...SECURITY_HEADERS },
		});
	}
	return secureJsonError(401, 'Unauthorized.');
}


// ─── Origin CRUD ────────────────────────────────────────────────────

async function listOrigins(env) {
	const { kvKeys, hasMore } = await listKvPrefix(env.WICKETGATE_KV, 'origin:');
	const origins = await batchKvFetch(env.WICKETGATE_KV, kvKeys, (k, data) => ({
		slug: k.name.replace(/^origin:/, ''),
		hostname: data?.hostname,
		label: data?.label,
		created: data?.created,
		// Redact all credential fields
	}));
	return adminJsonResponse(200, { origins, hasMore });
}

async function createOrigin(request, env) {
	const body = await safeLimitedJson(request, MAX_REQUEST_BODY);
	if (!body) return secureJsonError(400, 'Invalid or oversized request body.');

	const { slug, hostname, serviceTokenId, serviceTokenSecret, label } = body;
	if (!slug || !hostname || !serviceTokenId || !serviceTokenSecret)
		return secureJsonError(400, 'Required: slug, hostname, serviceTokenId, serviceTokenSecret');

	// Validate slug
	if (typeof slug !== 'string' || slug.length > MAX_SLUG_LENGTH)
		return secureJsonError(400, `Slug must be ${MAX_SLUG_LENGTH} characters or fewer.`);
	if (!SLUG_RE.test(slug))
		return secureJsonError(400, 'Slug must be lowercase alphanumeric with hyphens.');

	// Validate hostname — must look like a real public DNS name
	const hostnameError = validateHostname(hostname);
	if (hostnameError) return secureJsonError(400, hostnameError);
	const normalizedHostname = hostname.toLowerCase();

	// Validate label
	if (label && (typeof label !== 'string' || label.length > MAX_LABEL_LENGTH))
		return secureJsonError(400, `Label must be ${MAX_LABEL_LENGTH} characters or fewer.`);

	// Validate service token fields are strings
	if (typeof serviceTokenId !== 'string' || typeof serviceTokenSecret !== 'string')
		return secureJsonError(400, 'Service token fields must be strings.');
	if (serviceTokenId.length > 200 || serviceTokenSecret.length > 200)
		return secureJsonError(400, 'Service token fields are too long.');

	if (await env.WICKETGATE_KV.get(`origin:${slug}`))
		return secureJsonError(409, 'Origin already exists.');

	await env.WICKETGATE_KV.put(`origin:${slug}`, JSON.stringify({
		hostname: normalizedHostname, serviceTokenId, serviceTokenSecret,
		label: label || slug, created: new Date().toISOString(),
	}));

	return adminJsonResponse(201, { slug, hostname: normalizedHostname, label: label || slug });
}

async function updateOrigin(slug, request, env) {
	const existing = await kvGetJson(env.WICKETGATE_KV, `origin:${slug}`);
	if (!existing) return secureJsonError(404, 'Not found.');

	const body = await safeLimitedJson(request, MAX_REQUEST_BODY);
	if (!body) return secureJsonError(400, 'Invalid or oversized request body.');

	const updated = { ...existing };

	if (body.hostname) {
		const hostnameError = validateHostname(body.hostname);
		if (hostnameError) return secureJsonError(400, hostnameError);
		updated.hostname = body.hostname.toLowerCase();
	}
	if (body.serviceTokenId) {
		if (typeof body.serviceTokenId !== 'string' || body.serviceTokenId.length > 200)
			return secureJsonError(400, 'Invalid service token ID.');
		updated.serviceTokenId = body.serviceTokenId;
	}
	if (body.serviceTokenSecret) {
		if (typeof body.serviceTokenSecret !== 'string' || body.serviceTokenSecret.length > 200)
			return secureJsonError(400, 'Invalid service token secret.');
		updated.serviceTokenSecret = body.serviceTokenSecret;
	}
	if (body.label) {
		if (typeof body.label !== 'string' || body.label.length > MAX_LABEL_LENGTH)
			return secureJsonError(400, 'Invalid label.');
		updated.label = body.label;
	}

	await env.WICKETGATE_KV.put(`origin:${slug}`, JSON.stringify(updated));
	return adminJsonResponse(200, { slug, message: 'Updated.' });
}

async function deleteOrigin(slug, request, env) {
	if (!(await env.WICKETGATE_KV.get(`origin:${slug}`)))
		return secureJsonError(404, 'Not found.');

	// Accept an optional resumeCursor from the request body so the caller can
	// resume a previously truncated scan rather than always restarting from page 1.
	// This ensures forward progress when the namespace is very large.
	let cursor;
	const contentType = request.headers.get('content-type') || '';
	const contentTypeLc = contentType.toLowerCase();
	if (contentTypeLc === 'application/json' || contentTypeLc.startsWith('application/json;')) {
		const body = await safeLimitedJson(request, MAX_REQUEST_BODY);
		// Validate: cursor must be a non-empty string (opaque KV pagination token)
		if (typeof body?.resumeCursor === 'string' && body.resumeCursor.length > 0)
			cursor = body.resumeCursor;
		// safeLimitedJson returns null for oversized/malformed input; null body leaves cursor as undefined
	}

	// Scan every page of keys and delete matching ones immediately, page-by-page.
	// This avoids accumulating an unbounded list of key names in memory for large
	// namespaces. Per-page deletes are issued in bounded batches (LIST_BATCH_SIZE)
	// to keep concurrent KV operations predictable.
	// DELETE_MAX_PAGES caps the total pages scanned to prevent exceeding the Worker's
	// CPU/wall-clock time limit (30 s free / 15 min paid). If the namespace is larger
	// than DELETE_MAX_PAGES × LIST_MAX_ENTRIES keys, the caller should retry with the
	// returned resumeCursor so the scan resumes from where it stopped rather than
	// restarting from page 1 — origin entry is deleted last so retries are safe.
	let keysDeleted = 0;
	let pagesScanned = 0;
	let truncated = false;
	let page;
	do {
		try {
			page = await env.WICKETGATE_KV.list({ prefix: 'key:', cursor, limit: LIST_MAX_ENTRIES });
		} catch (err) {
			// kv.list() throws on an invalid or expired cursor (e.g., a tampered resumeCursor
			// from the request body). Return a 400 so the caller gets a clean JSON error
			// rather than an unhandled exception that would surface as a platform-level crash.
			return secureJsonError(400, 'Invalid resumeCursor.');
		}
		try {
			const keyData = await batchKvFetch(env.WICKETGATE_KV, page.keys, (k, data) => ({
				name: k.name,
				origin: data?.origin,
			}));
			const pageKeysToDelete = keyData
				.filter(key => key.origin === slug)
				.map(key => key.name);
			for (let i = 0; i < pageKeysToDelete.length; i += LIST_BATCH_SIZE) {
				const batch = pageKeysToDelete.slice(i, i + LIST_BATCH_SIZE);
				await Promise.all(batch.map(k => env.WICKETGATE_KV.delete(k)));
			}
			keysDeleted += pageKeysToDelete.length;
		} catch (err) {
			// batchKvFetch or kv.delete() threw a transient error. Return 500 so the caller
			// gets a JSON error rather than a platform-level crash.
			return secureJsonError(500, 'KV operation failed.');
		}
		pagesScanned++;
		cursor = page.list_complete ? undefined : page.cursor;
		if (!page.list_complete && pagesScanned >= DELETE_MAX_PAGES) {
			truncated = true;
			break;
		}
	} while (!page.list_complete);

	// Delete the origin entry itself last (after all associated keys are removed).
	// This ordering is intentional: if the operation is interrupted before this line,
	// the origin still exists and the delete can be retried cleanly. Deleting the
	// origin first would create orphaned keys that could silently resurrect if a new
	// origin were created with the same slug.
	// If the scan was truncated (namespace too large), skip deleting the origin so
	// the caller can safely retry with the returned resumeCursor — the next call will
	// resume from where this one stopped rather than rescanning from page 1.
	if (truncated) {
		return adminJsonResponse(202, {
			message: 'Partial delete: namespace too large for a single request. Retry with resumeCursor to continue.',
			keysDeleted,
			completed: false,
			originDeleted: false,
			truncated: true,
			pagesScanned,
			resumeCursor: cursor,
		});
	}

	await env.WICKETGATE_KV.delete(`origin:${slug}`);

	return adminJsonResponse(200, {
		message: 'Deleted.',
		keysDeleted,
		completed: true,
		originDeleted: true,
		truncated: false,
		pagesScanned,
	});
}


// ─── Key CRUD ───────────────────────────────────────────────────────

async function listKeys(env) {
	const { kvKeys, hasMore } = await listKvPrefix(env.WICKETGATE_KV, 'key:');
	const results = await batchKvFetch(env.WICKETGATE_KV, kvKeys, (k, data) => {
		const fullKey = k.name.replace(/^key:/, '');
		return {
			key: fullKey,
			keyPrefix: fullKey.slice(0, 8) + '...',
			name: data?.name,
			origin: data?.origin,
			created: data?.created,
		};
	});
	return adminJsonResponse(200, { keys: results, hasMore });
}

async function createKey(request, env) {
	const body = await safeLimitedJson(request, MAX_REQUEST_BODY);
	if (!body) return secureJsonError(400, 'Invalid or oversized request body.');

	const name = (typeof body.name === 'string' ? body.name.slice(0, MAX_NAME_LENGTH) : '') || 'unnamed';
	const origin = body?.origin;

	if (!origin || typeof origin !== 'string')
		return secureJsonError(400, 'Required: origin (slug).');

	if (origin.length > MAX_SLUG_LENGTH || !SLUG_RE.test(origin))
		return secureJsonError(400, 'Origin must be a valid slug (lowercase alphanumeric with hyphens).');

	if (!(await env.WICKETGATE_KV.get(`origin:${origin}`)))
		return secureJsonError(400, 'Origin does not exist.');

	const key = generateKey();
	await env.WICKETGATE_KV.put(`key:${key}`, JSON.stringify({
		name, origin, created: new Date().toISOString(),
	}));

	return adminJsonResponse(201, { key, name, origin });
}

async function deleteKey(key, env) {
	if (!(await env.WICKETGATE_KV.get(`key:${key}`)))
		return secureJsonError(404, 'Not found.');
	await env.WICKETGATE_KV.delete(`key:${key}`);
	return adminJsonResponse(200, { message: 'Revoked.' });
}


// ─── Tunnel discovery ───────────────────────────────────────────────

async function discoverTunnels(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID)
		return secureJsonError(500, 'Discovery requires CF_API_TOKEN and CF_ACCOUNT_ID.');

	try {
		// Fetch all pages of tunnels (with per-request timeout)
		let tunnels = [];
		let page = 1;
		const perPage = 50;

		while (true) {
			const tunnelAbort = new AbortController();
			const tunnelTimer = setTimeout(() => tunnelAbort.abort(), DISCOVER_TIMEOUT_MS);
			let tunnelsData;
			try {
				const tunnelsRes = await fetch(
					`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/cfd_tunnel?is_deleted=false&page=${page}&per_page=${perPage}`,
					{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` }, signal: tunnelAbort.signal }
				);
				if (!tunnelsRes.ok) {
					if (tunnelsRes.status === 429)
						return secureJsonError(502, 'Tunnel API rate limit reached. Try again later.');
					return secureJsonError(502, `Tunnel API error (HTTP ${tunnelsRes.status}).`);
				}
				// Parse the body inside the try block so the abort signal covers body delivery,
				// not just time-to-first-byte.
				tunnelsData = await tunnelsRes.json();
			} catch (fetchErr) {
				if (fetchErr?.name === 'AbortError')
					return secureJsonError(502, 'Tunnel API timed out. Try again later.');
				throw fetchErr;
			} finally {
				clearTimeout(tunnelTimer);
			}

			if (!tunnelsData.success)
				return secureJsonError(502, 'Tunnel API error.');

			const batch = tunnelsData.result || [];
			tunnels = tunnels.concat(batch);

			// Check if there are more pages using result_info
			const resultInfo = tunnelsData.result_info || {};
			const hasMore = resultInfo.total_pages && page < resultInfo.total_pages;

			if (!hasMore || batch.length === 0) break;

			page++;

			// Safety limit to prevent infinite loops (max 5000 tunnels)
			if (page > 100) break;
		}

		// Fetch tunnel configurations with bounded concurrency to avoid rate-limiting
		// and keep Wall-clock time predictable. Per-tunnel failures are tolerated and
		// noted in the warnings list so the caller knows the result may be incomplete.
		const hostnames = [];
		const warnings = [];
		for (let i = 0; i < tunnels.length; i += TUNNEL_FETCH_CONCURRENCY) {
			const batch = tunnels.slice(i, i + TUNNEL_FETCH_CONCURRENCY);
			await Promise.allSettled(
				batch.map(async (tunnel) => {
					try {
						const cfgAbort = new AbortController();
						const cfgTimer = setTimeout(() => cfgAbort.abort(), DISCOVER_TIMEOUT_MS);
						try {
							const cfgRes = await fetch(
								`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/cfd_tunnel/${encodeURIComponent(tunnel.id)}/configurations`,
								{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` }, signal: cfgAbort.signal }
							);
							if (!cfgRes.ok) {
								warnings.push(`Tunnel "${tunnel.name}" config fetch failed (HTTP ${cfgRes.status}).`);
								return;
							}
							// Parse the body inside the try block so the abort signal covers body delivery,
							// not just time-to-first-byte.
							const cfgData = await cfgRes.json();
							if (cfgData.success && cfgData.result?.config?.ingress) {
								for (const rule of cfgData.result.config.ingress) {
									if (rule.hostname) {
										hostnames.push({
											hostname: rule.hostname,
											tunnelName: tunnel.name,
											// Intentionally omit rule.service — it exposes internal network topology
											suggestedSlug: rule.hostname.split('.')[0].toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, MAX_SLUG_LENGTH),
										});
									}
								}
							} else if (!cfgData.success) {
								warnings.push(`Tunnel "${tunnel.name}" returned an API error.`);
							}
						} finally {
							clearTimeout(cfgTimer);
						}
					} catch (err) {
						let msg;
						if (err?.name === 'AbortError') {
							msg = `Tunnel "${tunnel.name}" config fetch timed out.`;
						} else {
							msg = `Tunnel "${tunnel.name}" config fetch failed due to an exception: ${err instanceof Error ? err.message : String(err)}`;
						}
						warnings.push(msg);
					}
				})
			);
			// Per-tunnel failures are recorded in warnings; the tunnel is omitted from results
		}

		// If no hostnames were discovered, there's nothing to check against KV.
		// Avoid scanning the entire `origin:` namespace in this case.
		if (hostnames.length === 0) {
			return adminJsonResponse(200, {
				hostnames: [],
				...(warnings.length > 0 ? { warnings } : {}),
			});
		}

		// Mark which hostnames are already configured. Stream KV pages (bounded by
		// LIST_MAX_ENTRIES per page) so only one page of keys is held in memory at a
		// time. `remaining` tracks unchecked tunnel hostnames and is decremented O(1)
		// per match; the loop exits early once all tunnel hostnames are confirmed.
		const configuredHostnames = new Set();
		const remaining = new Set(hostnames.map(h => h.hostname.toLowerCase()));
		let kvCursor = undefined;
		do {
			const kvPage = await env.WICKETGATE_KV.list({ prefix: 'origin:', cursor: kvCursor, limit: LIST_MAX_ENTRIES });
			const pageHostnames = await batchKvFetch(
				env.WICKETGATE_KV, kvPage.keys, (_, data) => data?.hostname ?? null
			);
			for (const h of pageHostnames) {
				if (h !== null) {
					configuredHostnames.add(h.toLowerCase());
					remaining.delete(h.toLowerCase());
				}
			}
			// Early exit: all tunnel hostnames accounted for, no need to read further pages
			if (remaining.size === 0) break;
			kvCursor = kvPage.list_complete ? undefined : kvPage.cursor;
		} while (kvCursor);

		return adminJsonResponse(200, {
			hostnames: hostnames.map(h => ({
				...h,
				configured: configuredHostnames.has(h.hostname.toLowerCase()),
			})),
			...(warnings.length > 0 ? { warnings } : {}),
		});
	} catch (err) {
		return secureJsonError(502, 'Discovery failed.');
	}
}


// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

async function kvGetJson(kv, key) {
	try {
		const val = await kv.get(key);
		return val ? JSON.parse(val) : null;
	} catch { return null; }
}

/**
 * List KV keys with the given prefix, paginating up to LIST_MAX_ENTRIES + 1.
 * Each page requests only as many keys as are still needed, so we never ask
 * the KV API for more than LIST_MAX_ENTRIES + 1 entries in total.
 *
 * Returns { kvKeys, hasMore } where hasMore indicates the namespace has more
 * entries beyond the cap.
 */
async function listKvPrefix(kv, prefix) {
	const allKeys = [];
	let cursor = undefined;
	do {
		// Request only the remaining entries needed (+1 to detect truncation)
		const limit = LIST_MAX_ENTRIES + 1 - allKeys.length;
		const page = await kv.list({ prefix, cursor, limit });
		allKeys.push(...page.keys);
		cursor = page.list_complete ? undefined : page.cursor;
	} while (cursor && allKeys.length < LIST_MAX_ENTRIES + 1);

	const hasMore = allKeys.length > LIST_MAX_ENTRIES;
	const kvKeys = hasMore ? allKeys.slice(0, LIST_MAX_ENTRIES) : allKeys;
	return { kvKeys, hasMore };
}

/**
 * Fetch KV values for an array of keys in sequential batches of LIST_BATCH_SIZE,
 * avoiding unbounded concurrent requests that could exceed Worker CPU/memory limits.
 * `mapFn(kvKey, data)` maps each key + parsed JSON value to a response object.
 */
async function batchKvFetch(kv, kvKeys, mapFn) {
	const results = [];
	for (let i = 0; i < kvKeys.length; i += LIST_BATCH_SIZE) {
		const batch = kvKeys.slice(i, i + LIST_BATCH_SIZE);
		const batchResults = await Promise.all(
			batch.map(async (k) => {
				const data = await kvGetJson(kv, k.name);
				return mapFn(k, data);
			})
		);
		results.push(...batchResults);
	}
	return results;
}

/**
 * Validate a hostname for use as an origin.
 * Returns an error message string on failure, or null if valid.
 * Rejects invalid DNS syntax, and the reserved names localhost, .local, .internal, and .localhost.
 * IP address literals (e.g. 1.2.3.4) are rejected by HOSTNAME_RE (no valid TLD).
 *
 * Note on wildcard-DNS-to-private-IP services (e.g. nip.io, sslip.io):
 * These are not blocked here because the admin API requires authentication
 * (Cloudflare Access on /admin* or ADMIN_SECRET), so only trusted operators
 * can register origins. A blocklist of such services would be an incomplete
 * and fragile defence; the correct mitigation is to ensure the admin API is
 * properly gated (see README — Auth modes).
 */
function validateHostname(hostname) {
	if (typeof hostname !== 'string' || hostname.length > MAX_HOSTNAME_LENGTH)
		return 'Invalid hostname.';
	if (!HOSTNAME_RE.test(hostname))
		return 'Hostname must be a valid public DNS name (e.g. app.yourdomain.com).';
	const lh = hostname.toLowerCase();
	if (lh === 'localhost' || lh.endsWith('.local') || lh.endsWith('.internal') || lh.endsWith('.localhost'))
		return 'Hostname must be a public DNS name, not an internal address.';
	return null;
}

/**
 * Parse JSON from request body with a size limit.
 * Reads the body incrementally and aborts as soon as maxBytes is exceeded.
 * Returns null if body is too large, invalid JSON, or missing.
 */
async function safeLimitedJson(request, maxBytes) {
	try {
		const clHeader = request.headers.get('Content-Length');
		if (clHeader !== null) {
			const contentLength = parseInt(clHeader, 10);
			if (isNaN(contentLength) || contentLength > maxBytes) return null;
		}

		if (!request.body) return null;

		// Read body incrementally, aborting early if limit is exceeded
		const reader = request.body.getReader();
		const chunks = [];
		let totalBytes = 0;
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			totalBytes += value.byteLength;
			if (totalBytes > maxBytes) {
				reader.cancel();
				return null;
			}
			chunks.push(value);
		}

		const combined = new Uint8Array(totalBytes);
		let offset = 0;
		for (const chunk of chunks) {
			combined.set(chunk, offset);
			offset += chunk.byteLength;
		}
		const text = new TextDecoder().decode(combined);
		return JSON.parse(text);
	} catch { return null; }
}

/**
 * Generate a cryptographically random access key.
 * 32 bytes = 256 bits of entropy, URL-safe base64 encoded.
 */
function generateKey() {
	const bytes = new Uint8Array(KEY_BYTES);
	crypto.getRandomValues(bytes);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Timing-safe string comparison.
 * Pads shorter string to prevent length oracle.
 */
function timingSafeEqual(a, b) {
	const enc = new TextEncoder();
	const aBuf = enc.encode(a);
	const bBuf = enc.encode(b);
	const maxLen = Math.max(aBuf.length, bBuf.length);
	const aPadded = new Uint8Array(maxLen);
	const bPadded = new Uint8Array(maxLen);
	aPadded.set(aBuf);
	bPadded.set(bBuf);
	let r = aBuf.length ^ bBuf.length;
	for (let i = 0; i < maxLen; i++) r |= aPadded[i] ^ bPadded[i];
	return r === 0;
}

/**
 * CORS headers for proxy responses.
 * Open by default — restrict Access-Control-Allow-Origin if you know your client origins.
 */
function proxyCorsHeaders() {
	return {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
		'Access-Control-Allow-Headers': 'Authorization, Content-Type',
		'Access-Control-Max-Age': '86400',
	};
}

/**
 * JSON response for admin API (no open CORS — same-origin only via dashboard).
 */
function adminJsonResponse(status, data) {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...SECURITY_HEADERS,
		},
	});
}

/**
 * Secure JSON error response with security headers, no CORS.
 */
function secureJsonError(status, message) {
	return new Response(JSON.stringify({ error: message }), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...SECURITY_HEADERS,
		},
	});
}

/**
 * Secure JSON response with security headers.
 * Used for non-admin public endpoints like auth-mode.
 */
function secureJsonResponse(status, data) {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...SECURITY_HEADERS,
		},
	});
}