import { createHash } from "node:crypto";
import { bearerToken, hashSecret, newSecret, safeEqual } from "./security.js";
import { checkRateLimit, ensureSchema, execute, queryOne } from "./store.js";

const ACCESS_TTL = 60 * 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL = 5 * 60 * 1000;
const AUTH_REQUEST_TTL = 10 * 60 * 1000;
const SCOPE = "mcp:tools";

function pendingRequestPath(req, requestId) {
  return `${baseUrl(req)}/api/oauth/authorize/request/${encodeURIComponent(requestId)}`;
}

function sendJson(res, status, body, extra = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "pragma": "no-cache",
    ...extra
  });
  res.end(JSON.stringify(body));
}

function htmlEscape(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

function baseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  return host ? `${proto}://${host}` : "";
}

async function readForm(req) {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === "string") {
    const type = String(req.headers["content-type"] || "");
    return type.includes("application/json") ? JSON.parse(req.body || "{}") : Object.fromEntries(new URLSearchParams(req.body));
  }
  const chunks = [];
  let size = 0;
  await new Promise((resolve, reject) => {
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(Object.assign(new Error("Request body too large."), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", resolve);
    req.on("error", reject);
    if (req.readableEnded) resolve();
  });
  const raw = Buffer.concat(chunks).toString("utf8");
  const type = String(req.headers["content-type"] || "");
  if (type.includes("application/json")) return JSON.parse(raw || "{}");
  return Object.fromEntries(new URLSearchParams(raw));
}

function validRedirectUri(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const u = new URL(value);
    if (u.hash) return false;
    return u.protocol === "https:" ||
      (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
  } catch {
    return false;
  }
}

function pkceChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

async function loadClient(clientId) {
  if (!clientId || typeof clientId !== "string") return null;
  return queryOne("SELECT client_id, client_name, redirect_uris_json FROM oauth_clients WHERE client_id=$1", [clientId]);
}

function resourceInstanceId(resource, origin) {
  try {
    const u = new URL(resource);
    if (u.origin !== origin || u.search || u.hash) return null;
    const match = /^\/api\/mcp\/([A-Za-z0-9-]{8,80})$/.exec(u.pathname);
    return match?.[1] || null;
  } catch {
    return null;
  }
}

async function protectedResourceMetadata(req, res, resourcePath) {
  const origin = baseUrl(req);
  const match = /^api\/mcp\/([A-Za-z0-9-]{8,80})$/.exec(resourcePath || "");
  if (!match) return sendJson(res, 404, { error: "resource_not_found" });
  return sendJson(res, 200, {
    resource: `${origin}/api/mcp/${match[1]}`,
    authorization_servers: [origin],
    scopes_supported: [SCOPE],
    bearer_methods_supported: ["header"]
  }, { "access-control-allow-origin": "*" });
}

async function authorizationServerMetadata(req, res) {
  const issuer = baseUrl(req);
  return sendJson(res, 200, {
    issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [SCOPE]
  }, { "access-control-allow-origin": "*" });
}

async function registerClient(req, res) {
  await ensureSchema();
  if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
  if (!(await checkRateLimit("oauth:dcr:" + (req.headers["x-forwarded-for"] || "unknown"), 20))) {
    return sendJson(res, 429, { error: "rate_limited" });
  }
  const body = await readForm(req);
  const redirects = body.redirect_uris;
  if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 10 ||
      !redirects.every(validRedirectUri) || new Set(redirects).size !== redirects.length) {
    return sendJson(res, 400, { error: "invalid_redirect_uri" });
  }
  const clientId = newSecret("vxc_");
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 120) : "MCP Client";
  await execute(
    "INSERT INTO oauth_clients(client_id, client_name, redirect_uris_json, created_at) VALUES($1,$2,$3,$4)",
    [clientId, name, JSON.stringify(redirects), Date.now()]
  );
  return sendJson(res, 201, {
    client_id: clientId,
    client_name: name,
    redirect_uris: redirects,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"]
  });
}

function authorizationError(res, error, description, status = 400) {
  return sendJson(res, status, { error, error_description: description });
}

async function authorize(req, res, origin) {
  await ensureSchema();
  const params = req.method === "POST" ? await readForm(req) : Object.fromEntries(new URL(req.url, origin).searchParams);
  if (req.method !== "GET" && req.method !== "POST") {
    return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET, POST" });
  }
  const {
    client_id: clientId, redirect_uri: redirectUri, response_type: responseType,
    state, code_challenge: challenge, code_challenge_method: challengeMethod,
    resource, scope
  } = params;
  const client = await loadClient(clientId);
  if (!client) return authorizationError(res, "invalid_client", "Unknown OAuth client.");
  const redirects = JSON.parse(client.redirect_uris_json || "[]");
  if (!redirects.includes(redirectUri) || !validRedirectUri(redirectUri)) {
    return authorizationError(res, "invalid_request", "The redirect URI is not registered.");
  }
  if (responseType !== "code" || typeof state !== "string" || state.length < 8 || state.length > 512 ||
      challengeMethod !== "S256" || typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) {
    return authorizationError(res, "invalid_request", "Authorization code flow with PKCE S256 and state is required.");
  }
  const requestedScope = scope || SCOPE;
  if (requestedScope !== SCOPE) return authorizationError(res, "invalid_scope", "Only mcp:tools is supported.");
  const instanceId = resourceInstanceId(resource, origin);
  if (!instanceId) return authorizationError(res, "invalid_target", "The resource must be this server's per-instance MCP URL.");
  const instance = await queryOne("SELECT instance_id, display_name, mcp_token_hash, mcp_token_revoked FROM instances WHERE instance_id=$1", [instanceId]);
  if (!instance || Number(instance.mcp_token_revoked || 0) === 1 || !instance.mcp_token_hash) {
    return authorizationError(res, "invalid_target", "The MCP instance is unavailable.", 404);
  }

  const now = Date.now();

  if (req.method === "GET") {
    // Best-effort cleanup of expired requests for this instance
    try { await execute("UPDATE oauth_authorization_requests SET status='expired' WHERE instance_id=$1 AND status='pending' AND expires_at <= $2", [instanceId, now]); } catch {}
    const requestId = newSecret("vxreq_");
    await execute(
      "INSERT INTO oauth_authorization_requests(request_id, instance_id, client_id, redirect_uri, state_value, code_challenge, scope, resource, status, expires_at, approved_at, consumed_at, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,NULL,NULL,$10)",
      [requestId, instanceId, clientId, redirectUri, state, challenge, requestedScope, resource, now + AUTH_REQUEST_TTL, now]
    );
    const callbackHost = new URL(redirectUri).host;
    const statusUrl = pendingRequestPath(req, requestId) + "/status";
    const completeUrl = pendingRequestPath(req, requestId) + "/complete";
    const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect VortexEditPro</title><style>body{margin:0;background:#101114;color:#f5f5f5;font:16px system-ui;display:grid;min-height:100vh;place-items:center}.card{width:min(520px,calc(100% - 40px));box-sizing:border-box;background:#1b1d22;border:1px solid #383b43;border-radius:18px;padding:28px}h1{font-size:22px;margin:0 0 8px}.muted{color:#aeb2bd;line-height:1.55}.status{margin-top:18px;padding:14px;border-radius:12px;background:#111318;border:1px solid #2d313a}.ok{color:#7fe3a1}.bad{color:#ff9b9b}.warn{color:#ffd479}.row{margin:8px 0}button{width:100%;padding:13px;margin-top:14px;border:0;border-radius:9px;background:#3a3f4a;color:#fff;font-weight:700;font:inherit;cursor:pointer}.primary{background:#d4ad62;color:#171717}</style><body><main class="card"><h1>Connect to VortexEditPro</h1><p class="muted"><b>${htmlEscape(client.client_name || "MCP Client")}</b> is requesting access to <b>${htmlEscape(instance.display_name || "VortexEditPro")}</b>.</p><div class="row muted">Callback destination: <b>${htmlEscape(callbackHost)}</b></div><div class="row muted">Access scope: <b>${htmlEscape(requestedScope)}</b> (tools on this instance only)</div><div class="row muted">This request is short-lived and single-use. Review the ChatGPT client, VortexEditPro device, and requested access before approving. No MCP token is entered in this page.</div><div id="status" class="status warn">Waiting for your decision in this browser…</div><form id="decision" method="post" action="${htmlEscape(pendingRequestPath(req, requestId) + "/decision")}"><button class="primary" type="submit" name="decision" value="approve">Approve and connect ChatGPT</button><button type="submit" name="decision" value="deny">Deny connection</button></form><form id="complete" method="post" action="${htmlEscape(completeUrl)}"></form><button id="cancel" type="button">Cancel request</button><p class="muted" style="margin-top:14px;font-size:13px">If you did not start this connection, choose Deny or close this page.</p></main><script>(function(){var statusUrl=${JSON.stringify(statusUrl)};var completeUrl=${JSON.stringify(completeUrl)};var box=document.getElementById('status');var form=document.getElementById('complete');var done=false;async function poll(){if(done) return;try{var r=await fetch(statusUrl,{cache:'no-store'});if(!r.ok){box.className='status bad';box.textContent='Request unavailable or expired. Close this page and try again.';done=true;return;}var j=await r.json();if(j.status==='approved'){box.className='status ok';box.textContent='Approved. Completing secure connection…';done=true;form.submit();return;}if(j.status==='denied'){box.className='status bad';box.textContent='You denied this connection.';done=true;return;}if(j.status==='expired' || j.status==='consumed'){box.className='status bad';box.textContent='Request expired or already used. Start a new connection.';done=true;return;}box.className='status warn';box.textContent='Waiting for your decision in this browser…';}catch(e){box.className='status warn';box.textContent='Waiting for your decision in this browser… (checking)';}}document.getElementById('decision').addEventListener('submit',function(){done=true;});document.getElementById('cancel').addEventListener('click',function(){try{window.close()}catch(e){} location.href='about:blank';});setInterval(poll,2000);poll();})();</script></body></html>`;
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer"
    });
    return res.end(html);
  }

  // POST: complete an approved request (no MCP token accepted; ownership proven via device-approved request)
  if (!(await checkRateLimit("oauth:authorize:complete:" + (req.headers["x-forwarded-for"] || "unknown"), 30))) {
    return authorizationError(res, "slow_down", "Too many requests. Try again shortly.", 429);
  }
  return authorizationError(res, "invalid_request", "Direct approval is not supported. Approve the pending request in VortexEditPro.", 400);
}

async function issueTokens(res, instanceId, clientId, scope, resource) {
  const accessToken = newSecret("vxo_");
  const refreshToken = newSecret("vxr_");
  const now = Date.now();
  await execute(
    "INSERT INTO oauth_access_tokens(token_hash, instance_id, client_id, scope, resource, expires_at, refresh_token_hash, refresh_expires_at, revoked_at, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9)",
    [hashSecret(accessToken), instanceId, clientId, scope, resource, now + ACCESS_TTL, hashSecret(refreshToken), now + REFRESH_TTL, now]
  );
  return sendJson(res, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TTL / 1000),
    refresh_token: refreshToken,
    scope
  });
}

async function token(req, res) {
  await ensureSchema();
  if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
  if (!(await checkRateLimit("oauth:token:" + (req.headers["x-forwarded-for"] || "unknown"), 60))) {
    return sendJson(res, 429, { error: "rate_limited" });
  }
  const body = await readForm(req);
  const clientId = body.client_id;
  const client = await loadClient(clientId);
  if (!client) return sendJson(res, 400, { error: "invalid_client" });
  if (body.grant_type === "authorization_code") {
    const code = typeof body.code === "string" ? body.code : "";
    const row = await queryOne("SELECT code_hash, instance_id, client_id, redirect_uri, code_challenge, scope, resource, expires_at, used_at FROM oauth_codes WHERE code_hash=$1", [hashSecret(code)]);
    if (!row || row.used_at || Number(row.expires_at) <= Date.now() ||
        row.client_id !== clientId || row.redirect_uri !== body.redirect_uri ||
        typeof body.code_verifier !== "string" ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier) ||
        !safeEqual(pkceChallenge(body.code_verifier), row.code_challenge) ||
        body.resource !== row.resource) {
      return sendJson(res, 400, { error: "invalid_grant" });
    }
    const used = await execute("UPDATE oauth_codes SET used_at=$1 WHERE code_hash=$2 AND used_at IS NULL", [Date.now(), hashSecret(code)]);
    if (!used.rowCount) return sendJson(res, 400, { error: "invalid_grant" });
    return issueTokens(res, row.instance_id, clientId, row.scope, row.resource);
  }
  if (body.grant_type === "refresh_token") {
    const refresh = typeof body.refresh_token === "string" ? body.refresh_token : "";
    const row = await queryOne("SELECT token_hash, instance_id, client_id, scope, resource, refresh_expires_at, revoked_at FROM oauth_access_tokens WHERE refresh_token_hash=$1", [hashSecret(refresh)]);
    if (!row || row.revoked_at || Number(row.refresh_expires_at) <= Date.now() || row.client_id !== clientId || body.resource !== row.resource) {
      return sendJson(res, 400, { error: "invalid_grant" });
    }
    const revoked = await execute("UPDATE oauth_access_tokens SET revoked_at=$1, refresh_token_hash=NULL WHERE token_hash=$2 AND revoked_at IS NULL AND refresh_token_hash=$3", [Date.now(), row.token_hash, hashSecret(refresh)]);
    if (!revoked.rowCount) return sendJson(res, 400, { error: "invalid_grant" });
    return issueTokens(res, row.instance_id, clientId, row.scope, row.resource);
  }
  return sendJson(res, 400, { error: "unsupported_grant_type" });
}

export async function oauthAccessInstance(accessToken, instanceId, resource) {
  if (!accessToken) return null;
  const row = await queryOne(
    `SELECT i.instance_id, i.display_name, i.status, i.app_version, i.tools_json, i.last_seen, i.created_at, i.updated_at
       FROM oauth_access_tokens t JOIN instances i ON i.instance_id=t.instance_id
      WHERE t.token_hash=$1 AND t.instance_id=$2 AND t.resource=$3
        AND t.expires_at>$4 AND t.revoked_at IS NULL`,
    [hashSecret(accessToken), instanceId, resource, Date.now()]
  );
  return row || null;
}

async function getPendingRequest(requestId) {
  if (!requestId || typeof requestId !== "string") return null;
  const row = await queryOne(
    `SELECT r.request_id, r.instance_id, r.client_id, r.redirect_uri, r.state_value, r.code_challenge, r.scope, r.resource, r.status, r.expires_at, r.approved_at, r.consumed_at, r.created_at,
            c.client_name
       FROM oauth_authorization_requests r
       JOIN oauth_clients c ON c.client_id = r.client_id
      WHERE r.request_id=$1`,
    [requestId]
  );
  if (!row) return null;
  const now = Date.now();
  if (row.status === "pending" && Number(row.expires_at) <= now) {
    try { await execute("UPDATE oauth_authorization_requests SET status='expired' WHERE request_id=$1 AND status='pending'", [requestId]); } catch {}
    row.status = "expired";
  }
  return row;
}

async function pendingRequestStatus(req, res, requestId) {
  await ensureSchema();
  if (req.method !== "GET") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
  const row = await getPendingRequest(requestId);
  if (!row) return sendJson(res, 404, { error: "not_found" });
  return sendJson(res, 200, {
    request_id: row.request_id,
    status: row.status,
    instance_id: row.instance_id,
    client_name: row.client_name || "",
    scope: row.scope,
    expires_at: Number(row.expires_at || 0)
  });
}

async function decideBrowserRequest(req, res, requestId, origin) {
  await ensureSchema();
  if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });

  // The request ID is a short-lived, high-entropy capability. Also require a
  // same-origin browser form submission to prevent cross-site approval.
  const requestOrigin = String(req.headers.origin || "");
  if (!requestOrigin || requestOrigin !== origin ||
      (req.headers["sec-fetch-site"] && req.headers["sec-fetch-site"] !== "same-origin")) {
    return sendJson(res, 403, { error: "cross_origin_forbidden" });
  }
  if (!(await checkRateLimit("oauth:browser-decision:" + (req.headers["x-forwarded-for"] || "unknown"), 30))) {
    return sendJson(res, 429, { error: "rate_limited" });
  }

  const body = await readForm(req);
  const decision = body.decision;
  if (decision !== "approve" && decision !== "deny") {
    return sendJson(res, 400, { error: "invalid_decision" });
  }

  const row = await getPendingRequest(requestId);
  if (!row) return sendJson(res, 404, { error: "not_found" });
  const result = await decidePendingOAuthRequest(row.instance_id, requestId, decision);
  if (!result.ok) {
    const status = result.code === "expired" ? 410 : result.code === "not_pending" || result.code === "conflict" ? 409 : 404;
    return sendJson(res, status, { error: result.code || "decision_failed", status: result.status || null });
  }

  if (decision === "approve") {
    res.writeHead(307, {
      location: pendingRequestPath(req, requestId) + "/complete",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer"
    });
    return res.end();
  }

  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connection denied</title><style>body{margin:0;background:#101114;color:#f5f5f5;font:16px system-ui;display:grid;min-height:100vh;place-items:center}.card{width:min(520px,calc(100% - 40px));box-sizing:border-box;background:#1b1d22;border:1px solid #383b43;border-radius:18px;padding:28px}.muted{color:#aeb2bd;line-height:1.55}</style><main class="card"><h1>Connection denied</h1><p class="muted">ChatGPT was not connected to VortexEditPro. You can close this page.</p></main></html>`;
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  });
  return res.end(html);
}

async function completePendingRequest(req, res, requestId) {
  await ensureSchema();
  if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
  if (!(await checkRateLimit("oauth:authorize:complete:" + (req.headers["x-forwarded-for"] || "unknown"), 30))) {
    return sendJson(res, 429, { error: "rate_limited" });
  }
  const row = await getPendingRequest(requestId);
  if (!row) return sendJson(res, 404, { error: "not_found" });
  if (row.status !== "approved") return sendJson(res, 409, { error: "not_approved", status: row.status });
  if (Number(row.expires_at) <= Date.now()) return sendJson(res, 410, { error: "expired" });

  // consume atomically
  const consumed = await execute(
    "UPDATE oauth_authorization_requests SET status='consumed', consumed_at=$1 WHERE request_id=$2 AND status='approved' AND expires_at > $1",
    [Date.now(), requestId]
  );
  if (!consumed.rowCount) return sendJson(res, 409, { error: "not_consumable" });

  const code = newSecret("vxo_code_");
  const now = Date.now();
  await execute(
    "INSERT INTO oauth_codes(code_hash, instance_id, client_id, redirect_uri, code_challenge, scope, resource, expires_at, used_at, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9)",
    [hashSecret(code), row.instance_id, row.client_id, row.redirect_uri, row.code_challenge, row.scope, row.resource, now + CODE_TTL, now]
  );
  const target = new URL(row.redirect_uri);
  target.searchParams.set("code", code);
  target.searchParams.set("state", row.state_value);
  res.writeHead(302, { location: target.toString(), "cache-control": "no-store" });
  return res.end();
}

export async function listPendingOAuthRequests(instanceId) {
  await ensureSchema();
  const now = Date.now();
  try { await execute("UPDATE oauth_authorization_requests SET status='expired' WHERE instance_id=$1 AND status='pending' AND expires_at <= $2", [instanceId, now]); } catch {}
  const { queryAll } = await import("./store.js");
  const rows = await queryAll(
    `SELECT r.request_id, r.instance_id, r.client_id, c.client_name, r.scope, r.resource, r.status, r.expires_at, r.created_at, r.redirect_uri
       FROM oauth_authorization_requests r
       JOIN oauth_clients c ON c.client_id = r.client_id
      WHERE r.instance_id=$1 AND r.status='pending' AND r.expires_at > $2
      ORDER BY r.created_at DESC
      LIMIT 20`,
    [instanceId, now]
  );
  return rows.map((r) => ({
    request_id: r.request_id,
    client_id: r.client_id,
    client_name: r.client_name || "MCP Client",
    scope: r.scope,
    resource: r.resource,
    redirect_uri: r.redirect_uri,
    expires_at: Number(r.expires_at || 0),
    created_at: Number(r.created_at || 0),
    status: r.status
  }));
}

export async function decidePendingOAuthRequest(instanceId, requestId, decision) {
  await ensureSchema();
  const row = await getPendingRequest(requestId);
  if (!row || row.instance_id !== instanceId) return { ok: false, code: "not_found" };
  if (row.status !== "pending") return { ok: false, code: "not_pending", status: row.status };
  if (Number(row.expires_at) <= Date.now()) return { ok: false, code: "expired" };
  if (decision === "approve") {
    const updated = await execute(
      "UPDATE oauth_authorization_requests SET status='approved', approved_at=$1 WHERE request_id=$2 AND instance_id=$3 AND status='pending' AND expires_at > $1",
      [Date.now(), requestId, instanceId]
    );
    return updated.rowCount ? { ok: true, status: "approved" } : { ok: false, code: "conflict" };
  }
  if (decision === "deny") {
    const updated = await execute(
      "UPDATE oauth_authorization_requests SET status='denied' WHERE request_id=$1 AND instance_id=$2 AND status='pending'",
      [requestId, instanceId]
    );
    return updated.rowCount ? { ok: true, status: "denied" } : { ok: false, code: "conflict" };
  }
  return { ok: false, code: "invalid_decision" };
}

export async function handleOAuthRoute(req, res, parts) {
  if (parts[0] !== "oauth") return false;
  const origin = baseUrl(req);
  if (parts[0] === "oauth" && parts[1] === "authorization-server" && parts.length === 2) {
    if (req.method !== "GET") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
    await authorizationServerMetadata(req, res);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "protected-resource" && parts.length === 2) {
    const resource = new URL(req.url || "/", origin).searchParams.get("resource") || "";
    const instanceId = resourceInstanceId(resource, origin);
    if (!instanceId) {
      sendJson(res, 400, { error: "invalid_resource", error_description: "A valid per-instance MCP resource URL is required." });
      return true;
    }
    await protectedResourceMetadata(req, res, `api/mcp/${instanceId}`);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "register" && parts.length === 2) {
    await registerClient(req, res);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "authorize" && parts[2] === "request" && parts.length >= 4) {
    const requestId = parts[3];
    if (parts[4] === "status" && parts.length === 5) {
      await pendingRequestStatus(req, res, requestId);
      return true;
    }
    if (parts[4] === "complete" && parts.length === 5) {
      await completePendingRequest(req, res, requestId);
      return true;
    }
    if (parts[4] === "decision" && parts.length === 5) {
      await decideBrowserRequest(req, res, requestId, origin);
      return true;
    }
  }
  if (parts[0] === "oauth" && parts[1] === "authorize" && parts.length === 2) {
    await authorize(req, res, origin);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "token" && parts.length === 2) {
    await token(req, res);
    return true;
  }
  return false;
}
