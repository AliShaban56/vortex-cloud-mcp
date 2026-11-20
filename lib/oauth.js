import { createHash } from "node:crypto";
import { bearerToken, hashSecret, newSecret, safeEqual } from "./security.js";
import { checkRateLimit, ensureSchema, execute, queryOne } from "./store.js";

const ACCESS_TTL = 60 * 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL = 5 * 60 * 1000;
const SCOPE = "mcp:tools";

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
  const instance = await queryOne("SELECT instance_id FROM instances WHERE instance_id=$1", [match[1]]);
  if (!instance) return sendJson(res, 404, { error: "resource_not_found" });
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

  if (req.method === "GET") {
    const hidden = { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, state, code_challenge: challenge, code_challenge_method: challengeMethod, resource, scope: requestedScope };
    const fields = Object.entries(hidden).map(([k, v]) =>
      `<input type="hidden" name="${htmlEscape(k)}" value="${htmlEscape(v)}">`).join("");
    const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect VortexEditPro</title><style>body{margin:0;background:#101114;color:#f5f5f5;font:16px system-ui;display:grid;min-height:100vh;place-items:center}.card{width:min(440px,calc(100% - 40px));box-sizing:border-box;background:#1b1d22;border:1px solid #383b43;border-radius:18px;padding:28px}h1{font-size:22px;margin:0 0 8px}.muted{color:#aeb2bd;line-height:1.5}label{display:block;margin:20px 0 8px;font-weight:600}input{box-sizing:border-box;width:100%;padding:13px;border:1px solid #555b66;border-radius:9px;background:#111318;color:white;font:inherit}button{width:100%;padding:13px;margin-top:18px;border:0;border-radius:9px;background:#d4ad62;color:#171717;font-weight:700;font:inherit;cursor:pointer}.note{font-size:13px;color:#aeb2bd;margin-top:14px}</style><body><main class="card"><h1>Connect to VortexEditPro</h1><p class="muted"><b>${htmlEscape(client.client_name || "MCP Client")}</b> is requesting access to <b>${htmlEscape(instance.display_name)}</b>.</p><p class="muted">Enter this instance's existing MCP access token to approve the connection. The token is checked securely and is never shown back.</p><form method="post" action="/api/oauth/authorize">${fields}<label for="mcp_token">MCP access token</label><input id="mcp_token" name="mcp_token" type="password" autocomplete="off" required><button type="submit">Approve connection</button></form><p class="note">Access is limited to this VortexEditPro instance. You can revoke it by rotating or revoking the instance's MCP token.</p></main></body></html>`;
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer"
    });
    return res.end(html);
  }

  const supplied = typeof params.mcp_token === "string" ? params.mcp_token.trim() : "";
  if (!supplied || !safeEqual(hashSecret(supplied), instance.mcp_token_hash)) {
    return authorizationError(res, "access_denied", "The MCP access token is incorrect.", 401);
  }
  const code = newSecret("vxo_code_");
  const now = Date.now();
  await execute(
    "INSERT INTO oauth_codes(code_hash, instance_id, client_id, redirect_uri, code_challenge, scope, resource, expires_at, used_at, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9)",
    [hashSecret(code), instanceId, clientId, redirectUri, challenge, requestedScope, resource, now + CODE_TTL, now]
  );
  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  target.searchParams.set("state", state);
  res.writeHead(302, { location: target.toString(), "cache-control": "no-store" });
  return res.end();
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
        body.code_verifier?.length < 43 || body.code_verifier?.length > 128 ||
        !safeEqual(pkceChallenge(body.code_verifier), row.code_challenge) ||
        (body.resource && body.resource !== row.resource)) {
      return sendJson(res, 400, { error: "invalid_grant" });
    }
    const used = await execute("UPDATE oauth_codes SET used_at=$1 WHERE code_hash=$2 AND used_at IS NULL", [Date.now(), hashSecret(code)]);
    if (!used.rowCount) return sendJson(res, 400, { error: "invalid_grant" });
    return issueTokens(res, row.instance_id, clientId, row.scope, row.resource);
  }
  if (body.grant_type === "refresh_token") {
    const refresh = typeof body.refresh_token === "string" ? body.refresh_token : "";
    const row = await queryOne("SELECT token_hash, instance_id, client_id, scope, resource, refresh_expires_at, revoked_at FROM oauth_access_tokens WHERE refresh_token_hash=$1", [hashSecret(refresh)]);
    if (!row || row.revoked_at || Number(row.refresh_expires_at) <= Date.now() || row.client_id !== clientId) {
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

export async function handleOAuthRoute(req, res, parts) {
  await ensureSchema();
  const origin = baseUrl(req);
  if (parts[0] === "oauth" && parts[1] === "authorization-server" && parts.length === 2) {
    if (req.method !== "GET") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
    await authorizationServerMetadata(req, res);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "protected-resource" && parts.length === 5 && parts[2] === "api" && parts[3] === "mcp") {
    await protectedResourceMetadata(req, res, `api/mcp/${parts[4]}`);
    return true;
  }
  if (parts[0] === "oauth" && parts[1] === "register" && parts.length === 2) {
    await registerClient(req, res);
    return true;
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
