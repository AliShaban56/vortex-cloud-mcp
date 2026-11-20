import { randomUUID } from "node:crypto";
import {
  bearerToken, hashSecret, isSafeToolName, jsonSchemaOrEmpty,
  newId, newSecret, safeEqual, nowMs
} from "./security.js";
import { checkRateLimit, ensureSchema, execute, queryOne } from "./store.js";
import { handleOAuthRoute, oauthAccessInstance } from "./oauth.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, accept, mcp-protocol-version, mcp-session-id",
  "access-control-expose-headers": "mcp-protocol-version, mcp-session-id"
};

const MAX_BODY_BYTES = 256 * 1024;
const MAX_RESULT_BYTES = 128 * 1024;
const MAX_TOOLS = 120;
const DEFAULT_STALE_SECONDS = Number(process.env.VORTEX_DEVICE_STALE_SECONDS || 45);
const DEFAULT_MCP_WAIT_MS = Math.min(Math.max(Number(process.env.VORTEX_MCP_WAIT_MS || 7000), 1000), 8000);
const COMMAND_TTL_MS = Number(process.env.VORTEX_COMMAND_TTL_MS || 10 * 60 * 1000); // 10 min
const STALE_RUNNING_MS = Number(process.env.VORTEX_STALE_RUNNING_MS || 90 * 1000);

function send(res, status, body, extra = {}) {
  res.writeHead(status, { ...JSON_HEADERS, ...extra });
  res.end(body === null ? "" : JSON.stringify(body));
}
function fail(res, status, code, message, extra = {}) {
  return send(res, status, { error: { code, message } }, extra);
}
function routePath(req) {
  const raw = new URL(req.url || "/", "https://vortex.invalid").pathname;
  if (raw === "/.well-known/oauth-authorization-server") return ["oauth", "authorization-server"];
  return raw.replace(/^\/api\/?/, "").split("/").filter(Boolean);
}

async function readBody(req) {
  const len = Number(req.headers?.["content-length"] || 0);
  if (len > MAX_BODY_BYTES) {
    const error = new Error("Request body is too large.");
    error.status = 413;
    throw error;
  }
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === "string") {
    const t = req.body.trim();
    return t ? JSON.parse(t) : {};
  }
  // Read stream (Vercel/Node)
  const chunks = [];
  let total = 0;
  await new Promise((resolve, reject) => {
    req.on?.("data", (chunk) => {
      total += chunk.length || 0;
      if (total > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body is too large."), { status: 413 }));
        try { req.destroy(); } catch {}
        return;
      }
      chunks.push(chunk);
    });
    req.on?.("end", resolve);
    req.on?.("error", reject);
    // if already ended/no stream events in some runtimes
    if (req.readableEnded) resolve();
  });
  if (!chunks.length) return {};
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  return raw ? JSON.parse(raw) : {};
}

function parseJson(value, fallback) {
  if (value == null) return fallback;
  if (typeof value === "object") return value;
  if (typeof value !== "string") return fallback;
  try { return JSON.parse(value); } catch { return fallback; }
}

function normalizeTools(tools) {
  if (!Array.isArray(tools)) return [];
  return tools.slice(0, MAX_TOOLS).filter((tool) =>
    tool && isSafeToolName(tool.name) &&
    typeof tool.description === "string" &&
    tool.description.length <= 2_000
  ).map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: jsonSchemaOrEmpty(tool.inputSchema)
  }));
}

function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim() || "https";
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

function instanceMcpUrl(req, instanceId) {
  const base = getBaseUrl(req);
  const path = `/api/mcp/${instanceId}`;
  return base ? `${base}${path}` : path;
}

async function authenticateInstance(req, instanceId, tokenColumn) {
  const token = bearerToken(req);
  if (!token || !instanceId) return null;
  const row = await queryOne(
    `SELECT instance_id, display_name, device_token_hash, mcp_token_hash, mcp_token_revoked,
            status, app_version, tools_json, last_seen, created_at, updated_at
       FROM instances WHERE instance_id = $1`,
    [instanceId]
  );
  if (!row) return null;
  if (tokenColumn === "device") {
    return safeEqual(hashSecret(token), row.device_token_hash) ? row : null;
  }
  if (tokenColumn === "mcp") {
    if (Number(row.mcp_token_revoked || 0) === 1) return null;
    if (!row.mcp_token_hash) return null;
    return safeEqual(hashSecret(token), row.mcp_token_hash) ? row : null;
  }
  return null;
}

function safeDatabaseDiagnostic(error) {
  // Never return raw error messages, connection strings, hostnames, usernames, or credentials.
  const code = typeof error?.code === "string" ? error.code : "";
  const message = typeof error?.message === "string" ? error.message.toLowerCase() : "";
  const knownCodes = new Set([
    "28P01", "3D000", "28000", "42501", "53300", "57P03",
    "08001", "08006", "ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND",
    "EAI_AGAIN", "EHOSTUNREACH", "ECONNRESET",
    "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "ERR_TLS_CERT_ALTNAME_INVALID", "SQLITE_BUSY", "SQLITE_LOCKED"
  ]);
  if (code === "28P01" || code === "28000" || message.includes("password authentication failed") || message.includes("unauthorized")) {
    return { category: "AUTHENTICATION_FAILED", code: knownCodes.has(code) ? code : null };
  }
  if (message.includes("client password must be a string") || message.includes("auth token") && message.includes("missing")) {
    return { category: "DATABASE_CREDENTIALS_MISSING", code: null };
  }
  if (code === "3D000") return { category: "DATABASE_NAME_INVALID", code };
  if (code === "53300" || message.includes("too many clients") || message.includes("too many connections")) {
    return { category: "CONNECTION_LIMIT_REACHED", code: knownCodes.has(code) ? code : null };
  }
  if (code === "42501") return { category: "DATABASE_PERMISSION_DENIED", code };
  if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "EHOSTUNREACH" || message.includes("getaddrinfo")) {
    return { category: "HOST_OR_NETWORK_UNREACHABLE", code: knownCodes.has(code) ? code : null };
  }
  if (code === "ETIMEDOUT" || message.includes("timeout") || message.includes("timed out")) {
    return { category: "CONNECTION_TIMEOUT", code: knownCodes.has(code) ? code : null };
  }
  if (code.startsWith("ERR_TLS") || code.startsWith("ERR_SSL") || code === "SELF_SIGNED_CERT_IN_CHAIN" || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") {
    return { category: "TLS_HANDSHAKE_FAILED", code: knownCodes.has(code) ? code : null };
  }
  if (code === "08001" || code === "08006" || code === "ECONNRESET") {
    return { category: "CONNECTION_FAILED", code: knownCodes.has(code) ? code : null };
  }
  if (code === "57P03") return { category: "DATABASE_TEMPORARILY_UNAVAILABLE", code };
  return { category: "UNKNOWN_DATABASE_ERROR", code: knownCodes.has(code) ? code : null };
}

async function databaseStatus() {
  if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
    return {
      database: "not_configured",
      diagnostic: { stage: "configuration", category: !process.env.TURSO_DATABASE_URL ? "TURSO_DATABASE_URL_MISSING" : "TURSO_AUTH_TOKEN_MISSING" }
    };
  }
  let stage = "connection";
  try {
    await queryOne("SELECT 1 AS ok");
    stage = "schema";
    await ensureSchema();
    return { database: "connected" };
  } catch (error) {
    return {
      database: "unavailable",
      diagnostic: { stage, ...safeDatabaseDiagnostic(error) }
    };
  }
}

// Liveness
async function health(res) {
  const db = await databaseStatus();
  return send(res, 200, {
    ok: true,
    service: "Vortex Cloud MCP",
    status: "running",
    ...db,
    checks: { api: "ok", database: db.database }
  });
}

// Readiness
async function readiness(res) {
  const db = await databaseStatus();
  const ready = db.database === "connected";
  return send(res, ready ? 200 : 503, {
    ok: ready,
    service: "Vortex Cloud MCP",
    status: ready ? "ready" : "degraded",
    ...db,
    checks: { api: "ok", database: db.database }
  });
}

function requireAdmin(req, res) {
  if (!process.env.VORTEX_ADMIN_SECRET) {
    fail(res, 503, "ADMIN_NOT_CONFIGURED", "The server administrator secret is not configured.");
    return false;
  }
  if (!safeEqual(bearerToken(req), process.env.VORTEX_ADMIN_SECRET)) {
    fail(res, 401, "UNAUTHORIZED", "Administrator authentication failed.");
    return false;
  }
  return true;
}

async function registerInstanceCore(req, displayName, meta = {}) {
  const instanceId = newId();
  const deviceToken = newSecret("vxd_");
  const mcpToken = newSecret("vxm_");
  const now = nowMs();
  const name = (typeof displayName === "string" ? displayName.trim().slice(0, 80) : "") || "VortexEditPro";
  await execute(
    `INSERT INTO instances
      (instance_id, display_name, device_token_hash, mcp_token_hash, mcp_token_revoked, status, tools_json, app_version, last_seen, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 0, 'offline', '[]', $5, NULL, $6, $6)`,
    [instanceId, name, hashSecret(deviceToken), hashSecret(mcpToken), String(meta.app_version || "").slice(0, 40), now]
  );
  return { instanceId, name, deviceToken, mcpToken, mcpUrl: instanceMcpUrl(req, instanceId) };
}

async function registerInstanceAdmin(req, res) {
  if (!requireAdmin(req, res)) return;
  await ensureSchema();
  const body = await readBody(req);
  const out = await registerInstanceCore(req, body.name, body);
  return send(res, 201, {
    instance_id: out.instanceId,
    name: out.name,
    device_token: out.deviceToken,
    mcp_token: out.mcpToken,
    mcp_url: out.mcpUrl,
    warning: "Save both tokens now. They are shown only once and cannot be recovered."
  });
}

async function createEnrollment(req, res) {
  if (!requireAdmin(req, res)) return;
  await ensureSchema();
  const body = await readBody(req);
  const enrollmentToken = newSecret("vxe_");
  const now = nowMs();
  const ttlMs = Math.min(Math.max(Number(body.ttl_seconds || 24 * 3600) * 1000, 5 * 60 * 1000), 7 * 24 * 3600 * 1000);
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : null;
  await execute(
    `INSERT INTO enrollment_tokens(token_hash, display_name, created_at, expires_at, used_at, used_by_instance)
     VALUES($1,$2,$3,$4,NULL,NULL)`,
    [hashSecret(enrollmentToken), name, now, now + ttlMs]
  );
  return send(res, 201, {
    enrollment_token: enrollmentToken,
    expires_at: now + ttlMs,
    warning: "Provide this enrollment token to the desktop app once. It cannot be recovered after creation."
  });
}

async function registerWithEnrollment(req, res) {
  await ensureSchema();
  if (!(await checkRateLimit(`enroll:${req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "ip"}`, 30))) {
    return fail(res, 429, "RATE_LIMITED", "Too many enrollment requests.");
  }
  const body = await readBody(req);
  const token = typeof body.enrollment_token === "string" ? body.enrollment_token.trim() : "";
  if (!token) return fail(res, 400, "INVALID_REQUEST", "enrollment_token is required.");
  const row = await queryOne(
    `SELECT token_hash, display_name, expires_at, used_at FROM enrollment_tokens WHERE token_hash=$1`,
    [hashSecret(token)]
  );
  if (!row) return fail(res, 401, "INVALID_ENROLLMENT", "Invalid enrollment token.");
  if (row.used_at) return fail(res, 409, "ENROLLMENT_USED", "Enrollment token has already been used.");
  if (Number(row.expires_at || 0) <= nowMs()) return fail(res, 410, "ENROLLMENT_EXPIRED", "Enrollment token has expired.");

  const displayName = (typeof body.name === "string" && body.name.trim()) ? body.name.trim().slice(0, 80) : (row.display_name || "VortexEditPro");
  const out = await registerInstanceCore(req, displayName, body);

  const used = await execute(
    `UPDATE enrollment_tokens SET used_at=$1, used_by_instance=$2 WHERE token_hash=$3 AND used_at IS NULL`,
    [nowMs(), out.instanceId, hashSecret(token)]
  );
  if (!used.rowCount) {
    // extremely unlikely race; cleanup best-effort
    await execute(`DELETE FROM instances WHERE instance_id=$1`, [out.instanceId]);
    return fail(res, 409, "ENROLLMENT_USED", "Enrollment token has already been used.");
  }

  return send(res, 201, {
    instance_id: out.instanceId,
    name: out.name,
    device_token: out.deviceToken,
    mcp_token: out.mcpToken,
    mcp_url: out.mcpUrl,
    warning: "Save device_token and mcp_token now. They are shown only once and cannot be recovered."
  });
}

async function heartbeat(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  if (!(await checkRateLimit(`hb:${instanceId}`, 120))) return fail(res, 429, "RATE_LIMITED", "Too many heartbeat requests.");
  const body = await readBody(req);
  const tools = normalizeTools(body.tools);
  const now = nowMs();
  await execute(
    "UPDATE instances SET status='online', last_seen=$1, app_version=$2, tools_json=$3, updated_at=$1 WHERE instance_id=$4",
    [now, String(body.app_version || instance.app_version || "").slice(0, 40), JSON.stringify(tools), instanceId]
  );
  return send(res, 200, { ok: true, server_time: now, accepted_tools: tools.length, instance_id: instanceId });
}

async function recoverStaleRunning(instanceId, now) {
  // Requeue stale running commands so a restarted/crashed agent can pick them up.
  // Agent must be idempotent for safety.
  await execute(
    `UPDATE commands SET status='queued', updated_at=$1
      WHERE instance_id=$2 AND status='running' AND updated_at <= $3 AND expires_at > $1`,
    [now, instanceId, now - STALE_RUNNING_MS]
  );
}

async function pollCommands(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  if (!(await checkRateLimit(`poll:${instanceId}`, 240))) return fail(res, 429, "RATE_LIMITED", "Too many polling requests.");
  const now = nowMs();

  // Mark expired queued/running commands
  await execute(
    "UPDATE commands SET status='expired', updated_at=$1 WHERE instance_id=$2 AND status IN ('queued','running') AND expires_at <= $1",
    [now, instanceId]
  );
  await recoverStaleRunning(instanceId, now);

  // Claim queued commands
  const claimed = await execute(
    `UPDATE commands SET status='running', claimed_at=$1, updated_at=$1
      WHERE command_id IN (
        SELECT command_id FROM commands
         WHERE instance_id=$2 AND status='queued' AND expires_at > $1
         ORDER BY created_at LIMIT 5
      ) AND status='queued'
      RETURNING command_id, tool_name, arguments_json, created_at`,
    [now, instanceId]
  );

  // Touch instance liveness on poll as well
  await execute("UPDATE instances SET status='online', last_seen=$1, updated_at=$1 WHERE instance_id=$2", [now, instanceId]);

  const commands = claimed.rows.map((row) => ({
    command_id: row.command_id,
    tool_name: row.tool_name,
    arguments: parseJson(row.arguments_json, {}),
    created_at: Number(row.created_at)
  }));
  return send(res, 200, { commands, server_time: now, instance_id: instanceId });
}

async function postResult(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  const body = await readBody(req);
  if (typeof body.command_id !== "string" || !body.command_id) {
    return fail(res, 400, "INVALID_REQUEST", "command_id is required.");
  }
  const isError = Boolean(body.error);
  const resultJson = JSON.stringify(body.result ?? null);
  if (!isError && resultJson.length > MAX_RESULT_BYTES) {
    return fail(res, 413, "RESULT_TOO_LARGE", "Command result is too large.");
  }
  const now = nowMs();
  const errText = isError ? String(body.error || body.message || "Command failed").slice(0, 2_000) : null;

  // Accept result for running commands; idempotently accept if already completed with same outcome when possible
  const result = await execute(
    `UPDATE commands SET status=$1, result_json=$2, error_text=$3, updated_at=$4, completed_at=$4
      WHERE command_id=$5 AND instance_id=$6 AND status IN ('running','queued')`,
    [isError ? "failed" : "completed", isError ? null : resultJson, errText, now, body.command_id, instanceId]
  );
  if (!result.rowCount) {
    // If already terminal, treat as ok for idempotency
    const existing = await queryOne(`SELECT status FROM commands WHERE command_id=$1 AND instance_id=$2`, [body.command_id, instanceId]);
    if (existing && ["completed", "failed", "expired", "cancelled"].includes(existing.status)) {
      return send(res, 200, { ok: true, idempotent: true, status: existing.status });
    }
    return fail(res, 404, "COMMAND_NOT_FOUND", "Command was not found or is no longer active.");
  }
  await execute("UPDATE instances SET status='online', last_seen=$1, updated_at=$1 WHERE instance_id=$2", [now, instanceId]);
  return send(res, 200, { ok: true });
}

async function rotateMcpToken(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  const mcpToken = newSecret("vxm_");
  const now = nowMs();
  await execute(
    `UPDATE instances SET mcp_token_hash=$1, mcp_token_revoked=0, updated_at=$2 WHERE instance_id=$3`,
    [hashSecret(mcpToken), now, instanceId]
  );
  await execute("UPDATE oauth_access_tokens SET revoked_at=$1, refresh_token_hash=NULL WHERE instance_id=$2 AND revoked_at IS NULL", [now, instanceId]);
  return send(res, 200, {
    ok: true,
    instance_id: instanceId,
    mcp_token: mcpToken,
    mcp_url: instanceMcpUrl(req, instanceId),
    warning: "Save the new MCP token now. The previous token is no longer valid."
  });
}

async function revokeMcpToken(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  const now = nowMs();
  await execute(
    `UPDATE instances SET mcp_token_revoked=1, updated_at=$1 WHERE instance_id=$2`,
    [now, instanceId]
  );
  await execute("UPDATE oauth_access_tokens SET revoked_at=$1, refresh_token_hash=NULL WHERE instance_id=$2 AND revoked_at IS NULL", [now, instanceId]);
  return send(res, 200, { ok: true, instance_id: instanceId, revoked: true });
}

async function instanceInfo(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  return send(res, 200, {
    ok: true,
    instance_id: instance.instance_id,
    name: instance.display_name,
    status: instance.status,
    app_version: instance.app_version || "",
    last_seen: instance.last_seen ? Number(instance.last_seen) : null,
    mcp_url: instanceMcpUrl(req, instanceId),
    mcp_token_revoked: Number(instance.mcp_token_revoked || 0) === 1,
  });
}

function isTerminalStatus(s) {
  return s === "completed" || s === "failed" || s === "expired" || s === "cancelled";
}

async function queueAndWait(instanceId, toolName, args) {
  const commandId = randomUUID();
  const now = nowMs();
  const waitMs = DEFAULT_MCP_WAIT_MS;
  const expiresAt = now + COMMAND_TTL_MS;
  await execute(
    `INSERT INTO commands
      (command_id, instance_id, tool_name, arguments_json, status, created_at, updated_at, expires_at)
     VALUES ($1, $2, $3, $4, 'queued', $5, $5, $6)`,
    [commandId, instanceId, toolName, JSON.stringify(args ?? {}), now, expiresAt]
  );

  const deadline = now + waitMs;
  while (Date.now() < deadline) {
    const row = await queryOne(
      "SELECT status, result_json, error_text FROM commands WHERE command_id=$1 AND instance_id=$2",
      [commandId, instanceId]
    );
    if (row?.status === "completed") {
      return { content: [{ type: "text", text: JSON.stringify(parseJson(row.result_json, null)) }], isError: false };
    }
    if (row?.status === "failed") {
      return { content: [{ type: "text", text: row.error_text || "The desktop command failed." }], isError: true };
    }
    if (row?.status === "cancelled") {
      return { content: [{ type: "text", text: row.error_text || "The command was cancelled." }], isError: true };
    }
    if (row?.status === "expired") {
      return { content: [{ type: "text", text: "The command expired before completion." }], isError: true };
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  // Timed out waiting in this request, but keep command alive for agent to complete.
  // Agent will still poll/complete and store result; caller gets a pending response.
  await execute(
    "UPDATE commands SET updated_at=$1, expires_at=$2 WHERE command_id=$3 AND instance_id=$4 AND status IN ('queued','running')",
    [nowMs(), Math.max(expiresAt, nowMs() + COMMAND_TTL_MS), commandId, instanceId]
  );
  const pending = {
    ok: true,
    pending: true,
    command_id: commandId,
    tool_name: toolName,
    message: "Command accepted by cloud relay and may still be running on the desktop app. For long operations, use the tool's async/job status tools (e.g. get_job_status/get_export_status) if available."
  };
  return { content: [{ type: "text", text: JSON.stringify(pending) }], isError: false };
}

async function handleMcp(req, res, instanceId) {
  await ensureSchema();
  const resource = `${getBaseUrl(req)}/api/mcp/${instanceId}`;
  const suppliedToken = bearerToken(req);
  let instance = await authenticateInstance(req, instanceId, "mcp");
  if (!instance) instance = await oauthAccessInstance(suppliedToken, instanceId, resource);
  if (!instance) {
    const metadata = `${getBaseUrl(req)}/api/oauth/protected-resource?resource=${encodeURIComponent(resource)}`;
    return fail(res, 401, "UNAUTHORIZED", "Authentication required.", {
      "www-authenticate": `Bearer resource_metadata="${metadata}", scope="mcp:tools"`
    });
  }
  if (!(await checkRateLimit(`mcp:${instanceId}`, 180))) return fail(res, 429, "RATE_LIMITED", "MCP request limit exceeded.");

  if (req.method === "GET") {
    // Streamable HTTP: if no SSE stream is offered, return 405
    res.writeHead(405, { ...JSON_HEADERS, "allow": "POST, OPTIONS" });
    return res.end();
  }
  if (req.method !== "POST") {
    res.setHeader("allow", "POST, OPTIONS");
    return fail(res, 405, "METHOD_NOT_ALLOWED", "Use POST for Streamable HTTP JSON-RPC requests.");
  }

  const body = await readBody(req);
  if (!body || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return send(res, 400, { jsonrpc: "2.0", id: body?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } });
  }
  const id = Object.prototype.hasOwnProperty.call(body, "id") ? body.id : null;
  const isNotification = !Object.prototype.hasOwnProperty.call(body, "id");
  const protocol = req.headers["mcp-protocol-version"] || body.params?.protocolVersion || "2025-03-26";
  const extra = { "mcp-protocol-version": String(protocol) };

  if (body.method.startsWith("notifications/") || isNotification) {
    return send(res, 202, null, extra);
  }
  if (body.method === "initialize") {
    const requested = body.params?.protocolVersion;
    const supported = ["2025-11-25", "2025-06-18", "2025-03-26"];
    const pv = supported.includes(requested) ? requested : "2025-03-26";
    return send(res, 200, {
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: pv,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "Vortex Cloud MCP", version: "0.3.0" },
        instructions: "This endpoint securely relays approved VortexEditPro tools to the user's connected desktop application. Tool execution happens locally on that desktop. For long operations, prefer async tools that return job/status IDs."
      }
    }, extra);
  }
  if (body.method === "ping") return send(res, 200, { jsonrpc: "2.0", id, result: {} }, extra);
  if (body.method === "tools/list") {
    const tools = normalizeTools(parseJson(instance.tools_json, []));
    return send(res, 200, { jsonrpc: "2.0", id, result: { tools } }, extra);
  }
  if (body.method === "tools/call") {
    const name = body.params?.name;
    const args = body.params?.arguments ?? {};
    if (!isSafeToolName(name)) {
      return send(res, 200, { jsonrpc: "2.0", id, error: { code: -32602, message: "Invalid tool name." } }, extra);
    }
    const tools = normalizeTools(parseJson(instance.tools_json, []));
    if (!tools.some((tool) => tool.name === name)) {
      return send(res, 200, { jsonrpc: "2.0", id, error: { code: -32602, message: "Tool is not advertised by the connected desktop application." } }, extra);
    }
    const staleAfter = DEFAULT_STALE_SECONDS * 1000;
    if (!instance.last_seen || Date.now() - Number(instance.last_seen) > staleAfter) {
      return send(res, 200, {
        jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: "VortexEditPro is currently offline or not connected. Open the desktop app and connect it to Vortex Cloud MCP, then retry." }], isError: true }
      }, extra);
    }
    const result = await queueAndWait(instanceId, name, args);
    return send(res, 200, { jsonrpc: "2.0", id, result }, extra);
  }
  return send(res, 200, { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found." } }, extra);
}

export default async function handler(req, res) {
  if (req.method === "OPTIONS") return send(res, 204, null);
  const parts = routePath(req);
  try {
    if (await handleOAuthRoute(req, res, parts)) return;
    if (parts.length === 0) {
      if (req.method !== "GET") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use GET.");
      return send(res, 200, {
        service: "Vortex Cloud MCP",
        status: "running",
        endpoints: {
          health: "/api/health",
          readiness: "/api/ready",
          enrollment: "/api/agent/register",
          admin_instances: "/api/admin/instances",
          admin_enrollments: "/api/admin/enrollments",
          mcp: "/api/mcp/:instanceId"
        }
      });
    }
    if (parts.length === 1 && parts[0] === "health") {
      if (req.method !== "GET") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use GET.");
      return await health(res);
    }
    if (parts.length === 1 && parts[0] === "ready") {
      if (req.method !== "GET") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use GET.");
      return await readiness(res);
    }
    if (parts.length === 2 && parts[0] === "admin" && parts[1] === "instances") {
      if (req.method !== "POST") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use POST.");
      return await registerInstanceAdmin(req, res);
    }
    if (parts.length === 2 && parts[0] === "admin" && parts[1] === "enrollments") {
      if (req.method !== "POST") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use POST.");
      return await createEnrollment(req, res);
    }
    if (parts.length === 2 && parts[0] === "agent" && parts[1] === "register") {
      if (req.method !== "POST") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use POST.");
      return await registerWithEnrollment(req, res);
    }
    if (parts.length === 3 && parts[0] === "agent") {
      const instanceId = parts[1];
      if (parts[2] === "heartbeat" && req.method === "POST") return await heartbeat(req, res, instanceId);
      if (parts[2] === "poll" && req.method === "POST") return await pollCommands(req, res, instanceId);
      if (parts[2] === "result" && req.method === "POST") return await postResult(req, res, instanceId);
      if (parts[2] === "info" && req.method === "GET") return await instanceInfo(req, res, instanceId);
    }
    if (parts.length === 4 && parts[0] === "agent" && parts[2] === "mcp-token") {
      const instanceId = parts[1];
      if (parts[3] === "rotate" && req.method === "POST") return await rotateMcpToken(req, res, instanceId);
      if (parts[3] === "revoke" && req.method === "POST") return await revokeMcpToken(req, res, instanceId);
    }
    if (parts.length === 2 && parts[0] === "mcp") return await handleMcp(req, res, parts[1]);

    return fail(res, 404, "NOT_FOUND", "Route not found.");
  } catch (error) {
    const status = error?.status || (error?.code === "DATABASE_NOT_CONFIGURED" ? 503 : 500);
    const code = error?.code === "DATABASE_NOT_CONFIGURED" ? "DATABASE_NOT_CONFIGURED" : "INTERNAL_ERROR";
    const message = status === 500 ? "The server could not complete the request." : (error.message || "Request failed.");
    return fail(res, status, code, message);
  }
}
