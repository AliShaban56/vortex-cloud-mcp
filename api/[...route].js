import { randomUUID } from "node:crypto";
import {
  bearerToken, hashSecret, isSafeToolName, jsonSchemaOrEmpty,
  newId, newSecret, safeEqual
} from "../lib/security.js";
import { checkRateLimit, ensureSchema, execute, queryOne } from "../lib/store.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, accept, mcp-protocol-version"
};

function send(res, status, body, extra = {}) {
  res.writeHead(status, { ...JSON_HEADERS, ...extra });
  res.end(body === null ? "" : JSON.stringify(body));
}
function fail(res, status, code, message) {
  return send(res, status, { error: { code, message } });
}
function routePath(req) {
  const raw = new URL(req.url, "https://vortex.invalid").pathname;
  return raw.replace(/^\/api\/?/, "").split("/").filter(Boolean);
}
function readBody(req) {
  if (Number(req.headers["content-length"] || 0) > 256 * 1024) {
    const error = new Error("Request body is too large.");
    error.status = 413;
    throw error;
  }
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return JSON.parse(req.body || "{}");
  return {};
}
async function authenticateInstance(req, instanceId, tokenColumn) {
  const token = bearerToken(req);
  if (!token || !instanceId) return null;
  const row = await queryOne(
    `SELECT instance_id, display_name, device_token_hash, mcp_token_hash,
            status, app_version, tools_json, last_seen
       FROM instances WHERE instance_id = $1`,
    [instanceId]
  );
  if (!row) return null;
  const expected = tokenColumn === "device" ? row.device_token_hash : row.mcp_token_hash;
  return safeEqual(hashSecret(token), expected) ? row : null;
}
function parseJson(value, fallback) {
  if (typeof value !== "string") return value ?? fallback;
  try { return JSON.parse(value); } catch { return fallback; }
}
function normalizeTools(tools) {
  if (!Array.isArray(tools)) return [];
  return tools.slice(0, 80).filter((tool) =>
    tool && isSafeToolName(tool.name) &&
    typeof tool.description === "string" &&
    tool.description.length <= 2_000
  ).map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: jsonSchemaOrEmpty(tool.inputSchema)
  }));
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
    "ERR_TLS_CERT_ALTNAME_INVALID"
  ]);

  if (code === "28P01" || code === "28000" || message.includes("password authentication failed")) {
    return { category: "AUTHENTICATION_FAILED", code: knownCodes.has(code) ? code : null };
  }
  if (message.includes("client password must be a string") || message.includes("password must be a string")) {
    return { category: "DATABASE_PASSWORD_MISSING", code: null };
  }
  if ((message.includes("tenant/user") || message.includes("tenant or user")) &&
      message.includes("not found")) {
    return { category: "POOLER_TENANT_OR_USERNAME_NOT_FOUND", code: knownCodes.has(code) ? code : null };
  }
  if (message.includes("invalid user")) {
    return { category: "POOLER_USERNAME_INVALID", code: knownCodes.has(code) ? code : null };
  }
  if (code === "3D000") return { category: "DATABASE_NAME_INVALID", code };
  if (code === "53300" || message.includes("too many clients") || message.includes("too many connections")) {
    return { category: "CONNECTION_LIMIT_REACHED", code: knownCodes.has(code) ? code : null };
  }
  if (code === "42501") return { category: "DATABASE_PERMISSION_DENIED", code };
  if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "EAI_AGAIN" ||
      code === "EHOSTUNREACH" || message.includes("getaddrinfo")) {
    return { category: "HOST_OR_NETWORK_UNREACHABLE", code: knownCodes.has(code) ? code : null };
  }
  if (code === "ETIMEDOUT" || message.includes("timeout") || message.includes("timed out")) {
    return { category: "CONNECTION_TIMEOUT", code: knownCodes.has(code) ? code : null };
  }
  if (code.startsWith("ERR_TLS") || code.startsWith("ERR_SSL") ||
      code === "SELF_SIGNED_CERT_IN_CHAIN" || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") {
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

// Liveness: confirms the Vercel function is running, regardless of database state.
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

// Readiness: used by deploy monitors that require both API and database availability.
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
async function registerInstance(req, res) {
  if (!process.env.VORTEX_ADMIN_SECRET) return fail(res, 503, "ADMIN_NOT_CONFIGURED", "The server administrator secret is not configured.");
  if (!safeEqual(bearerToken(req), process.env.VORTEX_ADMIN_SECRET)) return fail(res, 401, "UNAUTHORIZED", "Administrator authentication failed.");
  await ensureSchema();
  const body = readBody(req);
  const displayName = typeof body.name === "string" ? body.name.trim().slice(0, 80) : "VortexEditPro";
  const instanceId = newId();
  const deviceToken = newSecret("vxd_");
  const mcpToken = newSecret("vxm_");
  const now = Date.now();
  await execute(
    `INSERT INTO instances
      (instance_id, display_name, device_token_hash, mcp_token_hash, status, tools_json, created_at)
     VALUES ($1, $2, $3, $4, 'offline', '[]', $5)`,
    [instanceId, displayName || "VortexEditPro", hashSecret(deviceToken), hashSecret(mcpToken), now]
  );
  return send(res, 201, {
    instance_id: instanceId, name: displayName || "VortexEditPro",
    device_token: deviceToken, mcp_token: mcpToken,
    mcp_url: `/api/mcp/${instanceId}`,
    warning: "Save both tokens now. They are shown only once and cannot be recovered."
  });
}
async function heartbeat(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  if (!(await checkRateLimit(`hb:${instanceId}`, 90))) return fail(res, 429, "RATE_LIMITED", "Too many heartbeat requests.");
  const body = readBody(req);
  const tools = normalizeTools(body.tools);
  await execute(
    "UPDATE instances SET status='online', last_seen=$1, app_version=$2, tools_json=$3 WHERE instance_id=$4",
    [Date.now(), String(body.app_version || "").slice(0, 40), JSON.stringify(tools), instanceId]
  );
  return send(res, 200, { ok: true, server_time: Date.now(), accepted_tools: tools.length });
}
async function pollCommands(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  if (!(await checkRateLimit(`poll:${instanceId}`, 180))) return fail(res, 429, "RATE_LIMITED", "Too many polling requests.");
  const now = Date.now();
  const result = await execute(
    `UPDATE commands SET status='running', updated_at=$1
      WHERE command_id IN (
        SELECT command_id FROM commands
         WHERE instance_id=$2 AND status='queued' AND expires_at>$1
         ORDER BY created_at LIMIT 5
      ) AND status='queued'
      RETURNING command_id, tool_name, arguments_json, created_at`,
    [now, instanceId]
  )
  const commands = result.rows.map((row) => ({
    command_id: row.command_id, tool_name: row.tool_name,
    arguments: parseJson(row.arguments_json, {}), created_at: Number(row.created_at)
  }));
  await execute(
    "UPDATE commands SET status='expired', updated_at=$1 WHERE instance_id=$2 AND status='queued' AND expires_at<=$1",
    [now, instanceId]
  );
  return send(res, 200, { commands, server_time: now });
}
async function postResult(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "device");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid device credentials.");
  const body = readBody(req);
  if (typeof body.command_id !== "string") return fail(res, 400, "INVALID_REQUEST", "command_id is required.");
  const resultJson = JSON.stringify(body.result ?? null);
  if (resultJson.length > 128 * 1024) return fail(res, 413, "RESULT_TOO_LARGE", "Command result is too large.");
  const result = await execute(
    `UPDATE commands SET status=$1, result_json=$2, error_text=$3, updated_at=$4
      WHERE command_id=$5 AND instance_id=$6 AND status='running'`,
    [body.error ? "failed" : "completed", body.error ? null : resultJson,
     body.error ? String(body.error).slice(0, 2_000) : null, Date.now(), body.command_id, instanceId]
  );
  if (!result.rowCount) return fail(res, 404, "COMMAND_NOT_FOUND", "Command was not found or is no longer active.");
  return send(res, 200, { ok: true });
}
async function queueAndWait(instanceId, toolName, args) {
  const commandId = randomUUID();
  const now = Date.now();
  const waitMs = Math.min(Math.max(Number(process.env.VORTEX_MCP_WAIT_MS || 7000), 1000), 7500);
  await execute(
    `INSERT INTO commands
      (command_id, instance_id, tool_name, arguments_json, status, created_at, updated_at, expires_at)
     VALUES ($1, $2, $3, $4, 'queued', $5, $5, $6)`,
    [commandId, instanceId, toolName, JSON.stringify(args ?? {}), now, now + waitMs + 10_000]
  );
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    const row = await queryOne(
      "SELECT status, result_json, error_text FROM commands WHERE command_id=$1 AND instance_id=$2",
      [commandId, instanceId]
    );
    if (row?.status === "completed") {
      return { content: [{ type: "text", text: JSON.stringify(parseJson(row.result_json, null)) }], isError: false };
    }
    if (row?.status === "failed") return { content: [{ type: "text", text: row.error_text || "The desktop command failed." }], isError: true };
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  await execute(
    "UPDATE commands SET status='expired', updated_at=$1 WHERE command_id=$2 AND status IN ('queued','running')",
    [Date.now(), commandId]
  );
  return { content: [{ type: "text", text: "The connected VortexEditPro device did not respond in time. Check that the desktop app is running and connected, then retry." }], isError: true };
}
async function handleMcp(req, res, instanceId) {
  await ensureSchema();
  const instance = await authenticateInstance(req, instanceId, "mcp");
  if (!instance) return fail(res, 401, "UNAUTHORIZED", "Invalid MCP access token.");
  if (!(await checkRateLimit(`mcp:${instanceId}`, 120))) return fail(res, 429, "RATE_LIMITED", "MCP request limit exceeded.");
  if (req.method !== "POST") {
    res.setHeader("allow", "POST, OPTIONS");
    return fail(res, 405, "METHOD_NOT_ALLOWED", "Use POST for Streamable HTTP JSON-RPC requests.");
  }
  const body = readBody(req);
  if (!body || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return send(res, 400, { jsonrpc: "2.0", id: body?.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } });
  }
  const id = body.id ?? null;
  const protocol = req.headers["mcp-protocol-version"] || "2025-03-26";
  const extra = { "mcp-protocol-version": protocol };
  if (body.method.startsWith("notifications/")) return send(res, 202, null, extra);
  if (body.method === "initialize") {
    return send(res, 200, {
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: ["2025-06-18", "2025-03-26"].includes(body.params?.protocolVersion) ? body.params.protocolVersion : "2025-03-26",
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "Vortex Cloud MCP", version: "0.2.0" },
        instructions: "This endpoint securely relays approved VortexEditPro tools to the user's connected desktop application. Tool execution happens on that desktop."
      }
    }, extra);
  }
  if (body.method === "ping") return send(res, 200, { jsonrpc: "2.0", id, result: {} }, extra);
  if (body.method === "tools/list") {
    return send(res, 200, { jsonrpc: "2.0", id, result: { tools: normalizeTools(parseJson(instance.tools_json, [])) } }, extra);
  }
  if (body.method === "tools/call") {
    const name = body.params?.name;
    const args = body.params?.arguments ?? {};
    if (!isSafeToolName(name)) return send(res, 200, { jsonrpc: "2.0", id, error: { code: -32602, message: "Invalid tool name." } }, extra);
    const tools = normalizeTools(parseJson(instance.tools_json, []));
    if (!tools.some((tool) => tool.name === name)) return send(res, 200, { jsonrpc: "2.0", id, error: { code: -32602, message: "Tool is not advertised by the connected desktop application." } }, extra);
    const staleAfter = Number(process.env.VORTEX_DEVICE_STALE_SECONDS || 45) * 1000;
    if (!instance.last_seen || Date.now() - Number(instance.last_seen) > staleAfter) {
      return send(res, 200, { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "VortexEditPro is currently offline. Open the desktop app and connect it to Vortex Cloud MCP." }], isError: true } }, extra);
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
    if (parts.length === 0) {
      if (req.method !== "GET") return fail(res, 405, "METHOD_NOT_ALLOWED", "Use GET.");
      return send(res, 200, {
        service: "Vortex Cloud MCP",
        status: "running",
        endpoints: { health: "/api/health", readiness: "/api/ready" }
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
      return await registerInstance(req, res);
    }
    if (parts.length === 3 && parts[0] === "agent") {
      const instanceId = parts[1];
      if (parts[2] === "heartbeat" && req.method === "POST") return await heartbeat(req, res, instanceId);
      if (parts[2] === "poll" && req.method === "POST") return await pollCommands(req, res, instanceId);
      if (parts[2] === "result" && req.method === "POST") return await postResult(req, res, instanceId);
    }
    if (parts.length === 2 && parts[0] === "mcp") return await handleMcp(req, res, parts[1]);
    return fail(res, 404, "NOT_FOUND", "Route not found.");
  } catch (error) {
    const status = error?.status || (error?.code === "DATABASE_NOT_CONFIGURED" ? 503 : 500);
    const code = error?.code === "DATABASE_NOT_CONFIGURED" ? "DATABASE_NOT_CONFIGURED" : "INTERNAL_ERROR";
    return fail(res, status, code, status === 500 ? "The server could not complete the request." : error.message);
  }
}
