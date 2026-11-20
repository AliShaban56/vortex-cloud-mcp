import { createClient } from "@libsql/client";

let client;
let schemaReady;

export function getDb() {
  if (client) return client;
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;
  if (!url || !authToken) {
    const error = new Error("Database is not configured. Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN to the Vercel project environment.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }
  client = createClient({ url, authToken });
  return client;
}

function bind(sql, args = []) {
  const ordered = [];
  const statement = sql.replace(/\$(\d+)/g, (_match, index) => {
    ordered.push(args[Number(index) - 1]);
    return "?";
  });
  return { sql: statement, args: ordered };
}

export async function ensureSchema() {
  if (schemaReady) return schemaReady;
  schemaReady = (async () => {
    const db = getDb();
    await db.execute(`CREATE TABLE IF NOT EXISTS instances (
      instance_id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      device_token_hash TEXT NOT NULL,
      mcp_token_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'offline',
      app_version TEXT,
      tools_json TEXT NOT NULL DEFAULT '[]',
      last_seen INTEGER,
      created_at INTEGER NOT NULL
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS commands (
      command_id TEXT PRIMARY KEY,
      instance_id TEXT NOT NULL REFERENCES instances(instance_id) ON DELETE CASCADE,
      tool_name TEXT NOT NULL,
      arguments_json TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'queued',
      result_json TEXT,
      error_text TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`);
    await db.execute("CREATE INDEX IF NOT EXISTS idx_commands_instance_status ON commands(instance_id, status, created_at)");
    await db.execute(`CREATE TABLE IF NOT EXISTS rate_limits (
      bucket_key TEXT PRIMARY KEY,
      window_start INTEGER NOT NULL,
      request_count INTEGER NOT NULL
    )`);
  })().catch((error) => {
    schemaReady = undefined;
    throw error;
  });
  return schemaReady;
}

export async function queryOne(sql, args = []) {
  const result = await getDb().execute(bind(sql, args));
  return result.rows[0] || null;
}

export async function execute(sql, args = []) {
  const result = await getDb().execute(bind(sql, args));
  return { rows: Array.from(result.rows || []), rowCount: result.rowsAffected || 0 };
}

export async function checkRateLimit(key, limit, windowMs = 60_000) {
  const now = Date.now();
  const start = Math.floor(now / windowMs) * windowMs;
  const result = await queryOne(
    `INSERT INTO rate_limits(bucket_key, window_start, request_count)
     VALUES($1, $2, 1)
     ON CONFLICT(bucket_key) DO UPDATE SET
       request_count = CASE
         WHEN rate_limits.window_start = excluded.window_start
         THEN rate_limits.request_count + 1 ELSE 1 END,
       window_start = excluded.window_start
     RETURNING request_count`,
    [key, start]
  );
  return Number(result?.request_count || 0) <= limit;
}
