import { createClient } from "@libsql/client";

let client;
let schemaReady;

export function getDb() {
  if (client) return client;
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;
  if (!url || !authToken) {
    const error = new Error("Database is not configured. Connect a Turso database to this Vercel project.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }
  client = createClient({ url, authToken });
  return client;
}

export async function ensureSchema() {
  if (schemaReady) return schemaReady;
  schemaReady = (async () => {
    const db = getDb();
    await db.batch([
      `CREATE TABLE IF NOT EXISTS instances (
        instance_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        device_token_hash TEXT NOT NULL,
        mcp_token_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'offline',
        app_version TEXT,
        tools_json TEXT NOT NULL DEFAULT '[]',
        last_seen INTEGER,
        created_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS commands (
        command_id TEXT PRIMARY KEY,
        instance_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        arguments_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        result_json TEXT,
        error_text TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(instance_id) REFERENCES instances(instance_id)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_commands_instance_status
        ON commands(instance_id, status, created_at)`,
      `CREATE TABLE IF NOT EXISTS rate_limits (
        bucket_key TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        request_count INTEGER NOT NULL
      )`
    ], "write");
  })().catch((error) => {
    schemaReady = undefined;
    throw error;
  });
  return schemaReady;
}

export async function queryOne(sql, args = []) {
  const result = await getDb().execute({ sql, args });
  return result.rows[0] || null;
}

export async function execute(sql, args = []) {
  return getDb().execute({ sql, args });
}

export async function checkRateLimit(key, limit, windowMs = 60_000) {
  const now = Date.now();
  const start = Math.floor(now / windowMs) * windowMs;
  const result = await queryOne(
    `INSERT INTO rate_limits(bucket_key, window_start, request_count)
     VALUES(?, ?, 1)
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
