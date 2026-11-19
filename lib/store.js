import pg from "pg";

const { Pool } = pg;
let pool;
let schemaReady;

export function getDb() {
  if (pool) return pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    const error = new Error("Database is not configured. Add DATABASE_URL to the Vercel project environment.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }
  pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 8_000,
    allowExitOnIdle: true
  });
  return pool;
}

export async function ensureSchema() {
  if (schemaReady) return schemaReady;
  schemaReady = (async () => {
    const db = getDb();
    await db.query(`CREATE TABLE IF NOT EXISTS public.instances (
      instance_id text PRIMARY KEY,
      display_name text NOT NULL,
      device_token_hash text NOT NULL,
      mcp_token_hash text NOT NULL,
      status text NOT NULL DEFAULT 'offline',
      app_version text,
      tools_json jsonb NOT NULL DEFAULT '[]'::jsonb,
      last_seen bigint,
      created_at bigint NOT NULL
    )`);
    await db.query(`CREATE TABLE IF NOT EXISTS public.commands (
      command_id text PRIMARY KEY,
      instance_id text NOT NULL REFERENCES public.instances(instance_id) ON DELETE CASCADE,
      tool_name text NOT NULL,
      arguments_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      status text NOT NULL DEFAULT 'queued',
      result_json jsonb,
      error_text text,
      created_at bigint NOT NULL,
      updated_at bigint NOT NULL,
      expires_at bigint NOT NULL
    )`);
    await db.query("CREATE INDEX IF NOT EXISTS idx_commands_instance_status ON public.commands(instance_id, status, created_at)");
    await db.query(`CREATE TABLE IF NOT EXISTS public.rate_limits (
      bucket_key text PRIMARY KEY,
      window_start bigint NOT NULL,
      request_count integer NOT NULL
    )`);
  })().catch((error) => {
    schemaReady = undefined;
    throw error;
  });
  return schemaReady;
}

export async function queryOne(sql, args = []) {
  const result = await getDb().query(sql, args);
  return result.rows[0] || null;
}

export async function execute(sql, args = []) {
  return getDb().query(sql, args);
}

export async function checkRateLimit(key, limit, windowMs = 60_000) {
  const now = Date.now();
  const start = Math.floor(now / windowMs) * windowMs;
  const result = await queryOne(
    `INSERT INTO public.rate_limits(bucket_key, window_start, request_count)
     VALUES($1, $2, 1)
     ON CONFLICT(bucket_key) DO UPDATE SET
       request_count = CASE
         WHEN public.rate_limits.window_start = EXCLUDED.window_start
         THEN public.rate_limits.request_count + 1 ELSE 1 END,
       window_start = EXCLUDED.window_start
     RETURNING request_count`,
    [key, start]
  );
  return Number(result?.request_count || 0) <= limit;
}
