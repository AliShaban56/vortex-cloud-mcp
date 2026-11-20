# Vortex Cloud MCP

Central HTTPS relay for VortexEditPro desktop instances. ChatGPT connects to a per-instance MCP URL; commands are queued in Turso libSQL and executed by the user's own running desktop application. The Vercel service never receives project media or runs editing commands itself.

## Architecture
- Vercel Node.js Function: public HTTPS API and stateless MCP Streamable HTTP JSON-RPC endpoint.
- Turso libSQL: durable instance registry, hashed credentials, tool catalog, command queue, and rate-limit counters.
- VortexEditPro desktop: outbound HTTPS heartbeat/poll/result requests; no inbound port forwarding or tunnel-client required.
- Per-instance credentials: separate device token and MCP bearer token. Raw tokens are returned only once at registration.

## Routes
- `GET /` — basic service information (no database dependency).
- `GET /api/health` — liveness; returns HTTP 200 while the API is running and reports database state separately.
- `GET /api/ready` — readiness; returns HTTP 200 only when Turso libSQL and the required schema are available, otherwise HTTP 503.
- `POST /api/admin/instances` — create an instance (admin bearer required).
- `POST /api/agent/:instanceId/heartbeat` — device presence and tool catalog.
- `POST /api/agent/:instanceId/poll` — claim queued commands.
- `POST /api/agent/:instanceId/result` — return command result.
- `POST /api/mcp/:instanceId` — MCP JSON-RPC endpoint (MCP bearer required).

## Database setup
Set `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` in Vercel using the values from your Turso database. The app creates the required tables automatically on first use.

Set `VORTEX_ADMIN_SECRET` as a sensitive Vercel environment variable. Never commit it.

## Provisioning
1. Deploy and verify `GET /` and `GET /api/health` report the API is running. Then verify `GET /api/ready` reports `database: connected` before provisioning instances.
2. Create a desktop instance with an administrator bearer token:
```bash
curl -X POST "https://YOUR_HOST/api/admin/instances" \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name":"VortexEditPro on my PC"}'
```
3. Save the returned `device_token`, `mcp_token`, `instance_id`, and `mcp_url` securely. Tokens are displayed once.
4. Configure the desktop app with the HTTPS base URL, instance ID, and device token. Add the per-instance MCP URL to ChatGPT with the MCP token as a bearer credential.

## Security
- Never commit admin, device, or MCP tokens.
- Only tools advertised by the connected desktop are callable.
- Device and MCP tokens are stored as SHA-256 hashes.
- Turso credentials remain server-side in Vercel environment variables; never expose the auth token to desktop clients.
- Request payloads and command results are size-limited.
- All editing operations remain local to the user's desktop.

## Current limitations
This is the cloud relay foundation. The matching VortexEditPro desktop agent still needs to be implemented and integrated with the existing command/tool registry. Long-running exports should use a job-start/status pattern rather than hold an MCP request open.
