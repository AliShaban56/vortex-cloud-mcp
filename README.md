# Vortex Cloud MCP

Central HTTPS relay for VortexEditPro desktop instances. ChatGPT connects to a per-instance MCP URL; commands are queued in Turso libSQL and executed by the user's own running desktop application. The Vercel service never receives project media or runs editing commands itself.

## Architecture
- **Vercel (Node.js function):** public HTTPS API and stateless MCP Streamable HTTP JSON-RPC endpoint.
- **Turso libSQL:** durable instance registry, enrollment tokens, hashed credentials, tool catalog, command queue, and rate-limit counters.
- **VortexEditPro desktop (Vortex Cloud Agent):** outbound HTTPS registration (via enrollment token), heartbeat/poll/result; no inbound port forwarding or tunnel-client required.
- **Per-instance credentials:** separate `device_token` (desktop agent) and `mcp_token` (ChatGPT/MCP client). Raw tokens are returned only once (at registration/rotation).

## Routes
- `GET /` — service information.
- `GET /api/health` — liveness (API running; reports database state separately).
- `GET /api/ready` — readiness (200 only when Turso schema is available).
- `POST /api/admin/instances` — create an instance directly (admin bearer `VORTEX_ADMIN_SECRET`).
- `POST /api/admin/enrollments` — create a one-time enrollment token (admin bearer). **Use this so the desktop app never needs the admin secret.**
- `POST /api/agent/register` — register a desktop instance using `enrollment_token` (no admin secret).
- `GET /api/agent/:instanceId/info` — instance info (device bearer).
- `POST /api/agent/:instanceId/heartbeat` — device presence and tool catalog (device bearer).
- `POST /api/agent/:instanceId/poll` — claim queued commands (device bearer).
- `POST /api/agent/:instanceId/result` — return command result (device bearer).
- `POST /api/agent/:instanceId/mcp-token/rotate` — rotate MCP token (device bearer; invalidates previous token).
- `POST /api/agent/:instanceId/mcp-token/revoke` — revoke MCP token (device bearer).
- `GET|POST /api/mcp/:instanceId` — MCP Streamable HTTP JSON-RPC endpoint (MCP bearer). GET returns 405 (no SSE stream). POST supports `initialize`, `notifications/*`, `ping`, `tools/list`, `tools/call`.

## Environment variables (Vercel)
- `TURSO_DATABASE_URL` (required)
- `TURSO_AUTH_TOKEN` (required)
- `VORTEX_ADMIN_SECRET` (required for admin endpoints; keep secret, never in desktop app/Git)
- Optional: `VORTEX_DEVICE_STALE_SECONDS`, `VORTEX_MCP_WAIT_MS`, `VORTEX_COMMAND_TTL_MS`, `VORTEX_STALE_RUNNING_MS`

## Secure provisioning flow (recommended)
1. Deploy to Vercel and configure Turso env vars. Verify `GET /api/health` and `GET /api/ready`.
2. **Admin** creates an enrollment token (server-side, using admin secret):
   ```bash
   curl -X POST "https://YOUR_HOST/api/admin/enrollments" \
     -H "Authorization: Bearer $VORTEX_ADMIN_SECRET" \
     -H "Content-Type: application/json" \
     -d '{"name":"My PC","ttl_seconds":86400}'
   ```
3. In VortexEditPro, open **ChatGPT Cloud Connection** and enter the server base URL + enrollment token to register. The app receives and stores `instance_id`, `device_token`, and `mcp_token` locally (tokens shown once by server).
4. Copy the per-instance **MCP URL** into ChatGPT's custom connector and select **OAuth**. The server publishes MCP Protected Resource Metadata and OAuth Authorization Server Metadata, supports Dynamic Client Registration, Authorization Code + PKCE (S256), short-lived access tokens, and rotating refresh tokens.
5. During the OAuth approval page, enter the existing per-instance MCP access token saved by VortexEditPro. It is exchanged for a client-bound OAuth grant; it is not sent to ChatGPT. If the desktop app does not provide a way to view/copy its saved MCP token, add that UI before enabling OAuth for end users.
6. Keep VortexEditPro running and connected; tool execution happens locally on the user's machine.

## MCP notes
- `tools/list` exposes only tools advertised by the connected desktop instance.
- `tools/call` queues a command for the desktop agent. The server waits briefly for completion; if the command takes longer, it returns a pending response containing `command_id` (command remains active for the agent to complete). Long-running operations should be implemented as async tools that return job/status IDs (e.g. export/import jobs) and polled via status tools.
- Command results are stored in Turso; stale running commands may be re-queued for delivery (agents should be idempotent where possible).

## Security
- TLS/HTTPS for external access (Vercel).
- Separate per-instance device and MCP credentials; secrets stored as SHA-256 hashes server-side.
- Admin secret never embedded in desktop apps; use enrollment tokens for user/device registration.
- Request/rate/size limits and input validation; tool allowlist based on advertised desktop tools.
- No media files or Turso credentials sent to desktop clients.

## Deployment (vortex-cloud-mcp project)
- Push to the `vortex-cloud-mcp` repository and deploy to the corresponding Vercel project.
- Do not modify unrelated Vercel projects or existing Turso secrets/data.


## OAuth support
- `/.well-known/oauth-protected-resource/api/mcp/:instanceId` — per-instance RFC 9728 resource metadata.
- `/.well-known/oauth-authorization-server` — RFC 8414 authorization server metadata.
- `POST /api/oauth/register` — public-client registration (no client secret).
- `GET|POST /api/oauth/authorize` — user approval using the existing instance MCP token.
- `POST /api/oauth/token` — Authorization Code + PKCE S256 and rotating refresh-token exchange.
- OAuth access tokens are audience-bound to one instance MCP URL and one registered client. Rotating or revoking the instance MCP token revokes all OAuth grants for that instance.
- The authorization page requires the MCP token already stored by the desktop app. Do not paste it into ChatGPT or share it in support chats.
