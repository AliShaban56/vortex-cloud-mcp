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
- `GET|POST /api/mcp/:instanceId` — MCP Streamable HTTP JSON-RPC endpoint (MCP bearer or OAuth bearer bound to this instance/resource). GET returns 405 (no SSE stream). POST supports `initialize`, `notifications/*`, `ping`, `tools/list`, `tools/call`.
- `GET|POST /api/oauth/register` — OAuth dynamic client registration (public clients).
- `GET|POST /api/oauth/authorize` — OAuth Authorization Code + PKCE (S256) start; creates a pending, device-approved consent request (no MCP token entry in browser).
- `GET /api/oauth/authorize/request/:requestId/status` / `POST /api/oauth/authorize/request/:requestId/complete` — pending consent status/completion.
- `POST /api/oauth/token` — token exchange/refresh (refresh rotation, resource-bound).
- `GET /api/agent/:instanceId/oauth/requests` — list pending OAuth consent requests for this instance (device bearer).
- `POST /api/agent/:instanceId/oauth/requests/:requestId` — approve/deny pending OAuth consent request (`{ "decision": "approve"|"deny" }`, device bearer).

## Environment variables (Vercel)
- `TURSO_DATABASE_URL` (required)
- `TURSO_AUTH_TOKEN` (required)
- `VORTEX_ADMIN_SECRET` (required for admin endpoints; keep secret, never in desktop app/Git)
- Optional: `VORTEX_DEVICE_STALE_SECONDS`, `VORTEX_MCP_WAIT_MS`, `VORTEX_COMMAND_TTL_MS`, `VORTEX_STALE_RUNNING_MS`

## Secure provisioning and ChatGPT OAuth flow (recommended)
1. Deploy to Vercel and configure Turso env vars. Verify `GET /api/health` and `GET /api/ready`.
2. **Admin** creates an enrollment token (server-side, using admin secret):
   ```bash
   curl -X POST "https://YOUR_HOST/api/admin/enrollments" \
     -H "Authorization: Bearer $VORTEX_ADMIN_SECRET" \
     -H "Content-Type: application/json" \
     -d '{"name":"My PC","ttl_seconds":86400}'
   ```
3. In VortexEditPro, open **ChatGPT Integration / Cloud connection** and register the instance using the server base URL + enrollment token. The app stores credentials locally (sensitive tokens in OS-protected secure storage, not in plain settings files).
4. In ChatGPT, add a custom MCP connector using the per-instance **MCP URL** and select **OAuth**. The server publishes MCP Protected Resource Metadata and OAuth Authorization Server Metadata, supports Dynamic Client Registration, Authorization Code + PKCE (S256), short-lived access tokens, and rotating refresh tokens.
5. When ChatGPT starts authorization, the browser shows a pending consent request. **No MCP token or OAuth token is entered in the browser or sent to ChatGPT.** VortexEditPro (authenticated with its device credentials) lists and approves/denies the pending request for that instance; once approved, the browser flow completes and issues an authorization code to the registered client redirect URI.
6. Keep VortexEditPro running and connected; tool execution happens locally on the user's machine via the existing heartbeat/poll/result relay. OAuth bearer tokens are instance/resource-bound and are revoked when the instance MCP token is rotated/revoked.

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
- `GET /api/oauth/protected-resource?resource=<encoded MCP URL>` — per-instance RFC 9728 resource metadata, advertised in the MCP 401 `WWW-Authenticate` challenge.
- `GET /.well-known/oauth-authorization-server` — RFC 8414 authorization server metadata.
- `POST /api/oauth/register` — dynamic client registration (public clients).
- `GET /api/oauth/authorize` — Authorization Code + PKCE (S256) request creates a **pending, device-approved** consent transaction (short-lived, single-use, instance/client/resource-bound). The browser does **not** collect or transmit the instance MCP token.
- `GET /api/agent/:instanceId/oauth/requests` and `POST /api/agent/:instanceId/oauth/requests/:requestId` — device-authenticated ownership proof and approve/deny of pending requests.
- `GET /api/oauth/authorize/request/:requestId/status` and `POST /api/oauth/authorize/request/:requestId/complete` — browser polling/completion after in-app approval; issues code only for approved, unexpired, unconsumed requests.
- `POST /api/oauth/token` — Authorization Code + PKCE S256 and rotating refresh-token exchange; refresh requires matching client/resource binding.
- OAuth access tokens are audience-bound to one instance MCP URL and one registered client. Rotating or revoking the instance MCP token revokes all OAuth grants for that instance.
