// Explicit MCP instance route for Vercel's filesystem router.
// Delegate to the shared API handler so authentication, validation,
// queueing and JSON-RPC behavior remain implemented in one place.
import handler from "../[...route].js";

export default async function mcpInstanceHandler(req, res) {
  return handler(req, res);
}
