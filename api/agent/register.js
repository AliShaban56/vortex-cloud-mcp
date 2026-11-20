// Explicit desktop enrollment route for Vercel filesystem routing.
// Delegate to the shared API handler so token validation and registration
// behavior remain implemented in one place.
import handler from "../../[...route].js";

export default async function agentRegisterHandler(req, res) {
  return handler(req, res);
}
