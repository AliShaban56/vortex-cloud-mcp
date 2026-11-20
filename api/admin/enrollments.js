// Explicit admin enrollment route for Vercel's filesystem router.
// Delegate to the shared API handler so authentication, validation,
// token creation and database behavior remain implemented in one place.
import handler from "../[...route].js";

export default async function adminEnrollmentsHandler(req, res) {
  return handler(req, res);
}
