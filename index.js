import { getUserContext } from "./auth";
import { listWebexOrgs } from "./webex";

/**
 * JSON helper
 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Enforce Cloudflare Access
      const jwt = request.headers.get("cf-access-jwt-assertion");
      if (!jwt) {
        return json({ error: "Unauthorized" }, 401);
      }

      const user = await getUserContext(jwt);

      // ---- ROUTES ----

      if (path === "/api/me") {
        return json(user);
      }

      if (path === "/api/org") {
        // Admin sees all orgs
        if (user.role === "admin") {
          const orgs = await listWebexOrgs(env);
          return json({
            email: user.email,
            role: user.role,
            orgs
          });
        }

        // Customer logic later
        return json({
          email: user.email,
          role: user.role,
          org: null
        });
      }

      return json({ error: "Not Found" }, 404);

    } catch (err) {
      return json(
        { error: err.message || "Internal error" },
        500
      );
    }
  }
};
