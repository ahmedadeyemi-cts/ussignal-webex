import { requireAuth, getUserContext } from "./auth";
import { resolveOrgForUser } from "./org-resolver";
import { json } from "./responses";
console.log("US Signal Webex Worker deployed");

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Enforce Cloudflare Access
      const accessJwt = request.headers.get("cf-access-jwt-assertion");
      if (!accessJwt) {
        return json({ error: "Unauthorized" }, 401);
      }

      const user = await getUserContext(accessJwt);

      // Health check
      if (path === "/api/me") {
        return json({
          email: user.email,
          role: user.role
        });
      }

      // Customer summary (role-aware)
      if (path === "/api/customer/summary") {
        const org = await resolveOrgForUser(user, env);
        return json({
          orgName: org.name,
          orgId: org.id
        });
      }

      return json({ error: "Not Found" }, 404);

    } catch (err) {
      console.error(err);
      return json({ error: err.message }, 500);
    }
  }
};
