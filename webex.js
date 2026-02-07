import { getUserContext } from "./auth";
import { listWebexOrgs } from "./webex";
import { json } from "./responses";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      const jwt = request.headers.get("cf-access-jwt-assertion");
      if (!jwt) return json({ error: "Unauthorized" }, 401);

      const user = await getUserContext(jwt);

      if (path === "/api/me") {
        return json(user);
      }

      if (path === "/api/org") {
        if (user.role === "admin") {
          const orgs = await listWebexOrgs(env);
          return json({
            email: user.email,
            role: user.role,
            orgs
          });
        }

        return json({
          email: user.email,
          role: user.role,
          org: null
        });
      }

      return json({ error: "Not Found" }, 404);

    } catch (err) {
      console.error(err);
      return json({ error: err.message }, 500);
    }
  }
};
