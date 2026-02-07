import { getUserContext } from "./auth";
import { resolveOrgForUser } from "./org-resolver";
import { json } from "./responses";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const jwt = request.headers.get("cf-access-jwt-assertion");
    if (!jwt) return json({ error: "Unauthorized" }, 401);

    const user = await getUserContext(jwt);

    // Existing endpoint
    if (path === "/api/me") {
      return json(user);
    }

    // NEW endpoint
    if (path === "/api/org") {
      const org = await resolveOrgForUser(user, env);
      return json({ ...user, org });
    }

    return json({ error: "Not found" }, 404);
  }
};
