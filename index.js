// index.js
import { getUserContext } from "./auth";
import { resolveOrgForUser } from "./org-resolver";
import { json } from "./responses";
import { listWebexOrgs, webexFetchJson } from "./webex";

console.log("US Signal Webex Worker deployed");

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Enforce Cloudflare Access (your existing pattern)
      const accessJwt = request.headers.get("cf-access-jwt-assertion");
      if (!accessJwt) {
        return json({ error: "Unauthorized" }, 401);
      }

      const user = await getUserContext(accessJwt);

      // Health / identity
      if (path === "/api/me") {
        return json({ email: user.email, role: user.role }, 200);
      }

      // Resolve org for user (will be null until you populate ORG mapping logic)
      if (path === "/api/org") {
        const org = await resolveOrgForUser(env, user);
        return json({ email: user.email, role: user.role, org: org || null }, 200);
      }

      // Debug: raw orgs from Webex
      if (path === "/api/debug/orgs") {
        const orgs = await listWebexOrgs(env);
        return json({ ok: true, orgs }, 200);
      }

      // Example: passthrough test (if you want it)
      if (path === "/api/debug/me-webex") {
        const me = await webexFetchJson(env, "/people/me");
        return json({ ok: true, me }, 200);
      }

      return json({ error: "Not Found" }, 404);
    } catch (e) {
      return json(
        {
          ok: false,
          error: e?.message || String(e)
        },
        500
      );
    }
  }
};
