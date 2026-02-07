/**
 * index.js
 * Main Cloudflare Worker entry point
 */

import { getUserContext } from "./auth";
import { listWebexOrgs } from "./webex";
import { json } from "./responses";

console.log("US Signal Webex Worker deployed");

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // --------------------------------------------------
      // Enforce Cloudflare Access
      // --------------------------------------------------
      const accessJwt = request.headers.get("cf-access-jwt-assertion");
      if (!accessJwt) {
        return json({ error: "Unauthorized" }, 401);
      }

      const user = await getUserContext(accessJwt);

      // --------------------------------------------------
      // Health / Identity
      // --------------------------------------------------
      if (path === "/api/me") {
        return json({
          email: user.email,
          role: user.role
        });
      }

      // --------------------------------------------------
      // Organization Resolution
      // --------------------------------------------------
      if (path === "/api/org") {
        // US Signal admins see all orgs
        if (user.role === "admin") {
          const orgs = await listWebexOrgs(env);

          return json({
            email: user.email,
            role: user.role,
            orgs
          });
        }

        // Customers resolved later (KV + fuzzy match)
        return json({
          email: user.email,
          role: user.role,
          org: null
        });
      }

      // --------------------------------------------------
      // Default
      // --------------------------------------------------
      return json({ error: "Not Found" }, 404);

    } catch (err) {
      console.error("Worker error:", err);
      return json(
        { error: err.message || "Internal Server Error" },
        500
      );
    }
  }
};
