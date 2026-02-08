import { json } from "./responses";
import { getUserContext } from "./auth";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      /* ===============================
         Silence favicon
      =============================== */
      if (path === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      /* ===============================
         Enforce Cloudflare Access
      =============================== */
      const accessJwt = request.headers.get("cf-access-jwt-assertion");
      if (!accessJwt) {
        return json({ error: "Unauthorized" }, 401);
      }

      const user = await getUserContext(accessJwt);

      /* ===============================
         /api/me
      =============================== */
      if (path === "/api/me") {
        return json({
          email: user.email,
          role: user.role,
        });
      }

      /* ===============================
         /api/admin/seed-pins
         (WORKER-OWNED ROUTE)
      =============================== */
      if (path === "/api/admin/seed-pins") {
        if (user.role !== "admin") {
          return json({ error: "admin_only" }, 403);
        }

        await env.ORG_MAP_KV.put(
          "pin:39571",
          JSON.stringify({
            orgId: "city-of-norwalk-iowa",
            orgName: "City of Norwalk, Iowa",
          })
        );

        const verify = await env.ORG_MAP_KV.get("pin:39571", {
          type: "json",
        });

        return json({
          status: "seed_complete",
          verify,
        });
      }

      /* ===============================
         Fallthrough
      =============================== */
      return json({ error: "Not Found", path }, 404);

    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json(
        { error: "internal_error", message: err.message },
        500
      );
    }
  },
};
