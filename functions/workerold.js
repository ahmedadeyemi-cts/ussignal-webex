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
        return json({ error: "unauthorized" }, 401);
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
         ADMIN ONLY – WORKER OWNED
      =============================== */
      if (path === "/api/admin/seed-pins") {
        if (user.role !== "admin") {
          return json({ error: "admin_only" }, 403);
        }

        // 🔐 Seed ONE known-good PIN
        const pinKey = "pin:39571";

        await env.ORG_MAP_KV.put(
          pinKey,
          JSON.stringify({
            orgId: "city-of-norwalk-iowa",
            orgName: "City of Norwalk, Iowa",
            role: "customer",
            createdAt: Date.now(),
          })
        );

        const verify = await env.ORG_MAP_KV.get(pinKey, { type: "json" });

        return json({
          status: "seed_complete",
          key: pinKey,
          verify,
        });
      }

      /* ===============================
         /api/pin/verify
         POST { pin: "39571" }
      =============================== */
      if (path === "/api/pin/verify" && request.method === "POST") {
        const body = await request.json();
        const pin = String(body.pin || "").trim();

        if (!/^\d{5}$/.test(pin)) {
          return json({ error: "invalid_pin_format" }, 400);
        }

        const pinKey = `pin:${pin}`;
        const pinData = await env.ORG_MAP_KV.get(pinKey, { type: "json" });

        if (!pinData) {
          return json({ error: "invalid_pin" }, 403);
        }

        const session = {
          email: user.email,
          role: pinData.role || "customer",
          orgId: pinData.orgId,
          orgName: pinData.orgName,
          issuedAt: Date.now(),
        };

        await env.USER_SESSION_KV.put(
          user.email,
          JSON.stringify(session),
          { expirationTtl: 3600 } // 1 hour session
        );

        return json({
          status: "verified",
          org: pinData.orgName,
        });
      }

      /* ===============================
         /api/session
         Returns active PIN session
      =============================== */
      if (path === "/api/session") {
        const session = await env.USER_SESSION_KV.get(user.email, {
          type: "json",
        });

        if (!session) {
          return json({ active: false });
        }

        return json({
          active: true,
          session,
        });
      }

      /* ===============================
         Fallthrough
      =============================== */
      return json({ error: "not_found", path }, 404);

    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json(
        {
          error: "internal_error",
          message: err.message,
        },
        500
      );
    }
  },
};
