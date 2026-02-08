import { json } from "./responses";
import { getUserContext } from "./auth";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      /* ===============================
         Silence favicon (noise only)
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
         /api/me  (KNOWN WORKING)
      =============================== */
      if (path === "/api/me") {
        return json({
          email: user.email,
          role: user.role,
        });
      }

      /* =====================================================
         /api/admin/seed-pins
         Admin-only
         Writes a test PIN to ORG_MAP_KV
      ===================================================== */
      if (path === "/api/admin/seed-pins") {
        if (user.role !== "admin") {
          return json({ error: "admin_only" }, 403);
        }

        if (!env.ORG_MAP_KV) {
          return json({
            error: "kv_not_bound",
            message: "ORG_MAP_KV is not available in this worker",
          }, 500);
        }

        // WRITE
        await env.ORG_MAP_KV.put(
          "pin:39571",
          JSON.stringify({
            orgId: "city-of-norwalk-iowa",
            orgName: "City of Norwalk, Iowa",
          })
        );

        // READ BACK
        const verify = await env.ORG_MAP_KV.get("pin:39571", {
          type: "json",
        });

        return json({
          status: "seed_complete",
          pin: "39571",
          verify,
        });
      }

      /* =====================================================
         /api/pin/verify
         POST { pin: "39571" }
         Mirrors /api/org behavior
      ===================================================== */
      if (path === "/api/pin/verify" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const pin = String(body.pin || "").trim();

        if (!/^\d{5}$/.test(pin)) {
          return json({ error: "invalid_pin_format" }, 400);
        }

        if (!env.ORG_MAP_KV) {
          return json({
            error: "kv_not_bound",
            message: "ORG_MAP_KV is not available in this worker",
          }, 500);
        }

        const org = await env.ORG_MAP_KV.get(`pin:${pin}`, {
          type: "json",
        });

        if (!org) {
          return json({ error: "invalid_pin" }, 403);
        }

        return json({
          status: "pin_verified",
          email: user.email,
          orgId: org.orgId,
          orgName: org.orgName,
        });
      }

      /* ===============================
         Fallthrough
      =============================== */
      return json(
        {
          error: "not_found",
          path,
        },
        404
      );

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
