import { getUserContext } from "./auth";
import { resolveOrgForUser } from "./org-resolver";
import { json } from "./responses";

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      /* ===============================
         Silence favicon noise
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
          role: user.role
        });
      }

      /* ===============================
         ADMIN: seed PINs (TEST)
         GET /api/admin/seed-pins
      =============================== */
      if (path === "/api/admin/seed-pins") {
        if (user.role !== "admin") {
          return json({ error: "admin_only" }, 403);
        }

        // 🔑 write test PIN
        await env.ORG_MAP_KV.put(
          "pin:12345",
          JSON.stringify({
            orgId: "demo-org",
            orgName: "Demo Customer"
          })
        );

        return json({
          status: "ok",
          seeded: {
            pin: "12345",
            orgName: "Demo Customer"
          }
        });
      }

      /* ===============================
         PIN VERIFY
         POST /api/pin/verify
         body: { pin: "12345" }
      =============================== */
      if (path === "/api/pin/verify" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const pin = String(body.pin || "").trim();

        if (!/^\d{5}$/.test(pin)) {
          return json({ error: "invalid_pin_format" }, 400);
        }

        const record = await env.ORG_MAP_KV.get(`pin:${pin}`, {
          type: "json"
        });

        if (!record) {
          return json({ error: "invalid_pin" }, 403);
        }

        return json({
          status: "ok",
          orgId: record.orgId,
          orgName: record.orgName
        });
      }

      /* ===============================
         CUSTOMER SUMMARY
      =============================== */
      if (path === "/api/customer/summary") {
        const org = await resolveOrgForUser(user, env);
        return json({
          orgName: org.name,
          orgId: org.id
        });
      }

      /* ===============================
         FALLTHROUGH
      =============================== */
      return json({ error: "Not Found" }, 404);

    } catch (err) {
      console.error("Worker error:", err);
      return json({ error: err.message }, 500);
    }
  }
};
