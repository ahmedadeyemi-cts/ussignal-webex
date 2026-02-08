import { getUserContext } from "./auth";
import { resolveOrgForUser } from "./org-resolver";
import { json } from "./responses";

/**
 * REQUIRED KV BINDINGS
 * - ORG_MAP_KV
 * - USER_SESSION_KV
 */

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      /* =====================================================
         Cloudflare Access Enforcement
      ===================================================== */
      const accessJwt = request.headers.get("cf-access-jwt-assertion");
      if (!accessJwt) {
        return json({ error: "unauthorized" }, 401);
      }

      const user = await getUserContext(accessJwt);
      const email = user.email.toLowerCase();
      const isAdmin = user.role === "admin";

      /* =====================================================
         Helpers
      ===================================================== */
      const SESSION_TTL = 60 * 60; // 1 hour

      const sessKey = `sess:${email}`;
      const pinKey = (pin) => `pin:${pin}`;

      const getSession = async () =>
        env.USER_SESSION_KV.get(sessKey, { type: "json" });

      const setSession = async (session) =>
        env.USER_SESSION_KV.put(sessKey, JSON.stringify(session), {
          expirationTtl: SESSION_TTL
        });

      const clearSession = async () =>
        env.USER_SESSION_KV.delete(sessKey);

      /* =====================================================
         /api/me
      ===================================================== */
      if (path === "/api/me") {
        const session = await getSession();

        return json({
          email,
          role: user.role,
          orgId: session?.orgId || null,
          orgName: session?.orgName || null
        });
      }

      /* =====================================================
         /api/pin/verify
         POST { pin: "12345" }
      ===================================================== */
      if (path === "/api/pin/verify" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const pin = String(body.pin || "").trim();

        if (!/^\d{5}$/.test(pin)) {
          return json({ error: "invalid_pin_format" }, 400);
        }

        const mapping = await env.ORG_MAP_KV.get(pinKey(pin), {
          type: "json"
        });

        if (!mapping) {
          return json({ error: "invalid_pin" }, 403);
        }

        await setSession({
          email,
          orgId: mapping.orgId,
          orgName: mapping.orgName,
          issuedAt: Date.now()
        });

        return json({
          status: "ok",
          orgId: mapping.orgId,
          orgName: mapping.orgName
        });
      }

      /* =====================================================
         /api/pin/logout
      ===================================================== */
      if (path === "/api/pin/logout" && request.method === "POST") {
        await clearSession();
        return json({ status: "ok" });
      }

      /* =====================================================
         /api/customer/summary
         - Admin: resolved normally
         - Customer: requires PIN
      ===================================================== */
      if (path === "/api/customer/summary") {
        const session = await getSession();

        if (!isAdmin && !session) {
          return json({ error: "pin_required" }, 401);
        }

        if (isAdmin) {
          const org = await resolveOrgForUser(user, env);
          return json({
            orgName: org.name,
            orgId: org.id
          });
        }

        return json({
          orgName: session.orgName,
          orgId: session.orgId
        });
      }

      /* =====================================================
         /api/admin/seed-pins
         TEMP: seeds a demo PIN
      ===================================================== */
      if (path === "/api/admin/seed-pins") {
        if (!isAdmin) {
          return json({ error: "admin_only" }, 403);
        }

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

      /* =====================================================
         /api/debug/pin-test
         Verifies KV read/write
      ===================================================== */
      if (path === "/api/debug/pin-test") {
        await env.ORG_MAP_KV.put(
          "pin:99999",
          JSON.stringify({
            orgId: "kv-test",
            orgName: "KV Working"
          })
        );

        const readBack = await env.ORG_MAP_KV.get("pin:99999", {
          type: "json"
        });

        return json({
          wrote: "pin:99999",
          readBack,
          kvBound: !!env.ORG_MAP_KV
        });
      }

      return json({ error: "not_found" }, 404);

    } catch (err) {
      console.error("Worker error:", err);
      return json({ error: err.message }, 500);
    }
  }
};
