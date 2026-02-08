export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    /* =====================================================
       Helpers
    ===================================================== */

    function json(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: jsonHeaders,
      });
    }

    /* =====================================================
       Webex Token Handling (refresh + KV cache)
    ===================================================== */

    async function getAccessToken() {
      const cached = await env.WEBEX.get("access_token", { type: "json" });

      if (cached && cached.token && cached.expires_at > Date.now()) {
        return cached.token;
      }

      const body = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: env.CLIENT_ID,
        client_secret: env.CLIENT_SECRET,
        refresh_token: env.REFRESH_TOKEN,
      });

      const res = await fetch(
        "https://idbroker.webex.com/idb/oauth2/v1/access_token",
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        }
      );

      const data = await res.json();

      if (!res.ok) {
        throw new Error(
          `Webex token refresh failed (${res.status}): ${JSON.stringify(data)}`
        );
      }

      const expiresAt = Date.now() + data.expires_in * 1000 - 60000;

      await env.WEBEX.put(
        "access_token",
        JSON.stringify({
          token: data.access_token,
          expires_at: expiresAt,
        })
      );

      return data.access_token;
    }

    /* =====================================================
       Identity helpers
    ===================================================== */

    async function getCurrentUser(token) {
      const res = await fetch("https://webexapis.com/v1/people/me", {
        headers: { Authorization: `Bearer ${token}` },
      });

      const me = await res.json();
      if (!res.ok) {
        throw new Error(`/people/me failed: ${JSON.stringify(me)}`);
      }

      const email = me.emails?.[0]?.toLowerCase();
      if (!email) throw new Error("User email not found");

      return {
        email,
        isAdmin: email.endsWith("@ussignal.com"),
      };
    }

    /* =====================================================
       Routes
    ===================================================== */

    try {
      /* -----------------------------
         Root sanity
      ----------------------------- */
      if (url.pathname === "/") {
        return json({
          status: "ok",
          service: "ussignal-webex",
          time: new Date().toISOString(),
        });
      }

      /* -----------------------------
         /api/me
      ----------------------------- */
      if (url.pathname === "/api/me") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        return json({
          email: user.email,
          role: user.isAdmin ? "admin" : "customer",
        });
      }

      /* -----------------------------
         /api/pin  (POST)
         Body: { "pin": "12345" }
      ----------------------------- */
      if (url.pathname === "/api/pin" && request.method === "POST") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        const body = await request.json();
        const pin = String(body.pin || "").trim();

        if (!/^\d{5}$/.test(pin)) {
          return json({ error: "invalid_pin_format" }, 400);
        }

        const pinData = await env.ORG_MAP_KV.get(pin, { type: "json" });
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
          { expirationTtl: 3600 }
        );

        return json({ status: "ok", org: pinData.orgName });
      }

      /* -----------------------------
         /api/org
      ----------------------------- */
      if (url.pathname === "/api/org") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        const session = await env.USER_SESSION_KV.get(user.email, {
          type: "json",
        });

        if (!session && !user.isAdmin) {
          return json({ error: "pin_required" }, 401);
        }

        const orgRes = await fetch(
          "https://webexapis.com/v1/organizations",
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const orgData = await orgRes.json();

        if (!orgRes.ok) {
          throw new Error(`/organizations failed`);
        }

        if (user.isAdmin) {
          return json(orgData.items);
        }

        const filtered = orgData.items.filter(
          (o) => o.id === session.orgId
        );

        return json(filtered);
      }

      /* -----------------------------
         /api/admin/seed-pins
         Admin-only, one-time seeding
      ----------------------------- */
      if (url.pathname === "/api/admin/seed-pins") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        if (!user.isAdmin) {
          return json({ error: "admin_only" }, 403);
        }

        const res = await fetch(
          "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/org-pin-map.json"
        );

        if (!res.ok) {
          throw new Error("Failed to fetch org-pin-map.json");
        }

        const pinMap = await res.json();
        let written = 0;

        for (const pin of Object.keys(pinMap)) {
          await env.ORG_MAP_KV.put(
            pin,
            JSON.stringify(pinMap[pin])
          );
          written++;
        }

        return json({
          status: "ok",
          pinsLoaded: written,
        });
      }

      /* -----------------------------
         Favicon
      ----------------------------- */
      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      return json(
        { error: "not_found", path: url.pathname },
        404
      );
    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json(
        { error: "internal_error", message: err.message },
        500
      );
    }
  },
};
