export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    // -----------------------------
    // Helpers: org matching + RBAC
    // -----------------------------
    function normalize(str) {
      return str.toLowerCase().replace(/[^a-z0-9]/g, "");
    }

    function matchesOrg(input, orgName) {
      if (!input || input.length < 5) return false;
      return normalize(orgName).includes(normalize(input));
    }

    async function resolveUserContext(me, orgs) {
      const email = me.emails?.[0]?.toLowerCase();
      if (!email) throw new Error("User email not found");

      // Admin
      if (email.endsWith("@ussignal.com")) {
        return {
          email,
          role: "admin",
        };
      }

      // Customer — cached?
      const cached = await env.ORG_MAP_KV.get(email, { type: "json" });
      if (cached) return cached;

      const hint = email.split("@")[0];

      const match = orgs.find((o) =>
        matchesOrg(hint, o.displayName || o.name)
      );

      if (!match) {
        throw new Error("Unable to match customer to organization");
      }

      const context = {
        email,
        role: "customer",
        orgId: match.id,
        orgName: match.displayName || match.name,
      };

      await env.ORG_MAP_KV.put(email, JSON.stringify(context));

      return context;
    }

    try {
      // -----------------------------
      // Root sanity
      // -----------------------------
      if (url.pathname === "/") {
        return new Response(
          JSON.stringify({
            status: "ok",
            service: "ussignal-webex",
            time: new Date().toISOString(),
          }),
          { headers: jsonHeaders }
        );
      }

      // -----------------------------
      // Get valid Webex access token
      // -----------------------------
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

      // -----------------------------
      // /api/me  → role + org context
      // -----------------------------
      if (url.pathname === "/api/me") {
        const token = await getAccessToken();

        const meRes = await fetch("https://webexapis.com/v1/people/me", {
          headers: { Authorization: `Bearer ${token}` },
        });

        const me = await meRes.json();
        if (!meRes.ok) {
          throw new Error(`/people/me failed: ${JSON.stringify(me)}`);
        }

        const orgRes = await fetch(
          "https://webexapis.com/v1/organizations",
          { headers: { Authorization: `Bearer ${token}` } }
        );

        const orgData = await orgRes.json();
        if (!orgRes.ok) {
          throw new Error(`/organizations failed: ${JSON.stringify(orgData)}`);
        }

        const context = await resolveUserContext(me, orgData.items);

        await env.USER_SESSION_KV.put(
          context.email,
          JSON.stringify({
            ...context,
            lastSeen: Date.now(),
          }),
          { expirationTtl: 3600 }
        );

        return new Response(JSON.stringify(context), {
          headers: jsonHeaders,
        });
      }

      // -----------------------------
      // /api/org  → RBAC enforced
      // -----------------------------
      if (url.pathname === "/api/org") {
        const token = await getAccessToken();

        const meRes = await fetch("https://webexapis.com/v1/people/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const me = await meRes.json();

        const orgRes = await fetch(
          "https://webexapis.com/v1/organizations",
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const orgData = await orgRes.json();

        const context = await resolveUserContext(me, orgData.items);

        // Admin → all orgs
        if (context.role === "admin") {
          return new Response(JSON.stringify(orgData.items), {
            headers: jsonHeaders,
          });
        }

        // Customer → only their org
        const filtered = orgData.items.filter(
          (o) => o.id === context.orgId
        );

        return new Response(JSON.stringify(filtered), {
          headers: jsonHeaders,
        });
      }

      // -----------------------------
      // Favicon
      // -----------------------------
      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      return new Response(
        JSON.stringify({ error: "not_found", path: url.pathname }),
        { status: 404, headers: jsonHeaders }
      );
    } catch (err) {
      console.error("🔥 Worker error:", err);

      return new Response(
        JSON.stringify({
          error: "internal_error",
          message: err.message,
        }),
        { status: 500, headers: jsonHeaders }
      );
    }
  },
};
