export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

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

        // Refresh token flow
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
      // /api/me
      // -----------------------------
      if (url.pathname === "/api/me") {
        const token = await getAccessToken();

        const res = await fetch("https://webexapis.com/v1/people/me", {
          headers: { Authorization: `Bearer ${token}` },
        });

        const text = await res.text();

        if (!res.ok) {
          throw new Error(`/people/me failed (${res.status}): ${text}`);
        }

        return new Response(text, { headers: jsonHeaders });
      }

      // -----------------------------
      // /api/org
      // -----------------------------
      if (url.pathname === "/api/org") {
        const token = await getAccessToken();

        const res = await fetch("https://webexapis.com/v1/organizations", {
          headers: { Authorization: `Bearer ${token}` },
        });

        const text = await res.text();

        if (!res.ok) {
          throw new Error(`/organizations failed (${res.status}): ${text}`);
        }

        return new Response(text, { headers: jsonHeaders });
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
