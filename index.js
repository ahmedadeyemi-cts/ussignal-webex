export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ---- Common headers
    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    try {
      // ============================
      // Root sanity check
      // ============================
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

      // ============================
      // /api/me — token sanity check
      // ============================
      if (url.pathname === "/api/me") {
        if (!env.ACCESS_TOKEN) {
          throw new Error("ACCESS_TOKEN missing");
        }

        const res = await fetch("https://webexapis.com/v1/people/me", {
          headers: {
            Authorization: `Bearer ${env.ACCESS_TOKEN}`,
          },
        });

        const text = await res.text();

        if (!res.ok) {
          throw new Error(`Webex /people/me failed (${res.status}): ${text}`);
        }

        return new Response(text, {
          headers: jsonHeaders,
          status: 200,
        });
      }

      // ============================
      // /api/org — list orgs
      // ============================
      if (url.pathname === "/api/org") {
        if (!env.ACCESS_TOKEN) {
          throw new Error("ACCESS_TOKEN missing");
        }

        const res = await fetch("https://webexapis.com/v1/organizations", {
          headers: {
            Authorization: `Bearer ${env.ACCESS_TOKEN}`,
          },
        });

        const text = await res.text();

        if (!res.ok) {
          throw new Error(
            `Webex /organizations failed (${res.status}): ${text}`
          );
        }

        return new Response(text, {
          headers: jsonHeaders,
          status: 200,
        });
      }

      // ============================
      // Favicon (silence browser)
      // ============================
      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      // ============================
      // Not found
      // ============================
      return new Response(
        JSON.stringify({
          error: "not_found",
          path: url.pathname,
        }),
        { status: 404, headers: jsonHeaders }
      );
    } catch (err) {
      // ============================
      // HARD FAIL SAFETY NET
      // ============================
      console.error("🔥 Worker error:", err);

      return new Response(
        JSON.stringify({
          error: "internal_error",
          message: err?.message || String(err),
        }),
        { status: 500, headers: jsonHeaders }
      );
    }
  },
};
