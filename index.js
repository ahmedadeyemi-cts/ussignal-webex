import { getWebexMe, listWebexOrgs } from "./webex";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

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
      // /api/me — Webex user (KV-backed token)
      // ============================
      if (url.pathname === "/api/me") {
        const me = await getWebexMe(env);

        return new Response(JSON.stringify(me), {
          headers: jsonHeaders,
          status: 200,
        });
      }

      // ============================
      // /api/org — list orgs (KV-backed token)
      // ============================
      if (url.pathname === "/api/org") {
        const orgs = await listWebexOrgs(env);

        return new Response(JSON.stringify(orgs), {
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
