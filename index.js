import { getWebexMe, listWebexOrgs } from "./webex";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    try {
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

      if (url.pathname === "/api/me") {
        const me = await getWebexMe(env);
        return new Response(JSON.stringify(me), { headers: jsonHeaders, status: 200 });
      }

      if (url.pathname === "/api/org") {
        const orgs = await listWebexOrgs(env);
        return new Response(JSON.stringify(orgs), { headers: jsonHeaders, status: 200 });
      }

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
          message: err?.message || String(err),
        }),
        { status: 500, headers: jsonHeaders }
      );
    }
  },
};
