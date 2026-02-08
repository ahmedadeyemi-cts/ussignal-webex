import { listWebexOrgs, getWebexMe } from "./webex";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    try {
      if (url.pathname === "/") {
        return new Response(
          JSON.stringify({ status: "ok", service: "ussignal-webex" }),
          { headers }
        );
      }

      if (url.pathname === "/api/me") {
        const me = await getWebexMe(env);
        return new Response(JSON.stringify(me), { headers });
      }

      if (url.pathname === "/api/org") {
        const orgs = await listWebexOrgs(env);
        return new Response(JSON.stringify(orgs), { headers });
      }

      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      return new Response(
        JSON.stringify({ error: "not_found", path: url.pathname }),
        { status: 404, headers }
      );
    } catch (err) {
      console.error("🔥 Worker error:", err);
      return new Response(
        JSON.stringify({
          error: "internal_error",
          message: err.message,
        }),
        { status: 500, headers }
      );
    }
  },
};
