export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/seed-pins") {
      await env.ORG_MAP_KV.put(
        "pin:39571",
        JSON.stringify({
          orgId: "city-of-norwalk-iowa",
          orgName: "City of Norwalk, Iowa"
        })
      );

      const verify = await env.ORG_MAP_KV.get("pin:39571", { type: "json" });

      return new Response(JSON.stringify({
        status: "OK_FROM_PAGES",
        verify
      }), {
        headers: { "content-type": "application/json" }
      });
    }

    return new Response(JSON.stringify({
      error: "not_found",
      path: url.pathname
    }), {
      status: 404,
      headers: { "content-type": "application/json" }
    });
  }
};
