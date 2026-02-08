export async function onRequest(context) {
  const { env } = context;

  await env.ORG_MAP_KV.put(
    "pin:39571",
    JSON.stringify({
      orgId: "city-of-norwalk-iowa",
      orgName: "City of Norwalk, Iowa",
    })
  );

  const verify = await env.ORG_MAP_KV.get("pin:39571", { type: "json" });

  return new Response(
    JSON.stringify({
      status: "seed_complete",
      verify,
    }),
    { headers: { "content-type": "application/json" } }
  );
}
