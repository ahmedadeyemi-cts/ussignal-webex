function normalize(str) {
  return str.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function matchesOrg(input, orgName) {
  if (!input || input.length < 5) return false;
  return normalize(orgName).includes(normalize(input));
}

export async function resolveUserContext(env, webexMe, orgs) {
  const email = webexMe.emails?.[0]?.toLowerCase();
  if (!email) throw new Error("User email not found");

  // Admin
  if (email.endsWith("@ussignal.com")) {
    return {
      email,
      role: "admin",
      orgs,
    };
  }

  // Customer — check cache
  const cached = await env.ORG_MAP_KV.get(email, { type: "json" });
  if (cached) return cached;

  // Try fuzzy match using email local-part
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
