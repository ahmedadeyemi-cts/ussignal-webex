export async function resolveOrgForUser(user, env) {
  // Admins do not belong to a customer org
  if (user.role === "admin") {
    return null;
  }

  const domain = user.email.split("@")[1];

  const record = await env.ORG_MAP_KV.get(domain, { type: "json" });

  if (!record) {
    throw new Error(`No org mapping found for domain: ${domain}`);
  }

  return record;
}
