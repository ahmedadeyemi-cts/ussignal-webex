import { normalizeOrgName } from "./utils";
import { getWebexOrgs } from "./webex";

export async function resolveOrgForUser(user, env) {
  // Admin sees all orgs
  if (user.role === "admin") {
    return { id: "*", name: "ALL_CUSTOMERS" };
  }

  // Check cached mapping
  const cached = await env.ORG_MAP_KV.get(user.email, { type: "json" });
  if (cached) return cached;

  const orgs = await getWebexOrgs(env);

  const normalizedUser = normalizeOrgName(
    user.email.split("@")[0]
  );

  let bestMatch = null;
  let bestScore = 0;

  for (const org of orgs) {
    const normOrg = normalizeOrgName(org.displayName);

    if (normOrg.length >= 5 && normOrg.includes(normalizedUser)) {
      const score = normalizedUser.length / normOrg.length;
      if (score > bestScore) {
        bestScore = score;
        bestMatch = org;
      }
    }
  }

  if (!bestMatch) {
    throw new Error("Unable to resolve organization for user");
  }

  const result = {
    id: bestMatch.id,
    name: bestMatch.displayName
  };

  await env.ORG_MAP_KV.put(user.email, JSON.stringify(result));
  return result;
}
