import { err } from "./responses.js";

const keyEmail = (email) => `email:${email.toLowerCase()}`;
const keyOrg = (orgId) => `org:${orgId}`;

export async function resolveOrgForEmail(env, email) {
  const mapped = await env.ORG_MAP_KV.get(keyEmail(email), { type: "json" });
  if (!mapped?.orgId) return null;
  return mapped; // { orgId, orgName }
}

export async function upsertOrg(env, org) {
  const orgId = String(org.orgId || "").trim();
  const orgName = String(org.orgName || "").trim();
  const emails = Array.isArray(org.emails) ? org.emails.map((e) => String(e).trim().toLowerCase()).filter(Boolean) : [];

  if (!orgId || !orgName) {
    throw new Error("orgId and orgName are required");
  }

  // Write org record
  await env.ORG_MAP_KV.put(keyOrg(orgId), JSON.stringify({ orgId, orgName, emails }));

  // Write reverse email mappings
  // (If an email exists, last write wins — BUT we also expose collision checks in admin endpoints.)
  await Promise.all(
    emails.map((email) =>
      env.ORG_MAP_KV.put(keyEmail(email), JSON.stringify({ orgId, orgName }))
    )
  );

  return { orgId, orgName, emailsCount: emails.length };
}

export async function getOrg(env, orgId) {
  return await env.ORG_MAP_KV.get(keyOrg(orgId), { type: "json" });
}

export function forbidMultipleOrgCollision(email, existing, incomingOrgId) {
  if (existing && existing.orgId && existing.orgId !== incomingOrgId) {
    return err(409, "email_org_collision", "Email is already assigned to a different org", {
      email,
      existingOrgId: existing.orgId,
      incomingOrgId,
    });
  }
  return null;
}
