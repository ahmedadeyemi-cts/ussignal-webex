import { err } from "./responses.js";

export function getAccessEmail(request) {
  // Cloudflare Access header we saw working in your screenshot:
  const e =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("cf-access-user-email") ||
    "";
  const email = String(e).trim().toLowerCase();
  return email || null;
}

export function requireEmail(request) {
  const email = getAccessEmail(request);
  if (!email) {
    return { ok: false, response: err(401, "not_authenticated", "Missing Cloudflare Access email header") };
  }
  return { ok: true, email };
}

export function isAdminEmail(email, env) {
  const adminDomain = String(env.ADMIN_DOMAIN || "ussignal.com").toLowerCase();
  return email.endsWith("@" + adminDomain);
}
