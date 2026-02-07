/**
 * webex.js
 * Partner-safe Webex OAuth + API client
 */

const WEBEX_BASE = "https://webexapis.com/v1";
const TOKEN_ENDPOINT = "https://webexapis.com/v1/access_token";

/**
 * Get a valid Webex access token (auto-refresh)
 */
export async function getWebexAccessToken(env) {
  const cached = await env.WEBEX.get("access_token", { type: "json" });

  if (cached && cached.expires_at > Date.now()) {
    return cached.token;
  }

  const res = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET,
      refresh_token: env.REFRESH_TOKEN
    })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webex token refresh failed: ${text}`);
  }

  const json = await res.json();

  const expiresAt =
    Date.now() + (json.expires_in - 60) * 1000;

  await env.WEBEX.put(
    "access_token",
    JSON.stringify({
      token: json.access_token,
      expires_at: expiresAt
    }),
    { expirationTtl: json.expires_in }
  );

  return json.access_token;
}

/**
 * List all Webex orgs visible to the partner
 */
export async function listWebexOrgs(env) {
  const token = await getWebexAccessToken(env);

  const res = await fetch(`${WEBEX_BASE}/organizations`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webex org fetch failed: ${text}`);
  }

  const json = await res.json();
  return json.items || [];
}
