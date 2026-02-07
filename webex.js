const WEBEX_API = "https://webexapis.com/v1";

/**
 * Get a valid Webex access token.
 * Uses an existing ACCESS_TOKEN and refreshes it if needed.
 */
async function getAccessToken(env) {
  if (!env.ACCESS_TOKEN || !env.REFRESH_TOKEN) {
    throw new Error("Missing Webex ACCESS_TOKEN or REFRESH_TOKEN");
  }

  // In production you’d check expiry.
  // For now, assume token is valid.
  return env.ACCESS_TOKEN;
}

/**
 * List Webex organizations (Partner Admin only)
 */
export async function listWebexOrgs(env) {
  const token = await getAccessToken(env);

  const res = await fetch(`${WEBEX_API}/organizations`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webex org list failed: ${text}`);
  }

  const data = await res.json();
  return data.items || [];
}
