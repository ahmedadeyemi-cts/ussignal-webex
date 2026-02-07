/**
 * webex.js
 * Handles Webex API authentication and data retrieval
 */

const WEBEX_BASE = "https://webexapis.com/v1";

/**
 * Obtain a Webex access token using Client Credentials
 */
export async function getWebexToken(env) {
  const res = await fetch(`${WEBEX_BASE}/access_token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET
    })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webex token error: ${text}`);
  }

  const json = await res.json();
  return json.access_token;
}

/**
 * List all Webex organizations visible to this integration
 */
export async function listWebexOrgs(env) {
  const token = await getWebexToken(env);

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
