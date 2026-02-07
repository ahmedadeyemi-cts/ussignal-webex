const WEBEX_API = "https://webexapis.com/v1";

/**
 * Internal helper to call Webex APIs
 */
async function webexFetch(env, path) {
  const res = await fetch(`${WEBEX_API}${path}`, {
    headers: {
      Authorization: `Bearer ${env.ACCESS_TOKEN}`,
      "Content-Type": "application/json"
    }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webex API error (${res.status}): ${text}`);
  }

  return res.json();
}

/**
 * List all orgs visible to the partner admin
 */
export async function listWebexOrgs(env) {
  const data = await webexFetch(env, "/organizations");
  return data.items || [];
}
