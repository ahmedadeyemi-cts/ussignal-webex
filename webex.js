const WEBEX_API = "https://webexapis.com/v1";

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

export async function listWebexOrgs(env) {
  const data = await webexFetch(env, "/organizations");
  return data.items || [];
}
