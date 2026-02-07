const BASE = "https://webexapis.com/v1";

export async function getWebexOrgs(env) {
  const res = await fetch(`${BASE}/organizations`, {
    headers: {
      Authorization: `Bearer ${env.INTEGRATION_ID}`
    }
  });

  if (!res.ok) {
    throw new Error("Failed to fetch Webex orgs");
  }

  const data = await res.json();
  return data.items || [];
}
