const WEBEX_TOKEN_URL =
  "https://idbroker.webex.com/idb/oauth2/v1/access_token";

async function refreshWebexToken(env) {
  if (!env.CLIENT_ID || !env.CLIENT_SECRET || !env.REFRESH_TOKEN) {
    throw new Error("Missing CLIENT_ID / CLIENT_SECRET / REFRESH_TOKEN");
  }

  const basicAuth = btoa(`${env.CLIENT_ID}:${env.CLIENT_SECRET}`);

  const res = await fetch(WEBEX_TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: env.REFRESH_TOKEN,
    }),
  });

  const text = await res.text();

  if (!res.ok) {
    throw new Error(
      `Webex token refresh failed (${res.status}): ${text}`
    );
  }

  const data = JSON.parse(text);

  await env.WEBEX.put(
    "webex_tokens",
    JSON.stringify({
      access_token: data.access_token,
      refresh_token: data.refresh_token ?? env.REFRESH_TOKEN,
      expires_at: Date.now() + data.expires_in * 1000,
    })
  );

  return data.access_token;
}

async function getValidAccessToken(env) {
  const cached = await env.WEBEX.get("webex_tokens", { type: "json" });

  if (cached && cached.expires_at > Date.now() + 60_000) {
    return cached.access_token;
  }

  return await refreshWebexToken(env);
}

export async function getWebexMe(env) {
  const token = await getValidAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/people/me", {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    throw new Error(
      `Webex /people/me failed (${res.status}): ${await res.text()}`
    );
  }

  return await res.json();
}

export async function listWebexOrgs(env) {
  const token = await getValidAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    throw new Error(
      `Webex /organizations failed (${res.status}): ${await res.text()}`
    );
  }

  return await res.json();
}
