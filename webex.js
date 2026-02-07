// webex.js
const WEBEX_TOKEN_URL = "https://idbroker.webex.com/idb/oauth2/v1/access_token";
const WEBEX_API_BASE = "https://webexapis.com/v1";

function asFormUrlEncoded(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

async function refreshAccessToken(env) {
  if (!env.CLIENT_ID || !env.CLIENT_SECRET || !env.REFRESH_TOKEN) {
    throw new Error("Missing CLIENT_ID, CLIENT_SECRET, or REFRESH_TOKEN in env");
  }

  const body = asFormUrlEncoded({
    grant_type: "refresh_token",
    client_id: env.CLIENT_ID,
    client_secret: env.CLIENT_SECRET,
    refresh_token: env.REFRESH_TOKEN
  });

  const res = await fetch(WEBEX_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!res.ok) {
    throw new Error(`Webex token refresh failed (${res.status}): ${text}`);
  }

  // Webex returns access_token, and sometimes a new refresh_token
  const accessToken = data.access_token;
  const refreshToken = data.refresh_token;

  if (!accessToken) throw new Error("Token refresh succeeded but no access_token returned");

  return { accessToken, refreshToken };
}

async function webexFetch(env, path, init = {}) {
  const url = path.startsWith("http") ? path : `${WEBEX_API_BASE}${path}`;

  // Prefer env.ACCESS_TOKEN; if missing, try refresh immediately
  let token = env.ACCESS_TOKEN;
  if (!token) {
    const refreshed = await refreshAccessToken(env);
    token = refreshed.accessToken;
  }

  const doReq = async (tkn) => {
    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${tkn}`);
    headers.set("Accept", "application/json");

    return fetch(url, { ...init, headers });
  };

  // First try
  let res = await doReq(token);

  // If token is stale, refresh once and retry
  if (res.status === 401) {
    const refreshed = await refreshAccessToken(env);
    token = refreshed.accessToken;

    // NOTE: If you want to persist the new token, do it in the CF dashboard manually
    // or store in KV. For now we just retry in-memory.
    res = await doReq(token);
  }

  return res;
}

export async function webexFetchJson(env, path, init = {}) {
  const res = await webexFetch(env, path, init);
  const text = await res.text();

  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!res.ok) {
    const msg = typeof data === "object" ? JSON.stringify(data) : String(data);
    throw new Error(`Webex API ${path} failed (${res.status}): ${msg}`);
  }
  return data;
}

// ✅ This is the export you were missing
export async function listWebexOrgs(env) {
  // Partner/admin capable token should allow org listing depending on scopes
  // Most common endpoint:
  // GET /organizations
  const data = await webexFetchJson(env, "/organizations");
  return data;
}
