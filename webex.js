// webex.js
// KV-backed Webex token management (refresh_token grant) + safe API wrapper

const TOKEN_URL = "https://idbroker.webex.com/idb/oauth2/v1/access_token";
const API_BASE = "https://webexapis.com/v1";

// Stored in KV namespace bound as env.WEBEX
const KV_KEY = "webex_tokens";

function formEncode(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

async function kvGetTokens(env) {
  const raw = await env.WEBEX.get(KV_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    // corrupted KV value
    return null;
  }
}

async function kvPutTokens(env, tokens) {
  await env.WEBEX.put(KV_KEY, JSON.stringify(tokens));
}

async function refreshWithToken(env, refreshToken) {
  if (!env.CLIENT_ID || !env.CLIENT_SECRET) {
    throw new Error("Missing CLIENT_ID or CLIENT_SECRET in env");
  }
  if (!refreshToken) {
    throw new Error("No refresh token available for Webex");
  }

  const body = formEncode({
    grant_type: "refresh_token",
    client_id: env.CLIENT_ID,
    client_secret: env.CLIENT_SECRET,
    refresh_token: refreshToken,
  });

  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Webex token refresh failed (${res.status}): ${text}`);
  }

  const data = JSON.parse(text);

  const tokens = {
    access_token: data.access_token,
    // Webex may or may not rotate refresh_token; keep the old if not returned
    refresh_token: data.refresh_token || refreshToken,
    // subtract 60s as safety buffer
    expires_at: Date.now() + (Number(data.expires_in || 0) * 1000) - 60_000,
  };

  if (!tokens.access_token) {
    throw new Error("Webex token refresh succeeded but no access_token returned");
  }

  await kvPutTokens(env, tokens);
  return tokens;
}

async function getValidAccessToken(env) {
  // 1) Try KV
  let tokens = await kvGetTokens(env);

  // 2) If no KV record, seed via env.REFRESH_TOKEN
  if (!tokens) {
    if (!env.REFRESH_TOKEN) {
      throw new Error("REFRESH_TOKEN missing (seed token required)");
    }
    tokens = await refreshWithToken(env, env.REFRESH_TOKEN);
  }

  // 3) If still valid, return access token
  if (tokens.expires_at && Date.now() < tokens.expires_at) {
    return tokens.access_token;
  }

  // 4) Expired -> refresh using stored refresh token
  tokens = await refreshWithToken(env, tokens.refresh_token);
  return tokens.access_token;
}

export async function webexFetchJson(env, path, init = {}) {
  const url = path.startsWith("http") ? path : `${API_BASE}${path}`;

  const doFetch = async (accessToken) => {
    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${accessToken}`);
    headers.set("Accept", "application/json");

    return fetch(url, { ...init, headers });
  };

  // first attempt
  let accessToken = await getValidAccessToken(env);
  let res = await doFetch(accessToken);

  // if token was revoked/invalid, refresh once and retry
  if (res.status === 401) {
    const tokens = await kvGetTokens(env);
    if (!tokens?.refresh_token) {
      throw new Error("401 from Webex and no refresh_token available in KV");
    }
    accessToken = (await refreshWithToken(env, tokens.refresh_token)).access_token;
    res = await doFetch(accessToken);
  }

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Webex API ${path} failed (${res.status}): ${text}`);
  }

  // If Webex returned empty body (rare), return {}
  if (!text) return {};
  return JSON.parse(text);
}

// ✅ Exports that index.js expects
export async function getWebexMe(env) {
  return webexFetchJson(env, "/people/me");
}

export async function listWebexOrgs(env) {
  return webexFetchJson(env, "/organizations");
}
