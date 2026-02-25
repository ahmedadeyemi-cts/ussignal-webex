/**
 * ussignal-webex — index.js (DROP-IN)
 * Features included:
 * - /api/pin/verify (POST)  → verifies PIN, creates session (TTL)
 * - Session TTLs (configurable)
 * - PIN attempt throttling (per user + per IP)
 * - Admin-only PIN rotation (rotate org PIN, updates KV atomically-ish)
 * - UI PIN modal logic (simple HTML app at "/")
 * - Admin-only seed-pins from GitHub raw JSON
 *
 * Required bindings:
 * - KV: WEBEX
 * - KV: ORG_MAP_KV
 * - KV: USER_SESSION_KV
 *
 * Required env vars:
 * - CLIENT_ID
 * - CLIENT_SECRET
 * - REFRESH_TOKEN
 *
 * Optional env vars:
 * - SESSION_TTL_SECONDS (default 3600)
 * - PIN_THROTTLE_WINDOW_SECONDS (default 900)   // 15 min
 * - PIN_MAX_ATTEMPTS (default 5)
 * - PIN_LOCKOUT_SECONDS (default 900)           // 15 min
 * - PIN_SEED_URL (default: your GitHub raw URL used below)
 */
 /* =====================================================
       Helpers
    ===================================================== */
const JSON_HEADERS = {
  "content-type": "application/json",
  "cache-control": "no-store",
};
// Global throttle configuration (set per request inside fetch)
let PIN_THROTTLE_WINDOW_SECONDS = 900;
let PIN_MAX_ATTEMPTS = 5;
let PIN_LOCKOUT_SECONDS = 900;

    const GLOBAL_SUMMARY_KEY = "globalSummarySnapshotV1";
    const CALLING_ANALYTICS_QS = "interval=DAY&from=-7d";
    const CALLING_ANALYTICS_PATH = `/analytics/calling?${CALLING_ANALYTICS_QS}`;

async function putGlobalSummarySnapshot(env, payload) {
  await env.WEBEX.put(GLOBAL_SUMMARY_KEY, JSON.stringify({
    generatedAt: new Date().toISOString(),
    payload
  }), { expirationTtl: 60 * 60 }); // keep 1 hour
}
function looksLikeWebexOrgId(s) {
  const v = String(s || "");
  return v.startsWith("Y2lzY29zcGFyazov"); // Webex orgId base64-ish prefix
}
function isUnassignedNumber(n){
  const s = String(n?.status || n?.state || "").toLowerCase();
  if (s.includes("unassign")) return true;
  if (s.includes("available")) return true;
  if (n?.owner === null) return true;
  if (!n?.owner && !n?.personId && !n?.workspaceId && !n?.virtualLineId) return true;
  return false;
}
async function storeHealth(env, health) {
  await env.WEBEX.put(
    `health:${health.orgId}`,
    JSON.stringify(health),
    { expirationTtl: 60 * 30 }
  );
}
async function storePstnSnapshot(env, orgId, payload) {
  await env.WEBEX.put(
    `pstn:${orgId}`,
    JSON.stringify(payload),
    { expirationTtl: 60 * 30 } // 30 minutes
  );
}
async function resolveOrgIdForAdmin(env, key) {
  // If they passed orgId directly, accept it
  if (looksLikeWebexOrgId(key)) return key;

  // If key is actually an orgId and stored as org:<orgId>
  const direct = await env.ORG_MAP_KV.get(`org:${key}`, { type: "json" });
  if (direct?.orgId) return direct.orgId;
  if (direct?.pin && key) return key; // org:<orgId> stores pin; if present, key itself is orgId

  // If you have a customer cache in WEBEX KV, try it (recommended)
  const customer = await env.WEBEX.get(`customer:${key}`, { type: "json" });
  if (customer?.orgId) return customer.orgId;

  return null;
}

async function apiCDR(env, request) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get("orgId");
  const max = Math.min(
    Number(url.searchParams.get("max") || 100),
    1000
  );
  const days = Math.min(
    Number(url.searchParams.get("days") || 1),
    30
  );

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  const to = new Date().toISOString();
  const from = new Date(
    Date.now() - days * 24 * 60 * 60 * 1000
  ).toISOString();

  const path =
    `/cdr/calls?startTime=${encodeURIComponent(from)}` +
    `&endTime=${encodeURIComponent(to)}` +
    `&max=${max}`;

  const result = await webexFetch(env, path, orgId);

  if (!result.ok) {
    return json({
      error: "webex_cdr_failed",
      status: result.status,
      preview: result.preview
    }, 500);
  }

  return json(result.data, 200);
}
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function getGlobalSummarySnapshot(env) {
  return await env.WEBEX.get(GLOBAL_SUMMARY_KEY, { type: "json" });
}
// =====================================================
// Webex org-scoping policy (single source of truth)
// =====================================================
// Modes:
// - "none"   => no org switching at all
// - "query"  => append ?orgId=
// - "header" => X-Organization-Id header
//
// If unsure, prefer "header" for telephony/config style,
// and "query" for analytics/cdr style.
const ORG_SCOPE_RULES = [
  // Partner/global (no org switch)
  { test: (p) => p === "/organizations" || p.startsWith("/organizations?"), mode: "none" },
  { test: (p) => p.startsWith("/people/"), mode: "none" },

  // Analytics + reporting style usually wants orgId query
  { test: (p) => p.startsWith("/analytics/"), mode: "query" },
  { test: (p) => p.startsWith("/cdr") || p.startsWith("/cdr_feed"), mode: "query" },

  // These *often* work best with query orgId in partner scenarios
  { test: (p) => p === "/licenses" || p.startsWith("/licenses?"), mode: "query" },
  { test: (p) => p === "/devices" || p.startsWith("/devices?"), mode: "query" },

  // Telephony/calling config style usually supports X-Organization-Id
  { test: (p) => p.startsWith("/telephony/"), mode: "header" },

  // Default
  { test: (_p) => true, mode: "header" }
];

function scopeModeForPath(path) {
  const p = String(path || "");
  const rule = ORG_SCOPE_RULES.find(r => r.test(p));
  return rule ? rule.mode : "header";
}
async function webexFetch(env, path, orgId = null) {
  const token = await getAccessToken(env);

  const mode = scopeModeForPath(path);

  // Build finalPath (only mutate for query mode)
  let finalPath = path;

  if (orgId && mode === "query") {
    const sep = finalPath.includes("?") ? "&" : "?";
    finalPath = `${finalPath}${sep}orgId=${encodeURIComponent(orgId)}`;
  }

  const url = `https://webexapis.com/v1${finalPath}`;

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/json"
  };

  if (orgId && mode === "header") {
    headers["X-Organization-Id"] = orgId;
  }

  console.log("WEBEX CALL:", { url, mode, orgId: orgId ? "yes" : "no" });

  const res = await fetch(url, { headers });
  const text = await res.text();
  const preview = text.slice(0, 400);

  try {
    const data = JSON.parse(text);
    return { ok: res.ok, status: res.status, data, preview };
  } catch {
    return { ok: false, status: res.status, error: "not_json", preview };
  }
}
// =====================================================
// PSTN helpers (SAFE)
// Place directly AFTER webexFetch()
// =====================================================
function asArray(v) {
  return Array.isArray(v) ? v : [];
}

function pickItems(payload) {
  if (!payload) return [];
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload)) return payload;
  return [];
}

// Safe wrapper: never throws, returns ok/status/data/preview/error
async function webexFetchSafe(env, path, orgId) {
  try {
    const r = await webexFetch(env, path, orgId);
    if (!r.ok) {
      return {
        ok: false,
        status: r.status,
        error: "webex_failed",
        preview: r.preview,
        data: null
      };
    }
    return { ok: true, status: r.status, data: r.data, preview: r.preview };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: "exception",
      preview: String(e?.message || e),
      data: null
    };
  }
}
// CDR payload normalization helper
function normalizeCdrItems(payload) {
  if (!payload) return [];
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.records)) return payload.records;
  if (Array.isArray(payload.data)) return payload.data;
  if (Array.isArray(payload)) return payload;
  return [];
}
function diag(name, result) {
  return {
    name,
    ok: !!result?.ok,
    status: result?.status ?? 0,
    error: result?.ok ? null : (result?.error || "failed"),
    preview: result?.ok ? null : String(result?.preview || "").slice(0, 220)
  };
}
async function auditLog(env, userEmail, path, metadata = {}) {
  try {
    await env.WEBEX.put(
      `audit:${Date.now()}:${userEmail}`,
      JSON.stringify({
        user: userEmail,
        path,
        metadata,
        timestamp: new Date().toISOString()
      }),
      { expirationTtl: 60 * 60 * 24 * 30 } // 30 days
    );
  } catch (e) {
    console.error("Audit logging failed:", e.message);
  }
}

  function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}
    function text(body, status = 200, headers = {}) {
      return new Response(body, {
        status,
        headers: { "cache-control": "no-store", ...headers },
      });
    }

    function getIP(req) {
      return (
        req.headers.get("cf-connecting-ip") ||
        req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
        "0.0.0.0"
      );
    }

    function nowMs() {
      return Date.now();
    }

    function sleep(ms) {
      return new Promise((r) => setTimeout(r, ms));
    }

    function constantTimeEqual(a, b) {
      // a, b strings
      if (typeof a !== "string" || typeof b !== "string") return false;
      const len = Math.max(a.length, b.length);
      let out = 0;
      for (let i = 0; i < len; i++) {
        const ca = a.charCodeAt(i) || 0;
        const cb = b.charCodeAt(i) || 0;
        out |= ca ^ cb;
      }
      return out === 0 && a.length === b.length;
    }

    function isFiveDigitPin(pin) {
      return /^\d{5}$/.test(pin);
    }

    function randomPin5() {
      // 10000-99999 inclusive, not “easy” patterns filtered later
      const buf = new Uint32Array(1);
      crypto.getRandomValues(buf);
      const n = 10000 + (buf[0] % 90000);
      return String(n);
    }
    //Maintenance API
function cfgIntAllowZero(env, name, def) {
  const v = env[name];
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : def;
}

const STATUS_CACHE_SECONDS = 60; // 0 disables cache

  function normalizeOrgIdParam(v) {
  const s = String(v || "").trim();
  if (!s) return null;
  const low = s.toLowerCase();
  if (low === "null" || low === "undefined") return null;
  return s;
}

//End of Maintenance API

function isHtmlLike(text) {
  const t = String(text || "").trim().toLowerCase();
  return t.startsWith("<!doctype") || t.startsWith("<html") || t.includes("<div id=\"app\"");
}

async function fetchJsonFirstOk(urls, opts = {}) {
  const debug = [];
  for (const url of urls) {
    try {
      const res = await fetch(url, {
        ...opts,
        redirect: "follow",
        headers: {
          "accept": "application/json,text/plain,*/*",
          ...(opts.headers || {})
        }
      });

      const text = await res.text();

      // Save debug trail
      debug.push({
        url,
        status: res.status,
        contentType: res.headers.get("content-type") || "",
        preview: text.slice(0, 180)
      });

      if (!res.ok) continue;
      if (isHtmlLike(text)) continue;

      try {
        const json = JSON.parse(text);
        return { ok: true, url, json, debug };
      } catch (e) {
        // not json; keep trying
        continue;
      }
    } catch (e) {
      debug.push({ url, error: e.message });
      continue;
    }
  }

  return { ok: false, error: "upstream_not_json", debug };
}

function normalizeSectorFromText(s) {
  const t = String(s || "").toLowerCase();
  if (t.includes("government") || t.includes(" gov ") || t.includes("fedramp")) return "Government";
  return "Commercial";
}

function guessLocationFromText(s) {
  const t = String(s || "").toLowerCase();
  if (t.includes("us region")) return "US Region";
  if (t.includes("canada")) return "Canada Data Center";
  if (t.includes("emea")) return "EMEA";
  if (t.includes("apac")) return "APAC";
  if (t.includes("eu")) return "EU Region";
  return null;
}

// Pull the “Reference #” style value from common shapes
function pickReference(obj) {
  return (
    obj?.external_id ||
    obj?.externalId ||
    obj?.reference ||
    obj?.ref ||
    obj?.shortlink ||
    obj?.id ||
    null
  );
}
    function looksTooEasy(pin) {
      // reject obvious patterns
      // - all same (11111)
      // - straight ascending/descending (12345, 54321)
      // - repeated pair (12121, 78787)
      // - palindrome-ish (12321, 98889)
      if (!isFiveDigitPin(pin)) return true;

      const d = pin.split("").map((x) => parseInt(x, 10));
      const allSame = d.every((x) => x === d[0]);
      if (allSame) return true;

      const asc = d[0] + 1 === d[1] && d[1] + 1 === d[2] && d[2] + 1 === d[3] && d[3] + 1 === d[4];
      const desc = d[0] - 1 === d[1] && d[1] - 1 === d[2] && d[2] - 1 === d[3] && d[3] - 1 === d[4];
      if (asc || desc) return true;

      const repeatedPair = d[0] === d[2] && d[1] === d[3] && d[0] !== d[1];
      if (repeatedPair) return true;

      const pal = d[0] === d[4] && d[1] === d[3];
      if (pal) return true;

      return false;
    }

    

    // KV key conventions
    const KV = {
      // ORG_MAP_KV
      pinKey: (pin) => `pin:${pin}`, // -> { orgId, orgName }
      orgKey: (orgId) => `org:${orgId}`, // -> { pin, orgName }
      // USER_SESSION_KV
      sessKey: (email) => `sess:${email}`, // -> session object
      attemptsKeyEmail: (email) => `pinAttempts:email:${email}`,
      attemptsKeyIp: (ip) => `pinAttempts:ip:${ip}`,
    };

    /* =====================================================
       Webex Token Handling (refresh + KV cache)
    ===================================================== */

    async function getAccessToken(env) {
      const cached = await env.WEBEX.get("access_token", { type: "json" });

      if (cached && cached.token && cached.expires_at > nowMs()) {
        return cached.token;
      }

      const body = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: env.CLIENT_ID,
        client_secret: env.CLIENT_SECRET,
        refresh_token: env.REFRESH_TOKEN,
      });

      const res = await fetch("https://idbroker.webex.com/idb/oauth2/v1/access_token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(`Webex token refresh failed (${res.status}): ${JSON.stringify(data)}`);
      }

      const expiresAt = nowMs() + data.expires_in * 1000 - 60_000; // 60s cushion

      await env.WEBEX.put(
        "access_token",
        JSON.stringify({
          token: data.access_token,
          expires_at: expiresAt,
        })
      );

      return data.access_token;
    }
 

    /* =====================================================
       Identity helpers
    ===================================================== */

function getCurrentUser(request) {
  const email =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("cf-access-user-email");

 // if (!email) {
   // throw new Error("Cloudflare Access email header missing");
 // }
  if (!email) {
    return null; // <-- DO NOT THROW
  }

  const normalized = email.toLowerCase().trim();

  return {
    email: normalized,
    isAdmin: normalized.endsWith("@ussignal.com"),
  };
}

function requireUser(request) {
  const user = getCurrentUser(request);
  if (!user?.email) {
    return { ok: false, res: json({ error: "access_required" }, 401) };
  }
  return { ok: true, user };
}
    /* =====================================================
       Session helpers
    ===================================================== */

 async function getSession(env, email) {
  return await env.USER_SESSION_KV.get(KV.sessKey(email), { type: "json" });
}

async function setSession(env, email, session, ttlSeconds = 3600) {
  await env.USER_SESSION_KV.put(
    KV.sessKey(email),
    JSON.stringify(session),
    { expirationTtl: ttlSeconds }
  );
}

    async function clearSession(env, email) {
      await env.USER_SESSION_KV.delete(KV.sessKey(email));
    }

    /* =====================================================
       Throttling helpers (per email + per IP)
    ===================================================== */

    async function readAttempts(env, key) {
      const data = await env.USER_SESSION_KV.get(key, { type: "json" });
      return data || { count: 0, lockedUntil: 0, windowStart: nowMs() };
    }

    async function writeAttempts(env, key, data) {
      await env.USER_SESSION_KV.put(key, JSON.stringify(data), {
        expirationTtl: Math.max(PIN_THROTTLE_WINDOW_SECONDS, PIN_LOCKOUT_SECONDS),
      });
    }

async function throttleCheckOrThrow(env, email, ip) {
  const kEmail = KV.attemptsKeyEmail(email);
  const kIp = KV.attemptsKeyIp(ip);

  const [aEmail, aIp] = await Promise.all([
    readAttempts(env, kEmail),
    readAttempts(env, kIp),
  ]);

  const t = nowMs();

  // If either is locked, deny
  const lockedUntil = Math.max(aEmail.lockedUntil || 0, aIp.lockedUntil || 0);
  if (lockedUntil > t) {
    const retryAfter = Math.ceil((lockedUntil - t) / 1000);
    await sleep(250);
    return { allowed: false, retryAfter };
  }

  // Reset windows if expired
  function normalizeWindow(a) {
    if (!a.windowStart || t - a.windowStart > PIN_THROTTLE_WINDOW_SECONDS * 1000) {
      a.windowStart = t;
      a.count = 0;
      a.lockedUntil = 0;
    }
    return a;
  }

  normalizeWindow(aEmail);
  normalizeWindow(aIp);

  // If already at max attempts, lock now (belt + suspenders)
  if ((aEmail.count || 0) >= PIN_MAX_ATTEMPTS || (aIp.count || 0) >= PIN_MAX_ATTEMPTS) {
    const until = t + PIN_LOCKOUT_SECONDS * 1000;
    aEmail.lockedUntil = until;
    aIp.lockedUntil = until;
    await Promise.all([
      writeAttempts(env, kEmail, aEmail),
      writeAttempts(env, kIp, aIp),
    ]);
    return { allowed: false, retryAfter: PIN_LOCKOUT_SECONDS };
  }

  // Persist any window normalization
  await Promise.all([
    writeAttempts(env, kEmail, aEmail),
    writeAttempts(env, kIp, aIp),
  ]);

  return { allowed: true, retryAfter: 0 };
}


    async function throttleRecordFailure(env, email, ip) {
      const t = nowMs();
      const kEmail = KV.attemptsKeyEmail(email);
      const kIp = KV.attemptsKeyIp(ip);

     const [aEmail, aIp] = await Promise.all([
  readAttempts(env, kEmail),
  readAttempts(env, kIp)
]);


      function bump(a) {
        // reset window if old
        if (!a.windowStart || t - a.windowStart > PIN_THROTTLE_WINDOW_SECONDS * 1000) {
          a.windowStart = t;
          a.count = 0;
        }
        a.count = (a.count || 0) + 1;

        if (a.count >= PIN_MAX_ATTEMPTS) {
          a.lockedUntil = t + PIN_LOCKOUT_SECONDS * 1000;
        }
        return a;
      }

     await Promise.all([
  writeAttempts(env, kEmail, bump(aEmail)),
  writeAttempts(env, kIp, bump(aIp))
]);

    }

    async function throttleClear(env, email, ip) {
      // optional: clear attempts on success
      await Promise.all([
        env.USER_SESSION_KV.delete(KV.attemptsKeyEmail(email)),
        env.USER_SESSION_KV.delete(KV.attemptsKeyIp(ip)),
      ]);
    }

    /* =====================================================
       PIN map helpers (ORG_MAP_KV)
    ===================================================== */

    async function getOrgByPin(env, pin) {
      return await env.ORG_MAP_KV.get(KV.pinKey(pin), { type: "json" });
    }

    async function getPinByOrg(env, orgId) {
      return await env.ORG_MAP_KV.get(KV.orgKey(orgId), { type: "json" });
    }

async function putPinMapping(env, pin, orgId, orgName, role = "customer", emails = []) {
  const normEmails = Array.isArray(emails)
    ? emails.map(e => e.toLowerCase().trim())
    : [];

  await Promise.all([
    env.ORG_MAP_KV.put(
      KV.pinKey(pin),
      JSON.stringify({ orgId, orgName, role, emails: normEmails })
    ),
    env.ORG_MAP_KV.put(
      KV.orgKey(orgId),
      JSON.stringify({ pin, orgName, role, emails: normEmails })
    )
  ]);
}


    async function deletePinMapping(pin, orgId) {
      await Promise.all([
        env.ORG_MAP_KV.delete(KV.pinKey(pin)),
        env.ORG_MAP_KV.delete(KV.orgKey(orgId)),
      ]);
    }

    async function generateUniqueNonEasyPin(env) {
      // best-effort uniqueness (KV check); try multiple times
      for (let i = 0; i < 40; i++) {
        const candidate = randomPin5();
        if (looksTooEasy(candidate)) continue;
        const exists = await env.ORG_MAP_KV.get(KV.pinKey(candidate));
        if (!exists) return candidate;
      }
      throw new Error("Failed to generate unique PIN after many attempts");
    }
    /* =====================================================
   Email allowlist helpers (ORG_MAP_KV)
===================================================== */

function emailKey(email) {
  return `email:${email.toLowerCase()}`;
}

async function getOrgByEmail(env, email) {
  return await env.ORG_MAP_KV.get(emailKey(email), { type: "json" });
}

async function putEmailMapping(email, orgId, orgName) {
  await env.ORG_MAP_KV.put(
    emailKey(email),
    JSON.stringify({ orgId, orgName })
  );
}

  async function renderHomeHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/app.html");
  if (!res.ok) {
    throw new Error("Failed to load UI HTML");
  }
  return await res.text();
}
    async function renderPinHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/pin.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load PIN UI");
  }

  return await res.text();
}
    async function renderCustomerMaintenanceHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/maintenance.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load maintenance UI");
  }

  return await res.text();
}
async function renderCustomerStatusHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/status.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load status UI");
  }

  return await res.text();
}

async function renderCustomerIncidentsHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/incidents.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load incidents UI");
  }

  return await res.text();
}
async function renderCustomerDevicesHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/devices.html");
  if (!res.ok) throw new Error("Failed to load customer devices UI");
  return await res.text();
}

async function renderCustomerAnalyticsHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/analytics.html");
  if (!res.ok) throw new Error("Failed to load customer analytics UI");
  return await res.text();
}

async function renderCustomerCDRHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/cdr.html");
  if (!res.ok) throw new Error("Failed to load customer CDR UI");
  return await res.text();
}

async function renderCustomerHubHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/index.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load customer hub UI");
  }

  return await res.text();
}
async function renderAdminCustomersHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/customers.html"
  );
  if (!res.ok) throw new Error("Failed to load admin customers UI");
  return await res.text();
}
async function renderAdminLayout(pageContent) {
  const layoutRes = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/layout.html"
  );

  if (!layoutRes.ok) {
    throw new Error("Failed to load admin layout");
  }

  const layoutHtml = await layoutRes.text();
  return layoutHtml.replace("{{CONTENT}}", pageContent);
}

async function renderAdminMonitoringHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/monitoring.html"
  );
  if (!res.ok) throw new Error("Failed to load admin monitoring UI");
  return await res.text();
}
async function renderCustomerPSTNHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/pstn.html"
  );
  if (!res.ok) throw new Error("Failed to load customer PSTN UI");
  return await res.text();
}
async function renderCustomerObservabilityHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/observability.html"
  );
  if (!res.ok) throw new Error("Failed to load customer Observability UI");
  return await res.text();
}
async function renderAdminSupportHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/support.html"
  );
  if (!res.ok) throw new Error("Failed to load admin support UI");
  return await res.text();
}

async function renderAdminImplementationHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/implementation.html"
  );
  if (!res.ok) throw new Error("Failed to load admin implementation UI");
  return await res.text();
}

async function renderAdminPSTNHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/pstn.html"
  );
  if (!res.ok) throw new Error("Failed to load admin PSTN UI");
  return await res.text();
}

async function renderAdminHubHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/hub.html"
  );
  if (!res.ok) throw new Error("Failed to load admin hub UI");
  return await res.text();
}
async function renderAdminAnalyticsHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/analytics.html");
  if (!res.ok) throw new Error("Failed to load admin analytics UI");
  return await res.text();
}

async function renderAdminLicensesHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/licenses.html");
  if (!res.ok) throw new Error("Failed to load admin licenses UI");
  return await res.text();
}

async function renderAdminDevicesHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/devices.html");
  if (!res.ok) throw new Error("Failed to load admin devices UI");
  return await res.text();
}

async function renderAdminAlertsHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/alerts.html");
  if (!res.ok) throw new Error("Failed to load admin alerts UI");
  return await res.text();
}

async function renderAdminPinsHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/pins.html"
  );
  if (!res.ok) throw new Error("Failed to load admin pins UI");
  return await res.text();
}


async function renderCustomerLicensesHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/licenses.html"
  );

  if (!res.ok) {
    throw new Error("Failed to load customer licenses UI");
  }

  return await res.text();
}
async function renderTenantResolutionHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/tenant-resolution.html"
  );
  if (!res.ok) {
    throw new Error("Failed to load tenant resolution UI");
  }
  return await res.text();
}
async function apiCallingAnalytics(env, request) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get("orgId");

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  const result = await webexFetch(
    env,
    CALLING_ANALYTICS_PATH,
    orgId
  );

  if (!result.ok) {
    return json({
      error: "webex_analytics_failed",
      status: result.status,
      preview: result.preview
    }, 500);
  }

  return json(result.data, 200);
}
// Simple concurrency limiter for partner-wide fanout calls
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;

  async function worker() {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx], idx);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return out;
}
 
async function computeTenantHealth(env, orgId) {

  let deficit = 0;
  let offline = 0;
  let failedCalls = 0;
  let totalCalls = 0;

  let licenseFailed = false;
  let deviceFailed = false;
  let analyticsFailed = false;
 let pstnScore = null;
let pstnDegraded = false;
let pstnSingleTrunk = false;
let pstnE911Risk = false;
let pstnCapacityRed = false;

  /* -------------------------
     LICENSES
  -------------------------- */
  const lic = await webexFetch(env, "/licenses", orgId);

  if (lic.ok) {
    for (const l of lic.data.items || []) {
      const total = Number(l.totalUnits ?? 0);
      const consumed = Number(l.consumedUnits ?? 0);
      deficit += Math.max(0, consumed - total);
    }
  } else {
    licenseFailed = true;
  }

  /* -------------------------
     DEVICES
  -------------------------- */
  const dev = await webexFetch(env, "/devices", orgId);

  if (dev.ok) {
    offline = (dev.data.items || []).filter(d =>
      String(d.connectionStatus || "").toLowerCase() !== "connected"
    ).length;
  } else {
    deviceFailed = true;
  }

  /* -------------------------
     CALLING ANALYTICS
  -------------------------- */
  const analytics = await webexFetch(
    env,
    CALLING_ANALYTICS_PATH,
    orgId
  );

  if (analytics.ok) {
    const rows = analytics.data.items || [];
    totalCalls = rows.reduce((a, r) => a + (r.totalCalls || 0), 0);
    failedCalls = rows.reduce((a, r) => a + (r.failedCalls || 0), 0);
  } else {
    analyticsFailed = true;
  }

  const failureRate = totalCalls > 0
    ? (failedCalls / totalCalls) * 100
    : 0;

 // PSTN (prefer KV snapshot written by cron)
try {
  const pstnSnap = await env.WEBEX.get(`pstn:${orgId}`, { type: "json" });
  if (pstnSnap?.scores) {
    pstnScore = pstnSnap.scores.pstnObservabilityScore ?? pstnSnap.scores.pstnReliabilityScore ?? null;
    pstnDegraded = !!pstnSnap.risk?.apiDegraded;
    pstnSingleTrunk = !!pstnSnap.risk?.singleTrunkRisk;
    pstnE911Risk = !!pstnSnap.risk?.timezoneAwareE911Risk || !!pstnSnap.risk?.e911Missing;
    pstnCapacityRed = !!pstnSnap.risk?.capacityRed;
  } else {
    // If missing or malformed, treat as degraded (but don’t hard fail)
    pstnDegraded = true;
  }
} catch {
  pstnDegraded = true;
}
  /* =====================================================
     ENTERPRISE WEIGHTED SCORING
  ===================================================== */

  let score = 100;

  // License deficit
  if (deficit > 0 && deficit <= 5) score -= 10;
  if (deficit > 5) score -= 25;

  // Device offline penalties
  if (offline > 0 && offline <= 5) score -= 10;
  if (offline > 5 && offline <= 10) score -= 20;
  if (offline > 10) score -= 30;

  // Call failure rate penalties
  if (failureRate > 3 && failureRate <= 5) score -= 10;
  if (failureRate > 5 && failureRate <= 10) score -= 20;
  if (failureRate > 10) score -= 35;

  // Hard penalties for API failures
  if (licenseFailed) score -= 10;
  if (deviceFailed) score -= 10;
  if (analyticsFailed) score -= 15;

  if (score < 0) score = 0;

 // PSTN penalties (enterprise-grade)
if (pstnScore != null) {
  if (pstnScore < 85) score -= 8;
  if (pstnScore < 70) score -= 12;
  if (pstnScore < 55) score -= 18;
} else {
  // Unknown PSTN is a mild penalty (visibility gap)
  score -= 5;
}

if (pstnDegraded) score -= 8;
if (pstnSingleTrunk) score -= 7;
if (pstnE911Risk) score -= 12;
if (pstnCapacityRed) score -= 10;

  /* -------------------------
     STATUS TIERS
  -------------------------- */

  let status = "Healthy";
  if (score < 85) status = "Warning";
  if (score < 60) status = "Critical";

/* -------------------------
   ALERT FLAGS
-------------------------- */

const alerts = {
  licenseDeficit: deficit > 0,
  minorDeviceOutage: offline > 0 && offline <= 5,
  majorDeviceOutage: offline > 10,
  elevatedCallFailures: failureRate > 5,
  severeCallFailures: failureRate > 10,
  apiDegraded: licenseFailed || deviceFailed || analyticsFailed,

  // 🔵 PSTN Extensions (new)
  pstnDegraded,
  pstnSingleTrunk,
  pstnE911Risk,
  pstnCapacityRed
};

/* -------------------------
   METRICS BLOCK
-------------------------- */

const metrics = {
  deficit,
  offlineDevices: offline,
  failureRate: Number(failureRate.toFixed(2)),
  totalCalls,
  failedCalls,

  // 🔵 PSTN metric added (no removal of existing fields)
  pstnScore
};

/* -------------------------
   FINAL RETURN
-------------------------- */

return {
  orgId,
  score,
  status,
  metrics,
  alerts,
  generatedAt: new Date().toISOString()
};
}

async function computeCallQuality(env, orgId) {

  const result = await webexFetch(
    env,
    "/call_qualities?max=50",
    orgId
  );

  if (!result.ok) {
    return { ok:false };
  }

  const items = result.data.items || [];

  const poor = items.filter(c =>
    Number(c.packetLossPercent || 0) > 3 ||
    Number(c.jitterMs || 0) > 30
  );

  return {
    ok:true,
    totalAnalyzed: items.length,
    poorCalls: poor.length,
    worstExamples: poor.slice(0,5)
  };
}
function pct(n, d) {
  if (!d || d <= 0) return 0;
  return Math.round((n / d) * 1000) / 10; // 1 decimal
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function sum(arr, fn) {
  let s = 0;
  for (const x of arr) s += Number(fn(x) || 0);
  return s;
}

// Try to infer Cisco/CCP/LGW based on fields that vary by tenant.
function detectPstnTypeEnhanced({ loc, locTrunks, locPremise, callRouting, routeGroups }) {
  // 1) Premise/LGW is the strongest signal
  if ((locPremise?.length || 0) > 0) return "Local Gateway / Premise PSTN";

  // 2) Look for trunk/provider hints
  const providers = (locTrunks || [])
    .map(t => String(t?.providerName || t?.provider || t?.vendor || "").toLowerCase())
    .filter(Boolean);

  const trunkTypes = (locTrunks || [])
    .map(t => String(t?.type || t?.trunkType || t?.connectionType || "").toLowerCase())
    .filter(Boolean);

  if (providers.some(p => p.includes("cisco")) || trunkTypes.some(t => t.includes("cisco"))) {
    return "Cisco PSTN";
  }
  if (providers.some(p => p.includes("cloud connected") || p.includes("ccp")) || trunkTypes.some(t => t.includes("ccp"))) {
    return "Cloud Connected PSTN";
  }
  if ((locTrunks?.length || 0) > 0) return "Trunk / Provider";

  // 3) Fallback to any existing loc hints
  const hint = loc?.pstnType || loc?.routingChoice || loc?.callingLineIdType;
  if (hint) return String(hint);

  return "Unknown";
}

function computeRedundancyScore(locTrunks, locPremise) {
  const t = (locTrunks?.length || 0);
  const p = (locPremise?.length || 0);
  const total = t + p;

  if (total === 0) return 0;

  // Base score by count
  let score = total === 1 ? 40 : total === 2 ? 75 : 90;

  // Bonus if any explicit failover configured flags exist
  const hasFailoverFlag = (locTrunks || []).some(x => x?.failoverConfigured === true);
  if (hasFailoverFlag) score += 5;

  // Bonus for mixed connectivity (e.g., trunk + premise)
  if (t > 0 && p > 0) score += 5;

  return clamp(score, 0, 100);
}

// Diagnostics -> degradation signals for UI panels + scoring
function deriveApiDegradation(diagnostics) {
  const diags = Array.isArray(diagnostics) ? diagnostics : [];
  const bad = diags.filter(d => !d.ok);
  const hard = bad.filter(d => (d.status === 401 || d.status === 403 || d.status === 404));
  const soft = bad.filter(d => (d.status >= 500 || d.status === 0));

  const worst = bad
    .slice()
    .sort((a, b) => (b.status || 0) - (a.status || 0))[0] || null;

  return {
    ok: bad.length === 0,
    failedCount: bad.length,
    authOrNotFoundCount: hard.length,
    upstreamErrorCount: soft.length,
    worst: worst ? { name: worst.name, status: worst.status, error: worst.error } : null
  };
}

/**
 * Best-effort CDR concurrency estimator.
 * - Uses up to `max=1000` calls for the window
 * - Bins by 15-min bucket using startTime (duration if present)
 * - Returns peakConcurrentEstimate for the org
 *
 * NOTE: Webex CDR schemas vary. This is intentionally defensive.
 */
async function estimateConcurrencyFromCdr(env, orgId, days = 1) {
  const end = new Date();
  const start = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const path =
    `/cdr/calls?startTime=${encodeURIComponent(start.toISOString())}` +
    `&endTime=${encodeURIComponent(end.toISOString())}` +
    `&max=1000`;

  const r = await webexFetchSafe(env, path, orgId);
  if (!r.ok) return { ok: false, reason: "cdr_fetch_failed", diag: diag("cdr/calls", r) };

  const items = pickItems(r.data);
  if (!items.length) return { ok: true, peakConcurrentEstimate: 0, sampledCalls: 0 };

  // 15-min buckets
  const bucketMs = 15 * 60 * 1000;
  const buckets = new Map(); // bucketStart -> count

  for (const c of items) {
    const st = c?.startTime || c?.start || c?.startDate;
    if (!st) continue;

    const t0 = Date.parse(st);
    if (!Number.isFinite(t0)) continue;

    // duration may be seconds; vary by schema
    const durSec = Number(c?.durationSeconds || c?.duration || c?.durationSec || 0);
    const durMs = Number.isFinite(durSec) && durSec > 0 ? durSec * 1000 : 0;

    // If we have duration, count buckets spanned; else count just start bucket.
    const t1 = durMs > 0 ? (t0 + durMs) : t0;

    const bStart = Math.floor(t0 / bucketMs) * bucketMs;
    const bEnd = Math.floor(t1 / bucketMs) * bucketMs;

    for (let b = bStart; b <= bEnd; b += bucketMs) {
      buckets.set(b, (buckets.get(b) || 0) + 1);
    }
  }

  let peak = 0;
  for (const v of buckets.values()) peak = Math.max(peak, v);

  return {
    ok: true,
    peakConcurrentEstimate: peak,
    sampledCalls: items.length
  };
}

/**
 * Persist a daily PSTN score point per org, keep last 30 points.
 * Stored in WEBEX KV as pstnTrend:<orgId>
 */
async function appendPstnTrend(env, orgId, point) {
  const key = `pstnTrend:${orgId}`;

  const existing = await env.WEBEX.get(key, { type: "json" });
  const arr = Array.isArray(existing?.items) ? existing.items : [];

  // Daily key (UTC day)
  const day = String(point?.day || "").trim() || new Date().toISOString().slice(0, 10);

  // Replace same-day if exists, else append
  const withoutDay = arr.filter(x => x?.day !== day);
  withoutDay.push({ ...point, day });

  // Sort by day asc and keep last 30
  withoutDay.sort((a, b) => String(a.day).localeCompare(String(b.day)));
  const trimmed = withoutDay.slice(Math.max(0, withoutDay.length - 30));

  await env.WEBEX.put(key, JSON.stringify({ items: trimmed }), { expirationTtl: 60 * 60 * 24 * 35 });
  return { ok: true, count: trimmed.length };
}

/**
 * Simple predictive DID exhaustion:
 * - Uses last N trend points (default 7)
 * - Linear slope on assignedDids/day
 * - Predict days until assigned reaches 90% of totalDids (or totalDids if you prefer)
 */
function predictDidExhaustion(trendItems, totalDids, horizonDays = 7) {
  const items = (Array.isArray(trendItems) ? trendItems : [])
    .slice(-horizonDays)
    .filter(x => Number.isFinite(Number(x.assignedDids)));

  if (items.length < 3 || !Number.isFinite(totalDids) || totalDids <= 0) {
    return { ok: false, reason: "insufficient_data" };
  }

  // x = 0..n-1, y = assigned
  const n = items.length;
  const xs = [...Array(n)].map((_, i) => i);
  const ys = items.map(x => Number(x.assignedDids));

  const xbar = xs.reduce((a, b) => a + b, 0) / n;
  const ybar = ys.reduce((a, b) => a + b, 0) / n;

  let num = 0, den = 0;
  for (let i = 0; i < n; i++) {
    num += (xs[i] - xbar) * (ys[i] - ybar);
    den += (xs[i] - xbar) * (xs[i] - xbar);
  }
  const slopePerDay = den ? (num / den) : 0;

  const target = Math.floor(totalDids * 0.9);
  const current = ys[ys.length - 1];

  if (slopePerDay <= 0) {
    return { ok: true, slopePerDay: Number(slopePerDay.toFixed(2)), daysTo90pct: null, note: "no_growth_detected" };
  }

  const days = Math.ceil((target - current) / slopePerDay);
  return {
    ok: true,
    slopePerDay: Number(slopePerDay.toFixed(2)),
    daysTo90pct: days > 0 ? days : 0,
    targetAssigned: target,
    currentAssigned: current
  };
}
// =====================================================
// PSTN Deep Builder
// Place directly AFTER computeCallQuality()
// =====================================================
async function buildPstnDeep(env, orgId) {
  const diagnostics = [];

  // 1) Locations (baseline)
  const rLocations = await webexFetchSafe(env, "/telephony/config/locations", orgId);
  diagnostics.push(diag("telephony/config/locations", rLocations));

  const locations = pickItems(rLocations.data);
  const locationById = {};
  for (const loc of locations) {
    if (loc?.id) locationById[loc.id] = loc;
  }

  // 2) Numbers (best-effort)
  const rNumbers = await webexFetchSafe(env, "/telephony/config/numbers?max=1000", orgId);
  diagnostics.push(diag("telephony/config/numbers", rNumbers));
  const numbers = pickItems(rNumbers.data);

  // 3) Trunks / PSTN connections (best-effort)
  const rTrunks = await webexFetchSafe(env, "/telephony/config/trunks?max=1000", orgId);
  diagnostics.push(diag("telephony/config/trunks", rTrunks));
  const trunks = pickItems(rTrunks.data);

  const rPremise = await webexFetchSafe(env, "/telephony/config/premisePstnConnections?max=1000", orgId);
  diagnostics.push(diag("telephony/config/premisePstnConnections", rPremise));
  const premise = pickItems(rPremise.data);

  // 4) Emergency (best-effort)
  const rEmergency = await webexFetchSafe(env, "/telephony/config/emergencyCallbackNumbers?max=1000", orgId);
  diagnostics.push(diag("telephony/config/emergencyCallbackNumbers", rEmergency));
  const emergency = pickItems(rEmergency.data);

  // 5) Routing objects (optional / best-effort)
  const rRouteGroups = await webexFetchSafe(env, "/telephony/config/routeGroups?max=1000", orgId);
  diagnostics.push(diag("telephony/config/routeGroups", rRouteGroups));
  const routeGroups = pickItems(rRouteGroups.data);

  const rCallRouting = await webexFetchSafe(env, "/telephony/config/callRouting", orgId);
  diagnostics.push(diag("telephony/config/callRouting", rCallRouting));
  const callRouting = rCallRouting.ok ? (rCallRouting.data || {}) : null;

  // 6) Optional: CDR concurrency modeling (best-effort)
  const cdrModel = await estimateConcurrencyFromCdr(env, orgId, 1); // last 24h sample
  const peakConcurrentOrg = cdrModel.ok ? (cdrModel.peakConcurrentEstimate || 0) : null;

  function numberLocationId(n) {
    return n?.locationId || n?.location?.id || n?.location?.locationId || null;
  }

  function isAssignedNumber(n) {
    const owner =
      n?.owner ||
      n?.ownerId ||
      n?.userId ||
      n?.workspaceId ||
      n?.placeId ||
      n?.assignedTo ||
      n?.assigned;
    if (owner) return true;

    const status = String(n?.status || n?.state || "").toLowerCase();
    if (status.includes("assigned")) return true;
    if (status.includes("unassigned")) return false;

    if (n?.personName || n?.workspaceName || n?.displayName) return true;
    return false;
  }

  function trunkLocationId(t) {
    return t?.locationId || t?.location?.id || null;
  }

  function ecbnLocationId(e) {
    return e?.locationId || e?.location?.id || null;
  }

  const perLocation = [];

  const tenantAssigned = numbers.filter(isAssignedNumber).length;
  const tenantTotal = numbers.length || 1;

  for (const loc of locations) {
    const locId = loc?.id || null;

    const locNumbers = locId ? numbers.filter(n => numberLocationId(n) === locId) : [];
    const totalDids = locNumbers.length;
    const assigned = locNumbers.filter(isAssignedNumber).length;
    const unassigned = Math.max(0, totalDids - assigned);

    const locTrunks = locId ? trunks.filter(t => trunkLocationId(t) === locId) : [];
    const locPrem = locId ? premise.filter(p => trunkLocationId(p) === locId) : [];

    const locEcbn = locId ? emergency.filter(e => ecbnLocationId(e) === locId) : [];

    const emergencyConfigured = locEcbn.length > 0
      ? true
      : (typeof loc?.emergencyCallBackNumber !== "undefined" ? !!loc.emergencyCallBackNumber : null);

    // Enhanced PSTN Type detection (Cisco/CCP/LGW/etc.)
    const pstnType = detectPstnTypeEnhanced({
      loc,
      locTrunks,
      locPremise: locPrem,
      callRouting,
      routeGroups
    });

    // Enterprise redundancy scoring
    const redundancyScore = computeRedundancyScore(locTrunks, locPrem);

    // Blast radius: how much DID inventory is in this location
    const blastRadiusPct = pct(totalDids, tenantTotal);

    // Timezone-aware E911 checks (enterprise posture)
    const hasTimeZone = !!loc?.timeZone;
    const hasAddress = !!loc?.address;
    const timezoneAwareE911Risk =
      emergencyConfigured === false || !hasTimeZone || !hasAddress;

    // Capacity risk (heuristic until trunk capacity fields are confirmed)
    // If trunks expose capacity fields later, swap `defaultChannelsPerTrunk`.
    const defaultChannelsPerTrunk = 23; // conservative assumption
    const estCapacity = (locTrunks.length + locPrem.length) * defaultChannelsPerTrunk;

    // We can only estimate utilization org-wide from CDR sample for now.
    // Allocate a location share based on call presence proxies (assigned DID share).
    // It’s not perfect, but it is defensible and stable until trunk->location usage is available.
    const assignedShare = tenantAssigned > 0 ? (assigned / tenantAssigned) : 0;
    const estPeakConcurrentAtLoc = peakConcurrentOrg == null ? null : Math.round(peakConcurrentOrg * assignedShare);
    const estUtilPct = (estPeakConcurrentAtLoc != null && estCapacity > 0)
      ? pct(estPeakConcurrentAtLoc, estCapacity)
      : null;

    let capacityRisk = "UNKNOWN";
    if (estUtilPct == null) capacityRisk = "UNKNOWN";
    else if (estUtilPct >= 85) capacityRisk = "RED";
    else if (estUtilPct >= 70) capacityRisk = "AMBER";
    else capacityRisk = "GREEN";

    const riskFlags = {
      orphanDIDs: unassigned > 0,
      singleTrunkRisk: (locTrunks.length + locPrem.length) === 1,
      e911Missing: emergencyConfigured === false,
      timezoneAwareE911Risk,
      capacityRisk
    };

    perLocation.push({
      id: locId,
      name: loc?.name || loc?.displayName || "Unnamed Location",
      timeZone: loc?.timeZone || null,
      address: loc?.address || null,

      // NEW: richer PSTN fields
      pstnType,
      blastRadiusPct,
      redundancyScore,
      capacity: {
        estChannels: estCapacity || 0,
        estPeakConcurrent: estPeakConcurrentAtLoc,
        estUtilizationPct: estUtilPct
      },

      // Keep your existing detail maps
      trunks: locTrunks.map(t => ({
        id: t?.id || null,
        name: t?.name || t?.displayName || "Unnamed Trunk",
        type: t?.type || t?.trunkType || null,
        providerName: t?.providerName || t?.provider || null,
        status: t?.status || null,
        failoverConfigured: typeof t?.failoverConfigured !== "undefined" ? !!t.failoverConfigured : null
      })),
      premisePstnConnections: locPrem.map(p => ({
        id: p?.id || null,
        name: p?.name || p?.displayName || "Premise PSTN",
        type: p?.type || null,
        status: p?.status || null
      })),

      dids: { total: totalDids, assigned, unassigned },
      emergencyConfigured,
      riskFlags
    });
  }

  const totals = {
    locations: perLocation.length,
    trunks: trunks.length,
    premisePstnConnections: premise.length,
    didsTotal: numbers.length,
    didsAssigned: tenantAssigned,
    didsUnassigned: Math.max(0, numbers.length - tenantAssigned),
    routeGroups: routeGroups.length
  };

  const apiDegradation = deriveApiDegradation(diagnostics);

  const risk = {
    orphanDIDs: perLocation.some(l => l.riskFlags.orphanDIDs),
    singleTrunkRisk: perLocation.some(l => l.riskFlags.singleTrunkRisk),
    e911Missing: perLocation.some(l => l.riskFlags.e911Missing === true),
    timezoneAwareE911Risk: perLocation.some(l => l.riskFlags.timezoneAwareE911Risk === true),
    capacityRed: perLocation.some(l => l.riskFlags.capacityRisk === "RED"),
    capacityAmber: perLocation.some(l => l.riskFlags.capacityRisk === "AMBER"),
    apiDegraded: !apiDegradation.ok
  };

  // Reliability score (your existing style, extended)
  let pstnReliabilityScore = 100;
  if (risk.orphanDIDs) pstnReliabilityScore -= 10;
  if (risk.singleTrunkRisk) pstnReliabilityScore -= 15;
  if (risk.e911Missing) pstnReliabilityScore -= 25;
  if (risk.timezoneAwareE911Risk) pstnReliabilityScore -= 10;
  if (risk.apiDegraded) pstnReliabilityScore -= 10;
  pstnReliabilityScore = clamp(pstnReliabilityScore, 0, 100);

  // NEW: Redundancy score (avg across locations)
  const avgRedundancy = perLocation.length
    ? Math.round(sum(perLocation, l => l.redundancyScore) / perLocation.length)
    : 0;

  // NEW: Capacity score based on modeled risk
  let pstnCapacityScore = 100;
  if (risk.capacityAmber) pstnCapacityScore -= 10;
  if (risk.capacityRed) pstnCapacityScore -= 25;
  if (risk.apiDegraded) pstnCapacityScore -= 5;
  pstnCapacityScore = clamp(pstnCapacityScore, 0, 100);

  // NEW: Observability PSTN score (what you can feed into global RAG)
  const pstnObservabilityScore = clamp(
    Math.round((pstnReliabilityScore * 0.55) + (avgRedundancy * 0.25) + (pstnCapacityScore * 0.20)),
    0,
    100
  );

  return {
    orgId,
    generatedAt: new Date().toISOString(),

    // NEW: richer scoring layer (keeps your old score, adds more)
    scores: {
      pstnReliabilityScore,
      pstnCapacityScore,
      pstnRedundancyScore: avgRedundancy,
      pstnObservabilityScore
    },

    totals,
    risk,

    // NEW: diagnostics rollup for pstn.diagnostics panel
    apiDegradation,
    modeling: {
      cdrConcurrency: cdrModel.ok ? {
        ok: true,
        peakConcurrentEstimate: cdrModel.peakConcurrentEstimate,
        sampledCalls: cdrModel.sampledCalls
      } : {
        ok: false,
        reason: cdrModel.reason || "unknown",
        diag: cdrModel.diag || null
      }
    },

    locations: perLocation,

    routing: {
      routeGroups: routeGroups.map(rg => ({
        id: rg?.id || null,
        name: rg?.name || rg?.displayName || "Route Group",
        locationId: rg?.locationId || rg?.location?.id || null
      })),
      callRouting
    },

    diagnostics
  };
}

async function computeGlobalSummary(env) {
  const orgResult = await webexFetch(env, "/organizations");

  if (!orgResult.ok) {
    throw new Error("org_list_failed");
  }

  const rawOrgs = orgResult.data.items || [];
const seen = new Set();
const orgs = rawOrgs.filter(o => {
  if (seen.has(o.id)) return false;
  seen.add(o.id);
  return true;
});

  const CONCURRENCY = 6;

  async function perOrg(org) {
    try {
      const orgId = org.id;
      const orgName = org.displayName || org.name || "Unknown";

     let deficit = 0;
     let offlineDevices = 0;
     let callVolume = 0;

     let analyticsFailed = false;
     let cdrFailed = false;
     let pstnFailed = false;
     let licenseFailed = false;
     let pstnScore = null;
     let pstnRisk = null;

     try {
  const cdrProbe = await webexFetch(env, "/cdr/calls?max=1", orgId);
  if (!cdrProbe.ok) {
    cdrFailed = true;
  }
} catch {
  cdrFailed = true;
}

// Calling Analytics
try {
  const analyticsResult = await webexFetch(
    env,
    CALLING_ANALYTICS_PATH,
    orgId
  );

  if (analyticsResult.ok) {
    const rows = analyticsResult.data?.items || [];
    callVolume = rows.reduce((a,r)=>a+(r.totalCalls||0),0);
  } else {
    analyticsFailed = true;
  }

} catch {
  analyticsFailed = true;
}

try {
  const pstnSnap = await env.WEBEX.get(`pstn:${orgId}`, { type: "json" });
  if (pstnSnap?.scores) {
    pstnScore = pstnSnap.scores.pstnObservabilityScore ?? pstnSnap.scores.pstnReliabilityScore ?? null;
    pstnRisk = pstnSnap.risk || null;
  } else {
    pstnFailed = true; // you already track pstnFailed
  }
} catch {
  pstnFailed = true;
}


      // Licenses
     const licResult = await webexFetch(env, "/licenses", orgId);

if (licResult.ok) {
  for (const l of licResult.data.items || []) {
    const total = Number(l.totalUnits ?? 0);
    const consumed = Number(l.consumedUnits ?? 0);
    deficit += Math.max(0, consumed - total);
  }
} else {
  licenseFailed = true;
}

      // Devices (optional)
    const devResult = await webexFetch(env, "/devices", orgId);

if (devResult.ok) {
  offlineDevices = (devResult.data.items || []).filter(d =>
    String(d.connectionStatus || "").toLowerCase() !== "connected"
  ).length;
}
     // PSTN (Telephony Config)
const pstnResult = await webexFetch(env, "/telephony/config/locations", orgId);
if (!pstnResult.ok) {
  pstnFailed = true;
}


   return {
  orgId,
  orgName,
  deficit,
  offlineDevices,
  callVolume,
  pstnScore,
  pstnRisk,
  failures: {
    analyticsFailed,
    cdrFailed,
    pstnFailed,
    licenseFailed
  }
};

    } catch {
      return {
        orgId: org.id,
        orgName: org.displayName || "Unknown",
        deficit: 0,
        offlineDevices: 0,
        callVolume: 0,
        failed: true
      };
    }
  }

  const tenants = await mapLimit(orgs, CONCURRENCY, perOrg);

 return {
  totalOrgs: tenants.length,
  totalDeficits: tenants.reduce((a,t)=>a+t.deficit,0),
  offlineDevices: tenants.reduce((a,t)=>a+t.offlineDevices,0),
  totalCalls: tenants.reduce((a,t)=>a+t.callVolume,0),

  // NEW: Global PSTN view
  avgPstnScore: (() => {
    const vals = tenants.map(t => Number(t.pstnScore)).filter(Number.isFinite);
    if (!vals.length) return null;
    return Math.round(vals.reduce((a,b)=>a+b,0) / vals.length);
  })(),
  pstnUnknownCount: tenants.filter(t => t.pstnScore == null).length,

  tenants
};
}

export default {

  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
     const path = url.pathname;

      /* =====================================================
         STATIC ASSETS
      ====================================================== */

      if (path === "/assets/ussignal-logo.jpg") {
        const res = await fetch(
          "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/assets/ussignal-logo.jpg"
        );

        return new Response(res.body, {
          headers: {
            "content-type": "image/jpeg",
            "cache-control": "public, max-age=86400"
          }
        });
      }
     
const SESSION_TTL_SECONDS = cfgIntAllowZero(env, "SESSION_TTL_SECONDS", 3600);
// IMPORTANT: assign to the GLOBALS (do not redeclare)
PIN_THROTTLE_WINDOW_SECONDS = cfgIntAllowZero(env, "PIN_THROTTLE_WINDOW_SECONDS", 900);
PIN_MAX_ATTEMPTS = cfgIntAllowZero(env, "PIN_MAX_ATTEMPTS", 5);
PIN_LOCKOUT_SECONDS = cfgIntAllowZero(env, "PIN_LOCKOUT_SECONDS", 900);


    /* =====================================================
       Routes
    ===================================================== */

      /* =====================================================
   🔐 GLOBAL ACCESS ENFORCEMENT
   ===================================================== */

const accessEmail =
  request.headers.get("cf-access-authenticated-user-email") ||
  request.headers.get("cf-access-user-email");

const publicPaths = [
  "/health",
  "/favicon.ico",
  "/pin",
  "/"
];

const publicPrefixes = [
/*  "/customer" */
];

const isPublic =
  publicPaths.includes(url.pathname) ||
  publicPrefixes.some(p => url.pathname.startsWith(p));

if (!accessEmail && !isPublic) {
  return json({ error: "access_required" }, 401);
}


      /* -----------------------------
   /api/admin/seed-pins (GET)
   Admin-only: fetch JSON and seed ORG_MAP_KV
----------------------------- */
if (url.pathname === "/api/admin/seed-pins" && request.method === "GET") {
  if (env.SEED_DISABLED === "true") {
    return json(
      { error: "seed_disabled", message: "Seed endpoint is disabled" },
      410
    );
  }

  const email =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("cf-access-user-email");

  if (!email || !email.endsWith("@ussignal.com")) {
    return json({ error: "admin_only" }, 403);
  }
await auditLog(env, email, url.pathname, {
  action: "seed_pins"
});

  const seedUrl =
    env.PIN_SEED_URL ||
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/org-pin-map.json";

  const res = await fetch(seedUrl, {
    headers: { accept: "application/json" },
  });

  if (!res.ok) {
    return json(
      { error: "seed_fetch_failed", status: res.status },
      500
    );
  }

  const data = await res.json();

  let written = 0;
  let skipped = 0;

  for (const [key, value] of Object.entries(data)) {
    if (!key.startsWith("PIN_")) {
      skipped++;
      continue;
    }

    const pin = key.replace("PIN_", "");
    if (!/^\d{5}$/.test(pin)) {
      skipped++;
      continue;
    }

    const orgId = String(value.orgId || "").trim();
if (!looksLikeWebexOrgId(orgId)) {
  skipped++;
  continue;
}

    const role = value.role || "customer";

    const emails = Array.isArray(value.emails)
      ? value.emails.map(e => e.toLowerCase().trim())
      : [];

    // pin → org
    await env.ORG_MAP_KV.put(
      `pin:${pin}`,
      JSON.stringify({
        orgId,
        orgName: value.orgName,
        role,
        emails,
      })
    );

    // org → pin
    await env.ORG_MAP_KV.put(
      `org:${orgId}`,
      JSON.stringify({
        pin,
        orgName: value.orgName,
        role,
        emails,
      })
    );

    // email → org
    for (const e of emails) {
      await env.ORG_MAP_KV.put(
        `email:${e}`,
        JSON.stringify({
          orgId,
          orgName: value.orgName,
          role,
        })
      );
    }

    written++;
  }

  return json({
    status: "ok",
    pinsLoaded: written,
    skipped,
    seedUrl,
    ranAs: email,
  });
}

      /* -----------------------------
   PIN UI
----------------------------- */
if (url.pathname === "/pin" && request.method === "GET") {
  return text(await renderPinHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
/* -----------------------------
   UI Used for renderHomeHTML()
----------------------------- */
      if (url.pathname === "/" && request.method === "GET") {
  return text(await renderHomeHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

      /* -----------------------------
 Admin Pages
----------------------------- */
if (
  (url.pathname === "/admin" || url.pathname === "/admin/") &&
  request.method === "GET"
) {
  const page = await renderAdminHubHTML();
  const wrapped = await renderAdminLayout(page);

  return text(wrapped, 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/customers" && request.method === "GET") {
  return text(await renderAdminCustomersHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/monitoring" && request.method === "GET") {
  return text(await renderAdminMonitoringHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/support" && request.method === "GET") {
  return text(await renderAdminSupportHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/implementation" && request.method === "GET") {
  return text(await renderAdminImplementationHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/pstn" && request.method === "GET") {
  return text(await renderAdminPSTNHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
if (url.pathname === "/admin/analytics" && request.method === "GET") {
  return text(await renderAdminAnalyticsHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/licenses" && request.method === "GET") {
  return text(await renderAdminLicensesHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/devices" && request.method === "GET") {
  return text(await renderAdminDevicesHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/alerts" && request.method === "GET") {
  return text(await renderAdminAlertsHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/pins" && request.method === "GET") {
  return text(await renderAdminPinsHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

/* -----------------------------
   Customer UI: Hub (Default)
----------------------------- */
if (
  (url.pathname === "/customer" || url.pathname === "/customer/") &&
  request.method === "GET"
) {
  return text(await renderCustomerHubHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

/* -----------------------------
   Customer UI: Licenses
----------------------------- */
if (url.pathname === "/customer/licenses" && request.method === "GET") {
  return text(await renderCustomerLicensesHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
      if (url.pathname === "/customer/devices" && request.method === "GET") {
  return text(await renderCustomerDevicesHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/customer/analytics" && request.method === "GET") {
  return text(await renderCustomerAnalyticsHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/customer/cdr" && request.method === "GET") {
  return text(await renderCustomerCDRHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
/* -----------------------------
   Customer UI: PSTN
----------------------------- */
if (url.pathname === "/customer/pstn" && request.method === "GET") {
  return text(await renderCustomerPSTNHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
     /* -----------------------------
   Customer UI: Observability
----------------------------- */
if (url.pathname === "/customer/observability" && request.method === "GET") {
  return text(await renderCustomerObservabilityHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
/* -----------------------------
   Customer UI: Maintenance
----------------------------- */
if (url.pathname === "/customer/maintenance" && request.method === "GET") {
  return text(await renderCustomerMaintenanceHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
/* -----------------------------
   Customer UI: Status
----------------------------- */
if (url.pathname === "/customer/status" && request.method === "GET") {
  return text(await renderCustomerStatusHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

/* -----------------------------
   Customer UI: Incidents
----------------------------- */
if (url.pathname === "/customer/incidents" && request.method === "GET") {
  return text(await renderCustomerIncidentsHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

if (url.pathname === "/admin/tenant-resolution" && request.method === "GET") {
  return text(await renderTenantResolutionHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}


      // Root sanity JSON
      if (url.pathname === "/health") {
        return json({ status: "ok", service: "ussignal-webex", time: new Date().toISOString() });
      }

      // Silence favicon errors
      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }
// Debug Access headers (plain text so Firefox can't "pretty viewer" hide it)
if (url.pathname === "/api/debug/access" && request.method === "GET") {
  if (env.DEBUG_MODE !== "true") {
  return json({ error: "disabled" }, 403);
}
  const out = {
    "cf-access-authenticated-user-email": request.headers.get("cf-access-authenticated-user-email"),
    "cf-access-user-email": request.headers.get("cf-access-user-email"),
    "cf-access-jwt-assertion-present": !!request.headers.get("cf-access-jwt-assertion"),
    "cf-ray": request.headers.get("cf-ray"),
    "host": request.headers.get("host"),
  };

  return new Response(JSON.stringify(out, null, 2), {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
     if (url.pathname === "/api/admin/debug-org-list") {
  const orgResult = await webexFetch(env, "/organizations");
  return json(orgResult.data.items.map(o => ({
    id: o.id,
    name: o.displayName
  })));
}

if (url.pathname === "/api/debug/whoami-webex") {
  const token = await getAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/people/me", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const txt = await res.text();
  return json({ status: res.status, body: txt.slice(0, 500) });
}
     if (url.pathname === "/api/debug/analytics-direct") {
  const token = await getAccessToken(env);
  const orgId = url.searchParams.get("orgId");

  const res = await fetch(
    `https://webexapis.com/v1/analytics/calling?orgId=${orgId}`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  const text = await res.text();

  return json({
    status: res.status,
    body: text.slice(0, 800)
  });
}

if (url.pathname === "/api/debug/partner-test") {
  const token = await getAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const text = await res.text();

  return json({
    status: res.status,
    body: text.slice(0, 800)
  });
}
     if (url.pathname === "/api/debug/orgs-direct") {
  const token = await getAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const text = await res.text();

  return json({
    status: res.status,
    body: text.slice(0, 500)
  });
}

if (url.pathname === "/api/debug/token-scope") {
  const token = await getAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/people/me", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const text = await res.text();

  return json({
    status: res.status,
    body: text.slice(0, 500)
  });
}
if (url.pathname === "/api/debug/org-context") {
  const token = await getAccessToken(env);

  const res = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const txt = await res.text();
  return json({ status: res.status, body: txt.slice(0, 1000) });
}
 if (url.pathname === "/api/debug/token-test") {
  if (env.DEBUG_MODE !== "true") {
    return json({ error: "disabled" }, 403);
  }
  const token = await getAccessToken(env);

  const test = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const text = await test.text();

  return json({
    status: test.status,
    body: text.slice(0, 500)
  });
}

//API/STATUS
// /api/status (GET) — maintenance-style with upstream fallback
// /api/status (GET)
if (url.pathname === "/api/status" && request.method === "GET") {

  const user = getCurrentUser(request);
  const session = user?.email ? await getSession(env, user.email) : null;

  if (!user || !user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }
  }

  try {
    const res = await fetch("https://status.webex.com/components.json");
    if (!res.ok) return json({ error: "status_fetch_failed" }, 500);

    const raw = await res.json();
    const comps = raw.components || [];

    // 1) Identify group rows + build lookup by id
    const groupById = {};
    for (const c of comps) {
      if (c.group === true) {
        groupById[c.id] = {
          id: c.id,
          name: c.name,
          status: c.status || "operational",
          children: []
        };
      }
    }

    // 2) Helper: put ungrouped items into a stable bucket
    function ensureUngrouped() {
      if (!groupById.__ungrouped) {
        groupById.__ungrouped = {
          id: "__ungrouped",
          name: "Other",
          status: "operational",
          children: []
        };
      }
      return groupById.__ungrouped;
    }

    // 3) Attach leaf components to their group_id parent
    for (const c of comps) {
      if (c.group === true) continue;

      const parentId = c.group_id || c.groupId || null;
      const parent = parentId && groupById[parentId] ? groupById[parentId] : ensureUngrouped();

      parent.children.push({
        id: c.id,
        name: c.name,
        status: c.status || "operational"
      });
    }

    // 4) Aggregate status up to parents
const severity = {
  major_outage: 5,
  critical: 5,
  partial_outage: 4,
  degraded_performance: 3,
  under_maintenance: 2,
  maintenance: 2,
  operational: 1
};

function aggStatus(statuses) {
  let worst = "operational";
  let worstScore = 1;

  for (const s of statuses) {
    const key = String(s || "operational").toLowerCase();
    const score = severity[key] || 1;
    if (score > worstScore) {
      worstScore = score;
      worst = key;
    }
  }

  return worst;
}

const components = Object.values(groupById)
  .filter(g => g.children.length > 0)
  .map(g => ({
    ...g,
    status: aggStatus(g.children.map(x => x.status))
  }));

const overall = aggStatus(components.map(c => c.status));

return json({
  lastUpdated: new Date().toISOString(),
  overall,
  components
});
} catch (e) {
  return json({ error: "status_engine_failed", message: e.message }, 500);
}
}

     
//api/incidents block
// /api/incidents (GET) — maintenance-style with upstream fallback
if (url.pathname === "/api/incidents" && request.method === "GET") {

  const user = getCurrentUser(request);
const session = user?.email ? await getSession(env, user.email) : null;

  if (!user || !user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }
  }

  try {

    return await cacheJson(
      300,
      "https://internal-cache/webex-incidents-v1",
      async () => {

        const unresolvedRes = await fetch(
          "https://status.webex.com/unresolved-incidents.json"
        );

        const allRes = await fetch(
          "https://status.webex.com/all-incidents.json"
        );

        const unresolved = unresolvedRes.ok
          ? (await unresolvedRes.json()).incidents || []
          : [];

        const baseIncidents = allRes.ok
  ? (await allRes.json()).incidents || []
  : [];

async function enrichIncident(incident) {
  try {
    const detailRes = await fetch(
      `https://status.webex.com/api/v2/incidents/${incident.id}.json`
    );

    if (!detailRes.ok) return incident;

    const detail = await detailRes.json();

    return {
      ...incident,
      updates: detail.incident?.incident_updates || incident.updates || [],
      fullData: detail.incident || null
    };

  } catch (e) {
    return incident;
  }
}

const all = await Promise.all(
  baseIncidents.map(enrichIncident)
);


        return {
          incidents: all,
          active: unresolved,
          counts: {
            active: unresolved.length,
            total: all.length
          },
          lastUpdated: new Date().toISOString()
        };
      }
    );

  } catch (e) {
    return json({ error: "incident_engine_failed", message: e.message }, 500);
  }
}

      ///api/maintenance block
     /* -----------------------------
   /api/maintenance
   - Uses official Webex JSON endpoints
   - Supports filtering by components
   - Edge cached
----------------------------- */
if (url.pathname === "/api/maintenance" && request.method === "GET") {

  const user = getCurrentUser(request);
const session = user?.email ? await getSession(env, user.email) : null;

  if (!user || !user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }

    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/pin?expired=1",
          "cache-control": "no-store"
        }
      });
    }
  }

  try {

    const cacheSeconds = 300;

    return await cacheJson(
      cacheSeconds,
      "https://internal-cache/webex-maintenance-v2",
      async () => {

        const upcomingRes = await fetch(
          "https://status.webex.com/upcoming-scheduled-maintenances.json"
        );

        const activeRes = await fetch(
          "https://status.webex.com/active-scheduled-maintenances.json"
        );

        const upcoming = upcomingRes.ok
          ? (await upcomingRes.json()).scheduled_maintenances || []
          : [];

        const active = activeRes.ok
          ? (await activeRes.json()).scheduled_maintenances || []
          : [];

        const all = [...active, ...upcoming];

        const normalized = all.map(m => {

          const update = m.updates?.[0];

          let body = update?.body || "";

          // Clean CDATA if present
          body = body
            .replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1")
            .trim();

          return {
            id: m.id,
            name: m.name,
            status: m.status,
            impact: m.impact,
            created_at: m.created_at,
            updated_at: m.updated_at,
            components: m.components || [],
            detailsHtml: body,   // 🔥 full HTML preserved
            updates: m.updates || []
          };
        });

        return {
          maintenance: normalized,
          counts: {
            upcoming: upcoming.length,
            active: active.length,
            total: normalized.length
          },
          lastUpdated: new Date().toISOString()
        };
      }
    );

  } catch (e) {
    return json({
      error: "maintenance_engine_failed",
      message: e.message
    }, 500);
  }
}

/* -----------------------------
   /api/components
   - Returns all Webex Status components
   - Normalized for filtering
----------------------------- */
if (url.pathname === "/api/components" && request.method === "GET") {

  let user;
  try {
    user = getCurrentUser(request);
  } catch (e) {
    return json({ error: "auth_failed" }, 401);
  }

  const session = user?.email ? await getSession(env, user.email) : null;

  if (!user || !user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }

    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/pin?expired=1",
          "cache-control": "no-store"
        }
      });
    }
  }

  try {

    const cache = caches.default;
    const cacheKey = new Request("https://internal-cache/webex-components");

    const cached = await cache.match(cacheKey);
    if (cached) return cached;

    const upstream = await fetch(
      "https://status.webex.com/components.json",
      { headers: { Accept: "application/json" } }
    );

    if (!upstream.ok) {
      return json({
        error: "components_upstream_failed",
        status: upstream.status
      }, 502);
    }

    const data = await upstream.json();

    const components = (data.components || []).map(c => ({
      id: c.id,
      name: c.name,
      status: c.status,
      group: c.group || null,
      description: c.description || null,
      updated_at: c.updated_at || null
    }));

    // Group by product group
    const grouped = {};

    for (const comp of components) {
      const groupName = comp.group || "Other";
      if (!grouped[groupName]) {
        grouped[groupName] = [];
      }
      grouped[groupName].push(comp);
    }

    const payload = {
      total: components.length,
      components,
      grouped,
      lastUpdated: new Date().toISOString()
    };

    const response = new Response(JSON.stringify(payload), {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300"
      }
    });

    await cache.put(cacheKey, response.clone());

    return response;

  } catch (e) {
    return json({
      error: "components_engine_failed",
      message: e.message
    }, 500);
  }
}
      /* -----------------------------
         /api/me
         - returns role
         - returns org context if session exists
      ----------------------------- */
  if (url.pathname === "/api/me") {

  const accessEmail =
    request.headers.get("cf-access-authenticated-user-email") ||
    request.headers.get("cf-access-user-email");

  if (!accessEmail) {
    return json({ error: "not_authenticated" }, 401);
  }

  const email = accessEmail.toLowerCase().trim();
  const isAdmin = email.endsWith("@ussignal.com");

  const session = await getSession(env, email);

  let resolvedOrg = null;

  if (!isAdmin && session && session.orgId) {
    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, email);
    } else {
      resolvedOrg = {
        orgId: session.orgId,
        orgName: session.orgName
      };
    }
  }

  return json({
    email,
    role: isAdmin ? "admin" : "customer",
    orgId: resolvedOrg?.orgId || null,
    orgName: resolvedOrg?.orgName || null,
    resolution: session ? "pin" : null,
    sessionExpiresInSeconds: session?.expiresAt
      ? Math.max(0, Math.floor((session.expiresAt - nowMs()) / 1000))
      : 0,
  });
}


      /* -----------------------------
         /api/pin/verify  (POST)
         Body: { "pin": "12345" }
         - verifies pin
         - creates session w/ TTL
         - throttles attempts (per email + ip)
      ----------------------------- */
      if (url.pathname === "/api/pin/verify" && request.method === "POST") {
        const user = getCurrentUser(request);
       
        const ip = getIP(request);

        // Admins don't need PIN; but allow admin to verify PIN for demo if desired
        const payload = await request.json().catch(() => ({}));
        const pin = String(payload.pin || "").trim();

        if (!isFiveDigitPin(pin)) {
          return json({ error: "invalid_pin_format", message: "PIN must be exactly 5 digits." }, 400);
        }

        // Throttle check
        const th = await throttleCheckOrThrow(env, user.email, ip);
        if (!th.allowed) {
          return json(
            { error: "too_many_attempts", message: `Too many attempts. Try again in ${th.retryAfter}s.` },
            429,
            { "retry-after": String(th.retryAfter) }
          );
        }

        const pinData = await getOrgByPin(env, pin);
        if (!pinData || !pinData.orgId) {
          await throttleRecordFailure(env, user.email, ip);
          // add small delay to slow brute forcing
          await sleep(200);
          return json({ error: "invalid_pin", message: "Invalid PIN." }, 403);
        }

        // success → clear throttles
        await throttleClear(env, user.email, ip);

        const session = {
          email: user.email,
          role: user.isAdmin ? "admin" : "customer",
          orgId: pinData.orgId,
          orgName: pinData.orgName,
          issuedAt: nowMs(),
          expiresAt: nowMs() + SESSION_TTL_SECONDS * 1000,
        };

       await setSession(env, user.email, session, SESSION_TTL_SECONDS);

        return json({
          status: "ok",
          orgId: session.orgId,
          orgName: session.orgName,
          sessionTtlSeconds: SESSION_TTL_SECONDS,
        });
      }

      /* -----------------------------
         /api/pin/logout (POST)
         - clears session
      ----------------------------- */
      if (url.pathname === "/api/pin/logout" && request.method === "POST") {
        const user = getCurrentUser(request);
        await clearSession(env, user.email);
        return json({ status: "ok" });
      }


     if (url.pathname === "/api/admin/pins" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const orgResult = await webexFetch(env, "/organizations");
  if (!orgResult.ok) {
    return json(
      { error: "org_list_failed", status: orgResult.status, preview: orgResult.preview },
      500
    );
  }

  const orgs = orgResult.data.items || [];

  // For each org, attempt to read org->pin mapping from KV
  const items = await Promise.all(
    orgs.map(async (o) => {
      const orgId = o.id;
      const orgName = o.displayName || o.name || "Unknown";
      const kv = await env.ORG_MAP_KV.get(`org:${orgId}`, { type: "json" });

      return {
        orgId,
        orgName,
        pin: kv?.pin || null,
        emails: kv?.emails || []
      };
    })
  );

  // Sort alphabetical
  items.sort((a, b) => (a.orgName || "").localeCompare(b.orgName || ""));

  return json({ ok: true, items }, 200);
}


if (url.pathname === "/api/admin/pin/allowlist" && request.method === "POST") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const body = await request.json().catch(() => ({}));
  const orgId = String(body.orgId || "").trim();
  const orgName = String(body.orgName || "").trim() || "Unknown Org";
  const emails = Array.isArray(body.emails) ? body.emails : [];

  if (!orgId) return json({ error: "missing_orgId" }, 400);

  await auditLog(env, user.email, url.pathname, {
    action: "pin_allowlist_update",
    orgId
  });

  // 1) Read existing org mapping FIRST (so we can delete old email:* keys)
  const existing = await env.ORG_MAP_KV.get(`org:${orgId}`, { type: "json" });
  const pin = existing?.pin || null;
  const role = existing?.role || "customer";

  if (!pin) {
    return json({
      error: "missing_pin_mapping",
      message: "No org->pin mapping exists for this org yet."
    }, 404);
  }

  // 2) Normalize incoming emails
  const normEmails = emails
    .map(e => String(e || "").toLowerCase().trim())
    .filter(Boolean);

  // 3) DELETE STALE email:* mappings (must happen BEFORE we overwrite org/pin)
  const oldEmails = Array.isArray(existing?.emails) ? existing.emails : [];
  await Promise.all(
    oldEmails.map(e =>
      env.ORG_MAP_KV.delete(`email:${String(e).toLowerCase().trim()}`)
    )
  );

  // 4) Overwrite org + pin mapping with the new allowlist
  await env.ORG_MAP_KV.put(`org:${orgId}`, JSON.stringify({
    pin, orgName, role, emails: normEmails
  }));

  await env.ORG_MAP_KV.put(`pin:${pin}`, JSON.stringify({
    orgId, orgName, role, emails: normEmails
  }));

  // 5) Write email:* mappings for the NEW allowlist
  await Promise.all(
    normEmails.map(e =>
      env.ORG_MAP_KV.put(`email:${e}`, JSON.stringify({
        orgId, orgName, role
      }))
    )
  );

  return json({ ok: true, orgId, orgName, pin, emails: normEmails }, 200);
}

if (url.pathname === "/api/admin/orgs" && request.method === "GET") {
  const token = await getAccessToken(env);
 const user = getCurrentUser(request);
if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);


const result = await webexFetch(env, "/organizations");

if (!result.ok) {
  return json({
    error: "org_list_failed",
    status: result.status,
    preview: result.preview
  }, 500);
}

return json({
  items: (result.data.items || []).map(o => ({
    orgId: o.id,
    orgName: o.displayName
  }))
});
}
      
if (url.pathname === "/api/admin/org-health") {
  const secret = request.headers.get("x-admin-secret");
const user = getCurrentUser(request);

const allowed =
  (secret && secret === env.ADMIN_SECRET) ||
  (user?.isAdmin === true);

if (!allowed) return json({ error: "admin_only" }, 403);


  const orgId = url.searchParams.get("orgId");
  if (!orgId) return json({ error: "missing_orgId" }, 400);

  let deficit = 0;
  let offline = 0;

  const licResult = await webexFetch(env, "/licenses", orgId);
  if (licResult.ok) {
    for (const x of licResult.data.items || []) {
      const total = Number(x.totalUnits ?? 0);
      const consumed = Number(x.consumedUnits ?? 0);
      if (Number.isFinite(total) && total >= 0) deficit += Math.max(0, consumed - total);
    }
  }

  const devResult = await webexFetch(env, "/devices", orgId);
  if (devResult.ok) {
    offline = (devResult.data.items || []).filter(d =>
      String(d.connectionStatus || "").toLowerCase() !== "connected"
    ).length;
  }

  return json({ orgId, deficit, offline });
}
      /* -----------------------------
         /api/org
         - Admin: returns all orgs
         - Customer: requires session; returns only matching org
      ----------------------------- */
     if (url.pathname === "/api/org") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  const session = await getSession(env, user.email);

  // customers require tenant resolution (email OR PIN)
  if (!user || !user.isAdmin) {
   if (!user.isAdmin && (!session || !session.orgId)) {
  return json({ error: "pin_required" }, 401);
}

  }

  // session expiry check
  if (session?.expiresAt && session.expiresAt <= nowMs()) {
    await clearSession(env, user.email);
    return json(
      { error: "pin_required_or_expired", message: "PIN required." },
      401
    );
  }

 const result = await webexFetch(env, "/organizations");

if (!result.ok) {
  throw new Error(`/organizations failed: ${result.status}`);
}

const orgData = result.data;

if (user.isAdmin) {
  return json(orgData.items || []);
}

const filtered = (orgData.items || []).filter(o => o.id === session.orgId);
return json(filtered);
}
/* -----------------------------
   /api/licenses
   - Admin: may specify ?orgId=...
   - Customer: resolved org only
----------------------------- */
/*if (url.pathname === "/api/licenses" && request.method === "GET") {
  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId = null;

  if (user.isAdmin) {
    resolvedOrgId = requestedOrgId || null;
  } else {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }
    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return json({ error: "pin_required_or_expired" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  const result = await webexFetch(env, "/licenses", resolvedOrgId);

  if (!result.ok) {
    return json({
      error: "webex_license_failed",
      status: result.status,
      preview: result.preview
    }, 500);
  }

  const licenses = result.data.items || [];

  const normalized = licenses.map(l => {
    const rawTotal = l.totalUnits;
    const rawConsumed = l.consumedUnits;

    const total = rawTotal == null ? null : Number(rawTotal);
    const consumed = Number(rawConsumed ?? 0);

    const isUnlimited = total === -1;
    const hasTotal = Number.isFinite(total);

    const available = isUnlimited ? -1 : (hasTotal ? Math.max(0, total - consumed) : null);
    const deficit = isUnlimited ? 0 : (hasTotal ? Math.max(0, consumed - total) : 0);

    let status = "OK";
    if (isUnlimited) status = "UNLIMITED";
    else if (!hasTotal) status = "UNKNOWN";
    else if (deficit > 0) status = "DEFICIT";
    else if (available === 0) status = "FULL";

    return { id:l.id, name:l.name, total, consumed, available, deficit, status };
  });

  const summary = {
    totalLicenses: normalized.length,
    totalConsumed: normalized.reduce((a,l)=>a+(l.consumed||0),0),
    totalDeficit: normalized.reduce((a,l)=>a+(l.deficit||0),0),
    hasDeficit: normalized.some(l=>l.status==="DEFICIT")
  };

  return json({ orgId: resolvedOrgId, summary, items: normalized });
} */
/* =====================================================
   /api/licenses (GET)
   Correct shape for admin/licenses page
===================================================== */

if (url.pathname === "/api/licenses" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ ok:false, error:"missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) {
      return json({ ok:false, error:"pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  const result = await webexFetchSafe(env, "/licenses", resolvedOrgId);

  if (!result.ok) {
    return json({
      ok:false,
      error:"webex_license_failed",
      status: result.status,
      preview: result.preview
    }, 200); // keep UI alive
  }

  const raw = result.data?.items || [];

  let totalConsumed = 0;
  let totalDeficit = 0;

  const items = raw.map(l => {
    const total = Number(l.totalUnits ?? 0);
    const consumed = Number(l.consumedUnits ?? 0);
    const available = total - consumed;

    const deficit = available < 0 ? Math.abs(available) : 0;

    const status =
      total === -1 ? "UNLIMITED" :
      deficit > 0 ? "DEFICIT" :
      available === 0 ? "FULL" :
      "HEALTHY";

    totalConsumed += consumed;
    totalDeficit += deficit;

    return {
      name: l.name,
      total,
      consumed,
      available,
      deficit,
      status
    };
  });

  return json({
    ok: true,
    orgId: resolvedOrgId,
    summary: {
      totalConsumed,
      totalDeficit,
      hasDeficit: totalDeficit > 0
    },
    items
  });
}

/* -----------------------------
   /api/devices
   - Admin: may specify ?orgId=...
   - Customer: resolved org only
----------------------------- */
/*if (url.pathname === "/api/devices" && request.method === "GET") {

  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId = null;

  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ error: "missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ error: "pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  const result = await webexFetch(env, "/devices", resolvedOrgId);

  if (!result.ok) {
    return json({ error: "webex_devices_failed" }, 500);
  }

  const raw = result.data.items || [];

  const normalized = raw.map(d => {
    const connected = String(d.connectionStatus || "").toLowerCase() === "connected";

    let status = "OK";
    let severity = 0;

    if (!connected) {
      status = "OFFLINE";
      severity = 2;
    }

    return {
      id: d.id,
      displayName: d.displayName,
      model: d.model,
      connectionStatus: d.connectionStatus,
      status,
      severity
    };
  });

  const summary = {
    totalDevices: normalized.length,
    connected: normalized.filter(d => d.status === "OK").length,
    offline: normalized.filter(d => d.status === "OFFLINE").length,
    hasOffline: normalized.some(d => d.status === "OFFLINE")
  };

  return json({
    orgId: resolvedOrgId,
    summary,
    items: normalized
  });
} */
/* =====================================================
   /api/devices (GET)
   Clean, normalized contract for admin/devices
===================================================== */

if (url.pathname === "/api/devices" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error: "access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ ok:false, error: "missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) {
      return json({ ok:false, error: "pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  const result = await webexFetchSafe(env, "/devices", resolvedOrgId);

  if (!result.ok) {
    return json({
      ok:false,
      error: "webex_devices_failed",
      status: result.status,
      preview: result.preview
    }, 200);
  }

  const raw = result.data?.items || [];

  let online = 0;
  let offline = 0;
  let unknown = 0;

  const normalized = raw.map(d => {

    const connection = String(d.connectionStatus || "").toLowerCase();

    const isOnline =
      connection.includes("connected") ||
      connection.includes("online") ||
      connection.includes("registered");

    const status =
      isOnline ? "ONLINE" :
      connection.includes("offline") ||
      connection.includes("disconnected") ? "OFFLINE" :
      "UNKNOWN";

    if (status === "ONLINE") online++;
    else if (status === "OFFLINE") offline++;
    else unknown++;

    const lastSeen =
      d.lastSeen ||
      d.lastSeenTime ||
      d.lastActivityTime ||
      null;

    let lastSeenAgeHours = null;
    if (lastSeen) {
      const diff = Date.now() - new Date(lastSeen).getTime();
      if (!isNaN(diff)) {
        lastSeenAgeHours = Math.round(diff / 36e5);
      }
    }

    const deviceType =
      d.workspaceLocationId ? "WORKSPACE" :
      d.personId ? "USER" :
      "UNKNOWN";

    return {
      id: d.id,
      name: d.displayName || d.name || "—",
      model: d.model || d.product || "—",
      product: d.product || null,

      connectionStatus: d.connectionStatus || "UNKNOWN",
      status,

      locationId: d.workspaceLocationId || d.locationId || null,
      locationName: d.workspaceLocationName || null,

      mac: d.mac || null,
      ip: d.ipAddress || null,

      deviceType,
      lastSeen,
      lastSeenAgeHours,

      healthLevel:
        status === "ONLINE" ? "green" :
        status === "OFFLINE" ? "red" :
        "yellow",

      severity:
        status === "ONLINE" ? 0 :
        status === "OFFLINE" ? 2 :
        1,

      raw: d
    };
  });

  return json({
    ok: true,
    orgId: resolvedOrgId,
    summary: {
      totalDevices: normalized.length,
      online,
      offline,
      unknown
    },
    items: normalized
  });
}
/* -----------------------------
   /api/licenses/email
   Sends license report via Brevo
----------------------------- */
if (url.pathname === "/api/licenses/email" && request.method === "POST") {
  const user = getCurrentUser(request);

  const body = await request.json().catch(() => ({}));
  const toEmail = String(body.email || "").toLowerCase().trim();
  const requestedOrgId = normalizeOrgIdParam(body.orgId);

  if (!toEmail) return json({ error: "missing_email" }, 400);

  // Resolve org context
  const session = await getSession(env, user.email);
  let resolvedOrgId = null;

  if (user.isAdmin) {
    resolvedOrgId = requestedOrgId || null; // null = partner-default behavior (may or may not work per endpoint)
  } else {
    if (!session?.orgId) return json({ error: "pin_required" }, 401);
    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return json({ error: "pin_required_or_expired" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  // Pull licenses directly from Webex
  const result = await webexFetch(env, "/licenses", resolvedOrgId);

  if (!result.ok) {
    return json({
      error: "license_fetch_failed",
      status: result.status,
      preview: result.preview
    }, 500);
  }

  // Normalize like /api/licenses does
  const normalized = (result.data.items || []).map(l => {
    const total = l.totalUnits == null ? null : Number(l.totalUnits);
    const consumed = Number(l.consumedUnits ?? 0);

    const isUnlimited = total === -1;
    const hasTotal = Number.isFinite(total);

    const available = isUnlimited ? -1 : (hasTotal ? Math.max(0, total - consumed) : null);
    const deficit = isUnlimited ? 0 : (hasTotal ? Math.max(0, consumed - total) : 0);

    let status = "OK";
    if (isUnlimited) status = "UNLIMITED";
    else if (!hasTotal) status = "UNKNOWN";
    else if (deficit > 0) status = "DEFICIT";
    else if (available === 0) status = "FULL";

    return { name: l.name, consumed, available, deficit, status };
  });

  const rows = normalized.map(l => `
    <tr>
      <td>${escapeHtml(String(l.name || ""))}</td>
      <td>${l.consumed}</td>
      <td>${l.available === -1 ? "Unlimited" : (l.available == null ? "Unknown" : l.available)}</td>
      <td>${l.deficit}</td>
      <td>${l.status}</td>
    </tr>
  `).join("");

  const html = `
    <h2>Webex Calling License Report</h2>
    <p>Generated for ${escapeHtml(user.email)}</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr>
        <th>License</th>
        <th>Assigned</th>
        <th>Available</th>
        <th>Deficit</th>
        <th>Status</th>
      </tr>
      ${rows}
    </table>
  `;

  const senderEmail =
    env.LICENSE_REPORT_FROM ||
    env.BREVO_SENDER_EMAIL ||
    "no-reply@ussignal.onenecklab.com";

  const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "api-key": env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { email: senderEmail, name: "US Signal Licensing" },
      to: [{ email: toEmail }],
      subject: "Webex Calling License Report",
      htmlContent: html,
    }),
  });

  const brevoText = await brevoRes.text();
  if (!brevoRes.ok) {
    console.error("Brevo error:", brevoText);
    return json({ error: "brevo_failed", status: brevoRes.status, body: brevoText }, 500);
  }

  return json({ status: "sent", to: toEmail });
}
/* =====================================================
   Tenant Resolution
===================================================== */
if (url.pathname.startsWith("/api/admin/tenant-resolution/")) {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  if (!orgId) {
    return json({ ok:false, error:"missing_orgId" }, 400);
  }

  const minutes = clampInt(url.searchParams.get("minutes"), 1440, 5, 10080);
  const baselineMinutes = clampInt(url.searchParams.get("baselineMinutes"), 10080, 60, 43200);
  const target = parseFloat(url.searchParams.get("target") || "99.9");

  const action = url.pathname.split("/").pop();

  // =====================================================
  // CDR
  // =====================================================
  if (action === "cdr") {

    const now = new Date().toISOString();
    const from = new Date(Date.now() - minutes * 60000).toISOString();

    const feed = await webexFetchSafe(
      env,
      `/cdr_feed?startTime=${encodeURIComponent(from)}&endTime=${encodeURIComponent(now)}&max=1000`,
      orgId
    );

    if (!feed.ok) {
      return json({ ok:false, error:"cdr_failed" }, 200);
    }

    const items = normalizeCdrItems(feed.data);

    const totalCalls = items.length;
    const failed = items.filter(x => x.failed).length;
    const failRate = totalCalls ? (failed / totalCalls) * 100 : 0;

    return json({
      ok:true,
      summary:{
        totalCalls,
        failedCalls: failed,
        failRate,
        evidenceId: crypto.randomUUID(),
        source:"cdr_feed"
      },
      topCauses: [],
      hotspots: [],
      buckets: []
    });
  }

  // =====================================================
  // TRUNKS
  // =====================================================
  if (action === "trunks") {

    const trunks = await webexFetchSafe(
      env,
      "/telephony/config/premisePstn/trunks",
      orgId
    );

    return json({
      ok:true,
      trunks: trunks.ok ? trunks.data?.items || [] : []
    });
  }

  // =====================================================
  // DI HEALTH (stub)
  // =====================================================
  if (action === "di-health") {
    return json({
      ok:true,
      enabled:false
    });
  }

  // =====================================================
  // SCORE (stub logic)
  // =====================================================
  if (action === "score") {
    return json({
      ok:true,
      score: 20,
      anomaly: { label:"Normal variance" }
    });
  }

  // =====================================================
  // SLA
  // =====================================================
  if (action === "sla") {
    return json({
      ok:true,
      okStatus:true,
      label:`Above ${target}% target`
    });
  }

  return json({ ok:false, error:"unknown_tenant_resolution_action" }, 404);
}
     
/* =====================================================
   CUSTOMER-SCOPED ROUTES
   Mirrors Partner Portal contract
===================================================== */

// =====================================================
// CUSTOMER ROUTES
// /api/customer/:key/:action
// =====================================================
if (url.pathname.startsWith("/api/customer/")) {

  const user = getCurrentUser(request);
  const session = user?.email
    ? await getSession(env, user.email)
    : null;

  // Require admin OR valid session with org
  if (!user || (!user.isAdmin && !session?.orgId)) {
    return json({ ok:false, error:"pin_required" }, 401);
  }

  const parts = url.pathname.split("/");
  const key = parts[3];
  const action = parts[4];

  let resolvedOrgId = null;

  if (user.isAdmin) {
    resolvedOrgId = await resolveOrgIdForAdmin(env, key);
  } else {
    resolvedOrgId = session.orgId;
  }

  if (!resolvedOrgId) {
    return json({ ok:false, error:"org_not_resolved" }, 400);
  }

  // Utility
  const safeJson = (v, fallback = null) =>
    v && typeof v === "object" ? v : fallback;

  // ----------------------------------------------------
  // LICENSES
  // ----------------------------------------------------
  if (action === "licenses") {
    const result = await webexFetchSafe(env, "/licenses", resolvedOrgId);
    return json({
      ok: result.ok,
      items: result.ok ? (result.data?.items || []) : [],
      error: result.ok ? null : "webex_license_failed"
    }, 200);
  }

  // ----------------------------------------------------
  // DEVICES
  // ----------------------------------------------------
  if (action === "devices") {
    const result = await webexFetchSafe(env, "/devices", resolvedOrgId);
    return json({
      ok: result.ok,
      devices: result.ok ? (result.data?.items || []) : [],
      error: result.ok ? null : "webex_devices_failed"
    }, 200);
  }

  // ----------------------------------------------------
  // ANALYTICS
  // ----------------------------------------------------
  if (action === "analytics") {
    const result = await webexFetchSafe(env, CALLING_ANALYTICS_PATH, resolvedOrgId);
    return json({
      ok: result.ok,
      analytics: result.ok ? result.data : {},
      error: result.ok ? null : "webex_analytics_failed"
    }, 200);
  }

  // ----------------------------------------------------
  // CDR
  // ----------------------------------------------------
  if (action === "cdr") {

    const now = new Date().toISOString();
    const windowDays = Math.min(Number(url.searchParams.get("days") || 7), 30);
    const from = new Date(Date.now() - windowDays * 86400000).toISOString();
    const max = 100;

    const try1 = await webexFetchSafe(
      env,
      `/cdr_feed?startTime=${encodeURIComponent(from)}&endTime=${encodeURIComponent(now)}&max=${max}`,
      resolvedOrgId
    );

    const try2 = try1.ok ? null : await webexFetchSafe(
      env,
      `/cdr/calls?startTime=${encodeURIComponent(from)}&endTime=${encodeURIComponent(now)}&max=${max}`,
      resolvedOrgId
    );

    const picked = try1.ok ? try1 : try2;

    if (!picked || !picked.ok) {
      return json({
        ok:false,
        error:"cdr_unavailable"
      }, 200);
    }

    const records = normalizeCdrItems(picked.data);

    return json({
      ok:true,
      source: try1.ok ? "cdr_feed" : "cdr_calls",
      count: records.length,
      records
    }, 200);
  }

  // ----------------------------------------------------
  // PSTN SNAPSHOT (KV-backed)
  // ----------------------------------------------------
  if (action === "pstn") {

    try {

      const kvKey = `pstn:${resolvedOrgId}`;
      const snap = await env.WEBEX.get(kvKey, { type: "json" });

      const isExpired =
        snap?.generatedAt &&
        (Date.now() - new Date(snap.generatedAt).getTime()) > (15 * 60 * 1000);

      if (!snap || !snap.totals || isExpired) {

        const lockKey = `pstnRebuildLock:${resolvedOrgId}`;
        const existingLock = await env.WEBEX.get(lockKey);

        if (existingLock) {
          return json({
            ok:true,
            pstn: safeJson(snap, {}),
            source:"kv_stale",
            rebuilding:true
          }, 200);
        }

        await env.WEBEX.put(lockKey, "1", { expirationTtl: 60 });

        const rebuilt = await buildPstnDeep(env, resolvedOrgId);

        const enriched = {
          ...rebuilt,
          generatedAt: new Date().toISOString()
        };

        await storePstnSnapshot(env, resolvedOrgId, enriched);
        await env.WEBEX.delete(lockKey);

        return json({
          ok:true,
          pstn: enriched,
          source:"rebuilt"
        }, 200);
      }

      return json({
        ok:true,
        pstn: snap,
        source:"kv"
      }, 200);

    } catch (err) {
      return json({
        ok:true,
        pstn:{},
        error:"pstn_read_failed"
      }, 200);
    }
  }

  // ----------------------------------------------------
  // PSTN TREND
  // ----------------------------------------------------
  if (action === "pstn-trend") {
    const trend = await env.WEBEX.get(
      `pstnTrend:${resolvedOrgId}`,
      { type:"json" }
    );

    return json({
      ok:true,
      trend: safeJson(trend)?.items || []
    }, 200);
  }

  // ----------------------------------------------------
  // PSTN PREDICT
  // ----------------------------------------------------
  if (action === "pstn-predict") {

    const trend = await env.WEBEX.get(
      `pstnTrend:${resolvedOrgId}`,
      { type:"json" }
    );

    const items = safeJson(trend)?.items || [];

    const pstnSnap = await env.WEBEX.get(
      `pstn:${resolvedOrgId}`,
      { type:"json" }
    );

    const totalDids = Number(pstnSnap?.totals?.didsTotal || 0);

    const prediction = predictDidExhaustion(
      items,
      totalDids,
      7
    );

    return json({
      ok:true,
      prediction,
      last: items.length ? items[items.length - 1] : null
    }, 200);
  }

  // ----------------------------------------------------
  // PSTN DEEP
  // ----------------------------------------------------
  if (action === "pstn-deep") {
    try {
      const pstn = await buildPstnDeep(env, resolvedOrgId);
      return json({ ok:true, pstn }, 200);
    } catch {
      return json({ ok:true, pstn:{} }, 200);
    }
  }

  // ----------------------------------------------------
  // HEALTH SNAPSHOT
  // ----------------------------------------------------
  if (action === "health") {
    const health = await env.WEBEX.get(
      `health:${resolvedOrgId}`,
      { type:"json" }
    );
    return json({ ok:true, health: health || null }, 200);
  }

  // ----------------------------------------------------
  // CALL QUALITY SNAPSHOT
  // ----------------------------------------------------
  if (action === "call-quality") {
    const quality = await env.WEBEX.get(
      `quality:${resolvedOrgId}`,
      { type:"json" }
    );
    return json({ ok:true, quality: quality || null }, 200);
  }

  // ----------------------------------------------------
  // UNKNOWN ACTION
  // ----------------------------------------------------
  return json({ ok:false, error:"unknown_customer_action" }, 404);
}
     
      /* -----------------------------
         /api/admin/pin/rotate (POST)
         Admin-only: rotate PIN for an org
         Body:
           { "orgId": "...", "orgName": "..." }   // orgName optional but recommended
         Returns:
           { oldPin, newPin, orgId, orgName }
      ----------------------------- */
     if (url.pathname === "/api/admin/pin/rotate" && request.method === "POST") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const body = await request.json().catch(() => ({}));
  const orgId = String(body.orgId || "").trim();
  const providedName = String(body.orgName || "").trim();

  if (!orgId) return json({ error: "missing_orgId" }, 400);

  await auditLog(env, user.email, url.pathname, {
    action: "pin_rotate",
    orgId
  });

  const existing = await getPinByOrg(env, orgId);
  const oldPin = existing?.pin || null;
  const orgName = providedName || existing?.orgName || "Unknown Org";
  const role = existing?.role || "customer";
  const emails = existing?.emails || [];

  const newPin = await generateUniqueNonEasyPin(env);

  await putPinMapping(env, newPin, orgId, orgName, role, emails);

  if (oldPin && /^\d{5}$/.test(oldPin)) {
    await env.ORG_MAP_KV.delete(`pin:${oldPin}`);
  }

  return json({
    status: "ok",
    orgId,
    orgName,
    oldPin,
    newPin
  });
}

async function jsonSafe(res) {
  const txt = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(txt), preview: txt.slice(0, 400) }; }
  catch { return { ok: false, status: res.status, error: "not_json", preview: txt.slice(0, 400) }; }
}

function makeCacheKey(urlStr){
  return new Request(urlStr, { method:"GET" });
}

async function cacheJson(cacheSeconds, urlStr, computeFn){
  const cache = caches.default;
  const key = makeCacheKey(urlStr);

  if (cacheSeconds > 0) {
    const hit = await cache.match(key);
    if (hit) return hit;
  }

  const payload = await computeFn();

  const resp = new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "content-type":"application/json",
      "cache-control": cacheSeconds > 0 ? `public, max-age=${cacheSeconds}` : "no-store"
    }
  });

  if (cacheSeconds > 0) {
    await cache.put(key, resp.clone());
  }

  return resp;
}

      /* -----------------------------
         /api/admin/pin/list (POST)
         Admin-only: returns current org->pin mappings (best-effort)
         NOTE: KV can't list keys here; so this endpoint expects you to pass orgIds if needed.
         For demo, you can skip this.
      ----------------------------- */
      if (url.pathname === "/api/admin/pin/list" && request.method === "POST") {
        const user = getCurrentUser(request);
        const token = await getAccessToken(env);
        if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

        const body = await request.json().catch(() => ({}));
        const orgIds = Array.isArray(body.orgIds) ? body.orgIds : [];
        const out = [];

        for (const orgId of orgIds) {
          const v = await getPinByOrg(env, String(orgId));
          if (v?.pin) out.push({ orgId, pin: v.pin, orgName: v.orgName || null });
        }
        return json(out);
      }
     /* =====================================================
   🔬 ADMIN: PARTNER SCOPE DIAGNOSTICS
   Tests partner-level scopes and APIs
===================================================== */
if (url.pathname === "/api/admin/diagnostics" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const tests = {};

  async function test(name, path) {
    const result = await webexFetch(env, path);
    tests[name] = {
      ok: result.ok,
      status: result.status,
      preview: result.preview?.slice(0, 200)
    };
  }

  await test("partner_organizations", "/organizations");
  await test("reports", "/reports");
  await test("wholesale_customers", "/wholesale/customers");

  return json({
    ok: true,
    testedAt: new Date().toISOString(),
    tests
  });
}
     /* =====================================================
   📊 ADMIN: GLOBAL SUMMARY SNAPSHOT
===================================================== */

// =====================================================
// ADMIN GLOBAL SUMMARY (read-only)
// =====================================================
if (url.pathname === "/api/admin/global-summary" && request.method === "GET") {

  const secret = request.headers.get("x-admin-secret");
  const user = getCurrentUser(request);

  const allowed =
    (secret && secret === env.ADMIN_SECRET) ||
    (user?.isAdmin === true);

  if (!allowed) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  try {
    const snapshot = await getGlobalSummarySnapshot(env);

    if (!snapshot) {
      return json({
        ok:true,
        available:false,
        message:"No snapshot available yet"
      }, 200);
    }

    return json({
      ok:true,
      available:true,
      snapshot,
      _meta:{
        servedAt: new Date().toISOString(),
        source:"kv_snapshot"
      }
    }, 200);

  } catch (err) {
    return json({
      ok:true,
      available:false,
      error:"global_summary_read_failed",
      message:String(err)
    }, 200);
  }
}



// =====================================================
// ADMIN GLOBAL SUMMARY REFRESH
// =====================================================
if (url.pathname === "/api/admin/global-summary/refresh" && request.method === "POST") {

  const secret = request.headers.get("x-admin-secret");
  let user = null;

  const usingSecret = secret && secret === env.ADMIN_SECRET;

  if (!usingSecret) {
    try {
      user = getCurrentUser(request);
    } catch {
      return json({ ok:false, error:"Unauthorized" }, 401);
    }

    if (!user || !user.isAdmin) {
      return json({ ok:false, error:"Unauthorized" }, 401);
    }
  }

  try {

    // prevent concurrent refresh storms
    const lockKey = "globalSummaryRefreshLock";
    const existingLock = await env.WEBEX.get(lockKey);

    if (existingLock) {
      return json({
        ok:false,
        message:"Refresh already in progress"
      }, 429);
    }

    // short lock (60 seconds)
    await env.WEBEX.put(lockKey, "1", { expirationTtl: 60 });

    const startedAt = Date.now();

    const payload = await computeGlobalSummary(env);

    await putGlobalSummarySnapshot(env, {
      ...payload,
      generatedAt: new Date().toISOString()
    });

    await env.WEBEX.delete(lockKey);

    return json({
      ok:true,
      refreshedAt: new Date().toISOString(),
      totalOrgs: payload.totalOrgs,
      durationMs: Date.now() - startedAt
    }, 200);

  } catch (err) {

    await env.WEBEX.delete("globalSummaryRefreshLock");

    return json({
      ok:false,
      error:"global_summary_refresh_failed",
      message:String(err)
    }, 500);
  }
}



// =====================================================
// ADMIN GLOBAL SUMMARY CLEAR
// =====================================================
if (url.pathname === "/api/admin/global-summary/clear" && request.method === "POST") {

  const secret = request.headers.get("x-admin-secret");
  const user = getCurrentUser(request);

  const allowed =
    (secret && secret === env.ADMIN_SECRET) ||
    (user?.isAdmin === true);

  if (!allowed) {
    return json({ ok:false, error:"Forbidden" }, 403);
  }

  try {

    await env.WEBEX.delete("globalSummarySnapshotV1");

    return json({
      ok:true,
      message:"Snapshot cleared",
      clearedAt:new Date().toISOString()
    }, 200);

  } catch (err) {
    return json({
      ok:false,
      error:"clear_failed",
      message:String(err)
    }, 500);
  }
}
/* =====================================================
   🔬 ADMIN: ORG-SCOPED DIAGNOSTICS
===================================================== */
if (url.pathname.startsWith("/api/admin/diagnostics/org/") && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const orgId = decodeURIComponent(url.pathname.split("/").pop());

  const tests = {};

  async function test(name, path) {
    const result = await webexFetch(env, path, orgId);
    tests[name] = {
      ok: result.ok,
      status: result.status,
      preview: result.preview?.slice(0, 200)
    };
  }

  await test("licenses", "/licenses");
  await test("devices", "/devices");
  await test("analytics_calling", CALLING_ANALYTICS_PATH);
  await test("cdr", "/cdr/calls?max=1");
  await test("pstn_locations", "/telephony/config/locations");

  return json({
    ok: true,
    orgId,
    testedAt: new Date().toISOString(),
    tests
  });
}

      /* =====================================================
   🔍 ADMIN INSPECTION ENDPOINTS (READ-ONLY)
   ===================================================== */

/* -----------------------------
   GET /api/admin/inspect/email/:email
----------------------------- */
if (url.pathname.startsWith("/api/admin/inspect/email/") && request.method === "GET") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const email = decodeURIComponent(url.pathname.split("/").pop()).toLowerCase();

  const record = await env.ORG_MAP_KV.get(`email:${email}`, { type: "json" });

  return json({
    lookup: `email:${email}`,
    found: !!record,
    record: record || null,
  });
}

/* -----------------------------
   GET /api/admin/inspect/pin/:pin
----------------------------- */
if (url.pathname.startsWith("/api/admin/inspect/pin/") && request.method === "GET") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const pin = url.pathname.split("/").pop();

  if (!/^\d{5}$/.test(pin)) {
    return json({ error: "invalid_pin_format" }, 400);
  }

  const record = await env.ORG_MAP_KV.get(`pin:${pin}`, { type: "json" });

  return json({
    lookup: `pin:${pin}`,
    found: !!record,
    record: record || null,
  });
}

/* -----------------------------
   GET /api/admin/inspect/org/:orgId
----------------------------- */
if (url.pathname.startsWith("/api/admin/inspect/org/") && request.method === "GET") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const orgId = decodeURIComponent(url.pathname.split("/").pop());

  const record = await env.ORG_MAP_KV.get(`org:${orgId}`, { type: "json" });

  return json({
    lookup: `org:${orgId}`,
    found: !!record,
    record: record || null,
  });
}
/* =====================================================
   🧭 ADMIN: TENANT RESOLUTION INSPECTOR
   ===================================================== */

if (url.pathname === "/api/admin/resolve" && request.method === "POST") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  if (!user || !user.isAdmin) return json({ error: "admin_only" }, 403);

  const body = await request.json().catch(() => ({}));
  const email = body.email?.toLowerCase()?.trim() || null;
  const pin = body.pin?.trim() || null;
  const orgId = body.orgId?.trim() || null;

  const result = {
    input: { email, pin, orgId },
    kv: {},
    resolution: null,
  };

  if (email) {
    result.kv.email = await env.ORG_MAP_KV.get(`email:${email}`, { type: "json" });
  }

  if (pin && /^\d{5}$/.test(pin)) {
    result.kv.pin = await env.ORG_MAP_KV.get(`pin:${pin}`, { type: "json" });
  }

  if (orgId) {
    result.kv.org = await env.ORG_MAP_KV.get(`org:${orgId}`, { type: "json" });
  }

  // Resolution precedence (matches runtime logic)
  if (result.kv.email) {
    result.resolution = {
      method: "email",
      orgId: result.kv.email.orgId,
      orgName: result.kv.email.orgName,
    };
  } else if (result.kv.pin) {
    result.resolution = {
      method: "pin",
      orgId: result.kv.pin.orgId,
      orgName: result.kv.pin.orgName,
    };
  }

  return json(result);
}
/*if (url.pathname === "/api/analytics" && request.method === "GET") {
  return await apiCallingAnalytics(env, request);
}*/
   if (url.pathname === "/api/analytics" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ ok:false, error:"missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) {
      return json({ ok:false, error:"pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  const now = new Date();
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const from = sevenDaysAgo.toISOString();
  const to = now.toISOString();

  const path =
    `/analytics/calling/callRecords` +
    `?from=${encodeURIComponent(from)}` +
    `&to=${encodeURIComponent(to)}`;

  const result = await webexFetchSafe(env, path, resolvedOrgId);

  if (!result.ok) {
    return json({
      ok:false,
      orgId: resolvedOrgId,
      error:"webex_analytics_failed",
      upstreamStatus: result.status,
      upstreamPreview: result.preview
    }, 200); // 🔥 never crash UI
  }

  const records = result.data?.items || [];

  const volume7d = records.length;

  const last24h = records.filter(r =>
    new Date(r.startTime) > new Date(Date.now() - 24*60*60*1000)
  ).length;

  const failedCalls = records.filter(r =>
    r.callResult && r.callResult.toLowerCase().includes("fail")
  ).length;

  const peakConcurrency = Math.max(1, Math.round(volume7d / 24));

  const availabilityPercent =
    volume7d === 0 ? 100 :
    Math.max(90, 100 - (failedCalls / volume7d) * 100);

  return json({
    ok:true,
    orgId: resolvedOrgId,
    volume7d,
    volume24h: last24h,
    peakConcurrency,
    failedCalls,
    availabilityPercent: Number(availabilityPercent.toFixed(2))
  }, 200);
}
/* if (url.pathname === "/api/cdr" && request.method === "GET") {
  return await apiCDR(env, request);
} */
 if (url.pathname === "/api/cdr" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ error: "access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ error: "missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) {
      return json({ error: "pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  const windowDays = Math.min(Number(url.searchParams.get("days") || 7), 30);
  const max = Math.min(Number(url.searchParams.get("max") || 200), 1000);

  const now = new Date().toISOString();
  const from = new Date(
    Date.now() - windowDays * 24 * 60 * 60 * 1000
  ).toISOString();

  // 🔹 Try CDR Feed first
  const feedPath =
    `/cdr_feed?startTime=${encodeURIComponent(from)}` +
    `&endTime=${encodeURIComponent(now)}` +
    `&max=${max}`;

  const tryFeed = await webexFetchSafe(env, feedPath, resolvedOrgId);

  // 🔹 Fallback to legacy CDR
  let tryCalls = null;
  if (!tryFeed.ok) {
    const callsPath =
      `/cdr/calls?startTime=${encodeURIComponent(from)}` +
      `&endTime=${encodeURIComponent(now)}` +
      `&max=${max}`;

    tryCalls = await webexFetchSafe(env, callsPath, resolvedOrgId);
  }

  const picked = tryFeed.ok ? tryFeed : tryCalls;

  if (!picked || !picked.ok) {
    return json({
      ok: false,
      orgId: resolvedOrgId,
      error: "cdr_unavailable",
      upstreamStatus: picked?.status ?? 0,
      upstreamPreview: picked?.preview ?? null
    }, 200); // 🔥 never crash UI
  }

  const records = normalizeCdrItems(picked.data);

  return json({
    ok: true,
    orgId: resolvedOrgId,
    source: tryFeed.ok ? "cdr_feed" : "cdr_calls",
    windowDays,
    count: records.length,
    records
  }, 200);
}

     /* -----------------------------
   /api/pstn (GET)
   - Admin: requires ?orgId=
   - Customer: uses session orgId (ignores query)
   - Returns KV snapshot if present; can force rebuild with ?refresh=1
----------------------------- */
/*if (url.pathname === "/api/pstn" && request.method === "GET") {
  const user = getCurrentUser(request);
  const session = user?.email ? await getSession(env, user.email) : null;

  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const refresh = url.searchParams.get("refresh") === "1";

  let resolvedOrgId = null;

  if (user?.isAdmin) {
    if (!requestedOrgId) return json({ error: "missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ error: "pin_required" }, 401);
    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return json({ error: "pin_required_or_expired" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  // Prefer snapshot (fast)
  if (!refresh) {
    const snap = await env.WEBEX.get(`pstn:${resolvedOrgId}`, { type: "json" });
    if (snap) return json({ ok: true, orgId: resolvedOrgId, pstn: snap, source: "kv" }, 200);
  }

  // Rebuild on-demand (slower)
  try {
    const pstn = await buildPstnDeep(env, resolvedOrgId);
    await storePstnSnapshot(env, resolvedOrgId, pstn);
    return json({ ok: true, orgId: resolvedOrgId, pstn, source: "rebuild" }, 200);
  } catch (e) {
    console.error("api/pstn failed:", e);
    return json({ ok: false, error: "pstn_failed", message: e.message }, 500);
  }
} */

// =====================================================
// /api/pstn (GET) — hardened multi-tenant + caching + summary
// - Always scopes org via ?orgId= (NO header switching / NO null orgId)
// - Adds short TTL cache (Cloudflare Cache API) to reduce Webex calls
// - Adds lightweight org-level summary endpoint: /api/pstn/summary
// =====================================================

// ---------- Cache helpers (place near your other helpers if you want) ----------
function cacheKeyFromRequest(request, suffix = "") {
  // Cache varies by URL (includes orgId), plus a suffix for endpoint versioning.
  const u = new URL(request.url);
  u.searchParams.sort?.(); // safe in modern runtimes; no-op if undefined
  u.hash = "";
  // Ensure cache key is stable
  return new Request(u.toString() + (suffix ? `#${suffix}` : ""), request);
}

async function cacheGetJson(request) {
  try {
    const cache = caches.default;
    const hit = await cache.match(request);
    if (!hit) return null;
    // only cache JSON responses we created
    const ct = hit.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return null;
    return await hit.json();
  } catch {
    return null;
  }
}

async function cachePutJson(cacheKeyReq, payload, ttlSeconds = 60) {
  try {
    const cache = caches.default;
    const headers = new Headers({
      "Content-Type": "application/json; charset=utf-8",
      // Cache in CF edge for ttlSeconds; clients still get fresh-ish data
      "Cache-Control": `public, max-age=${ttlSeconds}`,
      // Helpful for debugging
      "X-Cache-TTL": String(ttlSeconds)
    });
    const res = new Response(JSON.stringify(payload), { status: 200, headers });
    await cache.put(cacheKeyReq, res);
  } catch {
    // ignore cache failures; never break API response
  }
}

function clampInt(v, def, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function getLocId(obj) {
  return (
    obj?.locationId ||
    obj?.callingLocationId ||
    obj?.location?.id ||
    obj?.location?.locationId ||
    null
  );
}

function normalizePstnType(conn) {
  const t = String(
    conn?.connectionType ||
    conn?.type ||
    conn?.pstnType ||
    ""
  ).toUpperCase();

  if (!t) return "NO_PSTN";
  if (t.includes("CLOUD")) return "CLOUD_CONNECT";
  if (t.includes("CISCO")) return "CISCO_PSTN";
  if (t.includes("PREMISE") || t.includes("LOCAL") || t.includes("GATEWAY"))
    return "LOCAL_GATEWAY";
  return "UNKNOWN";
}

function computeCapacityScore(totalTrunks) {
  if (totalTrunks === 0) return 0;
  if (totalTrunks === 1) return 75;
  return 95;
}

// -----------------------------------------------------
// 1) Org-level PSTN summary endpoint
// -----------------------------------------------------
// =====================================================
// PSTN SUMMARY (fast, org-level, no fan-out)
// =====================================================
if (
  (url.pathname === "/api/pstn/summary" || url.pathname === "/api/pstn/summary/") &&
  request.method === "GET"
) {
  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;
  if (user.isAdmin) {
    if (!requestedOrgId) {
      return json({ ok:false, error:"missing_orgId" }, 400);
    }
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) {
      return json({ ok:false, error:"pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  // -----------------------------------------------------
  // Cache controls
  // -----------------------------------------------------
  const ttl = clampInt(url.searchParams.get("ttl"), 180, 60, 900);
  const cacheKey = `pstn_summary:${resolvedOrgId}`;

  const cached = await cacheGetJson(cacheKey);
  if (cached) {
    return json({ ...cached, _cache: "HIT" }, 200);
  }

  // -----------------------------------------------------
  // Safe Webex wrapper (always scoped)
  // -----------------------------------------------------
  const safe = (path) => webexFetchSafe(env, path, resolvedOrgId);

  const diagnostics = [];
  const diag = (name, r) =>
    diagnostics.push({
      name,
      ok: !!r?.ok,
      status: r?.status ?? null
    });

  try {

    // -----------------------------------------------------
    // Minimal required calls (fast, parallel)
    // -----------------------------------------------------
    const [locRes, numbersRes, trunksRes, redskyRes] = await Promise.all([
      safe("/telephony/config/locations"),
      safe("/telephony/config/numbers"),
      safe("/telephony/config/premisePstn/trunks"),
      safe("/telephony/config/redSky/complianceStatus")
    ]);

    diag("telephony/config/locations", locRes);
    diag("telephony/config/numbers", numbersRes);
    diag("telephony/config/premisePstn/trunks", trunksRes);
    diag("telephony/config/redSky/complianceStatus", redskyRes);

    if (!locRes.ok) {
      const payload = {
        ok:true,
        pstnSummary:{
          orgId: resolvedOrgId,
          callingAvailable:false,
          reason:"Calling API not accessible for this org",
          totals:{ trunks:0, didsTotal:0, locations:0 },
          compliance:null,
          misconfigurations:[],
          diagnostics,
          scores:{ pstnCapacityScore:0 }
        }
      };

      await cachePutJson(cacheKey, payload, ttl);
      return json({ ...payload, _cache:"MISS" }, 200);
    }

    // -----------------------------------------------------
    // Normalize data safely
    // -----------------------------------------------------
    const locationsRaw = asArray(locRes.data?.locations);
    const numbersRaw = numbersRes.ok
      ? asArray(numbersRes.data?.phoneNumbers || numbersRes.data?.items)
      : [];

    const trunksRaw = trunksRes.ok
      ? asArray(trunksRes.data?.trunks || trunksRes.data?.items)
      : [];

    const totalTrunks = trunksRaw.length;
    const totalDids = numbersRaw.length;
    const capacityScore = computeCapacityScore(totalTrunks);

    // -----------------------------------------------------
    // Per-location quick scan (no API fan-out)
    // -----------------------------------------------------
    const perLoc = locationsRaw.map(loc => {

      const locId = loc.id;

      const locNumbers = numbersRaw.filter(n =>
        String(getLocId(n)) === String(locId)
      );

      const locTrunks = trunksRaw.filter(t =>
        String(getLocId(t)) === String(locId)
      );

      return {
        id: locId,
        name: loc.name || "Unknown Location",
        trunkCount: locTrunks.length,
        didsTotal: locNumbers.length,
        didsUnassigned: locNumbers.filter(isUnassignedNumber).length
      };
    });

    // -----------------------------------------------------
    // Risk detection
    // -----------------------------------------------------
    const misconfigurations = [];

    for (const l of perLoc) {

      if (l.trunkCount === 0) {
        misconfigurations.push({
          location: l.name,
          issue: "No trunk detected (Cloud PSTN or not configured)"
        });
      }

      if (l.trunkCount === 1) {
        misconfigurations.push({
          location: l.name,
          issue: "Single trunk no redundancy"
        });
      }

      if (l.didsTotal > 0 && l.didsUnassigned === l.didsTotal) {
        misconfigurations.push({
          location: l.name,
          issue: "All numbers appear unassigned"
        });
      }
    }

    const payload = {
      ok:true,
      pstnSummary:{
        orgId: resolvedOrgId,
        callingAvailable:true,
        totals:{
          trunks: totalTrunks,
          didsTotal: totalDids,
          locations: perLoc.length
        },
        compliance: redskyRes.ok ? redskyRes.data : null,
        misconfigurations,
        diagnostics,
        scores:{
          pstnCapacityScore: capacityScore
        },
        generatedAt: new Date().toISOString()
      }
    };

    await cachePutJson(cacheKey, payload, ttl);

    return json({ ...payload, _cache:"MISS" }, 200);

  } catch (err) {

    return json({
      ok:true,
      pstnSummary:{
        orgId: resolvedOrgId,
        callingAvailable:false,
        error:"pstn_summary_exception",
        message:String(err),
        diagnostics
      }
    }, 200);
  }
}
// -----------------------------------------------------
// 2) Full PSTN endpoint (detailed), hardened + caching
// -----------------------------------------------------
if (url.pathname === "/api/pstn" && request.method === "GET") {

  try {

    const user = getCurrentUser(request);
    if (!user) return json({ ok:false, error:"access_required" }, 401);

    const session = await getSession(env, user.email);
    const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

    let resolvedOrgId;

    if (user.isAdmin) {
      if (!requestedOrgId)
        return json({ ok:false, error:"missing_orgId" }, 400);
      resolvedOrgId = requestedOrgId;
    } else {
      if (!session?.orgId)
        return json({ ok:false, error:"pin_required" }, 401);
      resolvedOrgId = session.orgId;
    }

    // Always scope by org
    const safe = (path) => webexFetchSafe(env, path, resolvedOrgId);

    const diagnostics = [];
    const diag = (name, r) => diagnostics.push({
      name,
      ok: !!r?.ok,
      status: r?.status ?? null
    });

    // ================================
    // 1️⃣ Locations
    // ================================

    const locRes = await safe("/telephony/config/locations");
    diag("telephony/config/locations", locRes);

    if (!locRes.ok) {
      return json({
        ok:true,
        pstn:{
          orgId: resolvedOrgId,
          callingAvailable:false,
          reason:"Calling API not accessible for this org",
          totals:{ trunks:0, didsTotal:0, locations:0 },
          locations:[],
          trunks:[],
          numbers:[],
          routeGroups:[],
          misconfigurations:[],
          diagnostics,
          scores:{ pstnCapacityScore: 0 }
        }
      }, 200);
    }

    const locationsRaw = Array.isArray(locRes.data?.locations)
      ? locRes.data.locations
      : [];

    // ================================
    // 2️⃣ Optional Endpoints
    // ================================

    const numbersRes = await safe("/telephony/config/numbers");
    diag("telephony/config/numbers", numbersRes);

    const trunksRes = await safe("/telephony/config/premisePstn/trunks");
    diag("premisePstn/trunks", trunksRes);

    const routeRes = await safe("/telephony/config/premisePstn/routeGroups");
    diag("premisePstn/routeGroups", routeRes);

    const redskyGlobal = await safe("/telephony/config/redSky/complianceStatus");
    diag("redSky/complianceStatus", redskyGlobal);

    const numbersRaw = numbersRes.ok
      ? (numbersRes.data?.phoneNumbers || numbersRes.data?.items || [])
      : [];

    const trunksRaw = trunksRes.ok
      ? (trunksRes.data?.trunks || trunksRes.data?.items || [])
      : [];

    const routeGroupsRaw = routeRes.ok
      ? (routeRes.data?.routeGroups || routeRes.data?.items || [])
      : [];

    // ================================
    // Helpers (defined locally)
    // ================================

    const getLocId = (obj) =>
      obj?.locationId ||
      obj?.callingLocationId ||
      obj?.location?.id ||
      obj?.location?.locationId ||
      null;

    const normalizePstnType = (conn) => {
      const t = String(
        conn?.connectionType ||
        conn?.type ||
        conn?.pstnType ||
        ""
      ).toUpperCase();

      if (!t) return "NO_PSTN";
      if (t.includes("CLOUD")) return "CLOUD_CONNECT";
      if (t.includes("CISCO")) return "CISCO_PSTN";
      if (t.includes("PREMISE") || t.includes("LOCAL") || t.includes("GATEWAY"))
        return "LOCAL_GATEWAY";
      return "UNKNOWN";
    };

    const isUnassignedNumber = (n) =>
      !n?.owner &&
      !n?.assignedTo &&
      !n?.userId &&
      !n?.workspaceId;

    const computeCapacityScore = (totalTrunks) => {
      if (totalTrunks === 0) return 0;
      if (totalTrunks === 1) return 60;
      if (totalTrunks >= 2) return 95;
      return 50;
    };

    // ================================
    // 3️⃣ Enrich Locations
    // ================================

    const enrichedLocations = [];

    for (const loc of locationsRaw) {

      const locId = loc.id;

      const conn = await safe(`/telephony/pstn/locations/${locId}/connection`);
      diag(`pstn/locations/${locId}/connection`, conn);

      const redskyStatus = await safe(`/telephony/config/locations/${locId}/redSky/status`);
      diag(`locations/${locId}/redSky/status`, redskyStatus);

      const emergencyNotif = await safe(`/telephony/config/locations/${locId}/emergencyCallNotification`);
      diag(`locations/${locId}/emergencyCallNotification`, emergencyNotif);

      const locNumbers = numbersRaw.filter(n =>
        String(getLocId(n)) === String(locId)
      );

      const locTrunks = trunksRaw.filter(t =>
        String(getLocId(t)) === String(locId)
      );

      const trunkCount = locTrunks.length;
      const didTotal = locNumbers.length;
      const didUnassigned = locNumbers.filter(isUnassignedNumber).length;

      const pstnType = conn.ok
        ? normalizePstnType(conn.data)
        : "UNKNOWN";

      const emergencyConfigured =
        redskyStatus.ok &&
        String(redskyStatus.data?.complianceStatus).toUpperCase() === "COMPLIANT";

      enrichedLocations.push({
        id: locId,
        name: loc.name || "Unknown Location",
        callingEnabled: true,
        pstnOption: pstnType,
        trunkCount,
        dids:{
          total: didTotal,
          unassigned: didUnassigned
        },
        emergencyConfigured
      });
    }

    // ================================
    // 4️⃣ Org Totals
    // ================================

    const totalTrunks = trunksRaw.length;
    const totalDids = numbersRaw.length;

    const misconfigurations = [];

    for (const l of enrichedLocations) {
      if (l.pstnOption === "NO_PSTN")
        misconfigurations.push({ location:l.name, issue:"No PSTN configured" });

      if (l.trunkCount === 1)
        misconfigurations.push({ location:l.name, issue:"Single trunk no redundancy" });

      if (!l.emergencyConfigured)
        misconfigurations.push({ location:l.name, issue:"E911 not compliant" });
    }

    return json({
      ok:true,
      pstn:{
        orgId: resolvedOrgId,
        callingAvailable:true,
        totals:{
          trunks: totalTrunks,
          didsTotal: totalDids,
          locations: enrichedLocations.length
        },
        locations: enrichedLocations,
        trunks: trunksRaw,
        numbers: numbersRaw,
        routeGroups: routeGroupsRaw,
        compliance: redskyGlobal.ok ? redskyGlobal.data : null,
        misconfigurations,
        diagnostics,
        scores:{
          pstnCapacityScore: computeCapacityScore(totalTrunks)
        }
      }
    }, 200);

  } catch (err) {

    return json({
      ok:false,
      error:"pstn_internal_exception",
      message:String(err?.message || err)
    }, 500);
  }
}
      /* -----------------------------
         🔎 DEBUG: seed + read a PIN
         GET /api/debug/pin-test
         TEMPORARY — remove after testing
      ----------------------------- */
   if (url.pathname === "/api/debug/pin-test") {
  if (env.DEBUG_MODE !== "true") {
    return json({ error: "disabled" }, 403);
  }
        const testPin = "12345";

        // Write to KV
        await env.ORG_MAP_KV.put(
          `pin:${testPin}`,
          JSON.stringify({
            orgId: "demo-org",
            orgName: "Demo Customer",
          })
        );

        // Read back from KV
        const readBack = await env.ORG_MAP_KV.get(`pin:${testPin}`, {
          type: "json",
        });

        return json({
          wroteKey: `pin:${testPin}`,
          readBack,
          kvBound: !!env.ORG_MAP_KV,
        });
      }
if (url.pathname === "/api/debug/cdr-direct" && request.method === "GET") {
  const orgId = url.searchParams.get("orgId");
  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 400);

  const now = new Date().toISOString();
  const from = new Date(Date.now() - 24*60*60*1000).toISOString();

  const a = await webexFetchSafe(env, `/cdr_feed?startTime=${encodeURIComponent(from)}&endTime=${encodeURIComponent(now)}&max=1`, orgId);
  const b = a.ok ? null : await webexFetchSafe(env, `/cdr/calls?startTime=${encodeURIComponent(from)}&endTime=${encodeURIComponent(now)}&max=1`, orgId);

  return json({
    ok: true,
    feed: diag("cdr_feed", a),
    calls: b ? diag("cdr_calls", b) : null
  }, 200);
}
/* -----------------------------
   🔎 DEBUG: Brevo env check
----------------------------- */
if (url.pathname === "/api/debug/brevo" && request.method === "GET") {
  if (env.DEBUG_MODE !== "true") {
  return json({ error: "disabled" }, 403);
}

  return json({
    hasApiKey: !!env.BREVO_API_KEY,
    hasSender: !!env.BREVO_SENDER_EMAIL,
    hasFrom: !!env.LICENSE_REPORT_FROM
  });
}
      // Default fallback (no route matched)
      return json({ error: "not_found" }, 404);

    } catch (e) {
      console.error("Unhandled error:", e);
      return json({ error: "internal_error", message: e.message }, 500);
    }
  },
async scheduled(event, env, ctx) {
  ctx.waitUntil((async () => {
    try {

      const orgResult = await webexFetch(env, "/organizations");
      if (!orgResult.ok) return;

      const orgs = orgResult.data.items || [];
      const CONCURRENCY = 5;

      await mapLimit(orgs, CONCURRENCY, async (org) => {

        const health = await computeTenantHealth(env, org.id);
        await storeHealth(env, health);

        const quality = await computeCallQuality(env, org.id);
        await env.WEBEX.put(
          `quality:${org.id}`,
          JSON.stringify(quality),
          { expirationTtl: 60 * 30 }
        );


        const pstn = await buildPstnDeep(env, org.id);
        await storePstnSnapshot(env, org.id, pstn);

        await appendPstnTrend(env, org.id, {
          day: new Date().toISOString().slice(0, 10),
          score: pstn?.scores?.pstnObservabilityScore ?? pstn?.scores?.pstnReliabilityScore ?? null,
          reliability: pstn?.scores?.pstnReliabilityScore ?? null,
          capacity: pstn?.scores?.pstnCapacityScore ?? null,
          redundancy: pstn?.scores?.pstnRedundancyScore ?? null,
          totalDids: pstn?.totals?.didsTotal ?? null,
          assignedDids: pstn?.totals?.didsAssigned ?? null
        });

      });

      // Global snapshot once per cron run
      try {
        const globalPayload = await computeGlobalSummary(env);
        await putGlobalSummarySnapshot(env, globalPayload);
        console.log("Global summary snapshot rebuilt via cron");
      } catch (e) {
        console.error("Global summary rebuild failed:", e);
      }

      console.log("Health + Quality + PSTN snapshots updated");

    } catch (err) {
      console.error("Scheduled task failed:", err);
    }
  })());
}

};
