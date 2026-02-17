/**
 * ussignal-webex — index.js (DROP-IN)
 *
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

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  const result = await webexFetch(env, "/cdr", orgId);

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
async function webexFetch(env, path, orgId = null) {
  const token = await getAccessToken(env);

  const headers = { Authorization: `Bearer ${token}` };
  if (orgId) headers["X-Organization-Id"] = orgId;

  const res = await fetch(`https://webexapis.com/v1${path}`, { headers });
  const text = await res.text();
  const preview = text.slice(0, 400);

  try {
    const data = JSON.parse(text);
    return { ok: res.ok, status: res.status, data, preview };
  } catch {
    return { ok: false, status: res.status, error: "not_json", preview };
  }
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

  if (!email) {
    throw new Error("Cloudflare Access email header missing");
  }

  const normalized = email.toLowerCase().trim();

  return {
    email: normalized,
    isAdmin: normalized.endsWith("@ussignal.com"),
  };
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
  readAttempts(env, kIp)
]);


      const t = nowMs();

      const lockedUntil = Math.max(aEmail.lockedUntil || 0, aIp.lockedUntil || 0);
      if (lockedUntil && lockedUntil > t) {
        const retryAfter = Math.ceil((lockedUntil - t) / 1000);
        // add mild delay to frustrate brute forcing
        await sleep(250);
        return { allowed: false, retryAfter };
      }

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
    "/analytics/calling?interval=DAY&from=-7d",
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
 
  

async function computeGlobalSummary(env) {
  const orgResult = await webexFetch(env, "/partner/organizations");

  if (!orgResult.ok) {
    throw new Error("org_list_failed");
  }

  const orgs = orgResult.data.items || [];
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


// Calling Analytics
try {
  const analyticsResult = await webexFetch(
    env,
    "/analytics/calling?interval=DAY&from=-7d",
    orgId
  );

  if (analyticsResult.ok) {
    const a = analyticsResult.data || {};
    callVolume =
      Number(a.totalCalls ?? 0) ||
      Number(a.totalConnectedCalls ?? 0) ||
      0;
  } else {
    analyticsFailed = true;
  }
} catch {
  analyticsFailed = true;
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

// CDR (Call Detail Records)
const cdrResult = await webexFetch(env, "/cdr", orgId);
if (!cdrResult.ok) {
  cdrFailed = true;
}


     return {
  orgId,
  orgName,
  deficit,
  offlineDevices,
  callVolume,
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
    tenants
  };
}

export default {

  async fetch(request, env) {
    try {
      const url = new URL(request.url);

const SESSION_TTL_SECONDS = cfgIntAllowZero(env, "SESSION_TTL_SECONDS", 3600);
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

if (!accessEmail && !publicPaths.includes(url.pathname)) {
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
if (url.pathname === "/api/status" && request.method === "GET") {

  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);

  if (!user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }
  }

  try {

    const res = await fetch("https://status.webex.com/components.json");
    if (!res.ok) {
      return json({ error: "status_fetch_failed" }, 500);
    }

    const raw = await res.json();

    const groups = {};

    (raw.components || []).forEach(c => {

      const groupName = c.group || c.name;

      if (!groups[groupName]) {
        groups[groupName] = {
          name: groupName,
          status: "operational",
          children: []
        };
      }

      groups[groupName].children.push({
        name: c.name,
        status: c.status
      });
    });

    /* ===== Calculate Parent Status ===== */

    Object.values(groups).forEach(group => {

      if (group.children.some(c => c.status === "major_outage" || c.status === "critical")) {
        group.status = "major_outage";
      }
      else if (group.children.some(c => c.status !== "operational")) {
        group.status = "degraded_performance";
      }
      else {
        group.status = "operational";
      }

    });

    const components = Object.values(groups);

    const overall =
      components.some(c => c.status === "major_outage")
        ? "major_outage"
        : components.some(c => c.status !== "operational")
          ? "degraded_performance"
          : "operational";

    return json({
      lastUpdated: new Date().toISOString(),
      overall,
      components
    });

  } catch (e) {

    return json({
      error: "status_engine_failed",
      message: e.message
    }, 500);

  }
}
      
//api/incidents block
// /api/incidents (GET) — maintenance-style with upstream fallback
if (url.pathname === "/api/incidents" && request.method === "GET") {

  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);

  if (!user.isAdmin) {
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
  const session = await getSession(env, user.email);

  if (!user.isAdmin) {
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

  const session = await getSession(env, user.email);

  if (!user.isAdmin) {
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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const orgResult = await webexFetch(env, "/partner/organizations");
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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const body = await request.json().catch(() => ({}));
  const orgId = String(body.orgId || "").trim();
  const orgName = String(body.orgName || "").trim() || "Unknown Org";
  const emails = Array.isArray(body.emails) ? body.emails : [];

  if (!orgId) return json({ error:"missing_orgId" }, 400);

  await auditLog(env, user.email, url.pathname, {
    action: "pin_allowlist_update",
    orgId
  });

  const existing = await env.ORG_MAP_KV.get(`org:${orgId}`, { type:"json" });
  const pin = existing?.pin || null;
  const role = existing?.role || "customer";

  if (!pin) {
    return json({
      error:"missing_pin_mapping",
      message:"No org->pin mapping exists for this org yet."
    }, 404);
  }

  const normEmails = emails
    .map(e => String(e || "").toLowerCase().trim())
    .filter(Boolean);

  await env.ORG_MAP_KV.put(`org:${orgId}`, JSON.stringify({
    pin, orgName, role, emails: normEmails
  }));

  await env.ORG_MAP_KV.put(`pin:${pin}`, JSON.stringify({
    orgId, orgName, role, emails: normEmails
  }));

  for (const e of normEmails) {
    await env.ORG_MAP_KV.put(`email:${e}`, JSON.stringify({
      orgId, orgName, role
    }));
  }

  return json({ ok:true, orgId, orgName, pin, emails: normEmails }, 200);
}

if (url.pathname === "/api/admin/orgs" && request.method === "GET") {
  const token = await getAccessToken(env);
 const user = getCurrentUser(request);
if (!user.isAdmin) return json({ error: "admin_only" }, 403);


const result = await webexFetch(env, "/partner/organizations");

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
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  if (!user.isAdmin) {
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

 const result = await webexFetch(env, "/partner/organizations");

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
if (url.pathname === "/api/licenses" && request.method === "GET") {
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
   CUSTOMER-SCOPED ROUTES
   Mirrors Partner Portal contract
===================================================== */

if (url.pathname.startsWith("/api/customer/")) {

  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);

  if (!user.isAdmin) {
    if (!session || !session.orgId) {
      return json({ ok:false, error:"pin_required" }, 401);
    }
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

  if (action === "licenses") {
    const result = await webexFetch(env, "/licenses", resolvedOrgId);
    if (!result.ok) return json({ ok:false, error:"webex_license_failed" }, 500);
    return json({ ok:true, items: result.data.items || [] });
  }

  if (action === "devices") {
    const result = await webexFetch(env, "/devices", resolvedOrgId);
    if (!result.ok) return json({ ok:false, error:"webex_devices_failed" }, 500);
    return json({ ok:true, devices: result.data.items || [] });
  }

  if (action === "analytics") {
    const result = await webexFetch(env, "/analytics/calling?interval=DAY&from=-7d", resolvedOrgId);
    if (!result.ok) return json({ ok:false, error:"webex_analytics_failed" }, 500);
    return json({ ok:true, analytics: result.data });
  }

  if (action === "cdr") {
    const result = await webexFetch(env, "/cdr", resolvedOrgId);
    if (!result.ok) return json({ ok:false, error:"webex_cdr_failed" }, 500);
    return json({ ok:true, records: result.data.items || [] });
  }

  if (action === "pstn-health") {
    const result = await webexFetch(env, "/telephony/config/locations", resolvedOrgId);
    if (!result.ok) return json({ ok:false, error:"webex_pstn_failed" }, 500);
    return json({ ok:true, locations: result.data.items || [] });
  }

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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
         /api/admin/pin/list (GET)
         Admin-only: returns current org->pin mappings (best-effort)
         NOTE: KV can't list keys here; so this endpoint expects you to pass orgIds if needed.
         For demo, you can skip this.
      ----------------------------- */
      if (url.pathname === "/api/admin/pin/list" && request.method === "POST") {
        const user = getCurrentUser(request);
        const token = await getAccessToken(env);
        if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const tests = {};

  async function test(name, path) {
    const result = await webexFetch(env, path);
    tests[name] = {
      ok: result.ok,
      status: result.status,
      preview: result.preview?.slice(0, 200)
    };
  }

  await test("partner_organizations", "/partner/organizations");
  await test("reports", "/reports");
  await test("wholesale_customers", "/wholesale/customers");

  return json({
    ok: true,
    testedAt: new Date().toISOString(),
    tests
  });
}
/* =====================================================
   🔬 ADMIN: ORG-SCOPED DIAGNOSTICS
===================================================== */
if (url.pathname.startsWith("/api/admin/diagnostics/org/") && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  await test("analytics_calling", "/analytics/calling?interval=DAY&from=-7d");
  await test("cdr", "/cdr");
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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

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
if (url.pathname === "/api/analytics" && request.method === "GET") {
  return await apiCallingAnalytics(env, request);
}

if (url.pathname === "/api/cdr" && request.method === "GET") {
  return await apiCDR(env, request);
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
}// GET snapshot (already fine above)
if (url.pathname === "/api/admin/global-summary" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const snapshot = await getGlobalSummarySnapshot(env);
  if (!snapshot) {
    return json({ ok: false, message: "No snapshot available yet" }, 404);
  }

  return json({
    ok: true,
    generatedAt: snapshot.generatedAt,
    ...snapshot.payload
  }, 200);
}

// POST refresh snapshot
if (url.pathname === "/api/admin/global-summary/refresh") {
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  if (request.method !== "POST") {
    return json({ error: "method_not_allowed", allowed: ["POST"] }, 405);
  }

  const payload = await computeGlobalSummary(env);
  await putGlobalSummarySnapshot(env, payload);

  return json({
    ok: true,
    message: "Snapshot refreshed",
    generatedAt: new Date().toISOString()
  }, 200);
}

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const payload = await computeGlobalSummary(env);
        await putGlobalSummarySnapshot(env, payload);
        console.log("Global summary snapshot updated");
      } catch (e) {
        console.error("Scheduled snapshot failed:", e.message);
      }
    })());
  }

};
