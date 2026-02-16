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

async function getGlobalSummarySnapshot(env) {
  return await env.WEBEX.get(GLOBAL_SUMMARY_KEY, { type: "json" });
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
 
async function getAnalyticsAccessToken(env) {
  const cached = await env.WEBEX.get("analytics_access_token", { type: "json" });

  if (cached && cached.token && cached.expires_at > nowMs()) {
    return cached.token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: env.ANALYTICS_CLIENT_ID,
    client_secret: env.ANALYTICS_CLIENT_SECRET,
    refresh_token: env.ANALYTICS_REFRESH_TOKEN,
  });

  const res = await fetch("https://idbroker.webex.com/idb/oauth2/v1/access_token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error("Analytics token refresh failed");
  }

  const expiresAt = nowMs() + data.expires_in * 1000 - 60_000;

  await env.WEBEX.put(
    "analytics_access_token",
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

async function setSession(env, email, session) {
  await env.USER_SESSION_KV.put(
    KV.sessKey(email),
    JSON.stringify(session)
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

async function getOrgByEmail(email) {
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

  const token = await getAccessToken(env);

  const res = await fetch(
    `https://webexapis.com/v1/analytics/calling?orgId=${encodeURIComponent(orgId)}&interval=DAY&from=-7d`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  const data = await res.json();

  if (!res.ok) {
    return json({ error: "webex_analytics_failed", details: data }, 500);
  }

  return json(data, 200);
}
async function apiCDR(env, request) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get("orgId");

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  const token = await getAccessToken(env);

  const res = await fetch(
    `https://webexapis.com/v1/cdr?orgId=${encodeURIComponent(orgId)}&max=200`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  const data = await res.json();

  if (!res.ok) {
    return json({ error: "webex_cdr_failed", details: data }, 500);
  }

  return json(data, 200);
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
  const token = await getAccessToken(env);

  const orgRes = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const orgData = await orgRes.json();
  if (!orgRes.ok) {
    throw new Error("org_list_failed");
  }

  const orgs = orgData.items || [];
  const CONCURRENCY = 6;

  async function perOrg(org) {
    try {
      const orgId = org.id;
      const orgName = org.displayName || org.name || "Unknown";

      let deficit = 0;
      let offlineDevices = 0;
      let callVolume = 0;

      // Licenses
      const licRes = await fetch(
        `https://webexapis.com/v1/licenses?orgId=${encodeURIComponent(orgId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (licRes.ok) {
        const licData = await licRes.json();
        for (const l of licData.items || []) {
          const total = Number(l.totalUnits ?? 0);
          const consumed = Number(l.consumedUnits ?? 0);
          deficit += Math.max(0, consumed - total);
        }
      }

      // Devices
     // const devRes = await fetch(
   //       `https://webexapis.com/v1/devices?orgId=${encodeURIComponent(orgId)}`,
    //      { headers: { Authorization: `Bearer ${token}` } }
   //     );

   //     if (devRes.ok) {
   //       const devData = await devRes.json();
     //     offlineDevices = (devData.items || []).filter(d =>
    //        String(d.connectionStatus || "").toLowerCase() !== "connected"
    //      ).length;
   //     }
     // Devices disabled for Free plan stability
offlineDevices = 0;


      return {
        orgId,
        orgName,
        deficit,
        offlineDevices,
        callVolume
      };

    } catch (e) {
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
  "/pin",   // ✅ allow PIN page
  "/",      // ✅ allow home UI
  "/api/admin/global-summary/refresh"
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

    const orgId =
      value.orgId ||
      String(value.orgName || "")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

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
if (url.pathname === "/api/status" && request.method === "GET") {

  let user;
  try {
    user = getCurrentUser(request);
  } catch (e) {
    return json({ error: "auth_failed", message: e.message }, 401);
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
    const upstream = await fetch(
      "https://status.webex.com/api/status.json",
      { headers: { Accept: "application/json" } }
    );

    const textBody = await upstream.text();

    let data;
    try {
      data = JSON.parse(textBody);
    } catch {
      return json({ error: "status_not_json" }, 500);
    }

    if (!upstream.ok) {
      return json({
        error: "status_upstream_failed",
        upstreamStatus: upstream.status
      }, 502);
    }

    return json({
      globalIndicator: data.status?.indicator || "unknown",
      globalDescription: data.status?.description || null,
      components: data.components || [],
      lastUpdated: new Date().toISOString()
    });

  } catch (e) {
    return json({
      error: "status_engine_failed",
      message: e.message
    }, 500);
  }
}

      
//api/incidents block
if (url.pathname === "/api/incidents" && request.method === "GET") {

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

    const FEEDS = [
      { group: "Webex Meetings", url: "https://status.webex.com/history/rss/webex-meetings" },
      { group: "Webex App", url: "https://status.webex.com/history/rss/webex-app" },
      { group: "Webex Messaging", url: "https://status.webex.com/history/rss/webex-messaging" },
      { group: "Webex User Hub", url: "https://status.webex.com/history/rss/webex-user-hub" },
      { group: "Webex Control Hub", url: "https://status.webex.com/history/rss/webex-control-hub" },
      { group: "Webex Cloud Registered Device", url: "https://status.webex.com/history/rss/webex-cloud-registered-device" },
      { group: "Webex Hybrid Services", url: "https://status.webex.com/history/rss/webex-hybrid-services" },
      { group: "Webex Events", url: "https://status.webex.com/history/rss/webex-events" },
      { group: "Slido", url: "https://status.webex.com/history/rss/slido" },

      { group: "Webex Calling", url: "https://status.webex.com/history/rss/webex-calling" },
      { group: "Cisco BroadCloud", url: "https://status.webex.com/history/rss/cisco-broadcloud" },
      { group: "Dedicated Instance/UCM Cloud", url: "https://status.webex.com/history/rss/dedicated-instance-ucm-cloud" },
      { group: "Webex for BroadWorks", url: "https://status.webex.com/history/rss/webex-for-broadworks" },
      { group: "Gateway and Solutions", url: "https://status.webex.com/history/rss/gateway-and-solutions" },

      { group: "Webex Contact Center", url: "https://status.webex.com/history/rss/webex-contact-center" },
      { group: "Webex Contact Center Enterprise", url: "https://status.webex.com/history/rss/webex-contact-center-enterprise" },
      { group: "Developer API", url: "https://status.webex.com/history/rss/developer-api" }
    ];

    const cache = caches.default;
    const cacheKey = new Request("https://internal-cache/webex-incidents-multi");

    const cached = await cache.match(cacheKey);
    if (cached) return cached;

    async function fetchFeed(feed) {

      const res = await fetch(feed.url, {
        headers: { "Accept": "application/rss+xml, application/xml" }
      });

      if (!res.ok) return [];

      const text = await res.text();

      const items = [...text.matchAll(/<item[\s\S]*?<\/item>/g)];

      return items.map(match => {

        const block = match[0];

        const title =
          (block.match(/<title>([\s\S]*?)<\/title>/) || [])[1] || "Incident";

        const pubDate =
          (block.match(/<pubDate>(.*?)<\/pubDate>/) || [])[1] || null;

        const guid =
          (block.match(/<guid>(.*?)<\/guid>/) || [])[1] || title;

        const descriptionRaw =
          (block.match(/<description>([\s\S]*?)<\/description>/) || [])[1] || "";

        const clean = descriptionRaw
          .replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1")
          .replace(/<[^>]+>/g, "")
          .replace(/\s+/g, " ")
          .trim();

        const lower = clean.toLowerCase();

        let status = "investigating";

        if (lower.includes("resolved") || lower.includes("completed")) {
          status = "resolved";
        }
        else if (lower.includes("monitoring")) {
          status = "monitoring";
        }
        else if (lower.includes("identified")) {
          status = "identified";
        }

        return {
          id: guid,
          name: title,
          created: pubDate,
          status,
          productGroup: feed.group,
          impact: "incident",
          updates: [
            {
              status,
              updated: pubDate,
              body: clean.slice(0, 1500)
            }
          ]
        };
      });
    }

    const results = await Promise.all(FEEDS.map(fetchFeed));

    const allIncidents = [];
    const seen = new Set();

    for (const groupItems of results) {
      for (const item of groupItems) {
        if (!seen.has(item.id)) {
          seen.add(item.id);
          allIncidents.push(item);
        }
      }
    }

    const active = allIncidents.filter(i =>
      ["investigating", "identified", "monitoring"].includes(i.status)
    );

    const responsePayload = {
      incidents: allIncidents,
      active,
      counts: {
        active: active.length,
        total: allIncidents.length
      },
      lastUpdated: new Date().toISOString()
    };

    const response = new Response(JSON.stringify(responsePayload), {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300"
      }
    });

    await cache.put(cacheKey, response.clone());

    return response;

  } catch (e) {

    return json({
      error: "incident_engine_failed",
      message: e.message
    }, 500);

  }
}

      ///api/maintenance block
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

    const cache = caches.default;
    const cacheKey = new Request("https://internal-cache/webex-maintenance-v2");

    const cached = await cache.match(cacheKey);
    if (cached) return cached;

    async function fetchJson(endpoint) {
      const res = await fetch(
        `https://status.webex.com/api/${endpoint}`,
        {
          headers: {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0"
          },
          cf: {
            cacheTtl: 300
          }
        }
      );

      const text = await res.text();

      if (!res.ok) {
        throw new Error(`${endpoint} failed: ${res.status}`);
      }

      return JSON.parse(text);
    }

    const [upcomingData, activeData, allData] = await Promise.all([
      fetchJson("upcoming-scheduled-maintenances.json"),
      fetchJson("active-scheduled-maintenances.json"),
      fetchJson("all-scheduled-maintenances.json")
    ]);

    const normalize = (items) =>
      (items || []).map(m => ({
        id: m.incidentId,
        name: m.incidentName,
        status: m.status,
        impact: m.impact,
        productGroup: m.serviceId,
        locations: m.locations,
        startTime: m.startTime,
        endTime: m.endTime,
        changeId: m.changeId,
        messages: m.messages || []
      }));

    const upcoming = normalize(upcomingData);
    const active = normalize(activeData);
    const all = normalize(allData);

    const responsePayload = {
      maintenance: all,
      upcoming,
      active,
      counts: {
        upcoming: upcoming.length,
        active: active.length,
        total: all.length
      },
      lastUpdated: new Date().toISOString()
    };

    const response = new Response(JSON.stringify(responsePayload), {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300"
      }
    });

    await cache.put(cacheKey, response.clone());

    return response;

  } catch (e) {
    return json({
      error: "maintenance_engine_failed",
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
        const token = await getAccessToken(env);
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

        await setSession(env, user.email, session);

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
        const token = await getAccessToken(env);
        await clearSession(env, user.email);
        return json({ status: "ok" });
      }


      if (url.pathname === "/api/admin/pins" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const token = await getAccessToken(env);
  const orgRes = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });
  const orgData = await orgRes.json();

  if (!orgRes.ok) return json({ error:"org_list_failed", details: orgData }, 500);

  const orgs = orgData.items || [];

  // For each org, attempt to read org->pin mapping from KV
  const items = await Promise.all(orgs.map(async (o) => {
    const orgId = o.id;
    const orgName = o.displayName || o.name || "Unknown";
    const kv = await env.ORG_MAP_KV.get(`org:${orgId}`, { type:"json" });

    return {
      orgId,
      orgName,
      pin: kv?.pin || null,
      emails: kv?.emails || []
    };
  }));

  // Sort alphabetical
  items.sort((a,b) => (a.orgName || "").localeCompare(b.orgName || ""));

  return json({ ok:true, items }, 200);
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

if (url.pathname === "/api/admin/orgs") {
  const token = await getAccessToken(env);
 const user = getCurrentUser(request);
if (!user.isAdmin) return json({ error: "admin_only" }, 403);


  const res = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) {
    return json({ error: "org_list_failed" }, 500);
  }

  const data = await res.json();

  return json({
    items: (data.items || []).map(o => ({
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

  const token = await getAccessToken(env);

  let deficit = 0;
  let offline = 0;

  const lic = await fetch(
    `https://webexapis.com/v1/licenses?orgId=${encodeURIComponent(orgId)}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );

  if (lic.ok) {
    const l = await lic.json();
    for (const x of l.items || []) {
      if (x.totalUnits && x.consumedUnits)
        deficit += Math.max(0, x.consumedUnits - x.totalUnits);
    }
  }

  const dev = await fetch(
    `https://webexapis.com/v1/devices?orgId=${encodeURIComponent(orgId)}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );

  if (dev.ok) {
    const d = await dev.json();
    offline = (d.items || []).filter(x =>
      x.connectionStatus !== "connected"
    ).length;
  }

  return json({
    orgId,
    deficit,
    offline
  });
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

  const orgRes = await fetch("https://webexapis.com/v1/organizations", {
    headers: { Authorization: `Bearer ${token}` },
  });

  const orgData = await orgRes.json();

  if (!orgRes.ok) {
    throw new Error(`/organizations failed: ${JSON.stringify(orgData)}`);
  }

  if (user.isAdmin) {
    return json(orgData.items);
  }

  const filtered = orgData.items.filter(o => o.id === session.orgId);
  return json(filtered);
}
/* -----------------------------
   /api/licenses
   - Admin: may specify ?orgId=...
   - Customer: resolved org only
----------------------------- */
if (url.pathname === "/api/licenses" && request.method === "GET") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId = null;

if (user.isAdmin) {
  resolvedOrgId = requestedOrgId ? requestedOrgId : null;
} 
else {
    if (!session || !session.orgId) {
      return json({ error: "pin_required", message: "PIN required." }, 401);
    }

    if (session.expiresAt && session.expiresAt <= nowMs()) {
      await clearSession(env, user.email);
      return json({ error: "pin_required_or_expired", message: "PIN required." }, 401);
    }

    resolvedOrgId = session.orgId;
  }

  const headers = {
    Authorization: `Bearer ${token}`,
  };

  // 🚨 CRITICAL: Partner scope enforcement
  if (resolvedOrgId) {
  }

let licenseUrl = "https://webexapis.com/v1/licenses";

if (resolvedOrgId) {
  licenseUrl += `?orgId=${encodeURIComponent(resolvedOrgId)}`;
}

const res = await fetch(licenseUrl, {
  headers: {
    Authorization: `Bearer ${token}`
  }
});


const textBody = await res.text();

if (!res.ok) {
  return json({
    error: "webex_license_failed",
    status: res.status,
    bodyPreview: textBody.slice(0, 500)
  }, 500);
}

let data;
try {
  data = JSON.parse(textBody);
} catch {
  return json({
    error: "webex_license_not_json",
    status: res.status,
    bodyPreview: textBody.slice(0, 500)
  }, 500);
}

  const licenses = data.items || [];

const normalized = licenses.map(l => {
 const rawTotal = l.totalUnits;
const rawConsumed = l.consumedUnits;

const total = (rawTotal === null || rawTotal === undefined) ? null : Number(rawTotal);
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

  return {
    id: l.id,
    name: l.name,
    total,
    consumed,
    available,
    deficit,
    status
  };
});

const summary = {
  totalLicenses: normalized.length,
  totalConsumed: normalized.reduce((a, l) => a + (l.consumed || 0), 0),
  totalDeficit: normalized.reduce((a, l) => a + (l.deficit || 0), 0),
  hasDeficit: normalized.some(l => l.status === "DEFICIT")
};

return json({
  orgId: resolvedOrgId,
  summary,
  items: normalized
});
}
  

/* -----------------------------
   /api/licenses/email
   Sends license report via Brevo
----------------------------- */
if (url.pathname === "/api/licenses/email" && request.method === "POST") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
   const body = await request.json().catch(() => ({}));
  const toEmail = String(body.email || "").toLowerCase().trim();
  const requestedOrgId = body.orgId || null;

  if (!toEmail) {
    return json({ error: "missing_email" }, 400);
  }

//  if (requestedOrgId && user.isAdmin) {
 //   url.searchParams.set("orgId", requestedOrgId);
//  }
const licenseUrl = new URL(`${url.origin}/api/licenses`);

if (requestedOrgId && user.isAdmin) {
  licenseUrl.searchParams.set("orgId", requestedOrgId);
}
  // Begining of New Add
const licRes = await fetch(licenseUrl.toString(), {
  method: "GET"
});


const licText = await licRes.text();

if (!licRes.ok) {
  return json({
    error: "license_fetch_failed",
    status: licRes.status,
    body: licText.slice(0, 500)
  }, 500);
}

// Try to parse safely
let licData;
try {
  licData = JSON.parse(licText);
} catch (e) {
  return json({
    error: "license_not_json",
    status: licRes.status,
    bodyPreview: licText.slice(0, 500)
  }, 500);
}

const rows = (licData.items || [])
  .map(l => {
    const assigned = l.consumed ?? 0;
    const available = l.available ?? 0;
    const deficit = l.deficit ?? 0;
    const status = l.status ?? "OK";

    return `
      <tr>
        <td>${l.name}</td>
        <td>${assigned}</td>
        <td>${available === -1 ? "Unlimited" : available}</td>
        <td>${deficit}</td>
        <td>${status}</td>
      </tr>
    `;
  })
  .join("");

  const html = `
    <h2>Webex Calling License Report</h2>
    <p>Generated for ${user.email}</p>
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

  // ✅ Sender resolved OUTSIDE JSON
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
      sender: {
        email: senderEmail,
        name: "US Signal Licensing",
      },
      to: [{ email: toEmail }],
      subject: "Webex Calling License Report",
      htmlContent: html,
    }),
  });

  const brevoText = await brevoRes.text();

if (!brevoRes.ok) {
  console.error("Brevo error:", brevoText);
  return json({
    error: "brevo_failed",
    status: brevoRes.status,
    body: brevoText
  }, 500);
}


  return json({ status: "sent", to: toEmail });
}
if (url.pathname === "/api/devices" && request.method === "GET") {
  const user = getCurrentUser(request);
  const token = await getAccessToken(env);
  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  if (session?.expiresAt && session.expiresAt <= nowMs()) {
  await clearSession(env, user.email);
  return json({ error: "pin_required_or_expired" }, 401);
}

  let resolvedOrgId = null;

  if (user.isAdmin) {
    resolvedOrgId = requestedOrgId || null;
  } else {
    if (!session || !session.orgId) {
      return json({ error: "pin_required" }, 401);
    }
    resolvedOrgId = session.orgId;
  }

  let deviceUrl = "https://webexapis.com/v1/devices";

  if (resolvedOrgId) {
    deviceUrl += `?orgId=${encodeURIComponent(resolvedOrgId)}`;
  }

  const res = await fetch(deviceUrl, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const textBody = await res.text();
let data;

try {
  data = JSON.parse(textBody);
} catch {
  return json({
    error: "webex_devices_not_json",
    status: res.status,
    bodyPreview: textBody.slice(0, 500)
  }, 500);
}


  if (!res.ok) {
    return json({ error: "webex_devices_failed", body: data }, 500);
  }

  return json({
    count: data.items?.length || 0,
    items: data.items || []
  });
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
      return json({ ok: false, error: "pin_required" }, 401);
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

  const parts = url.pathname.split("/");
  const key = parts[3]; // customer key
  const action = parts[4]; // licenses/devices/analytics/etc

  let resolvedOrgId = null;

if (user.isAdmin) {
  // Look up orgId from KV using key mapping
  const mapping = await env.ORG_MAP_KV.get(`org:${key}`, { type: "json" });
  resolvedOrgId = mapping?.orgId || null;
} else {
  resolvedOrgId = session.orgId;
}


  /* ---------- LICENSES ---------- */
if (action === "licenses") {
  const token = await getAccessToken(env);

  const res = await fetch(
    `https://webexapis.com/v1/licenses?orgId=${encodeURIComponent(resolvedOrgId)}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );

  const textBody = await res.text();

  if (!res.ok) {
    return json({
      ok: false,
      error: "webex_license_failed",
      status: res.status,
      bodyPreview: textBody.slice(0, 500)
    }, 500);
  }

  let data;
  try {
    data = JSON.parse(textBody);
  } catch {
    return json({
      ok: false,
      error: "webex_license_not_json"
    }, 500);
  }

  const normalized = (data.items || []).map(l => {
    const rawTotal = l.totalUnits;
    const rawConsumed = l.consumedUnits;

    const total = (rawTotal === null || rawTotal === undefined)
      ? null
      : Number(rawTotal);

    const consumed = Number(rawConsumed ?? 0);

    const isUnlimited = total === -1;
    const hasTotal = Number.isFinite(total);

    const available = isUnlimited
      ? -1
      : (hasTotal ? Math.max(0, total - consumed) : null);

    const deficit = isUnlimited
      ? 0
      : (hasTotal ? Math.max(0, consumed - total) : 0);

    let status = "OK";
    if (isUnlimited) status = "UNLIMITED";
    else if (!hasTotal) status = "UNKNOWN";
    else if (deficit > 0) status = "DEFICIT";
    else if (available === 0) status = "FULL";

    return {
      id: l.id,
      name: l.name,
      total,
      consumed,
      available,
      deficit,
      status
    };
  });

  const summary = {
    totalLicenses: normalized.length,
    totalConsumed: normalized.reduce((a, l) => a + (l.consumed || 0), 0),
    totalDeficit: normalized.reduce((a, l) => a + (l.deficit || 0), 0),
    hasDeficit: normalized.some(l => l.status === "DEFICIT")
  };

  return json({
    ok: true,
    orgId: resolvedOrgId,
    summary,
    items: normalized
  });
}

  /* ---------- DEVICES ---------- */
  if (action === "devices") {
    const token = await getAccessToken(env);

    const res = await fetch(
      `https://webexapis.com/v1/devices?orgId=${encodeURIComponent(resolvedOrgId)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const textBody = await res.text();
let data;
try {
  data = JSON.parse(textBody);
} catch {
  return json({ ok: false, error: "webex_devices_not_json" }, 500);
}


    return json({
      ok: true,
      devices: data.items || []
    });
  }

  /* ---------- ANALYTICS ---------- */
  if (action === "analytics") {
    const token = await getAnalyticsAccessToken(env);

    const res = await fetch(
      `https://webexapis.com/v1/analytics/calling?orgId=${encodeURIComponent(resolvedOrgId)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const data = await res.json();

    return json({
      ok: true,
      analytics: data
    });
  }

  /* ---------- CDR ---------- */
  if (action === "cdr") {
    const token = await getAnalyticsAccessToken(env);

    const res = await fetch(
      `https://webexapis.com/v1/cdr?orgId=${encodeURIComponent(resolvedOrgId)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const data = await res.json();

    return json({
      ok: true,
      records: data.items || []
    });
  }

  /* ---------- PSTN HEALTH ---------- */
  if (action === "pstn-health") {
    const token = await getAccessToken(env);

    const res = await fetch(
      `https://webexapis.com/v1/telephony/config/locations?orgId=${encodeURIComponent(resolvedOrgId)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const data = await res.json();

    return json({
      ok: true,
      locations: data.items || []
    });
  }

  return json({ ok: false, error: "unknown_customer_action" }, 404);
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

  const newPin = await generateUniqueNonEasyPin();

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
          const v = await getPinByOrg(String(orgId));
          if (v?.pin) out.push({ orgId, pin: v.pin, orgName: v.orgName || null });
        }
        return json(out);
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
if (url.pathname === "/api/admin/global-summary" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const snapshot = await getGlobalSummarySnapshot(env);

  if (!snapshot) {
    return json({
      ok: false,
      message: "No snapshot available yet"
    }, 404);
  }

  return json({
    ok: true,
    generatedAt: snapshot.generatedAt,
    ...snapshot.payload
  }, 200);
}
if (url.pathname === "/api/admin/global-summary/refresh" && request.method === "POST") {
 const user = getCurrentUser(request);
 if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const payload = await computeGlobalSummary(env);
  await putGlobalSummarySnapshot(env, payload);

  return json({
    ok: true,
    message: "Snapshot refreshed",
    generatedAt: new Date().toISOString()
  }, 200);
}
         return json({ error: "not_found", path: url.pathname }, 404);
    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json({ error: "internal_error", message: err?.message || String(err) }, 500);
    }
  },

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
