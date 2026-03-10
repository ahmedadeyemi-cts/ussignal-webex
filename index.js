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
 * - KV: ORG_MAP_KV.
 * - KV: USER_SESSION_KV
 * Required env vars:
 * - CLIENT_ID
 * - CLIENT_SECRETS
 * - REFRESH_TOKEN
 *
 * Optional env vars:
 * - SESSION_TTL_SECONDS (default 3600)
 * - PIN_THROTTLE_WINDOW_SECONDS (default 900)   // 15 min
 * - PIN_MAX_ATTEMPTS (default 5)
 * - PIN_LOCKOUT_SECONDS (default 900)           // 15 min
 * - PIN_SEED_URL (default: your GitHub raw URL used below)
 */
import JSZip from "jszip";
import Papa from "papaparse";

 /* =====================================================
       Helpers
    ===================================================== */
const JSON_HEADERS = {
  "content-type": "application/json",
  "cache-control": "no-store",
};

// =============================================
// Webex API Base URLs
// =============================================

const WEBEX_API_BASE_DEFAULT = "https://webexapis.com/v1";

const ANALYTICS_BASE_DEFAULT = "https://analytics-calling.webexapis.com/v1";
// If you prefer the partner host instead, set:
// WEBEX_ANALYTICS_BASE = https://analytics-calling.webexapis.com/v1

function webexBase(env) {
  return (env.WEBEX_API_BASE || WEBEX_API_BASE_DEFAULT).replace(/\/+$/, "");
}

function analyticsBase(env) {
  return (env.WEBEX_ANALYTICS_BASE || ANALYTICS_BASE_DEFAULT).replace(/\/+$/, "");
}

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
async function ensureDelegation(env, orgId) {

  const key = `delegation:${orgId}`;
  const cached = await env.WEBEX.get(key);

  if (cached) return;

  let token = await getAccessToken(env);

  const url = `https://webexapis.com/v1/organizations/${orgId}`;

  let res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  // retry once on token expiration
  if (res.status === 401) {

    console.log("Delegation token expired — refreshing");

    await env.WEBEX.delete("access_token");

    token = await getAccessToken(env);

    res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      }
    });
  }

  if (!res.ok) {
    const text = await res.text();
    console.log("Delegation activation failed:", text);
    throw new Error("delegation_failed");
  }

  await env.WEBEX.put(key, "1", { expirationTtl: 86400 });

  console.log("Delegation activated for org:", orgId);
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
function computeWorkerQualityMetrics(rows = []) {

  let mosVals = [];
  let jitterVals = [];
  let lossVals = [];
  let latencyVals = [];

  for (const r of rows) {
    const mos = Number(r["MOS"] || r["Average MOS"]);
    const jitter = Number(r["Jitter (ms)"] || r["Jitter"]);
    const loss = Number(r["Packet Loss (%)"] || r["Loss (%)"]);
    const latency = Number(r["Latency (ms)"] || r["RTT"]);

    if (!isNaN(mos)) mosVals.push(mos);
    if (!isNaN(jitter)) jitterVals.push(jitter);
    if (!isNaN(loss)) lossVals.push(loss);
    if (!isNaN(latency)) latencyVals.push(latency);
  }

  const avg = arr => arr.length ? arr.reduce((a,b)=>a+b,0)/arr.length : null;
  const p95 = arr => {
    if (!arr.length) return null;
    const s = arr.slice().sort((a,b)=>a-b);
    return s[Math.floor(s.length * 0.95)];
  };

  const mosAvg = avg(mosVals);
  const jitP95 = p95(jitterVals);
  const lossP95 = p95(lossVals);
  const latP95 = p95(latencyVals);

  let score = 92;

  if (mosAvg != null && mosAvg < 3.9) score -= 15;
  if (jitP95 != null && jitP95 > 25) score -= 10;
  if (lossP95 != null && lossP95 > 2) score -= 15;
  if (latP95 != null && latP95 > 180) score -= 8;

  score = Math.max(0, Math.min(100, Math.round(score)));

  const alerts = [];

  if (mosAvg && mosAvg < 3.9)
    alerts.push({ sev: "WARN", msg: "Low MOS average detected" });

  if (jitP95 && jitP95 > 25)
    alerts.push({ sev: "WARN", msg: "High jitter p95 detected" });

  if (lossP95 && lossP95 > 2)
    alerts.push({ sev: "WARN", msg: "High packet loss p95 detected" });

  if (latP95 && latP95 > 180)
    alerts.push({ sev: "WARN", msg: "High latency p95 detected" });

  return {
    score,
    stats: {
      rows: rows.length,
      mosAvg,
      jitterP95: jitP95,
      lossP95,
      latencyP95: latP95
    },
    worst: [],
    alerts
  };
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
async function runCachedCallReports(env) {

  const orgResult = await webexFetch(env, "/organizations");
  if (!orgResult.ok) return;

  const orgs = orgResult.data.items || [];

  await mapLimit(orgs, 3, async (org) => {

    try {

      const end = new Date();
      const start = new Date();
      start.setDate(end.getDate() - 7);

      // -----------------------------
      // CALL DETAILED CALL HISTORY
      // -----------------------------
      const callHistory = await createWebexReport(
        env,
        org.id,
        "callingDetailedCallHistory",
        {
          startDate: start.toISOString().slice(0,10),
          endDate: end.toISOString().slice(0,10)
        }
      );

      if (callHistory.ok) {

        const reportId = callHistory.data.id;

        const file = await downloadWebexReport(
          env,
          org.id,
          reportId
        );

        if (file.ok) {

          const text = await file.body.text();
          const parsed = parseCsv(text);

          await env.WEBEX.put(
            `cdrCache:${org.id}`,
            JSON.stringify(parsed),
            { expirationTtl: 60 * 60 * 24 * 7 }
          );
        }
      }

      // -----------------------------
      // CALL MEDIA QUALITY REPORT
      // -----------------------------
      const mediaReport = await createWebexReport(
        env,
        org.id,
        "callingMediaQuality",
        {
          startDate: start.toISOString().slice(0,10),
          endDate: end.toISOString().slice(0,10)
        }
      );

      if (mediaReport.ok) {

        const reportId = mediaReport.data.id;

        const file = await downloadWebexReport(
          env,
          org.id,
          reportId
        );

        if (file.ok) {

          const text = await file.body.text();
          const parsed = parseCsv(text);

          await env.WEBEX.put(
            `mediaCache:${org.id}`,
            JSON.stringify(parsed),
            { expirationTtl: 60 * 60 * 24 * 7 }
          );
        }
      }

    } catch (e) {
      console.log("Cached report failed:", org.id);
    }

  });
}
function parseCsv(text) {

  const lines = text.split("\n");
  const headers = lines.shift().split(",");

  return lines
    .filter(l => l.trim().length)
    .map(line => {

      const values = line.split(",");
      const obj = {};

      headers.forEach((h,i)=>{
        obj[h.trim()] = values[i]?.trim();
      });

      return obj;

    });
}
async function ciPollAndProcess(env, orgId, reportType) {

  const state = await ciGetReportState(env, orgId, reportType);
  if (!state?.reportId) return null;

  const r = await webexFetchSafe(env, `/reports/${encodeURIComponent(state.reportId)}`, orgId);
  if (!r.ok) return null;

  if (r.data.status !== "done") {
    return { status:r.data.status };
  }

  // Download CSV (handle ZIP)
  const token = await getAccessToken(env);
  const csvRes = await fetch(r.data.downloadURL, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!csvRes.ok) return null;

  const contentType = csvRes.headers.get("content-type") || "";
  let csvText;

  if (
  contentType.includes("zip") ||
  contentType.includes("octet-stream")
) {

    const buffer = await csvRes.arrayBuffer();
    const zip = await JSZip.loadAsync(buffer);

    const fileNames = Object.keys(zip.files);
    const csvFileName = fileNames.find(name =>
      name.toLowerCase().endsWith(".csv")
    );

    if (!csvFileName) return null;

    csvText = await zip.files[csvFileName].async("string");

  } else {
    csvText = await csvRes.text();
  }

  // ✅ YOU WERE MISSING THIS
  const parsed = parseCsvToJson(csvText);

  // Process analytics
  const processed = ciProcessMediaQuality(parsed.rows);

  await env.WEBEX.put(
    `ci:processed:${orgId}:${reportType}`,
    JSON.stringify(processed),
    { expirationTtl: 60 * 60 * 24 * 7 }
  );

  await ciSetReportState(env, orgId, reportType, {
    reportId: state.reportId,
    status:"done",
    processedAt: Date.now()
  });

  return { status:"done", rows: parsed.rows.length };
}
function ciProcessMediaQuality(rows) {

  let total = 0;
  let mosSum = 0;
  let jitterSum = 0;
  let packetLossSum = 0;

  for (const r of rows) {

    const mos = parseFloat(r["MOS"] || r["Average MOS"] || 0);
    const jitter = parseFloat(r["Jitter (ms)"] || r["Average Jitter"] || 0);
    const loss = parseFloat(r["Packet Loss (%)"] || 0);

    if (!isNaN(mos)) mosSum += mos;
    if (!isNaN(jitter)) jitterSum += jitter;
    if (!isNaN(loss)) packetLossSum += loss;

    total++;
  }

  return {
    totalCalls: total,
    avgMOS: total ? (mosSum / total) : 0,
    avgJitter: total ? (jitterSum / total) : 0,
    avgPacketLoss: total ? (packetLossSum / total) : 0,
    generatedAt: new Date().toISOString()
  };
}
async function apiCDR(env, request) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get("orgId");

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  const max = Math.min(Number(url.searchParams.get("max") || 500), 5000);
  const days = Math.min(Number(url.searchParams.get("days") || 1), 30);

  const endTime = new Date().toISOString();
  const startTime = new Date(
    Date.now() - days * 24 * 60 * 60 * 1000
  ).toISOString();

  await ensureDelegation(env, orgId);
  const token = await getAccessToken(env);

  const base =
    (env.WEBEX_ANALYTICS_BASE ||
      "https://analytics-calling.webexapis.com/v1")
      .replace(/\/+$/, "");

  const endpoint =
    `${base}/cdr_feed?` +
    `startTime=${encodeURIComponent(startTime)}` +
    `&endTime=${encodeURIComponent(endTime)}` +
    `&max=${max}`;

  const res = await fetch(endpoint, {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Organization-Id": orgId,
      Accept: "application/json"
    }
  });

  const text = await res.text();

  try {
    const data = JSON.parse(text);
    return json({ ok: true, records: data.items || [] }, 200);
  } catch {
    return json({
      ok: false,
      error: "invalid_json",
      preview: text.slice(0, 400)
    }, 500);
  }
}
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
async function apiAnalytics(env, request) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get("orgId");

  if (!orgId) {
    return json({ error: "missing_orgId" }, 400);
  }

  await ensureDelegation(env, orgId);

  const token = await getAccessToken(env);
  const base = analyticsBase(env);

  const analyticsUrl =
    `${base}/calling/analytics/summary`;

  console.log("ANALYTICS CALL:", analyticsUrl);

  const res = await fetch(analyticsUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "X-Organization-Id": orgId
    }
  });

  const text = await res.text();

  try {
    const data = JSON.parse(text);

    return json({
      ok: res.ok,
      status: res.status,
      analytics: data
    }, res.ok ? 200 : 500);

  } catch {
    return json({
      error: "analytics_not_json",
      preview: text.slice(0, 400)
    }, 500);
  }
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

 // ✅ Reports API uses orgId as query param (matches your Postman example)
  { test: (p) => p === "/reports" || p.startsWith("/reports?") || p.startsWith("/reports/"), mode: "query" },
 
  // These *often* work best with query orgId in partner scenarios
  { test: (p) => p === "/licenses" || p.startsWith("/licenses?"), mode: "query" },
  { test: (p) => p === "/devices" || p.startsWith("/devices?"), mode: "query" },

  // Telephony/calling config style usually supports X-Organization-Id
  { test: (p) => p.startsWith("/telephony/"), mode: "header" },

  // Default
  { test: (_p) => true, mode: "header" }
];

function scopeModeForPath(path) {

  const p = String(path || "").toLowerCase();

  /* -------------------------
     APIs that REQUIRE header
     ------------------------- */

 // APIs that require orgId query parameter
if (
  p.startsWith("/devices") ||
  p.startsWith("/licenses") ||
  p.startsWith("/numbers") ||
  p.startsWith("/locations") ||
  p.startsWith("/workspaces") ||
  p.startsWith("/telephony") ||
  p.startsWith("/people")
) {
  return "query";
}

// APIs that require header
if (
  p.startsWith("/organizations")
) {
  return "header";
}

  /* -------------------------
     Webex Analytics APIs
     ------------------------- */

  if (
    p.startsWith("/analytics") ||
    p.startsWith("/calling/analytics") ||
    p.startsWith("/cdr_feed")
  ) {
    return "header";
  }

  /* -------------------------
     Default behavior
     ------------------------- */

  return "header";
}
/* =====================================================
   GLOBAL WEBEX API THROTTLE CONTROLLER
   - per-worker pacing
   - retry-after aware
   - exponential backoff with jitter
   - concurrency cap
===================================================== */

const WEBEX_THROTTLE = {
  minSpacingMs: 250,      // base spacing between outbound Webex calls
  maxRetries: 6,          // retries for 429/5xx
  baseBackoffMs: 1000,    // starting backoff
  maxBackoffMs: 20000,    // ceiling
  maxConcurrency: 2       // per worker isolate
};

let __webexInFlight = 0;
let __webexLastCallAt = 0;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
// =====================================================
// Utility helpers
// =====================================================

function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
// =====================================================
// OBSERVABILITY STREAM ENGINE
// =====================================================
async function startObservabilityStream(ws, env, orgId) {

  let closed = false;

  const interval = setInterval(async () => {

    if (closed) return;

    try {

      const telemetry =
        await loadTelemetry(env, orgId) ||
        await collectObservability(env, orgId);

      ws.send(JSON.stringify({
        type: "tenant_update",
        orgId,
        telemetry,
        ts: Date.now()
      }));

    } catch (err) {

      ws.send(JSON.stringify({
        type: "error",
        orgId,
        message: err.message || String(err)
      }));

    }

  }, 3000);

  ws.addEventListener("close", () => {
    closed = true;
    clearInterval(interval);
  });

}
function jitter(ms) {
  return Math.floor(ms * (0.85 + Math.random() * 0.3));
}

async function acquireWebexSlot() {
  while (__webexInFlight >= WEBEX_THROTTLE.maxConcurrency) {
    await sleep(100);
  }

  __webexInFlight++;

  const now = Date.now();
  const waitForSpacing = Math.max(
    0,
    (__webexLastCallAt + WEBEX_THROTTLE.minSpacingMs) - now
  );

  if (waitForSpacing > 0) {
    await sleep(waitForSpacing);
  }

  __webexLastCallAt = Date.now();
}

function releaseWebexSlot() {
  __webexInFlight = Math.max(0, __webexInFlight - 1);
}

function parseRetryAfter(headers) {
  const ra =
    headers.get("retry-after") ||
    headers.get("Retry-After") ||
    "";

  if (!ra) return null;

  const sec = Number(ra);
  if (Number.isFinite(sec)) {
    return sec * 1000;
  }

  const when = new Date(ra).getTime();
  if (Number.isFinite(when)) {
    return Math.max(0, when - Date.now());
  }

  return null;
}

async function throttledWebexFetch(url, init = {}) {
  let lastErr = null;

  for (let attempt = 0; attempt <= WEBEX_THROTTLE.maxRetries; attempt++) {
    await acquireWebexSlot();

    try {
      const res = await fetch(url, init);

      if (res.ok) {
        return res;
      }

      const shouldRetry =
        res.status === 429 ||
        res.status === 408 ||
        res.status === 425 ||
        res.status === 500 ||
        res.status === 502 ||
        res.status === 503 ||
        res.status === 504;

      if (!shouldRetry) {
        return res;
      }

      const retryAfterMs = parseRetryAfter(res.headers);

      const expBackoff = Math.min(
        WEBEX_THROTTLE.maxBackoffMs,
        WEBEX_THROTTLE.baseBackoffMs * Math.pow(2, attempt)
      );

      const waitMs = retryAfterMs ?? jitter(expBackoff);

      console.log("WEBEX RETRY", {
        status: res.status,
        attempt,
        waitMs,
        url: String(url).slice(0, 250)
      });

      if (attempt === WEBEX_THROTTLE.maxRetries) {
        return res;
      }

      await sleep(waitMs);
      continue;

    } catch (err) {
      lastErr = err;

      const waitMs = jitter(
        Math.min(
          WEBEX_THROTTLE.maxBackoffMs,
          WEBEX_THROTTLE.baseBackoffMs * Math.pow(2, attempt)
        )
      );

      console.log("WEBEX FETCH EXCEPTION RETRY", {
        attempt,
        waitMs,
        error: String(err)
      });

      if (attempt === WEBEX_THROTTLE.maxRetries) {
        throw err;
      }

      await sleep(waitMs);

    } finally {
      releaseWebexSlot();
    }
  }

  throw lastErr || new Error("webex_fetch_failed_unknown");
}
async function webexFetch(env, path, orgId = null, options = {}) {

  if (orgId) {
    await ensureDelegation(env, orgId);
  }

  const token = await getAccessToken(env);
  const mode = scopeModeForPath(path);

  let finalPath = path;

  if (orgId && mode === "query") {
    const sep = finalPath.includes("?") ? "&" : "?";
    finalPath = `${finalPath}${sep}orgId=${encodeURIComponent(orgId)}`;
  }

  const isAnalytics =
    finalPath.startsWith("/analytics") ||
    finalPath.startsWith("/calling/analytics") ||
    finalPath.startsWith("/cdr_feed");

  const base = isAnalytics ? analyticsBase(env) : webexBase(env);
  const url = `${base}${finalPath}`;

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    ...(options.headers || {})
  };

  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  if (orgId && isAnalytics) {
    headers["X-Organization-Id"] = orgId;
  }

  if (orgId && mode === "header") {
    headers["X-Organization-Id"] = orgId;
  }

  console.log("WEBEX CALL:", {
    url,
    method: options.method || "GET",
    orgId: orgId ? "yes" : "no",
    isAnalytics
  });

  let res = await throttledWebexFetch(url, {
    method: options.method || "GET",
    headers,
    body: options.body || null
  });

  // One automatic token refresh + retry on 401
  if (res.status === 401) {
    console.log("WEBEX 401 - clearing cached token and retrying once");

    try {
      await env.WEBEX.delete("access_token");
    } catch (err) {
      console.log("Failed clearing cached token:", err);
    }

    const freshToken = await getAccessToken(env);

    const retryHeaders = {
      ...headers,
      Authorization: `Bearer ${freshToken}`
    };

    res = await throttledWebexFetch(url, {
      method: options.method || "GET",
      headers: retryHeaders,
      body: options.body || null
    });
  }

  const text = await res.text();
  const preview = text.slice(0, 500);

  try {
    const data = JSON.parse(text);
    return {
      ok: res.ok,
      status: res.status,
      data,
      preview
    };
  } catch {
    return {
      ok: false,
      status: res.status,
      error: "not_json",
      preview
    };
  }
}
async function resolveCallingInsightOrg(request, env, url, body = null) {
  const user = getCurrentUser(request);
  if (!user) {
    return { ok: false, response: json({ ok:false, error:"access_required" }, 401) };
  }

  const session = await getSession(env, user.email);
  if (!session) {
    return { ok: false, response: json({ ok:false, error:"pin_required" }, 401) };
  }

  const requestedOrgId = normalizeOrgIdParam(
    body?.orgId ||
    url.searchParams.get("orgId") ||
    null
  );

  let resolvedOrgId = null;

  if (user.isAdmin || session.role === "admin") {
    resolvedOrgId = requestedOrgId || session.orgId || null;
  } else {
    resolvedOrgId = session.orgId || null;
  }

  if (!resolvedOrgId) {
    return { ok: false, response: json({ ok:false, error:"missing_orgId" }, 400) };
  }

  return {
    ok: true,
    user,
    session,
    orgId: resolvedOrgId
  };
}

async function getCachedOrganizations(env) {

  const key = "org_list_cache";

  const cached = await env.WEBEX.get(key, { type: "json" });

  if (cached?.items?.length) {
    return cached.items;
  }

  const result = await webexFetch(env, "/organizations");

  if (!result.ok) {
    throw new Error(`organizations_failed: ${result.preview}`);
  }

  const items = result.data?.items || [];

  await env.WEBEX.put(
    key,
    JSON.stringify({ items }),
    { expirationTtl: 300 } // 5 minute cache
  );

  return items;
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
async function webexFetchSafe(env, path, orgId = null, options = {}) {
  try {
    const r = await webexFetch(env, path, orgId, options);

    if (!r.ok) {
      return {
        ok: false,
        status: r.status,
        error: r.preview || "webex_failed",
        data: null
      };
    }

    return {
      ok: true,
      status: r.status,
      data: r.data,
      preview: r.preview
    };

  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: String(e?.message || e),
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
function parseCsvToJson(csvText){
  if(!csvText || !csvText.trim()) {
    return { headers:[], rows:[] };
  }

  const result = Papa.parse(csvText, {
    header: true,
    skipEmptyLines: true,
    dynamicTyping: false
  });

  return {
    headers: result.meta.fields || [],
    rows: result.data || []
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
function buildSimpleMediaSummary(csv){
  const lines = csv.split("\n");

  let poor = 0;
  let total = 0;

  for(const l of lines){
    if(!l.trim()) continue;

    total++;

    if(l.toLowerCase().includes("poor")) {
      poor++;
    }
  }

  return {
    total,
    poor,
    poorRate: total ? (poor / total) : 0
  };
}
function generateAiSummary(values){
  const avgPoor =
    values.reduce((a,b)=>a + (b.poorRate || 0),0) /
    (values.length || 1);

  if(avgPoor > 0.2)
    return { severity:"critical", message:"Consistent poor call quality detected." };

  if(avgPoor > 0.1)
    return { severity:"warning", message:"Quality degradation trending upward." };

  return { severity:"healthy", message:"Call quality within acceptable thresholds." };
}

function isHtmlLike(text) {
  const t = String(text || "").trim().toLowerCase();
  return t.startsWith("<!doctype") || t.startsWith("<html") || t.includes("<div id=\"app\"");
}
async function ciAutoRefreshAllTenants(env) {

  const orgRes = await webexFetchSafe(env, "/organizations", null);
  if (!orgRes.ok) return;

  const orgs = orgRes.data.items || [];

  for (const org of orgs) {

    const orgId = org.id;

    const startDate = dateISO(7);
    const endDate = dateISO(0);

    // Only create if none active
    const state = await ciGetReportState(env, orgId, CALLING_INSIGHT.TITLES.MEDIA);

    if (!state || state.status === "done") {

      await webexFetchSafe(
        env,
        "/reports",
        orgId,
        {
          method:"POST",
          body: JSON.stringify({
            title: CALLING_INSIGHT.TITLES.MEDIA,
            startDate,
            endDate,
            scheduleFrom:"api"
          })
        }
      );
    }

    await ciPollAndProcess(env, orgId, CALLING_INSIGHT.TITLES.MEDIA);
  }
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
// =====================================================
// REPORTS ENGINE (Partner Multi-Tenant)
// Place AFTER webexFetchSafe()
// =====================================================

const REPORTS_KV_PREFIX = "reports:";

// Create report
async function createWebexReport(env, orgId, reportType, params = {}) {

  const body = {
    reportType,
    parameters: params
  };

  const token = await getAccessToken(env);

  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json"
  };

  // Always use org query scoping for reports
  const url = `https://webexapis.com/v1/reports?orgId=${encodeURIComponent(orgId)}`;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });

  const text = await res.text();

  if (!res.ok) {
    return {
      ok:false,
      status:res.status,
      preview:text.slice(0,400)
    };
  }

  const data = JSON.parse(text);

  // Store metadata in KV
  await env.WEBEX.put(
    `${REPORTS_KV_PREFIX}${data.id}`,
    JSON.stringify({
      orgId,
      reportType,
      createdAt:new Date().toISOString(),
      status:data.status
    }),
    { expirationTtl: 60 * 60 * 24 * 7 } // 7 days
  );

  return { ok:true, data };
}

// Get report status
async function getWebexReport(env, orgId, reportId) {

  const token = await getAccessToken(env);

  const url = `https://webexapis.com/v1/reports/${reportId}?orgId=${encodeURIComponent(orgId)}`;

  const res = await fetch(url, {
    headers: { Authorization:`Bearer ${token}` }
  });

  const text = await res.text();

  if (!res.ok) {
    return {
      ok:false,
      status:res.status,
      preview:text.slice(0,400)
    };
  }

  return { ok:true, data:JSON.parse(text) };
}

// Proxy download file
async function downloadWebexReport(env, orgId, reportId) {

  const status = await getWebexReport(env, orgId, reportId);
  if (!status.ok) return status;

  if (status.data.status !== "completed") {
    return { ok:false, error:"not_completed" };
  }

  const token = await getAccessToken(env);

  const fileRes = await fetch(status.data.downloadUrl, {
    headers:{ Authorization:`Bearer ${token}` }
  });

  return {
    ok:fileRes.ok,
    status:fileRes.status,
    body:fileRes.body,
    contentType:fileRes.headers.get("content-type")
  };
}
    /* =====================================================
   Webex Token Handling (refresh + KV cache)
   Production Safe Version
===================================================== */

async function getAccessToken(env) {

  const cacheKey = "access_token";
  const lockKey = "access_token_lock";

  let cached = null;

  try {
    cached = await env.WEBEX.get(cacheKey, { type: "json" });
  } catch (err) {
    console.log("Token cache read error:", err);
  }

  // Use cached token if valid
  if (cached?.token && cached?.expires_at && cached.expires_at > Date.now()) {
    return cached.token;
  }

  // Prevent multiple refreshes
  const existingLock = await env.WEBEX.get(lockKey);

  if (existingLock) {

    // Wait for the other request to finish
    for (let i = 0; i < 10; i++) {
      await sleep(300);

      const retry = await env.WEBEX.get(cacheKey, { type: "json" });

      if (retry?.token && retry?.expires_at > Date.now()) {
        return retry.token;
      }
    }
  }

  // Acquire lock
  await env.WEBEX.put(lockKey, "1", { expirationTtl: 60 });

  console.log("Refreshing Webex OAuth token...");

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: env.CLIENT_ID,
    client_secret: env.CLIENT_SECRET,
    refresh_token: env.REFRESH_TOKEN
  });

  const res = await fetch(
    "https://idbroker.webex.com/idb/oauth2/v1/access_token",
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const data = await res.json();

  if (!res.ok) {
    await env.WEBEX.delete(lockKey);
    throw new Error(`Webex token refresh failed (${res.status}): ${JSON.stringify(data)}`);
  }

  const token = data.access_token;

  const expiresAt = Date.now() + ((data.expires_in - 300) * 1000);

  await env.WEBEX.put(
    cacheKey,
    JSON.stringify({
      token,
      expires_at: expiresAt
    }),
    { expirationTtl: data.expires_in }
  );

  await env.WEBEX.delete(lockKey);

  return token;
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
async function renderCustomerUSERGUIDEHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/user-guide.html"
  );
  if (!res.ok) throw new Error("Failed to load customer PSTN UI");
  return await res.text();
}
async function renderCustomerCALLINGINSIGHTHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/callinginsight.html"
  );
  if (!res.ok) throw new Error("Failed to load Calling Insight UI");
  return await res.text();
}
async function renderCustomerSUPPORTHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/customer/support.html"
  );
  if (!res.ok) throw new Error("Failed to load customer Support UI");
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
async function renderAdminProvisioningHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/provisioning.html"
  );
  if (!res.ok) throw new Error("Failed to load admin provisioning UI");
  return await res.text();
}
async function renderAdminOperationsHTML() {
  const res = await fetch(
    "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/operations.html"
  );
  if (!res.ok) throw new Error("Failed to load admin operations UI");
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
async function renderAdminObservabilityHTML() {
  const res = await fetch("https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/admin/observability.html");
  if (!res.ok) throw new Error("Failed to load admin Observability UI");
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

  let licenseItems = [];

  if (lic.ok) {

    licenseItems = lic.data?.items || [];

    for (const l of licenseItems) {

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

  let deviceItems = [];

  if (dev.ok) {

    deviceItems = dev.data?.items || [];

    offline = deviceItems.filter(d =>
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

    const rows = analytics.data?.items || [];

    totalCalls = rows.reduce((a, r) => a + (r.totalCalls || 0), 0);

    failedCalls = rows.reduce((a, r) => a + (r.failedCalls || 0), 0);

  } else {

    analyticsFailed = true;

  }

  const failureRate = totalCalls > 0
    ? (failedCalls / totalCalls) * 100
    : 0;

  /* -------------------------
     PSTN SNAPSHOT
  -------------------------- */

  try {

    const pstnSnap = await env.WEBEX.get(`pstn:${orgId}`, { type: "json" });

    if (pstnSnap?.scores) {

      pstnScore =
        pstnSnap.scores.pstnObservabilityScore ??
        pstnSnap.scores.pstnReliabilityScore ??
        null;

      pstnDegraded = !!pstnSnap.risk?.apiDegraded;
      pstnSingleTrunk = !!pstnSnap.risk?.singleTrunkRisk;
      pstnE911Risk =
        !!pstnSnap.risk?.timezoneAwareE911Risk ||
        !!pstnSnap.risk?.e911Missing;

      pstnCapacityRed = !!pstnSnap.risk?.capacityRed;

    } else {

      pstnDegraded = true;

    }

  } catch {

    pstnDegraded = true;

  }

  /* =====================================================
     ENTERPRISE WEIGHTED SCORING
  ===================================================== */

  let score = 100;

  if (deficit > 0 && deficit <= 5) score -= 10;
  if (deficit > 5) score -= 25;

  if (offline > 0 && offline <= 5) score -= 10;
  if (offline > 5 && offline <= 10) score -= 20;
  if (offline > 10) score -= 30;

  if (failureRate > 3 && failureRate <= 5) score -= 10;
  if (failureRate > 5 && failureRate <= 10) score -= 20;
  if (failureRate > 10) score -= 35;

  if (licenseFailed) score -= 10;
  if (deviceFailed) score -= 10;
  if (analyticsFailed) score -= 15;

  if (score < 0) score = 0;

  if (pstnScore != null) {

    if (pstnScore < 85) score -= 8;
    if (pstnScore < 70) score -= 12;
    if (pstnScore < 55) score -= 18;

  } else {

    score -= 5;

  }

  if (pstnDegraded) score -= 8;
  if (pstnSingleTrunk) score -= 7;
  if (pstnE911Risk) score -= 12;
  if (pstnCapacityRed) score -= 10;

  /* -------------------------
     STATUS TIERS
  -------------------------- */

  let status = "healthy";

  if (score < 85) status = "degraded";
  if (score < 60) status = "critical";

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

    pstnDegraded,
    pstnSingleTrunk,
    pstnE911Risk,
    pstnCapacityRed

  };

  /* -------------------------
     FINAL RETURN
  -------------------------- */

  return {

    orgId,

    metrics: {

      deviceCount: deviceItems.length,

      licenseCount: licenseItems.reduce(
        (a, l) => a + Number(l.consumedUnits || 0),
        0
      ),

      offlineDevices: offline,

      failureRate: Number(failureRate.toFixed(2)),

      totalCalls,
      failedCalls,

      pstnScore

    },

    ai: {

      riskScore: score,
      status,
      alerts

    },

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
async function prewarmAllTenants(env) {

  const orgs = await webexFetch(env, "/organizations");

  if (!orgs.ok) return;

  const items = orgs.data.items || [];

  await mapLimit(items, 5, async (o) => {
    try {
      await ensureDelegation(env, o.id);
    } catch {}
  });

  return items.length;
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
/* =====================================================
   🕒 SCHEDULED REPORT ENGINE (Partner multi-tenant)
   Place near computeGlobalSummary(), before export default
===================================================== */

function slaFromHealthLike({ score, alerts, metrics }) {
  // Simple, defensible SLA rollup using what you already compute
  // You can evolve this later without changing storage contract.
  const availability = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : null;

  const breachSignals = [
    alerts?.severeCallFailures,
    alerts?.pstnE911Risk,
    alerts?.pstnCapacityRed,
    alerts?.apiDegraded
  ].filter(Boolean).length;

  const status =
    availability == null ? "UNKNOWN" :
    availability >= 99 ? "MEETS_TARGET" :
    availability >= 95 ? "AT_RISK" :
    "BREACH";

  return {
    status,
    availabilityPercent: availability,
    breachSignals,
    inputs: {
      score,
      failureRate: metrics?.failureRate ?? null,
      pstnScore: metrics?.pstnScore ?? null
    }
  };
}

async function buildLicensesDaily(env, orgId) {
  const r = await webexFetchSafe(env, "/licenses", orgId);
  if (!r.ok) return { ok:false, diag: diag("licenses", r) };

  const items = r.data?.items || [];
  let totalConsumed = 0, totalDeficit = 0;

  const normalized = items.map(l => {
    const total = Number(l.totalUnits ?? 0);
    const consumed = Number(l.consumedUnits ?? 0);
    const available = total - consumed;
    const deficit = available < 0 ? Math.abs(available) : 0;
    totalConsumed += consumed;
    totalDeficit += deficit;

    return {
      name: l.name,
      total,
      consumed,
      available,
      deficit,
      status:
        total === -1 ? "UNLIMITED" :
        deficit > 0 ? "DEFICIT" :
        available === 0 ? "FULL" :
        "HEALTHY"
    };
  });

  return {
    ok:true,
    summary: { totalConsumed, totalDeficit, hasDeficit: totalDeficit > 0 },
    items: normalized
  };
}

async function buildAnalyticsDaily(env, orgId) {
  // Reuse your calling analytics path (7d). For daily, store “today snapshot + last 7d rollup”.
  const r = await webexFetchSafe(env, CALLING_ANALYTICS_PATH, orgId);
  if (!r.ok) return { ok:false, diag: diag("analytics/calling", r) };

  const rows = r.data?.items || [];
  const totalCalls = rows.reduce((a, r) => a + (r.totalCalls || 0), 0);
  const failedCalls = rows.reduce((a, r) => a + (r.failedCalls || 0), 0);
  const failureRate = totalCalls ? (failedCalls / totalCalls) * 100 : 0;

  return {
    ok:true,
    rollup7d: {
      totalCalls,
      failedCalls,
      failureRate: Number(failureRate.toFixed(2))
    },
    raw: { items: rows }
  };
}

async function buildSlaDaily(env, orgId) {
  // Use your existing health snapshot logic as the SLA input.
  const health = await computeTenantHealth(env, orgId);
  const sla = slaFromHealthLike(health);
  return { ok:true, health, sla };
}

// ---- Global scheduled job ----
async function runDailyPartnerReports(env, ctx, { fanout = 6 } = {}) {
  // Lock to avoid storms
  const lockKey = `reportsDailyLock:${dayKeyUTC()}`;
  const existing = await env.WEBEX.get(lockKey);
  if (existing) return { ok:false, error:"locked" };
  await env.WEBEX.put(lockKey, "1", { expirationTtl: 60 * 30 });

  const day = dayKeyUTC();
  const startedAt = Date.now();

  const orgRes = await webexFetch(env, "/organizations");
  if (!orgRes.ok) {
    await env.WEBEX.delete(lockKey);
    return { ok:false, error:"org_list_failed", status: orgRes.status, preview: orgRes.preview };
  }

  const orgs = (orgRes.data?.items || [])
    .filter(o => o?.id)
    .map(o => ({ orgId: o.id, orgName: o.displayName || o.name || "Unknown" }));

  const results = await mapLimit(orgs, fanout, async (o) => {
    const orgId = o.orgId;

    // PSTN: prefer snapshot builder you already have
    let pstnPayload = null;
    try {
      const deep = await buildPstnDeep(env, orgId);
      pstnPayload = deep;
      await storePstnSnapshot(env, orgId, deep); // keep your existing snapshot hot
      // Optional: append trend point (daily)
      const didsAssigned = Number(deep?.totals?.didsAssigned || 0);
      const didsTotal = Number(deep?.totals?.didsTotal || 0);
      await appendPstnTrend(env, orgId, {
        day,
        assignedDids: didsAssigned,
        totalDids: didsTotal,
        pstnScore: deep?.scores?.pstnObservabilityScore ?? null
      });
    } catch (e) {
      pstnPayload = { ok:false, error:"pstn_build_failed", message:String(e?.message || e) };
    }

    const licenses = await buildLicensesDaily(env, orgId);
    const analytics = await buildAnalyticsDaily(env, orgId);
    const sla = await buildSlaDaily(env, orgId);
    // ✅ Calling Insight: Reports API (7d rolling media + quality)
    try {
      await runCallingInsightForOrg(env, orgId, o.orgName);
    } catch (e) {
      // Don’t fail the whole daily job if reports are delayed/unsupported
      console.log("Calling Insight failed:", orgId, String(e?.message || e));
    }
    // Persist daily reports with retention
    await writeReport(env, {
      type: "pstn_daily",
      orgId,
      day,
      payload: pstnPayload,
      meta: { orgName: o.orgName }
    });

    await writeReport(env, {
      type: "licenses_daily",
      orgId,
      day,
      payload: licenses,
      meta: { orgName: o.orgName }
    });

    await writeReport(env, {
      type: "analytics_daily",
      orgId,
      day,
      payload: analytics,
      meta: { orgName: o.orgName }
    });

    await writeReport(env, {
      type: "sla_daily",
      orgId,
      day,
      payload: sla,
      meta: { orgName: o.orgName }
    });

    return {
      orgId,
      orgName: o.orgName,
      ok: true,
      slaStatus: sla?.sla?.status || "UNKNOWN",
      licenseDeficit: !!licenses?.summary?.hasDeficit,
      pstnScore: pstnPayload?.scores?.pstnObservabilityScore ?? null
    };
  });

  // Build admin-wide snapshot for dashboard
  const snapshot = {
    day,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    totals: {
      orgs: results.length,
      slaBreaches: results.filter(r => r.slaStatus === "BREACH").length,
      slaAtRisk: results.filter(r => r.slaStatus === "AT_RISK").length,
      licenseDeficitTenants: results.filter(r => r.licenseDeficit).length,
      pstnUnknown: results.filter(r => r.pstnScore == null).length
    },
    tenants: results
  };

  await env.WEBEX.put("adminReportsSnapshotV1", JSON.stringify(snapshot), {
    expirationTtl: 60 * 60 * 24 * 8
  });

  await env.WEBEX.delete(lockKey);
  return { ok:true, snapshot };
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

// 🔥 Allow ci-api subdomain to bypass Access completely
const isCiApiHost = url.hostname === "ci-api.onenecklab.com";

const publicPaths = [
  "/health",
  "/favicon.ico",
  "/pin",
  "/"
];

const publicPrefixes = [
  /* "/customer" */
];

const isPublic =
  isCiApiHost ||
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
if (path === "/api/delegation/warm" && request.method === "POST") {

  const { ok, user } = requireUser(request);
  if (!ok) return user;
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const body = await request.json();
  const orgId = body?.orgId;

  if (!orgId) return json({ error: "missing_orgId" }, 400);

  const success = await warmDelegation(env, orgId);

  return json({ ok: success });
}
if (path === "/api/admin/delegation-health") {

  const { ok, user } = requireUser(request);
  if (!ok) return user;
  if (!user.isAdmin) return json({ error: "admin_only" }, 403);

  const orgs = await webexFetch(env, "/organizations");
  if (!orgs.ok) return json({ error: "org_list_failed" }, 500);

  const results = [];

  for (const o of orgs.data.items || []) {
    const delegated = await isDelegated(env, o.id);
    results.push({
      orgId: o.id,
      orgName: o.displayName,
      delegated
    });
  }

  return json({
    total: results.length,
    delegatedCount: results.filter(r => r.delegated).length,
    results
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

     
if (url.pathname === "/admin/provisioning" && request.method === "GET") {
  return text(await renderAdminProvisioningHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
     if (url.pathname === "/admin/operations" && request.method === "GET") {
  return text(await renderAdminOperationsHTML(), 200, {
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
if (url.pathname === "/admin/observability") {
  return text(await renderAdminObservabilityHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}

     if (url.pathname === "/api/admin/observability" && request.method === "GET") {

  const user = getCurrentUser(request);

  if (!user?.isAdmin) {
    return json({ error: "admin_only" }, 403);
  }

  const orgs = await webexFetch(
    env,
    "/organizations?managedByPartner=true&max=100"
  );
  
  const items = orgs.data?.items || [];

  const results = [];

  for (const org of items) {

    try {

      const telemetry = await loadTelemetry(env, org.id);

      results.push({
        orgId: org.id,
        orgName: org.displayName,
        ...telemetry
      });

    } catch {}

  }

  const summary = {
    total: results.length,
    healthy: results.filter(o => o.ai?.status === "healthy").length,
    degraded: results.filter(o => o.ai?.status === "degraded").length,
    critical: results.filter(o => o.ai?.status === "critical").length
  };

  return json({
    summary,
    items: results
  });
}
     if (url.pathname === "/api/admin/run-telemetry") {

  const user = getCurrentUser(request);

  if (!user?.isAdmin) {
    return json({ error: "admin_only" }, 403);
  }

  await runTelemetryCycle(env);

  return json({ ok: true });
}
// =====================================================
// /api/routes — Dynamic Customer Portal Route Config
// =====================================================
if (url.pathname === "/api/routes" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ error: "unauthorized" }, 401);

  // You can later add role-based filtering here
  const routes = [
    {
      name: "Dashboard",
      path: "/customer/index",
      keywords: ["overview","health","status","tenant"],
      category: "Core",
      description: "High-level tenant health and service posture."
    },
    {
      name: "Licenses",
      path: "/customer/licenses",
      keywords: ["licenses","usage","subscription"],
      category: "Core",
      description: "License allocation and consumption visibility."
    },
    {
      name: "Call Detail Records (CDR)",
      path: "/customer/cdr",
      keywords: ["cdr","call history","detailed call history"],
      category: "Calling",
      description: "Detailed call history and reporting."
    },
    {
      name: "Analytics",
      path: "/customer/analytics",
      keywords: ["analytics","mos","jitter","packet loss"],
      category: "Calling",
      description: "Media and call quality analytics."
    },
    {
      name: "Calling Insight",
      path: "/customer/callinginsight",
      keywords: ["insight","sla","quality score"],
      category: "Calling",
      description: "Aggregated calling performance metrics."
    },
    {
      name: "Devices",
      path: "/customer/devices",
      keywords: ["devices","phones","offline"],
      category: "Infrastructure",
      description: "Webex endpoint inventory."
    },
    {
      name: "PSTN",
      path: "/customer/pstn",
      keywords: ["pstn","trunks","route groups","e911"],
      category: "Infrastructure",
      description: "PSTN architecture and routing."
    },
    {
      name: "Incidents",
      path: "/customer/incidents",
      keywords: ["incidents","outage","alerts"],
      category: "Operations",
      description: "Active and historical service incidents."
    },
    {
      name: "Maintenance",
      path: "/customer/maintenance",
      keywords: ["maintenance","scheduled","change"],
      category: "Operations",
      description: "Scheduled maintenance windows."
    },
    {
      name: "Observability",
      path: "/customer/observability",
      keywords: ["observability","monitoring","uptime"],
      category: "Operations",
      description: "Unified SLA monitoring dashboard."
    },
    {
      name: "Support",
      path: "/customer/support",
      keywords: ["support","ticket","case"],
      category: "Support",
      description: "Submit and track support tickets."
    }
  ];

   return new Response(JSON.stringify({ routes }), {
  headers: {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  }
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
   Customer UI: User-Guide
----------------------------- */
if (url.pathname === "/customer/user-guide" && request.method === "GET") {
  return text(await renderCustomerUSERGUIDEHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
     /* -----------------------------
   Customer UI: Calling Insight
----------------------------- */
if (url.pathname === "/customer/callinginsight" && request.method === "GET") {
  return text(await renderCustomerCALLINGINSIGHTHTML(), 200, {
    "content-type": "text/html; charset=utf-8",
  });
}
     /* -----------------------------
   Customer UI: Support
----------------------------- */
if (url.pathname === "/customer/support" && request.method === "GET") {
  return text(await renderCustomerSUPPORTHTML(), 200, {
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
  // =====================================================
// OBSERVABILITY WEBSOCKET
// =====================================================

if (url.pathname === "/ws/observability") {

  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected websocket", { status: 426 });
  }

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);

  server.accept();

  const orgId = url.searchParams.get("orgId");

  console.log("Observability websocket opened", {
    orgId: orgId || "partner"
  });

  // --------------------------------------------------
  // Send connection confirmation
  // --------------------------------------------------

  server.send(JSON.stringify({
    type: "connected",
    mode: orgId ? "tenant" : "partner",
    ts: Date.now(),
    orgId: orgId || null
  }));

  // --------------------------------------------------
  // Tenant Mode (single org)
  // --------------------------------------------------

  if (orgId) {

    startObservabilityStream(server, env, orgId)
      .catch(err => {
        console.log("Tenant stream error:", err);
      });

  }

  // --------------------------------------------------
  // Partner Mode (all tenants)
  // --------------------------------------------------

  else {

    startPartnerObservabilityStream(server, env)
      .catch(err => {
        console.log("Partner stream error:", err);
      });

  }

  // --------------------------------------------------
  // Handle socket close
  // --------------------------------------------------

  server.addEventListener("close", evt => {

    console.log("Observability websocket closed", {
      code: evt.code,
      reason: evt.reason
    });

  });

  // --------------------------------------------------
  // Handle socket errors
  // --------------------------------------------------

  server.addEventListener("error", err => {

    console.log("Observability websocket error:", err);

  });

  return new Response(null, {
    status: 101,
    webSocket: client
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

if (url.pathname === "/api/admin/observability") {

  const user = getCurrentUser(request);

  if (!user?.isAdmin) {
    return json({ error: "admin_only" }, 403);
  }

  try {

    // --------------------------------------------------
    // 1. FAST PATH: use global cached partner snapshot
    // --------------------------------------------------

    let snapshot = null;

    try {
      const cachedSnapshot = await env.OBS_CACHE.get("telemetry:partner_snapshot");
      if (cachedSnapshot) {
        snapshot = JSON.parse(cachedSnapshot);
      }
    } catch (err) {
      console.log("OBS snapshot read failed:", err);
    }

    if (
  Array.isArray(snapshot) &&
  snapshot.length &&
  snapshot[0]?.ai
) {

      const results = snapshot
        .filter(Boolean)
        .sort((a, b) => Number(b.ai?.riskScore || 0) - Number(a.ai?.riskScore || 0));

      const summary = {
        total: results.length,
        healthy: results.filter(o => o.ai?.status === "healthy").length,
        degraded: results.filter(o => o.ai?.status === "degraded").length,
        critical: results.filter(o => o.ai?.status === "critical").length,
        avgRiskScore: results.length
          ? Math.round(
              results.reduce((a, x) => a + Number(x.ai?.riskScore || 0), 0) / results.length
            )
          : 0,
        source: "partner_snapshot"
      };

      return json({
        summary,
        items: results
      });
    }

    // --------------------------------------------------
    // 2. FALLBACK: build from partner org list
    // --------------------------------------------------

    const orgs = await webexFetch(
      env,
      "/organizations?managedByPartner=true&max=100"
    );

    if (!orgs.ok) {
      return json({
        error: "partner_org_fetch_failed",
        detail: orgs.preview || orgs.status || "unknown"
      }, 500);
    }

    const items = orgs.data?.items || [];

    const batchSize = 4;
    const batches = chunkArray(items, batchSize);
    const results = [];

    for (const batch of batches) {

      const batchResults = await Promise.all(
        batch.map(async org => {
          try {

            const telemetry =
            await loadTelemetry(env, org.id) ||
            await computeTenantHealth(env, org.id);

            return {
              orgId: org.id,
              orgName: org.displayName,
              ...telemetry
            };

          } catch (err) {

            return {
              orgId: org.id,
              orgName: org.displayName,
              type: "observability",
              timestamp: Date.now(),
              metrics: {
                apiLatency: 0,
                licenseCount: 0,
                deviceCount: 0,
                licenseDeficit: 0,
                devicesOffline: 0
              },
              ai: {
                status: "critical",
                riskScore: 100,
                slaRisk: true,
                issues: [
                  {
                    level: "critical",
                    message: `Telemetry collection failed: ${String(err?.message || err)}`
                  }
                ]
              }
            };

          }
        })
      );

      results.push(...batchResults);

      // small delay between batches to avoid bursts against Webex
      await sleep(400);
    }

    results.sort((a, b) => Number(b.ai?.riskScore || 0) - Number(a.ai?.riskScore || 0));

    const summary = {
      total: results.length,
      healthy: results.filter(o => o.ai?.status === "healthy").length,
      degraded: results.filter(o => o.ai?.status === "degraded").length,
      critical: results.filter(o => o.ai?.status === "critical").length,
      avgRiskScore: results.length
        ? Math.round(
            results.reduce((a, x) => a + Number(x.ai?.riskScore || 0), 0) / results.length
          )
        : 0,
      source: "live_fallback"
    };

    return json({
      summary,
      items: results
    });

  } catch (err) {

    console.log("ADMIN OBSERVABILITY ROUTE ERROR:", err);

    return json({
      error: "admin_observability_failed",
      detail: String(err)
    }, 500);

  }
}
   function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

async function getObservability(env, orgId, opts = {}) {
  const maxAgeMs = opts.maxAgeMs ?? 5 * 60 * 1000;

  const cached = await loadTelemetry(env, orgId);

  if (cached && cached.timestamp && (Date.now() - cached.timestamp) < maxAgeMs) {
    return cached;
  }

  const fresh = await collectObservability(env, orgId);
  await storeTelemetry(env, orgId, fresh);
  return fresh;
}

async function getObservabilitySafe(env, org) {
  try {
    const telemetry = await getObservability(env, org.id);
    return {
      ok: true,
      orgId: org.id,
      orgName: org.displayName,
      ...telemetry
    };
  } catch (err) {
    return {
      ok: false,
      orgId: org.id,
      orgName: org.displayName,
      timestamp: Date.now(),
      metrics: {
        apiLatency: 0,
        licenseCount: 0,
        deviceCount: 0,
        licenseDeficit: 0,
        devicesOffline: 0
      },
      ai: {
        status: "critical",
        riskScore: 100,
        slaRisk: true,
        issues: [
          {
            level: "critical",
            message: `Telemetry collection failed: ${String(err.message || err)}`
          }
        ]
      }
    };
  }
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
/* =====================================================
   API: Calling Insight - Report Details
   GET /api/calling-insight/reports/:id
===================================================== */
if (
  request.method === "GET" &&
  /^\/api\/calling-insight\/reports\/[^\/]+$/.test(url.pathname)
) {
  const reportId = url.pathname.split("/")[4];

  const resolved = await resolveCallingInsightOrg(request, env, url);
  if (!resolved.ok) return resolved.response;

  await ensureDelegation(env, resolved.orgId);

  const r = await webexFetchSafe(
    env,
    `/reports/${encodeURIComponent(reportId)}`,
    resolved.orgId
  );

  if (!r.ok) return json({ ok:false, error: r.error, preview:r.preview || null }, 500);

  const payload = r.data?.items?.[0] || r.data;

  return json({ ok:true, orgId: resolved.orgId, ...payload });
}
/* =====================================================
   API: Calling Insight - CSV Download Proxy + KV Store
   GET /api/calling-insight/reports/:id/csv
===================================================== */
if (
  request.method === "GET" &&
  /^\/api\/calling-insight\/reports\/[^\/]+\/csv$/.test(url.pathname)
) {
  const parts = url.pathname.split("/");
  const reportId = parts[4];

  const resolved = await resolveCallingInsightOrg(request, env, url);
  if (!resolved.ok) return resolved.response;

  await ensureDelegation(env, resolved.orgId);

  const r = await webexFetchSafe(
    env,
    `/reports/${encodeURIComponent(reportId)}`,
    resolved.orgId
  );

  if (!r.ok) return json({ ok:false, error:"report_fetch_failed", preview:r.preview || null }, 500);

  const payload = r.data?.items?.[0] || r.data;
  if (!payload.downloadURL) return json({ ok:false, error:"not_ready" }, 400);

  const token = await getAccessToken(env);
  const csvRes = await fetch(payload.downloadURL, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!csvRes.ok) {
    return json({ ok:false, error:"csv_fetch_failed" }, 500);
  }

  const contentType = csvRes.headers.get("content-type") || "";
  let csvText;

  if (contentType.includes("zip") || contentType.includes("octet-stream")) {
    const buffer = await csvRes.arrayBuffer();
    const zip = await JSZip.loadAsync(buffer);

    const csvFileName = Object.keys(zip.files)
      .find(name => name.toLowerCase().endsWith(".csv"));

    if (!csvFileName) {
      return json({ ok:false, error:"csv_not_found_in_zip" }, 500);
    }

    csvText = await zip.files[csvFileName].async("string");
  } else {
    csvText = await csvRes.text();
  }

  const parsed = parseCsvToJson(csvText);
  const rows = parsed.rows || [];
  const metrics = computeWorkerQualityMetrics(rows);

  try {
    const summaryPayload = {
      lastReportId: reportId,
      generatedAt: new Date().toISOString(),
      score: metrics.score,
      metrics,
      alerts: metrics.alerts,
      worst: metrics.worst
    };

    await env.CI_SUMMARY_KV.put(
      `ci:summary:${resolved.orgId}`,
      JSON.stringify(summaryPayload),
      { expirationTtl: 60 * 60 * 24 * 30 }
    );
  } catch (e) {
    console.log("CI summary KV store failed:", e);
  }

  return json({
    ok: true,
    orgId: resolved.orgId,
    reportId,
    rows: parsed.rows,
    columns: parsed.headers
  });
}
     if (url.pathname === "/api/calling-insight/summary" && request.method === "GET") {
  const orgId = url.searchParams.get("orgId");
  if (!orgId) {
    return new Response(JSON.stringify({ error: "Missing orgId" }), { status: 400 });
  }

  const data = await env.CI_SUMMARY_KV.get(`ci:summary:${orgId}`);
  if (!data) {
    return new Response(JSON.stringify({ ok: true, empty: true }), {
      headers: { "content-type": "application/json" }
    });
  }

  return new Response(data, {
    headers: { "content-type": "application/json" }
  });
}
   if (
  request.method === "GET" &&
  url.pathname === "/api/calling-insight/templates"
) {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"auth_required" }, 401);

  const session = await getSession(env, user.email);
  if (!session) return json({ ok:false, error:"pin_required" }, 401);

  const requestedOrgId = url.searchParams.get("orgId");

  const orgId = user.isAdmin
    ? (requestedOrgId || session.orgId)
    : session.orgId;

  if (!orgId) {
    return json({ ok:false, error:"missing_orgId" }, 400);
  }

  await ensureDelegation(env, orgId);

  const r = await webexFetchSafe(env, "/report/templates", orgId);

  if (!r.ok) {
    return json({
      ok:false,
      error: r.error,
      preview: r.preview || null
    }, 500);
  }

  return json({
    ok:true,
    orgId,
    items: r.data?.items || []
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

if (url.pathname === "/api/admin/orgs") {

  try {

    const user = getCurrentUser(request);

    if (!user || user.isAdmin !== true) {
      return json({ error: "admin_required" }, 403);
    }

    const r = await webexFetch(env, "/organizations?managedByPartner=true&max=100");

    if (!r.ok) {

      console.log("ADMIN ORG FETCH FAILED:", r.preview);

      return json({
        error: "webex_orgs_failed",
        detail: r.preview
      }, 500);

    }

    const items = r.data?.items || [];

   // return json(
   //   items.map(x => ({
     //   id: x.id,
    //    displayName: x.displayName
  //    }))
  //  ); 
   return json({
  items: items.map(x => ({
    orgId: x.id,
    orgName: x.displayName
  }))
});

  } catch (err) {

    console.log("ADMIN ORGS ROUTE ERROR:", err);

    return json({
      error: "admin_orgs_route_failure",
      detail: String(err)
    }, 500);

  }

}
      
if (url.pathname === "/api/admin/org-health" && request.method === "GET") {

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

  /* --------------------------
     LICENSE DEFICIT CALCULATION
  -------------------------- */

  try {
    const licResult = await webexFetch(env, "/licenses", orgId);

    if (licResult?.ok && Array.isArray(licResult.data?.items)) {
      for (const x of licResult.data.items) {
        const total = Number(x.totalUnits ?? 0);
        const consumed = Number(x.consumedUnits ?? 0);

        if (Number.isFinite(total) && total >= 0) {
          deficit += Math.max(0, consumed - total);
        }
      }
    }
  } catch (e) {
    console.error("License fetch failed", e);
  }

  /* --------------------------
     DEVICE OFFLINE CALCULATION
     (MATCHES /api/devices LOGIC)
  -------------------------- */

  try {
    const devResult = await webexFetch(env, "/devices", orgId);

    if (devResult?.ok && Array.isArray(devResult.data?.items)) {

      for (const d of devResult.data.items) {

        const connection = String(d.connectionStatus || "").toLowerCase();

        const isOnline =
          connection.includes("connected") ||
          connection.includes("online") ||
          connection.includes("registered");

        const isOffline =
          connection.includes("offline") ||
          connection.includes("disconnected");

        if (!isOnline && isOffline) {
          offline++;
        }
      }
    }
  } catch (e) {
    console.error("Device fetch failed", e);
  }

  return new Response(
    JSON.stringify({ orgId, deficit, offline }),
    {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
      }
    }
  );
}
      /* -----------------------------
         /api/org
         - Admin: returns all orgs
         - Customer: requires session; returns only matching org
      ----------------------------- */
/* if (url.pathname === "/api/org") {
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
} */

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
     async function ciGetReportState(env, orgId, reportType) {
  const key = `ci:state:${orgId}:${reportType}`;
  const raw = await env.WEBEX.get(key);
  return raw ? JSON.parse(raw) : null;
}

async function ciSetReportState(env, orgId, reportType, data) {
  const key = `ci:state:${orgId}:${reportType}`;
  await env.WEBEX.put(key, JSON.stringify(data), {
    expirationTtl: 60 * 60 * 24 // 24 hours
  });
}
     /* =========================
   CALLING INSIGHT API (Reports + KV Rollups)
   Routes:
   - GET  /api/calling-insight/rollup?kind=media7d|quality7d&orgId=...
   - GET  /api/calling-insight/alerts?orgId=...
   - GET  /api/calling-insight/reports?orgId=...
   - POST /api/calling-insight/reports  (admin only) { title,startDate,endDate, orgId? }
   - POST /api/calling-insight/ingest   (admin only) { orgId }
========================= */
if (url.pathname === "/api/calling-insight/rollup" && request.method === "GET") {
  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);
  if (!session) return json({ ok:false, error:"unauthorized" }, 401);

  const kind = url.searchParams.get("kind") || "media7d";

  // orgId: customer = session org; admin may pass orgId
  const orgId =
    session.role === "admin"
      ? (url.searchParams.get("orgId") || session.orgId || null)
      : (session.orgId || null);

  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 200);

  const raw = await env.WEBEX.get(CALLING_INSIGHT.kv.rollup(orgId, kind));
  const data = raw ? JSON.parse(raw) : null;

  return json({ ok:true, orgId, kind, data }, 200);
}

if (url.pathname === "/api/calling-insight/alerts" && request.method === "GET") {
  const user = getCurrentUser(request);
  const session = await getSession(env, user.email);
  if (!session) return json({ ok:false, error:"unauthorized" }, 401);

  const orgId =
    session.role === "admin"
      ? (url.searchParams.get("orgId") || session.orgId || null)
      : (session.orgId || null);

  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 200);

  const raw = await env.WEBEX.get(CALLING_INSIGHT.kv.alerts(orgId));
  const data = raw ? JSON.parse(raw) : { orgId, alerts:[], updatedAt:null };

  return json({ ok:true, orgId, data }, 200);
}
    
     // =============================
// Calling Insight - AI Summary
// POST /api/calling-insight/ai/summary
// =============================
if (url.pathname === "/api/calling-insight/ai/summary" && request.method === "POST") {
  const user = getCurrentUser(request);
  const session = user ? await getSession(env, user.email) : null;
  if (!session) return json({ ok:false, error:"unauthorized" }, 401);

  const body = await request.json().catch(()=> ({}));

  // Resolve orgId safely
  const requestedOrgId = body.orgId || url.searchParams.get("orgId") || null;
  const orgId = (session.role === "admin")
    ? (requestedOrgId || session.orgId || null)
    : (session.orgId || null);

  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 400);

  // Minimal required inputs
  const reportId = body?.report?.id || null;
  const title = body?.report?.title || "Calling Insight";
  const tab = body?.tab || "overview";
  const metrics = body?.metrics || null;

  if (!reportId || !metrics) {
    return json({ ok:false, error:"missing_report_or_metrics" }, 400);
  }

  // Rate limit key (simple)
  const rlKey = `ci:ai:rl:${user.email}:${orgId}`;
  const rlRaw = await env.WEBEX.get(rlKey);
  const rl = rlRaw ? JSON.parse(rlRaw) : { ts: 0, count: 0 };
  const now = Date.now();
  const windowMs = 60 * 1000;
  if (now - rl.ts > windowMs) { rl.ts = now; rl.count = 0; }
  rl.count++;
  await env.WEBEX.put(rlKey, JSON.stringify(rl), { expirationTtl: 90 });
  if (rl.count > 8) {
    return json({ ok:false, error:"rate_limited", hint:"Too many AI summaries per minute" }, 429);
  }

  // Cache
  const cacheKey = `ci:ai:summary:${orgId}:${reportId}:${tab}`;
  const cached = await env.WEBEX.get(cacheKey);
  if (cached) {
    const out = JSON.parse(cached);
    return json({ ok:true, cache:"HIT", ...out }, 200);
  }

  // Build prompt (data-minimized)
  const payload = {
    tenant: { orgId },
    report: body.report,
    tab,
    metrics: {
      score: metrics.score,
      stats: metrics.stats,
      worst: (metrics.worst || []).slice(0, 12),
      alerts: (metrics.alerts || []).slice(0, 12)
    }
  };

  // Call OpenAI (you must set env.OPENAI_API_KEY)
  // This uses the Responses API. :contentReference[oaicite:3]{index=3}
  const ai = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.OPENAI_API_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      model: env.OPENAI_MODEL || "gpt-5.2-mini",
      input: [
        {
          role: "system",
          content: [
            {
              type: "text",
              text:
`You are a carrier-grade Webex Calling quality analyst.
Write a concise but high-signal troubleshooting summary for telecom operations.
No fluff. No marketing. Be specific.
Return JSON only with keys: summaryText, checks, likelyRootCauses, confidence, nextActions.
checks is an array of {title, detail}.
likelyRootCauses is an array of {cause, why, evidence}.
nextActions is an array of strings.
confidence is 0-100.`
            }
          ]
        },
        {
          role: "user",
          content: [{ type: "text", text: JSON.stringify(payload) }]
        }
      ],
      // Keep responses stable for ops workflows
      temperature: 0.2
    })
  }).catch(e => null);

  if (!ai) return json({ ok:false, error:"ai_fetch_failed" }, 502);

  const aiText = await ai.text();
  let aiJson = null;

  try { aiJson = JSON.parse(aiText); } catch {
    return json({ ok:false, error:"ai_not_json", preview: aiText.slice(0, 500) }, 502);
  }

  // Responses API returns output arrays; extract text or json-like content robustly
  const extracted = extractResponsesJson(aiJson);
  if (!extracted) {
    return json({ ok:false, error:"ai_parse_failed", preview: JSON.stringify(aiJson).slice(0, 500) }, 502);
  }

  const out = {
    model: env.OPENAI_MODEL || "gpt-5.2-mini",
    reportTitle: title,
    summaryText: extracted.summaryText || "",
    checks: extracted.checks || [],
    likelyRootCauses: extracted.likelyRootCauses || [],
    nextActions: extracted.nextActions || [],
    confidence: extracted.confidence ?? null
  };

  // Cache for fast reload (10 minutes default)
  await env.WEBEX.put(cacheKey, JSON.stringify(out), { expirationTtl: 600 });

  return json({ ok:true, cache:"MISS", ...out }, 200);
}

// Helper to extract JSON from Responses API result
function extractResponsesJson(r){
  // The API schema can evolve; be defensive.
  // Try: r.output_text (if present), else scan output content blocks for text.
  let text = r.output_text || null;

  if (!text && Array.isArray(r.output)) {
    for (const item of r.output) {
      const content = item?.content || [];
      for (const c of content) {
        if (c?.type === "output_text" && c?.text) { text = c.text; break; }
        if (c?.type === "text" && c?.text) { text = c.text; break; }
      }
      if (text) break;
    }
  }

  if (!text) return null;

  // The model was instructed to output JSON only, so parse it.
  try { return JSON.parse(text); } catch { return null; }
}
// ============================================================
// CALLING INSIGHT — REPORT LIST + INTELLIGENT CREATION
// ============================================================

// -------------------------------
// GET — List reports (Calling Insights)
// -------------------------------
if (url.pathname === "/api/calling-insight/reports" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"auth_required" }, 401);

  const session = await getSession(env, user.email);
  if (!session) return json({ ok:false, error:"pin_required" }, 401);

  const requestedOrgId = url.searchParams.get("orgId");

  // Admin can request any tenant
  // Customer always uses their own tenant
  const orgId = user.isAdmin
    ? (requestedOrgId || session.orgId)
    : session.orgId;

  if (!orgId) {
    return json({ ok:false, error:"missing_orgId" }, 400);
  }

  await ensureDelegation(env, orgId);

  const r = await webexFetchSafe(
    env,
    "/callingInsights/reports",
    orgId
  );

  return json({
    ok: r.ok,
    orgId,
    reports: r.data?.items || [],
    numberOfReports: r.data?.numberOfReports || 0,
    preview: r.preview || null,
    error: r.error || null
  });
}
// -------------------------------
// POST — Intelligent Report Create
// -------------------------------
// -------------------------------
// POST — Create Calling Insights report
// -------------------------------
if (url.pathname === "/api/calling-insight/reports" && request.method === "POST") {

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

  const body = await request.json();
  const { title, startDate, endDate } = body;

  if (!title || !startDate || !endDate) {
    return json({ ok:false, error:"missing_parameters" }, 400);
  }

  await ensureDelegation(env, resolvedOrgId);

  // 1️⃣ Get templates
  const tplRes = await webexFetchSafe(env, "/report/templates", resolvedOrgId);
  if (!tplRes.ok) {
    return json({ ok:false, error:"template_fetch_failed" }, 502);
  }

  const templates = tplRes.data?.items || [];
  const template = templates.find(t => t.title === title);

  if (!template) {
    return json({ ok:false, error:"template_not_found" }, 404);
  }

  const templateId = template.Id || template.id;

  // 2️⃣ Create report
  const createRes = await webexFetchSafe(
    env,
    "/reports",
    resolvedOrgId,
    {
      method: "POST",
      body: JSON.stringify({
        templateId,
        startDate,
        endDate
      })
    }
  );

  if (!createRes.ok) {
    return json({
      ok:false,
      error:"report_create_failed",
      preview:createRes.preview || null
    }, 502);
  }

  const raw = createRes.data;
  const report =
    raw?.items?.[0] ||
    raw?.items ||
    raw;

  const id =
    report?.Id ||
    report?.id ||
    report?.reportId ||
    null;

  if (!id) {
    return json({
      ok:false,
      error:"report_id_missing",
      preview:JSON.stringify(raw).slice(0,300)
    }, 502);
  }

  // 🔥 THIS LINE FIXES YOUR UI
  return json({
    ok:true,
    id,            // <-- UI needs this
    report,
    orgId: resolvedOrgId
  }, 200);
}

     // -----------------------------------
// POST — Run report (Create on Cisco)
// UI calls: POST /api/calling-insight/run
// Body: { orgId?, title, startDate, endDate }
// Returns: { ok:true, id, report }
// -----------------------------------
if (url.pathname === "/api/calling-insight/run" && request.method === "POST") {
  let body = {};
  try { body = await request.json(); } catch {}

  const resolved = await resolveCallingInsightOrg(request, env, url, body);
  if (!resolved.ok) return resolved.response;

  const resolvedOrgId = resolved.orgId;

  const title = String(body.title || "").trim();
  const today = new Date();
  today.setDate(today.getDate() - 1);

  const maxEndDate = today.toISOString().slice(0,10);

  let startDate = String(body.startDate || "").trim();
  let endDate = String(body.endDate || "").trim();

  if (endDate > maxEndDate) {
    endDate = maxEndDate;
  }

  if (!title || !startDate || !endDate) {
    return json({ ok:false, error:"missing_title_or_dates" }, 400);
  }

  await ensureDelegation(env, resolvedOrgId);

  const tplRes = await webexFetchSafe(env, "/report/templates", resolvedOrgId);
  if (!tplRes.ok) {
    return json({
      ok:false,
      error:"template_fetch_failed",
      preview: tplRes.preview || null
    }, 502);
  }

  const templates = tplRes.data?.items || [];
  const template = templates.find(t => String(t.title || "").trim() === title);

  if (!template) {
    return json({
      ok:false,
      error:"template_not_found",
      titleRequested: title,
      templateTitles: templates.slice(0, 50).map(t => t.title).filter(Boolean)
    }, 404);
  }

  const templateId = template.id || template.Id || template.templateId || template.templateID;
  if (!templateId) {
    return json({ ok:false, error:"template_id_missing" }, 500);
  }

  const createRes = await webexFetchSafe(
    env,
    "/reports",
    resolvedOrgId,
    {
      method: "POST",
      body: JSON.stringify({
        templateId,
        startDate,
        endDate
      })
    }
  );

  if (!createRes.ok) {
    return json({
      ok:false,
      error:"report_create_failed",
      status: createRes.status || 502,
      preview: createRes.preview || null
    }, 502);
  }

  const raw = createRes.data;
  const report = raw?.items?.[0] || raw?.items || raw;

  const id =
    report?.id ||
    report?.Id ||
    report?.reportId ||
    report?.reportID ||
    null;

  if (!id) {
    return json({
      ok:false,
      error:"report_id_missing_in_response",
      responsePreview: JSON.stringify(raw || {}).slice(0, 500)
    }, 502);
  }

  return json({
    ok: true,
    orgId: resolvedOrgId,
    id,
    report
  }, 200);
}
     // ============================================================
// CALLING INSIGHT — ENTERPRISE POLLING ENGINE
// ============================================================

if (url.pathname === "/api/calling-insight/poll" && request.method === "POST") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);
  const body = await request.json().catch(()=> ({}));

  const requestedOrgId =
    body.orgId ||
    url.searchParams.get("orgId") ||
    null;

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

  const reportType = body.title || CALLING_INSIGHT.TITLES.MEDIA;
  const stateKey = `ci:state:${resolvedOrgId}:${reportType}`;

  const existingRaw = await env.WEBEX.get(stateKey);
  if (!existingRaw) {
    return json({ ok:false, error:"no_active_report" }, 200);
  }

  const state = JSON.parse(existingRaw);

  if (!state.reportId) {
    return json({ ok:false, error:"invalid_state" }, 200);
  }

  // ---------------------------------------------------------
  // 1️⃣ Poll Cisco report status
  // ---------------------------------------------------------

  const r = await webexFetchSafe(
    env,
    `/reports/${encodeURIComponent(state.reportId)}`,
    resolvedOrgId
  );

  if (!r.ok) {
    return json({
      ok:false,
      error:r.error,
      preview:r.preview
    }, 200);
  }

  const status = r.data?.status;

  if (status !== "done") {
    return json({
      ok:true,
      orgId: resolvedOrgId,
      status,
      reportId: state.reportId
    }, 200);
  }

  // ---------------------------------------------------------
  // 2️⃣ Download CSV
  // ---------------------------------------------------------

  const downloadURL = r.data?.downloadURL;
  if (!downloadURL) {
    return json({ ok:false, error:"missing_download_url" }, 200);
  }

  const csvRes = await fetch(downloadURL);
  const csvText = await csvRes.text();

  // ---------------------------------------------------------
  // 3️⃣ Parse CSV
  // ---------------------------------------------------------

  const parsed = parseCsvToJson(csvText);
  const rows = parsed.rows || [];

  // ---------------------------------------------------------
  // 4️⃣ Process Analytics (Media Quality example)
  // ---------------------------------------------------------

  const processed = ciProcessMediaQuality(rows);

  // ---------------------------------------------------------
  // 5️⃣ Store Processed Data (7-day retention)
  // ---------------------------------------------------------

  const processedKey = `ci:processed:${resolvedOrgId}:${reportType}`;

  await env.WEBEX.put(
    processedKey,
    JSON.stringify({
      ...processed,
      reportId: state.reportId,
      rowCount: rows.length,
      processedAt: new Date().toISOString()
    }),
    { expirationTtl: 60 * 60 * 24 * 7 }
  );

  // ---------------------------------------------------------
  // 6️⃣ Update State
  // ---------------------------------------------------------

  await env.WEBEX.put(
    stateKey,
    JSON.stringify({
      reportId: state.reportId,
      status:"done",
      processedAt: Date.now()
    }),
    { expirationTtl: 60 * 60 * 24 }
  );

  return json({
    ok:true,
    orgId: resolvedOrgId,
    status:"processed",
    reportId: state.reportId,
    rows: rows.length
  }, 200);
}
// ============================================================
// CALLING INSIGHT — PROCESSED ANALYTICS FETCH
// ============================================================

if (url.pathname === "/api/calling-insight/processed" && request.method === "GET") {

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

  const reportType =
    url.searchParams.get("title") ||
    CALLING_INSIGHT.TITLES.MEDIA;

  const processedKey = `ci:processed:${resolvedOrgId}:${reportType}`;

  const raw = await env.WEBEX.get(processedKey);

  return json({
    ok:true,
    orgId: resolvedOrgId,
    data: raw ? JSON.parse(raw) : null
  }, 200);
}
     if (url.pathname === "/api/calling-insight/ingest" && request.method === "POST") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);

  const body = await request.json().catch(()=> ({}));

  const requestedOrgId =
    body.orgId ||
    url.searchParams.get("orgId") ||
    null;

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

  const out = await ciPollAndIngestPending(env, resolvedOrgId, null);

  return json({
    ok:true,
    orgId: resolvedOrgId,
    out
  }, 200);
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
// SUPPORT TICKET SUBMISSION
// POST /api/support/ticket
// =====================================================
if (url.pathname === "/api/support/ticket" && request.method === "POST") {
  try {

    let body = {};
    const contentType = request.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      body = await request.json();
    } else {
      const form = await request.formData();
      body = Object.fromEntries(form.entries());
    }

    // Map UI fields to backend fields
    const name =
      body.name ||
      body.fullName ||
      body.orgName ||
      "Portal User";

    const email =
      body.email ||
      body.contactEmail ||
      body.pointOfContact ||
      null;

    const subject =
      body.subject ||
      body.summary ||
      body.issueSummary ||
      null;

    const description =
      body.description ||
      body.details ||
      body.message ||
      null;

    const severity = body.severity || "Normal";
    const company = body.orgName || body.company || "Unknown";
    const callback = body.callback || body.callbackNumber || "";

    if (!email || !subject || !description) {
      return json({
        ok: false,
        error: "missing_fields",
        received: body
      }, 400);
    }

    if (!env.BREVO_API_KEY || !env.BREVO_SENDER_EMAIL) {
      return json({ ok:false, error:"email_not_configured" }, 500);
    }

    const emailPayload = {
      sender: {
        name: "US Signal Webex Portal",
        email: env.BREVO_SENDER_EMAIL
      },
      to: [
        { email: env.SUPPORT_EMAIL || "support@ussignal.com" }
      ],
      subject: `[Support Ticket] ${severity} - ${subject}`,
      htmlContent: `
        <h2>New Support Ticket</h2>
        <p><strong>Customer:</strong> ${company}</p>
        <p><strong>Submitted By:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Callback:</strong> ${callback}</p>
        <p><strong>Severity:</strong> ${severity}</p>
        <hr/>
        <p>${description.replace(/\n/g, "<br/>")}</p>
      `
    };

    const resp = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": env.BREVO_API_KEY
      },
      body: JSON.stringify(emailPayload)
    });

    if (!resp.ok) {
      const text = await resp.text();
      return json({ ok:false, error:"email_failed", details:text }, 500);
    }

    return json({ ok:true });

  } catch (e) {
    return json({ ok:false, error:"server_exception", details:String(e) }, 500);
  }
}
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
 // =====================================================
// ADMIN ALERTS
// GET /api/alerts?orgId=
// =====================================================
if (url.pathname === "/api/alerts" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  if (!orgId) {
    return json({ ok:false, error:"missing_orgId" }, 400);
  }

  // You can wire this to real data later.
  // For now return a safe structure so UI doesn’t explode.

  return json({
    ok: true,
    alerts: [],
    orgId,
    generatedAt: new Date().toISOString()
  }, 200);
}
     // =====================================================
// GET /api/alerts/summary
// =====================================================
if (url.pathname === "/api/alerts/summary" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  return json({
    ok:true,
    total:0,
    critical:0,
    warning:0,
    info:0,
    generatedAt:new Date().toISOString()
  });
}
     // =====================================================
// GET /api/devices/summary
// =====================================================
if (url.pathname === "/api/devices/summary" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  return json({
    ok:true,
    total:0,
    online:0,
    offline:0,
    unknown:0,
    generatedAt:new Date().toISOString()
  });
}
     // =====================================================
// GET /api/pstn/health
// =====================================================
if (url.pathname === "/api/pstn/health" && request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) {
    return json({ ok:false, error:"access_required" }, 401);
  }

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  return json({
    ok:true,
    orgId,
    health:"unknown",
    trunkCount:0,
    lastChecked:new Date().toISOString()
  });
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
/* =====================================================
   📦 REPORTS PIPELINE CORE (KV + Retention + CSV→JSON)
   Place AFTER cacheJson() helper block
===================================================== */

// --- Env-driven retention (days) ---
function retentionDaysFor(type, env) {
  // Allow per-type tuning:
  // REPORT_RETENTION_PSTN_DAYS=30, REPORT_RETENTION_LICENSES_DAYS=30, REPORT_RETENTION_SLA_DAYS=60, REPORT_RETENTION_ANALYTICS_DAYS=30
  const map = {
    pstn_daily: "REPORT_RETENTION_PSTN_DAYS",
    licenses_daily: "REPORT_RETENTION_LICENSES_DAYS",
    sla_daily: "REPORT_RETENTION_SLA_DAYS",
    analytics_daily: "REPORT_RETENTION_ANALYTICS_DAYS",
    webex_report: "REPORT_RETENTION_WEBEX_REPORT_DAYS",
  };
  const key = map[type] || "REPORT_RETENTION_DAYS";
  const n = Number(env[key] || env.REPORT_RETENTION_DAYS || 30);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 30;
}

function dayKeyUTC(d = new Date()) {
  return new Date(d).toISOString().slice(0, 10); // YYYY-MM-DD
}

function reportKey(type, orgId, day) {
  return `rpt:${type}:${orgId}:${day}`;
}

function reportIndexKey(type, orgId) {
  return `rptIndex:${type}:${orgId}`; // { items:[{day, key, generatedAt, meta}] }
}

async function writeReport(env, { type, orgId, day, payload, meta = {} }) {
  const generatedAt = new Date().toISOString();
  const key = reportKey(type, orgId, day);

  // Store report payload
  await env.WEBEX.put(key, JSON.stringify({
    type, orgId, day,
    generatedAt,
    meta,
    payload
  }), { expirationTtl: 60 * 60 * 24 * (retentionDaysFor(type, env) + 7) }); // KV TTL slightly > retention

  // Update index
  const idxKey = reportIndexKey(type, orgId);
  const existing = await env.WEBEX.get(idxKey, { type: "json" });
  const items = Array.isArray(existing?.items) ? existing.items : [];

  // Upsert day
  const next = items.filter(x => x?.day !== day);
  next.push({ day, key, generatedAt, meta });

  // Sort asc and keep last N days
  next.sort((a, b) => String(a.day).localeCompare(String(b.day)));
  const keep = retentionDaysFor(type, env);
  const trimmed = next.slice(Math.max(0, next.length - keep));

  await env.WEBEX.put(idxKey, JSON.stringify({ items: trimmed }), {
    expirationTtl: 60 * 60 * 24 * (keep + 10)
  });

  // Best-effort: delete keys that fell out of retention
  const dropped = next.slice(0, Math.max(0, next.length - keep));
  if (dropped.length) {
    await Promise.all(dropped.map(x => env.WEBEX.delete(x.key).catch(()=>null)));
  }

  return { ok: true, key, indexCount: trimmed.length };
}

async function readReportIndex(env, type, orgId) {
  const idx = await env.WEBEX.get(reportIndexKey(type, orgId), { type: "json" });
  return Array.isArray(idx?.items) ? idx.items : [];
}

async function readReport(env, type, orgId, day) {
  return await env.WEBEX.get(reportKey(type, orgId, day), { type: "json" });
}

// --- CSV parsing (robust enough for Webex CSV) ---
function parseCsvToJson(csvText, { maxRows = 50000 } = {}) {
  const text = String(csvText || "");
  if (!text.trim()) return { headers: [], rows: [] };

  const rows = [];
  let row = [];
  let cur = "";
  let i = 0;
  let inQuotes = false;

  while (i < text.length) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { // escaped quote
          cur += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      cur += ch;
      i++;
      continue;
    }

    if (ch === '"') { inQuotes = true; i++; continue; }
    if (ch === ",") { row.push(cur); cur = ""; i++; continue; }
    if (ch === "\r") { i++; continue; }
    if (ch === "\n") {
      row.push(cur);
      rows.push(row);
      if (rows.length >= maxRows) break;
      row = [];
      cur = "";
      i++;
      continue;
    }

    cur += ch;
    i++;
  }

  // flush last line if any
  if (cur.length || row.length) {
    row.push(cur);
    rows.push(row);
  }

  const headers = (rows.shift() || []).map(h => String(h || "").replace(/^\ufeff/, "").trim());
  const out = rows
    .filter(r => r.some(x => String(x || "").trim() !== ""))
    .map(r => {
      const obj = {};
      for (let c = 0; c < headers.length; c++) {
        obj[headers[c] || `col_${c}`] = r[c] ?? "";
      }
      return obj;
    });

  return { headers, rows: out };
}
     /* =========================
   CALLING INSIGHT (REPORTS API) — 7D ROLLUPS + ALERTS
   - Creates reports via POST /reports (orgId query-mode)
   - Polls GET /reports/{id}
   - Downloads CSV from downloadURL
   - Parses CSV -> JSON -> rollups (MOS/Jitter/Packet Loss)
   - Stores in KV for dashboards
========================= */

const CALLING_INSIGHT = {
  // Titles must match what Webex returns in /reports list
  TITLES: {
    MEDIA: "Calling Media Quality Report",
    QUALITY: "Calling Quality Report",
    CQ_STATS: "Call Queue Stats Report",
    CQ_AGENT: "Call Queue agent stats report",
    AA_SUMMARY: "Auto-attendant stats summary",
    AA_BIZ_AH: "Auto-attendant business & after-hours key details"
  },

  // KV keys
  kv: {
    pending: (orgId) => `ci:pending:v1:${orgId}`,                 // JSON array of pending report jobs
    rollup: (orgId, kind) => `ci:rollup:v1:${orgId}:${kind}`,     // JSON rollup payload
    alerts: (orgId) => `ci:alerts:v1:${orgId}`,                   // JSON alerts array
    lastCreate: (orgId, title) => `ci:lastcreate:v1:${orgId}:${title}:${dayKeyUTC()}` // daily idempotency
  }
};

function dateISO(daysAgo = 0) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - daysAgo);
  return d.toISOString().slice(0, 10);
}

function normalizeNum(v) {
  if (v == null) return null;
  const n = Number(String(v).replace(/[^0-9.\-]/g, ""));
  return Number.isFinite(n) ? n : null;
}

function pickField(row, candidates) {
  for (const c of candidates) {
    if (row[c] != null && row[c] !== "") return row[c];
  }
  // case-insensitive fallback
  const keys = Object.keys(row || {});
  for (const c of candidates) {
    const k = keys.find(x => String(x).toLowerCase() === String(c).toLowerCase());
    if (k && row[k] != null && row[k] !== "") return row[k];
  }
  return null;
}

function percentile(arr, p) {
  const a = (arr || []).filter(n => Number.isFinite(n)).sort((x,y)=>x-y);
  if (!a.length) return null;
  const idx = Math.min(a.length - 1, Math.max(0, Math.floor((p/100) * (a.length - 1))));
  return a[idx];
}

function computeQualityRollupFromRows(rows) {
  const mos = [];
  const jitter = [];
  const loss = [];
  const latency = [];

  // “Heatmap buckets” (by location/user/device if available)
  const bucketMap = new Map();

  for (const r of (rows || [])) {
    const mosVal = normalizeNum(pickField(r, ["MOS", "Mos", "mos", "Average MOS", "Avg MOS"]));
    const jitVal = normalizeNum(pickField(r, ["Jitter", "Jitter (ms)", "Average Jitter (ms)", "Avg Jitter (ms)"]));
    const lossVal = normalizeNum(pickField(r, ["Packet Loss", "Packet Loss (%)", "Average Packet Loss (%)", "Loss (%)"]));
    const latVal = normalizeNum(pickField(r, ["Latency", "Latency (ms)", "Round Trip Time (ms)", "RTT (ms)"]));

    if (Number.isFinite(mosVal)) mos.push(mosVal);
    if (Number.isFinite(jitVal)) jitter.push(jitVal);
    if (Number.isFinite(lossVal)) loss.push(lossVal);
    if (Number.isFinite(latVal)) latency.push(latVal);

    const loc =
      pickField(r, ["Location", "Site", "Calling Location", "Location Name"]) ||
      "Unknown";
    const who =
      pickField(r, ["User", "User Name", "Email", "Calling Line ID"]) ||
      pickField(r, ["Device", "Device Name", "MAC", "Phone"]) ||
      "Unknown";

    const bucketKey = `${loc} | ${who}`;
    const b = bucketMap.get(bucketKey) || { loc, who, count:0, mos:[], jitter:[], loss:[], latency:[] };
    b.count++;
    if (Number.isFinite(mosVal)) b.mos.push(mosVal);
    if (Number.isFinite(jitVal)) b.jitter.push(jitVal);
    if (Number.isFinite(lossVal)) b.loss.push(lossVal);
    if (Number.isFinite(latVal)) b.latency.push(latVal);
    bucketMap.set(bucketKey, b);
  }

  const buckets = [...bucketMap.values()].map(b => ({
    loc: b.loc,
    who: b.who,
    samples: b.count,
    mosAvg: b.mos.length ? Number((b.mos.reduce((a,n)=>a+n,0)/b.mos.length).toFixed(2)) : null,
    jitterP95: percentile(b.jitter, 95),
    lossP95: percentile(b.loss, 95),
    latencyP95: percentile(b.latency, 95)
  }));

  // “Top offenders” sorting: low MOS first, then high jitter/loss
  buckets.sort((a,b) => {
    const am = a.mosAvg ?? 999;
    const bm = b.mosAvg ?? 999;
    if (am !== bm) return am - bm;
    const aj = a.jitterP95 ?? -1;
    const bj = b.jitterP95 ?? -1;
    if (aj !== bj) return bj - aj;
    const al = a.lossP95 ?? -1;
    const bl = b.lossP95 ?? -1;
    return (bl - al);
  });

  const mosAvg = mos.length ? Number((mos.reduce((a,n)=>a+n,0)/mos.length).toFixed(2)) : null;
  const jitterP95 = percentile(jitter, 95);
  const lossP95 = percentile(loss, 95);
  const latencyP95 = percentile(latency, 95);

  return {
    summary: {
      samples: rows?.length || 0,
      mosAvg,
      jitterP95,
      lossP95,
      latencyP95
    },
    bucketsTop: buckets.slice(0, 50) // keep payload bounded
  };
}

function buildAlertsFromRollup(rollup) {
  const s = rollup?.summary || {};
  const alerts = [];

  // Basic thresholds (tune later)
  if (s.mosAvg != null && s.mosAvg < 3.6) alerts.push({ severity:"bad", signal:"MOS_LOW", value:s.mosAvg, threshold:"< 3.6" });
  if (s.jitterP95 != null && s.jitterP95 > 30) alerts.push({ severity:"warn", signal:"JITTER_HIGH_P95", value:s.jitterP95, threshold:"> 30ms" });
  if (s.lossP95 != null && s.lossP95 > 2) alerts.push({ severity:"warn", signal:"LOSS_HIGH_P95", value:s.lossP95, threshold:"> 2%" });
  if (s.latencyP95 != null && s.latencyP95 > 200) alerts.push({ severity:"warn", signal:"LATENCY_HIGH_P95", value:s.latencyP95, threshold:"> 200ms" });

  // Hotspots: any top bucket very bad MOS
  const worst = (rollup?.bucketsTop || [])[0];
  if (worst?.mosAvg != null && worst.mosAvg < 3.2) {
    alerts.push({
      severity:"bad",
      signal:"HOTSPOT_WORST_BUCKET",
      value: { loc: worst.loc, who: worst.who, mosAvg: worst.mosAvg },
      threshold:"bucket MOS < 3.2"
    });
  }

  return alerts;
}

async function ciQueuePending(env, orgId, job) {
  const key = CALLING_INSIGHT.kv.pending(orgId);
  const raw = await env.WEBEX.get(key);
  const arr = raw ? (JSON.parse(raw) || []) : [];
  arr.push(job);
  await env.WEBEX.put(key, JSON.stringify(arr), { expirationTtl: 60 * 60 * 24 * 10 }); // keep 10d
  return arr;
}

async function ciLoadPending(env, orgId) {
  const raw = await env.WEBEX.get(CALLING_INSIGHT.kv.pending(orgId));
  const arr = raw ? (JSON.parse(raw) || []) : [];
  return Array.isArray(arr) ? arr : [];
}

async function ciSavePending(env, orgId, arr) {
  await env.WEBEX.put(CALLING_INSIGHT.kv.pending(orgId), JSON.stringify(arr || []), { expirationTtl: 60 * 60 * 24 * 10 });
}

async function ciCreateReportIfNeeded(env, orgId, title, startDate, endDate) {
  // daily idempotency
  const lockKey = CALLING_INSIGHT.kv.lastCreate(orgId, title);
  const already = await env.WEBEX.get(lockKey);
  if (already) return { ok:true, skipped:true, reason:"already_created_today" };

  // Create report
  const body = { title, startDate, endDate, scheduleFrom: "api" };
  await webexFetchSafe(env, "/callingInsights/reports", orgId, {
  method: "POST",
  body: JSON.stringify(payload)
});

  if (!r.ok) return { ok:false, diag: diag("reports/create", r) };

  const reportId = r.data?.Id || r.data?.id || r.data?.reportId;
  if (!reportId) return { ok:false, error:"missing_report_id", preview: r.preview };

  await env.WEBEX.put(lockKey, "1", { expirationTtl: 60 * 60 * 24 }); // 24h

  // Queue pending job
  await ciQueuePending(env, orgId, {
    reportId,
    title,
    startDate,
    endDate,
    createdAt: new Date().toISOString(),
    state: "PENDING"
  });

  return { ok:true, reportId };
}

async function ciPollAndIngestPending(env, orgId, orgName) {

  const kinds = [
    CALLING_INSIGHT.TITLES.MEDIA,
    CALLING_INSIGHT.TITLES.QUALITY,
    CALLING_INSIGHT.TITLES.ENGAGEMENT
  ];

  let ingested = 0;

  for (const title of kinds) {

    const stateKey = `ci:state:${orgId}:${title}`;
    const raw = await env.WEBEX.get(stateKey);
    if (!raw) continue;

    const state = JSON.parse(raw);

    if (state.status !== "inProgress") continue;

    const reportId = state.reportId;
    if (!reportId) continue;

    console.log("Polling report:", reportId);

    const d = await webexFetchSafe(
      env,
      `/reports/${encodeURIComponent(reportId)}`,
      orgId
    );

    if (!d.ok) continue;

    const status = String(d.data?.status || "").toLowerCase();
    const downloadURL =
      d.data?.downloadURL ||
      d.data?.downloadUrl ||
      null;

    if (status !== "done" || !downloadURL) {
      await env.WEBEX.put(
        stateKey,
        JSON.stringify({
          ...state,
          lastChecked: Date.now(),
          lastStatus: d.data?.status || null
        }),
        { expirationTtl: 60 * 60 * 24 }
      );
      continue;
    }

    // Download CSV
    const token = await getAccessToken(env);

    const csvRes = await fetch(downloadURL, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "text/csv"
      }
    });

    const csvText = await csvRes.text();

    if (!csvRes.ok || !csvText) {
      console.log("CSV download failed:", csvRes.status);
      continue;
    }

    // Parse CSV
    const parsed = parseCsvToJson(csvText);

    const rollup = computeQualityRollupFromRows(parsed.rows || []);
    const alerts = buildAlertsFromRollup(rollup);

    const kind =
      title === CALLING_INSIGHT.TITLES.MEDIA ? "media7d" :
      title === CALLING_INSIGHT.TITLES.QUALITY ? "quality7d" :
      "engagement7d";

    // Store rollup
    await env.WEBEX.put(
      CALLING_INSIGHT.kv.rollup(orgId, kind),
      JSON.stringify({
        orgId,
        orgName: orgName || null,
        kind,
        title,
        startDate: state.startDate,
        endDate: state.endDate,
        generatedAt: new Date().toISOString(),
        rollup
      }),
      { expirationTtl: 60 * 60 * 24 * 10 }
    );

    // Store alerts
    await env.WEBEX.put(
      CALLING_INSIGHT.kv.alerts(orgId),
      JSON.stringify({
        orgId,
        orgName: orgName || null,
        updatedAt: new Date().toISOString(),
        alerts
      }),
      { expirationTtl: 60 * 60 * 24 * 10 }
    );

    // Persist artifact
    await writeReport(env, {
      type: `calling_insight_${kind}`,
      orgId,
      day: dayKeyUTC(),
      payload: {
        rollup,
        alerts,
        startDate: state.startDate,
        endDate: state.endDate,
        title
      },
      meta: {
        orgName: orgName || null,
        reportId
      }
    });

    // Mark state completed
    await env.WEBEX.put(
      stateKey,
      JSON.stringify({
        ...state,
        status: "completed",
        completedAt: Date.now()
      }),
      { expirationTtl: 60 * 60 * 24 }
    );

    ingested++;
  }

  return {
    ok: true,
    ingested
  };
}

// Runs inside your daily scheduled loop for each org
async function runCallingInsightForOrg(env, orgId, orgName) {
  const startDate = dateISO(7);
  const endDate = dateISO(0);

  // Create reports (idempotent daily)
  await ciCreateReportIfNeeded(env, orgId, CALLING_INSIGHT.TITLES.MEDIA, startDate, endDate);
  await ciCreateReportIfNeeded(env, orgId, CALLING_INSIGHT.TITLES.QUALITY, startDate, endDate);

  // Poll/ingest any completed pending reports
  return await ciPollAndIngestPending(env, orgId, orgName);
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


/* =====================================================
   📊 ADMIN REPORTS API (Unified)
   Place near other /api/admin/* routes
===================================================== */

if (url.pathname === "/api/admin/reports/snapshot" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const snap = await env.WEBEX.get("adminReportsSnapshotV1", { type: "json" });
  return json({ ok:true, snapshot: snap || null }, 200);
}

if (url.pathname === "/api/admin/reports/run-daily" && request.method === "POST") {
  // manual trigger (admin)
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const r = await runDailyPartnerReports(env, ctx, { fanout: 6 });
  return json({ ok: r.ok, result: r }, 200);
}

if (url.pathname === "/api/admin/reports/org" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const type = String(url.searchParams.get("type") || "sla_daily");

  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 400);

  const index = await readReportIndex(env, type, orgId);
  const days = index.map(x => x.day);

  return json({ ok:true, orgId, type, days, index }, 200);
}

if (url.pathname === "/api/admin/reports/org/latest" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const type = String(url.searchParams.get("type") || "sla_daily");
  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 400);

  const index = await readReportIndex(env, type, orgId);
  const last = index.length ? index[index.length - 1] : null;
  if (!last) return json({ ok:true, orgId, type, report: null }, 200);

  const report = await env.WEBEX.get(last.key, { type: "json" });
  return json({ ok:true, orgId, type, report: report || null }, 200);
}

if (url.pathname === "/api/admin/reports/org/day" && request.method === "GET") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const type = String(url.searchParams.get("type") || "sla_daily");
  const day = String(url.searchParams.get("day") || "").trim();

  if (!orgId) return json({ ok:false, error:"missing_orgId" }, 400);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return json({ ok:false, error:"invalid_day" }, 400);

  const report = await readReport(env, type, orgId, day);
  return json({ ok:true, orgId, type, day, report: report || null }, 200);
}

/* OPTIONAL: CSV→JSON transform endpoint (admin-only)
   Useful for manual imports or if Webex report download returns CSV.
*/
if (url.pathname === "/api/admin/reports/csv-to-json" && request.method === "POST") {
  const user = getCurrentUser(request);
  if (!user || !user.isAdmin) return json({ ok:false, error:"admin_only" }, 403);

  const textBody = await request.text();
  const parsed = parseCsvToJson(textBody, { maxRows: 200000 });
  return json({ ok:true, headers: parsed.headers, rows: parsed.rows.slice(0, 5000), rowCount: parsed.rows.length }, 200);
}
// =====================================================
// ADMIN GLOBAL SUMMARY REFRESH
// =====================================================
if (url.pathname === "/api/admin/global-summary/refresh" && request.method === "GET") {

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
if (url.pathname === "/api/admin/global-summary/clear" && request.method === "GET") {

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
     /* ============================================================
   MEDIA RECORDS ENDPOINT
   Used for device / location / quality drilldowns
============================================================ */

if (url.pathname === "/api/analytics/media" &&
    request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ error:"access_required" },401);

  const session = await getSession(env,user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {

    if (!requestedOrgId)
      return json({ error:"missing_orgId" },400);

    resolvedOrgId = requestedOrgId;

  } else {

    if (!session?.orgId)
      return json({ error:"pin_required" },401);

    resolvedOrgId = session.orgId;
  }

  const cached = await env.WEBEX.get(`mediaCache:${resolvedOrgId}`);

  if (!cached) {
    return json({
      ok:true,
      orgId:resolvedOrgId,
      count:0,
      records:[]
    });
  }

  const records = JSON.parse(cached);

  return json({
    ok:true,
    orgId:resolvedOrgId,
    count:records.length,
    records
  });
}
if (url.pathname === "/api/analytics-summary"){

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  const analytics = await env.WEBEX.get(
    `analyticsCache:${orgId}`,
    { type:"json" }
  );

  return json({
    ok:true,
    data:analytics
  });

}

/* ============================================================
   ANALYTICS DASHBOARD ENDPOINT
   Drives analytics.html
============================================================ */

if (url.pathname === "/api/analytics" &&
    request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" },401);

  const session = await getSession(env,user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;

  if (user.isAdmin) {

    if (!requestedOrgId)
      return json({ ok:false, error:"missing_orgId" },400);

    resolvedOrgId = requestedOrgId;

  } else {

    if (!session?.orgId)
      return json({ ok:false, error:"pin_required" },401);

    resolvedOrgId = session.orgId;
  }


  /* --------------------------------------------
     Load Cached Media Records
  -------------------------------------------- */

  const cached = await env.WEBEX.get(`mediaCache:${resolvedOrgId}`);

  if (!cached) {

    return json({
      ok:true,
      orgId:resolvedOrgId,
      summary:{
        totalCalls:0,
        successRate:1,
        mosAverage:0,
        packetLossAverage:0,
        jitterAverage:0
      },
      trends:[],
      devices:[],
      locations:[]
    });

  }

  const records = JSON.parse(cached);


  /* --------------------------------------------
     BASIC METRICS
  -------------------------------------------- */

  const totalCalls = records.length;

  const failures = records.filter(r =>
    String(r.callResult || "")
      .toLowerCase()
      .includes("fail")
  ).length;

  const successRate =
    totalCalls === 0 ? 1 :
    (totalCalls - failures) / totalCalls;


  /* --------------------------------------------
     QUALITY METRICS
  -------------------------------------------- */

  const mosValues = records
    .map(r => Number(r.mos))
    .filter(v => Number.isFinite(v));

  const packetValues = records
    .map(r => Number(r.packetLoss))
    .filter(v => Number.isFinite(v));

  const jitterValues = records
    .map(r => Number(r.jitter))
    .filter(v => Number.isFinite(v));

  const avg = arr =>
    arr.length
      ? arr.reduce((a,b)=>a+b,0) / arr.length
      : 0;

  const mosAverage = avg(mosValues);
  const packetLossAverage = avg(packetValues);
  const jitterAverage = avg(jitterValues);


  /* --------------------------------------------
     TREND ANALYTICS (30 days)
  -------------------------------------------- */

  const trendMap = {};

  for (const r of records) {

    if (!r.startTime) continue;

    const day = r.startTime.slice(0,10);

    if (!trendMap[day]) {
      trendMap[day] = {
        day,
        calls:0,
        failures:0,
        mos:[],
        packetLoss:[],
        jitter:[]
      };
    }

    trendMap[day].calls++;

    if (String(r.callResult || "")
        .toLowerCase()
        .includes("fail"))
      trendMap[day].failures++;

    if (Number.isFinite(Number(r.mos)))
      trendMap[day].mos.push(Number(r.mos));

    if (Number.isFinite(Number(r.packetLoss)))
      trendMap[day].packetLoss.push(Number(r.packetLoss));

    if (Number.isFinite(Number(r.jitter)))
      trendMap[day].jitter.push(Number(r.jitter));
  }

  const trends = Object.values(trendMap)
    .sort((a,b)=>a.day.localeCompare(b.day))
    .slice(-30)
    .map(d => ({
      day:d.day,
      calls:d.calls,
      failures:d.failures,
      mos:avg(d.mos),
      packetLoss:avg(d.packetLoss),
      jitter:avg(d.jitter)
    }));


  /* --------------------------------------------
     DEVICE QUALITY ANALYTICS
  -------------------------------------------- */

  const deviceMap = {};

  for (const r of records) {

    const device = r.device || "Unknown";

    if (!deviceMap[device]) {
      deviceMap[device] = {
        device,
        calls:0,
        mos:[],
        packetLoss:[]
      };
    }

    deviceMap[device].calls++;

    if (Number.isFinite(Number(r.mos)))
      deviceMap[device].mos.push(Number(r.mos));

    if (Number.isFinite(Number(r.packetLoss)))
      deviceMap[device].packetLoss.push(Number(r.packetLoss));
  }

  const devices = Object.values(deviceMap)
    .map(d => ({
      device:d.device,
      calls:d.calls,
      mos:avg(d.mos),
      packetLoss:avg(d.packetLoss)
    }))
    .sort((a,b)=>b.calls-a.calls)
    .slice(0,10);


  /* --------------------------------------------
     LOCATION QUALITY ANALYTICS
  -------------------------------------------- */

  const locationMap = {};

  for (const r of records) {

    const location = r.location || r.region || "Unknown";

    if (!locationMap[location]) {
      locationMap[location] = {
        location,
        calls:0,
        mos:[]
      };
    }

    locationMap[location].calls++;

    if (Number.isFinite(Number(r.mos)))
      locationMap[location].mos.push(Number(r.mos));
  }

  const locations = Object.values(locationMap)
    .map(l => ({
      location:l.location,
      calls:l.calls,
      mos:avg(l.mos)
    }))
    .sort((a,b)=>b.calls-a.calls)
    .slice(0,10);


  /* --------------------------------------------
     FINAL RESPONSE
  -------------------------------------------- */

  return json({

    ok:true,
    orgId:resolvedOrgId,

    summary:{
      totalCalls,
      successRate,
      mosAverage,
      packetLossAverage,
      jitterAverage
    },

    trends,
    devices,
    locations

  });

}


/* ============================================================
   DELEGATION WARM ENDPOINT
============================================================ */

if (path === "/api/delegation/warm" &&
    request.method === "POST") {

  const { ok, user } = requireUser(request);
  if (!ok) return user;

  const body = await request.json();
  const orgId = body?.orgId;

  if (!orgId)
    return json({ error:"missing_orgId" },400);

  const success = await warmDelegation(env,orgId);

  return json({ ok:success });
}
 /* ============================================================
MANUAL REPORT TRIGGER (FOR TESTING / ADMIN)
============================================================ */

if (url.pathname === "/api/admin/run-reports" && request.method === "POST") {

  const user = getCurrentUser(request);
  if (!user || !user.isAdmin)
    return json({ error: "admin_required" }, 403);

  const body = await request.json();
  const orgId = normalizeOrgIdParam(body?.orgId);

  if (!orgId)
    return json({ error: "missing_orgId" }, 400);

  try {

    // Only collect CDR history (Webex public analytics source)
    const result = await collectCdrHistory(env, orgId);

    return json({
      ok: true,
      orgId,
      cdrRecords: result?.records || result?.length || 0
    });

  } catch (err) {

    return json({
      ok: false,
      error: String(err)
    });

  }
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

  // ====================================
  // TRY KV CACHE FIRST
  // ====================================

  const cached = await env.WEBEX.get(`cdrCache:${resolvedOrgId}`);

  let records = [];

  if (cached) {

    records = JSON.parse(cached);

  } else {

    // ====================================
    // FALLBACK TO LIVE WEBEX CDR
    // ====================================

    const now = new Date().toISOString();
    const from = new Date(
      Date.now() - windowDays * 24 * 60 * 60 * 1000
    ).toISOString();

    const feedPath =
      `/cdr_feed?startTime=${encodeURIComponent(from)}` +
      `&endTime=${encodeURIComponent(now)}` +
      `&max=1000`;

    const tryFeed = await webexFetchSafe(env, feedPath, resolvedOrgId);

    if (!tryFeed.ok) {

      return json({
        ok:false,
        orgId:resolvedOrgId,
        error:"cdr_unavailable"
      },200);

    }

    records = normalizeCdrItems(tryFeed.data);

  }

  // ====================================
  // BUILD ANALYTICS
  // ====================================

  let mosTotal = 0;
  let mosCount = 0;

  let packetLossTotal = 0;
  let packetLossCount = 0;

  const trends = {};

  for (const r of records) {

    const day = (r.startTime || "").slice(0,10);

    if (!trends[day]) {
      trends[day] = {
        calls:0,
        mosTotal:0,
        mosCount:0,
        packetLossTotal:0,
        packetLossCount:0
      };
    }

    trends[day].calls++;

    const mos = Number(r.averageMos || r.mos || 0);

    if (mos) {
      mosTotal += mos;
      mosCount++;
      trends[day].mosTotal += mos;
      trends[day].mosCount++;
    }

    const packetLoss = Number(r.packetLossRate || 0);

    if (packetLoss) {
      packetLossTotal += packetLoss;
      packetLossCount++;
      trends[day].packetLossTotal += packetLoss;
      trends[day].packetLossCount++;
    }

  }

  // ====================================
  // BUILD 30 DAY TREND
  // ====================================

  const trendArray = Object.entries(trends)
    .sort((a,b)=>a[0].localeCompare(b[0]))
    .map(([day,v]) => {

      return {
        day,
        calls:v.calls,
        avgMos: v.mosCount ? v.mosTotal / v.mosCount : null,
        avgPacketLoss: v.packetLossCount ? v.packetLossTotal / v.packetLossCount : null
      };

    });

  // ====================================
  // MOS AVERAGE
  // ====================================

  const mosAverage = mosCount ? mosTotal / mosCount : null;

  // ====================================
  // PACKET LOSS
  // ====================================

  const packetLossAverage = packetLossCount
    ? packetLossTotal / packetLossCount
    : null;

  return json({

    ok:true,
    orgId:resolvedOrgId,
    source: cached ? "kv_cache" : "live_feed",

    windowDays,

    summary:{
      totalCalls:records.length,
      mosAverage,
      packetLossAverage
    },

    trends:trendArray,

    records

  },200);
}
     if (url.pathname === "/api/cdr/detail") {

  const orgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const callId = url.searchParams.get("callId");

  const cached = await env.WEBEX.get(`cdrCache:${orgId}`);

  if (!cached) return json({ ok:false });

  const records = JSON.parse(cached);

  const record = records.find(r => r.callId === callId);

  return json({
    ok:true,
    record
  });

}
     // =====================================================
// POST /api/reports
// =====================================================
if (url.pathname === "/api/reports" && request.method === "POST") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const session = await getSession(env, user.email);
  const body = await request.json().catch(()=>({}));

  const requestedOrgId = normalizeOrgIdParam(body.orgId);
  const reportType = body.reportType;

  if (!reportType) {
    return json({ ok:false, error:"missing_reportType" }, 400);
  }

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) return json({ ok:false, error:"missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ ok:false, error:"pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  const result = await createWebexReport(
    env,
    resolvedOrgId,
    reportType,
    body.parameters || {}
  );

  if (!result.ok) {
    return json({ ok:false, error:"report_create_failed", preview:result.preview }, 200);
  }

  return json({
    ok:true,
    orgId:resolvedOrgId,
    report:result.data
  }, 200);
}
 // =====================================================
// GET /api/reports/:id
// =====================================================
if (url.pathname.startsWith("/api/reports/") &&
    request.method === "GET" &&
    !url.pathname.endsWith("/file")) {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const reportId = url.pathname.split("/").pop();
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const session = await getSession(env, user.email);

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) return json({ ok:false, error:"missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ ok:false, error:"pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  const result = await getWebexReport(env, resolvedOrgId, reportId);

  if (!result.ok) {
    return json({ ok:false, error:"report_fetch_failed" }, 200);
  }

  return json({
    ok:true,
    report:result.data
  }, 200);
}
 // =====================================================
// GET /api/reports/:id
// =====================================================
if (url.pathname.startsWith("/api/reports/") &&
    request.method === "GET" &&
    !url.pathname.endsWith("/file")) {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const reportId = url.pathname.split("/").pop();
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const session = await getSession(env, user.email);

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) return json({ ok:false, error:"missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ ok:false, error:"pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  const result = await getWebexReport(env, resolvedOrgId, reportId);

  if (!result.ok) {
    return json({ ok:false, error:"report_fetch_failed" }, 200);
  }

  return json({
    ok:true,
    report:result.data
  }, 200);
}
 // =====================================================
// GET /api/reports/:id/file
// =====================================================
if (url.pathname.endsWith("/file") &&
    url.pathname.startsWith("/api/reports/") &&
    request.method === "GET") {

  const user = getCurrentUser(request);
  if (!user) return json({ ok:false, error:"access_required" }, 401);

  const parts = url.pathname.split("/");
  const reportId = parts[3];

  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));
  const session = await getSession(env, user.email);

  let resolvedOrgId;

  if (user.isAdmin) {
    if (!requestedOrgId) return json({ ok:false, error:"missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ ok:false, error:"pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  const result = await downloadWebexReport(env, resolvedOrgId, reportId);

  if (!result.ok) {
    return json({ ok:false, error:"download_failed" }, 200);
  }

  return new Response(result.body, {
    status:200,
    headers:{
      "Content-Type": result.contentType || "application/octet-stream"
    }
  });
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
async function collectCdrHistory(env, orgId){

  function isoNoMs(date){
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  const lastKey = `cdrLastFetch:${orgId}`;
  const cacheKey = `cdrCache:${orgId}`;
  const analyticsKey = `analyticsCache:${orgId}`;

  // Webex requires endTime older than 5 minutes
  const endMs = Date.now() - (6 * 60 * 1000);

  const chunkMs = 12 * 60 * 60 * 1000;

  // load last ingestion checkpoint
  let startMs = Number(await env.WEBEX.get(lastKey));

  // first run fallback = last 24h
  if (!startMs){
    startMs = endMs - (24 * 60 * 60 * 1000);
  }

  let all = [];
  let seen = new Set();

  const existing = await env.WEBEX.get(cacheKey);

  if (existing){
    try{
      const parsed = JSON.parse(existing);
      all = parsed;
      parsed.forEach(x => seen.add(x.callId));
    }catch{}
  }

  let totalCalls = 0;
  let failedCalls = 0;
  let durationSum = 0;

  for (let chunkStart = startMs; chunkStart < endMs; chunkStart += chunkMs){

    const chunkEnd = Math.min(chunkStart + chunkMs, endMs);

    const startTime = isoNoMs(new Date(chunkStart));
    const endTime = isoNoMs(new Date(chunkEnd));

    let url =
      "https://analytics-calling.webexapis.com/v1/cdr_feed" +
      `?startTime=${encodeURIComponent(startTime)}` +
      `&endTime=${encodeURIComponent(endTime)}` +
      `&max=1000`;

    while (url){

      const token = await getAccessToken(env);

      const res = await throttledWebexFetch(url,{
        method:"GET",
        headers:{
          "Authorization":`Bearer ${token}`,
          "Accept":"application/json"
        }
      });

      const text = await res.text();

      let data = {};
      try{
        data = JSON.parse(text);
      }catch{}

      if (!res.ok){

        const msg = String(data?.message || "");

        // Webex analytics throttling protection
        if (msg.includes("threshold") || res.status === 429){
          console.log("CDR throttle detected, backing off...");
          await sleep(4000);
          continue;
        }

        throw new Error(
          "cdr_fetch_failed: " + text.slice(0,400)
        );
      }

      const items = data?.items || [];

      for (const x of items){

        const callId = x.id || "";

        if (!callId || seen.has(callId)){
          continue;
        }

        seen.add(callId);

        const duration = x.durationSeconds || 0;
        const result = x.callResult || "unknown";

        all.push({
          callId,
          startTime: x.startTime || "",
          duration,
          result,
          caller: x.localCallId || "",
          callee: x.remoteCallId || "",
          direction: x.direction || "",
          device: x.deviceType || ""
        });

        totalCalls++;
        durationSum += duration;

        if (result.toLowerCase().includes("fail")){
          failedCalls++;
        }
      }

      // pagination
      url = data?.links?.next || data?.next || null;

      // small delay prevents Webex analytics throttling
      await sleep(350);
    }
  }

  /* ----------------------------
     Analytics Calculations
  -----------------------------*/

  const avgDuration = totalCalls
    ? Math.round(durationSum / totalCalls)
    : 0;

  const successRate = totalCalls
    ? Math.round((1 - failedCalls / totalCalls) * 100)
    : 100;

  const qualityScore = Math.max(
    0,
    100
    - (failedCalls * 2)
    - (avgDuration < 10 ? 5 : 0)
  );

  let predictedSlaRisk = "LOW";

  if (successRate < 98){
    predictedSlaRisk = "MEDIUM";
  }

  if (successRate < 95){
    predictedSlaRisk = "HIGH";
  }

  const aiInsight = analyzeCallQuality(all);

  const analytics = {
    totalCalls,
    failedCalls,
    successRate,
    avgDuration,
    qualityScore,
    predictedSlaRisk,
    aiInsight,
    lastUpdated: new Date().toISOString()
  };

  /* ----------------------------
     Cache Results
  -----------------------------*/

  await env.WEBEX.put(
    cacheKey,
    JSON.stringify(all),
    { expirationTtl: 604800 }
  );

  await env.WEBEX.put(
    analyticsKey,
    JSON.stringify(analytics),
    { expirationTtl: 604800 }
  );

  await env.WEBEX.put(
    lastKey,
    String(endMs)
  );

  return {
    records: all.length,
    newCalls: totalCalls,
    analytics
  };
}
  
     /*
 function analyzeCallQuality(cdrRecords, mediaRecords){

  const insights = [];

  let networkIssues = 0;
  let deviceIssues = 0;
  let pstnIssues = 0;
  let codecIssues = 0;

  for (const call of mediaRecords){

    const mos = call.mos || 0;
    const packetLoss = call.packetLoss || 0;
    const jitter = call.jitter || 0;
    const device = (call.deviceType || "").toLowerCase();
    const direction = (call.direction || "").toLowerCase();

    if (packetLoss > 3 || jitter > 30){
      networkIssues++;
      continue;
    }

    if (mos < 3.5 && device.includes("phone")){
      deviceIssues++;
      continue;
    }

    if (direction === "pstn" && mos < 3.5){
      pstnIssues++;
      continue;
    }

    if (mos < 3.5 && packetLoss < 1 && jitter < 10){
      codecIssues++;
    }
  }

  const total = mediaRecords.length || 1;

  function pct(x){
    return Math.round((x / total) * 100);
  }

  let primaryCause = "Healthy";

  const max = Math.max(networkIssues, deviceIssues, pstnIssues, codecIssues);

  if (max === networkIssues) primaryCause = "Network";
  else if (max === deviceIssues) primaryCause = "Device";
  else if (max === pstnIssues) primaryCause = "PSTN";
  else if (max === codecIssues) primaryCause = "Codec";

  return {
    primaryCause,
    breakdown:{
      network:pct(networkIssues),
      device:pct(deviceIssues),
      pstn:pct(pstnIssues),
      codec:pct(codecIssues)
    },
    summary:

      primaryCause === "Network"
        ? "Most degraded calls show packet loss or jitter consistent with network congestion."

      : primaryCause === "Device"
        ? "Call quality degradation is concentrated on endpoint devices suggesting firmware or headset issues."

      : primaryCause === "PSTN"
        ? "Degraded calls are primarily on PSTN routes indicating possible carrier path problems."

      : primaryCause === "Codec"
        ? "Low MOS without packet loss suggests codec negotiation or transcoding issues."

      : "Call quality metrics indicate healthy network and device conditions."
  };
} */
function analyzeCallQuality(records){

  if (!records || records.length === 0){
    return {
      title: "AI quality narrative",
      primaryCause: "Healthy",
      summary: "No call quality issues detected.",
      risk: "low",
      breachDays: null
    };
  }

  let failures = 0;
  let shortCalls = 0;
  let longCalls = 0;
  const deviceCounts = {};

  for (const r of records){
    const result = String(r.result || r.callResult || "").toLowerCase();
    const duration = Number(r.duration || 0);

    if (result.includes("fail")) failures++;
    if (duration > 0 && duration < 5) shortCalls++;
    if (duration > 1800) longCalls++;

    if (r.device){
      deviceCounts[r.device] = (deviceCounts[r.device] || 0) + 1;
    }
  }

  const total = records.length || 1;
  const failureRate = failures / total;
  const shortRate = shortCalls / total;

  let primaryCause = "Healthy";
  let summary = "Call quality operating normally.";
  let risk = "low";
  let breachDays = null;

  if (failureRate > 0.05){
    primaryCause = "Network";
    summary = "Elevated call failures suggest a likely network-path issue.";
    risk = "high";
    breachDays = 3;
  } else if (shortRate > 0.20){
    primaryCause = "Device";
    summary = "A high number of very short calls suggests endpoint or handset instability.";
    risk = "medium";
    breachDays = 7;
  } else if (longCalls > total * 0.10){
    primaryCause = "PSTN";
    summary = "Unusual call duration behavior suggests PSTN or signaling-path inconsistency.";
    risk = "medium";
    breachDays = 5;
  }

  return {
    title: "AI quality narrative",
    primaryCause,
    summary,
    risk,
    breachDays
  };
}
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
// =====================================================
// PSTN ENGINE (CLEAN REWRITE) — DROP-IN REPLACEMENT
// Replaces your current ~496-line PSTN section starting at:
//   async function cachePutJson(...)
// through the end of the "/api/pstn" handler.
// =====================================================

async function cachePutJson(cacheKeyReq, payload, ttlSeconds = 60) {
  try {
    const cache = caches.default;
    const headers = new Headers({
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${ttlSeconds}`,
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
    conn?.pstnConnectionType || // seen in PSTN connection payloads
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

function isUnassignedNumber(n) {
  return !n?.owner && !n?.assignedTo && !n?.userId && !n?.workspaceId;
}

/**
 * CRITICAL FIX:
 * Many Webex Calling endpoints (including the ones you tested in Postman)
 * REQUIRE orgId in the QUERY STRING:
 *   .../locations?orgId=...
 *   .../telephony/pstn/locations/{locId}/connection?orgId=...
 *   .../telephony/config/locations/{locId}/redSky/status?orgId=...
 *
 * Your previous implementation relied on header scoping for telephony/*,
 * which is why you saw lots of 400/404.
 */
function withOrgQuery(path, orgId) {
  if (!orgId) return path;

  // If caller already included orgId=, do nothing
  if (/[?&]orgId=/.test(path)) return path;

  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}orgId=${encodeURIComponent(orgId)}`;
}

function pstnCacheReq(request, suffix) {
  // Stable cache Request keyed by full URL + suffix/version
  return cacheKeyFromRequest(request, suffix);
}

function readDisplayNameFromConn(connData) {
  return (
    connData?.displayName ||
    connData?.name ||
    connData?.pstnConnectionName ||
    null
  );
}

function redSkyBadge(orgStatus) {
  const v = String(orgStatus || "").toUpperCase();
  if (!v) return "UNKNOWN";
  if (v === "ENABLED") return "ENABLED";
  if (v === "DISABLED") return "DISABLED";
  return v;
}

// =====================================================
// 1) PSTN SUMMARY (fast, org-level, minimal fan-out)
// =====================================================
if (
  (url.pathname === "/api/pstn/summary" || url.pathname === "/api/pstn/summary/") &&
  request.method === "GET"
) {
  const user = getCurrentUser(request);
  if (!user) return json({ ok: false, error: "access_required" }, 401);

  const session = await getSession(env, user.email);
  const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

  let resolvedOrgId;
  if (user.isAdmin) {
    if (!requestedOrgId) return json({ ok: false, error: "missing_orgId" }, 400);
    resolvedOrgId = requestedOrgId;
  } else {
    if (!session?.orgId) return json({ ok: false, error: "pin_required" }, 401);
    resolvedOrgId = session.orgId;
  }

  // Cache controls
  const ttl = clampInt(url.searchParams.get("ttl"), 180, 60, 900);
  const cacheReq = pstnCacheReq(request, `pstn_summary:v3:${resolvedOrgId}`);

  const cached = await cacheGetJson(cacheReq);
  if (cached) return json({ ...cached, _cache: "HIT" }, 200);

  // Safe Webex wrapper (forces orgId query formatting like your Postman examples)
  const safe = (path) => webexFetchSafe(env, withOrgQuery(path, resolvedOrgId), resolvedOrgId);

  const diagnostics = [];
  const diag = (name, r) =>
    diagnostics.push({
      name,
      ok: !!r?.ok,
      status: r?.status ?? null
    });

  try {
    // Minimal calls, parallel
    const [locRes, numbersRes, trunksRes, redskyRes] = await Promise.all([
      safe("/locations"),
      safe("/telephony/config/numbers"),
      safe("/telephony/config/premisePstn/trunks"),
      safe("/telephony/config/redSky/complianceStatus")
    ]);

    diag("locations", locRes);
    diag("telephony/config/numbers", numbersRes);
    diag("telephony/config/premisePstn/trunks", trunksRes);
    diag("telephony/config/redSky/complianceStatus", redskyRes);

    if (!locRes.ok) {
      const payload = {
        ok: true,
        pstnSummary: {
          orgId: resolvedOrgId,
          callingAvailable: false,
          reason: "Locations API not accessible for this org",
          totals: { trunks: 0, didsTotal: 0, locations: 0 },
          compliance: null,
          misconfigurations: [],
          diagnostics,
          scores: { pstnCapacityScore: 0 },
          generatedAt: new Date().toISOString()
        }
      };

      await cachePutJson(cacheReq, payload, ttl);
      return json({ ...payload, _cache: "MISS" }, 200);
    }

    const locationsRaw = Array.isArray(locRes.data?.items) ? locRes.data.items : [];
    const numbersRaw = numbersRes.ok ? asArray(numbersRes.data?.phoneNumbers || numbersRes.data?.items) : [];
    const trunksRaw = trunksRes.ok ? asArray(trunksRes.data?.trunks || trunksRes.data?.items) : [];

    const totalTrunks = trunksRaw.length;
    const totalDids = numbersRaw.length;

    // Per-location quick scan (NO per-location telephony fan-out in summary)
    const perLoc = locationsRaw.map((loc) => {
      const locId = loc.id;

      const locNumbers = numbersRaw.filter((n) => String(getLocId(n)) === String(locId));
      const locTrunks = trunksRaw.filter((t) => String(getLocId(t)) === String(locId));

      return {
        id: locId,
        name: loc.name || "Unknown Location",
        trunkCount: locTrunks.length,
        didsTotal: locNumbers.length,
        didsUnassigned: locNumbers.filter(isUnassignedNumber).length
      };
    });

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
      ok: true,
      pstnSummary: {
        orgId: resolvedOrgId,
        callingAvailable: true,
        totals: {
          trunks: totalTrunks,
          didsTotal: totalDids,
          locations: perLoc.length
        },
        compliance: redskyRes.ok ? redskyRes.data : null,
        misconfigurations,
        diagnostics,
        scores: {
          pstnCapacityScore: computeCapacityScore(totalTrunks)
        },
        generatedAt: new Date().toISOString()
      }
    };

    await cachePutJson(cacheReq, payload, ttl);
    return json({ ...payload, _cache: "MISS" }, 200);
  } catch (err) {
    return json(
      {
        ok: true,
        pstnSummary: {
          orgId: resolvedOrgId,
          callingAvailable: false,
          error: "pstn_summary_exception",
          message: String(err),
          diagnostics,
          generatedAt: new Date().toISOString()
        }
      },
      200
    );
  }
}

// =====================================================
// 2) FULL PSTN (detailed) — hardened + caching + clean fan-out
// Adds requested enhancements:
//   ✅ connectionOptions endpoint
//   ✅ displayName from PSTN connection
//   ✅ RedSky orgStatus badge (per location + org)
// =====================================================
if (url.pathname === "/api/pstn" && request.method === "GET") {
  try {
    const user = getCurrentUser(request);
    if (!user) return json({ ok: false, error: "access_required" }, 401);

    const session = await getSession(env, user.email);
    const requestedOrgId = normalizeOrgIdParam(url.searchParams.get("orgId"));

    let resolvedOrgId;
    if (user.isAdmin) {
      if (!requestedOrgId) return json({ ok: false, error: "missing_orgId" }, 400);
      resolvedOrgId = requestedOrgId;
    } else {
      if (!session?.orgId) return json({ ok: false, error: "pin_required" }, 401);
      resolvedOrgId = session.orgId;
    }

    // Cache controls (full PSTN is heavier; default TTL 180)
    const ttl = clampInt(url.searchParams.get("ttl"), 180, 60, 900);
    const cacheReq = pstnCacheReq(request, `pstn_full:v4:${resolvedOrgId}`);

    const cached = await cacheGetJson(cacheReq);
    if (cached) return json({ ...cached, _cache: "HIT" }, 200);

    // Safe Webex wrapper (forces orgId query formatting like your Postman examples)
    const safe = (path) => webexFetchSafe(env, withOrgQuery(path, resolvedOrgId), resolvedOrgId);

    const diagnostics = [];
    const diag = (name, r) =>
      diagnostics.push({
        name,
        ok: !!r?.ok,
        status: r?.status ?? null
      });

    // -------------------------------
    // 1) Locations (Postman-style)
    // -------------------------------
    const locRes = await safe("/locations");
    diag("locations", locRes);

    if (!locRes.ok) {
      const payload = {
        ok: true,
        pstn: {
          orgId: resolvedOrgId,
          callingAvailable: false,
          reason: "Locations API not accessible for this org",
          totals: { trunks: 0, didsTotal: 0, locations: 0 },
          locations: [],
          trunks: [],
          numbers: [],
          routeGroups: [],
          connectionOptions: null,
          compliance: null,
          redSky: { orgStatusBadge: "UNKNOWN" },
          misconfigurations: [],
          diagnostics,
          scores: { pstnCapacityScore: 0 },
          generatedAt: new Date().toISOString()
        }
      };

      await cachePutJson(cacheReq, payload, ttl);
      return json({ ...payload, _cache: "MISS" }, 200);
    }

    const locationsRaw = Array.isArray(locRes.data?.items) ? locRes.data.items : [];

    // -------------------------------
    // 2) Optional org-level endpoints
    // -------------------------------
    const [numbersRes, trunksRes, routeRes, redskyGlobal] = await Promise.all([
      safe("/telephony/config/numbers"),
      safe("/telephony/config/premisePstn/trunks"),
      safe("/telephony/config/premisePstn/routeGroups"),
      safe("/telephony/config/redSky/complianceStatus")
    ]);

    diag("telephony/config/numbers", numbersRes);
    diag("telephony/config/premisePstn/trunks", trunksRes);
    diag("telephony/config/premisePstn/routeGroups", routeRes);
    diag("telephony/config/redSky/complianceStatus", redskyGlobal);

    const numbersRaw = numbersRes.ok ? asArray(numbersRes.data?.phoneNumbers || numbersRes.data?.items) : [];
    const trunksRaw = trunksRes.ok ? asArray(trunksRes.data?.trunks || trunksRes.data?.items) : [];
    const routeGroupsRaw = routeRes.ok ? asArray(routeRes.data?.routeGroups || routeRes.data?.items) : [];

    const totalTrunks = trunksRaw.length;
    const totalDids = numbersRaw.length;

    // -------------------------------
    // 3) Enrich Locations (clean + controlled fan-out)
    //    Includes:
    //      - PSTN Connection (with displayName)
    //      - PSTN Connection Options
    //      - RedSky status (orgStatus badge + compliance)
    //      - Emergency call notification config
    // -------------------------------
    const CONCURRENCY = clampInt(url.searchParams.get("locConcurrency"), 4, 1, 10);

    const enrichedLocations = await mapLimit(locationsRaw, CONCURRENCY, async (loc) => {
      const locId = loc.id;
      const locIdEnc = encodeURIComponent(locId);

      // Postman format requires orgId query on these endpoints
      const connPath = `/telephony/pstn/locations/${locIdEnc}/connection`;
      const conn = await safe(connPath);
      diag(`telephony/pstn/locations/${locIdEnc}/connection`, conn);

      // Requested: connectionOptions endpoint (tolerate 404/403)
      const connOptPath = `/telephony/pstn/locations/${locIdEnc}/connectionOptions`;
      const connOptions = await safe(connOptPath);
      diag(`telephony/pstn/locations/${locIdEnc}/connectionOptions`, connOptions);

      // RedSky per-location status (your working Postman example)
      const redskyPath = `/telephony/config/locations/${locIdEnc}/redSky/status`;
      const redskyStatus = await safe(redskyPath);
      diag(`telephony/config/locations/${locIdEnc}/redSky/status`, redskyStatus);

      // Emergency call notification config (tolerate 404/403)
      const ecnPath = `/telephony/config/locations/${locIdEnc}/emergencyCallNotification`;
      const emergencyNotif = await safe(ecnPath);
      diag(`telephony/config/locations/${locIdEnc}/emergencyCallNotification`, emergencyNotif);

      const locNumbers = numbersRaw.filter((n) => String(getLocId(n)) === String(locId));
      const locTrunks = trunksRaw.filter((t) => String(getLocId(t)) === String(locId));

      const trunkCount = locTrunks.length;
      const didTotal = locNumbers.length;
      const didUnassigned = locNumbers.filter(isUnassignedNumber).length;

      const pstnType = conn.ok ? normalizePstnType(conn.data) : "UNKNOWN";
      const pstnDisplayName = conn.ok ? readDisplayNameFromConn(conn.data) : null;

      // Requested: RedSky orgStatus badge (from per-location status if present)
      const rsOrgStatus = redskyStatus.ok ? redSkyBadge(redskyStatus.data?.orgStatus) : "UNKNOWN";

      const rsCompliance =
        redskyStatus.ok ? String(redskyStatus.data?.complianceStatus || "").toUpperCase() : "";

      // Existing behavior: treat COMPLIANT as "configured"
      const emergencyConfigured = rsCompliance === "COMPLIANT";

      return {
        id: locId,
        name: loc.name || "Unknown Location",
        callingEnabled: true,

        // PSTN
        pstn: {
          option: pstnType,
          displayName: pstnDisplayName,
          connection: conn.ok ? conn.data : null,
          connectionOptions: connOptions.ok ? connOptions.data : null
        },

        // Counts
        trunkCount,
        dids: {
          total: didTotal,
          unassigned: didUnassigned
        },

        // E911 / RedSky
        redSky: {
          orgStatusBadge: rsOrgStatus,
          complianceStatus: redskyStatus.ok ? redskyStatus.data?.complianceStatus : null,
          adminExists: redskyStatus.ok ? redskyStatus.data?.adminExists : null,
          companyId: redskyStatus.ok ? redskyStatus.data?.companyId : null,
          redskyOrgId: redskyStatus.ok ? redskyStatus.data?.redskyOrgId : null,
          raw: redskyStatus.ok ? redskyStatus.data : null
        },

        // Emergency Call Notification
        emergencyCallNotification: emergencyNotif.ok ? emergencyNotif.data : null,

        emergencyConfigured
      };
    });

    // -------------------------------
    // 4) Org-level connection options (optional)
    //     (If unsupported, safe() will just capture diagnostics)
    // -------------------------------
    const orgConnOptionsRes = await safe("/telephony/pstn/connectionOptions");
    diag("telephony/pstn/connectionOptions", orgConnOptionsRes);

    // -------------------------------
    // 5) Risk detection (keeps your original intent)
    // -------------------------------
    const misconfigurations = [];

    for (const l of enrichedLocations) {
      if (l?.pstn?.option === "NO_PSTN") {
        misconfigurations.push({ location: l.name, issue: "No PSTN configured" });
      }

      if (l.trunkCount === 1) {
        misconfigurations.push({ location: l.name, issue: "Single trunk no redundancy" });
      }

      if (!l.emergencyConfigured) {
        misconfigurations.push({ location: l.name, issue: "E911 not compliant" });
      }
    }

    // Requested: RedSky orgStatus badge (org-level best-effort)
    // If global complianceStatus is available, we still may not have orgStatus here,
    // so we primarily use per-location badges; org badge is derived best-effort.
    const orgRedSkyBadge = (() => {
      // Prefer any per-location badge that is ENABLED
      const anyEnabled = enrichedLocations.some((l) => l?.redSky?.orgStatusBadge === "ENABLED");
      if (anyEnabled) return "ENABLED";
      // Otherwise unknown/disabled best-effort
      const anyDisabled = enrichedLocations.some((l) => l?.redSky?.orgStatusBadge === "DISABLED");
      if (anyDisabled) return "DISABLED";
      return "UNKNOWN";
    })();

    const payload = {
      ok: true,
      pstn: {
        orgId: resolvedOrgId,
        callingAvailable: true,

        totals: {
          trunks: totalTrunks,
          didsTotal: totalDids,
          locations: enrichedLocations.length
        },

        locations: enrichedLocations,

        // Raw lists (keeps your original output shape)
        trunks: trunksRaw,
        numbers: numbersRaw,
        routeGroups: routeGroupsRaw,

        // Requested additions
        connectionOptions: orgConnOptionsRes.ok ? orgConnOptionsRes.data : null,

        // Compliance
        compliance: redskyGlobal.ok ? redskyGlobal.data : null,
        redSky: {
          orgStatusBadge: orgRedSkyBadge
        },

        misconfigurations,
        diagnostics,

        scores: {
          pstnCapacityScore: computeCapacityScore(totalTrunks)
        },

        generatedAt: new Date().toISOString()
      }
    };

    await cachePutJson(cacheReq, payload, ttl);
    return json({ ...payload, _cache: "MISS" }, 200);
  } catch (err) {
    return json(
      {
        ok: false,
        error: "pstn_internal_exception",
        message: String(err?.message || err)
      },
      500
    );
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
   ctx.waitUntil(runTelemetryCycle(env));
   console.log("Running delegation prewarm");
    ctx.waitUntil(prewarmAllTenants(env));
   ctx.waitUntil(runDailyPartnerReports(env, ctx, { fanout: 6 }));
    try {

      const orgResult = await webexFetch(env, "/organizations");
      if (!orgResult.ok) return;

      const orgs = orgResult.data.items || [];
     // 🔵 Delegation prewarm (safe, lightweight)
   await mapLimit(orgs, 5, async (org) => {
   await runTelemetryCycle(env);
   try {
    await warmDelegation(env, org.id);
  } catch (e) {
    console.log("Delegation warm failed for:", org.id);
  }
});
     ctx.waitUntil(ciBackgroundPollAll(env));
     ctx.waitUntil(runCachedCallReports(env));
      const CONCURRENCY = 5;
      await ciAutoRefreshAllTenants(env);
     // 🔵 MEDIA QUALITY AUTO-RUN (4 hour throttle)
const FOUR_HOURS = 60 * 60 * 4;

await mapLimit(orgs, 3, async (org) => {
  try {

    const last = await env.WEBEX.get(`media:lastRun:${org.id}`);
    const now = Date.now();

    if (last && now - Number(last) < FOUR_HOURS * 1000) {
      return; // skip if not due
    }

    const tplRes = await webexFetchSafe(env, "/report/templates", org.id);
    if (!tplRes.ok) return;

    const template = tplRes.data.items.find(t =>
      t.title === "Calling Media Quality Report"
    );
    if (!template) return;

    const token = await getAccessToken(env);
  // const token = await getAccessTokenForOrg(env, org.id);

    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - 7);

   // await fetch("https://webexapis.com/v1/reports", {
   await fetch(`https://webexapis.com/v1/reports?orgId=${encodeURIComponent(org.id)}`, {

      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        templateId: template.Id,
        startDate: start.toISOString().slice(0,10),
        endDate: end.toISOString().slice(0,10)
      })
    });

    await env.WEBEX.put(`media:lastRun:${org.id}`, String(now));

  } catch(e){
    console.log("Media auto-run failed:", org.id);
  }
});
     
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
     // 🔵 Nightly AI summary (2AM UTC)
if (event.cron === "0 2 * * *") {

  for (const org of orgs) {

    const rollups = await env.WEBEX.list({
      prefix: `media:rollup:${org.id}`
    });

    const values = [];

    for (const key of rollups.keys) {
      const data = await env.WEBEX.get(key.name, "json");
      if (data) values.push(data);
    }

    const aiSummary = generateAiSummary(values);

    await env.WEBEX.put(
      `media:ai:${org.id}`,
      JSON.stringify(aiSummary)
    );
  }

  console.log("Nightly AI summaries computed");
}

    } catch (err) {
      console.error("Scheduled task failed:", err);
     
    }
  })());
}
 }; // 🔥 CLOSE EXPORT OBJECT HERE
async function ciBackgroundPollAll(env) {

  const orgRes = await webexFetchSafe(env, "/organizations", null);
  if (!orgRes.ok) return;

  const orgs = orgRes.data.items || [];

  for (const org of orgs) {

    try {
      await ciPollAndIngestPending(env, org.id, org.displayName || null);
    } catch (e) {
      console.error("CI poll failed for:", org.id, e);
    }

  }
}

// =====================================================
// OBSERVABILITY DATA COLLECTOR
// =====================================================

async function collectObservability(env, orgId) {

  const timestamp = Date.now();

  let apiLatency = 0;
  let licenseCount = 0;
  let deviceCount = 0;

  let licenseDeficit = 0;
  let devicesOffline = 0;

  try {

    const start = Date.now();

    const lic = await webexFetch(env, "/licenses", orgId);

    apiLatency = Date.now() - start;

    if (lic.ok) {

      const items = lic.data.items || [];

      licenseCount = items.length;

      for (const l of items) {

        const total = Number(l.totalUnits ?? -1);
        const consumed = Number(l.consumedUnits ?? 0);

        if (total >= 0 && consumed > total) {
          licenseDeficit += (consumed - total);
        }

      }

    }

  } catch {}

  try {

    const dev = await webexFetch(env, "/devices", orgId);

    if (dev.ok) {

      const devices = dev.data.items || [];

      deviceCount = devices.length;

      devicesOffline = devices.filter(d =>
        d.connectionStatus === "disconnected"
      ).length;

    }

  } catch {}

  const ai = computeAIStatus({
    apiLatency,
    licenseCount,
    deviceCount,
    licenseDeficit,
    devicesOffline
  });

  return {
    type: "observability",
    timestamp,
    orgId,

    metrics: {
      apiLatency,
      licenseCount,
      deviceCount,
      licenseDeficit,
      devicesOffline
    },

    ai
  };

}
// =====================================================
// AI STATUS ENGINE (Production Tuned)
// =====================================================

function computeAIStatus(data) {

  const issues = [];
  let riskScore = 0;

  // ---------------------------------------------------
  // API Latency
  // ---------------------------------------------------

  if (data.apiLatency > 2500) {

    issues.push({
      level: "warning",
      message: "Webex API latency elevated"
    });

    riskScore += 10;

  }

  // ---------------------------------------------------
  // License Issues
  // ---------------------------------------------------

  if (data.licenseDeficit > 0) {

    issues.push({
      level: "critical",
      message: `License deficit detected (${data.licenseDeficit})`
    });

    riskScore += 40;

  }

  if (data.licenseCount === 0) {

    issues.push({
      level: "critical",
      message: "No licenses returned from Webex"
    });

    riskScore += 50;

  }

  // ---------------------------------------------------
  // Device Health
  // ---------------------------------------------------

  if (data.deviceCount === 0) {

    issues.push({
      level: "warning",
      message: "No devices detected"
    });

    riskScore += 20;

  }

  if (data.devicesOffline > 5) {

    issues.push({
      level: "warning",
      message: `${data.devicesOffline} devices offline`
    });

    riskScore += 15;

  }

  // ---------------------------------------------------
  // Normalize Risk
  // ---------------------------------------------------

  if (riskScore > 100) riskScore = 100;

  // ---------------------------------------------------
  // Determine Status
  // ---------------------------------------------------

  let status = "healthy";

  if (riskScore >= 50) {
    status = "critical";
  }
  else if (riskScore >= 20) {
    status = "degraded";
  }

  // ---------------------------------------------------
  // SLA Risk
  // ---------------------------------------------------

  const slaRisk =
    riskScore >= 20 ||
    data.devicesOffline > 10 ||
    data.licenseDeficit > 0;

  return {
    status,
    riskScore,
    slaRisk,
    issues
  };

}
// =====================================================
// STORE TELEMETRY
// =====================================================

async function storeTelemetry(env, orgId, data) {
  try {
    await env.OBS_CACHE.put(
      `telemetry:${orgId}`,
      JSON.stringify(data),
      { expirationTtl: 300 }
    );

    await env.OBS_CACHE.put(
      `telemetry:${orgId}:${Date.now()}`,
      JSON.stringify(data),
      { expirationTtl: 86400 }
    );
  } catch (err) {
    console.log("Telemetry store error", err);
  }
}
// =====================================================
// LOAD TELEMETRY
// =====================================================

async function loadTelemetry(env, orgId) {

  try {

    const cached = await env.OBS_CACHE.get(`telemetry:${orgId}`);

    if (cached) {
      return JSON.parse(cached);
    }

  } catch {}

  return null;

}
async function getObservability(env, orgId) {

  const cached = await loadTelemetry(env, orgId);

  if (cached) {
    return cached;
  }

  const data = await collectObservability(env, orgId);

  await storeTelemetry(env, orgId, data);

  return data;

}

async function startPartnerObservabilityStream(server, env) {

  let closed = false;

  async function stream() {
    try {
      const orgs = await webexFetch(
        env,
        "/organizations?managedByPartner=true&max=100"
      );

      const items = orgs.data?.items || [];
      const batches = chunkArray(items, 4);

      for (const batch of batches) {
        if (closed) return;

        const batchResults = await Promise.all(
          batch.map(async org => {
            try {
              const telemetry = await getObservability(env, org.id);
              return {
                type: "tenant_update",
                orgId: org.id,
                orgName: org.displayName,
                telemetry
              };
            } catch (err) {
              return {
                type: "tenant_update",
                orgId: org.id,
                orgName: org.displayName,
                telemetry: {
                  timestamp: Date.now(),
                  metrics: {
                    apiLatency: 0,
                    licenseCount: 0,
                    deviceCount: 0,
                    licenseDeficit: 0,
                    devicesOffline: 0
                  },
                  ai: {
                    status: "critical",
                    riskScore: 100,
                    slaRisk: true,
                    issues: [
                      {
                        level: "critical",
                        message: `Telemetry collection failed: ${String(err.message || err)}`
                      }
                    ]
                  }
                }
              };
            }
          })
        );

        for (const payload of batchResults) {
          if (closed) return;
          server.send(JSON.stringify(payload));
        }

        await sleep(400);
      }

    } catch (err) {
      if (!closed) {
        server.send(JSON.stringify({
          type: "error",
          message: "partner_stream_failed"
        }));
      }
    }
  }

  await stream();

  const interval = setInterval(stream, 30000);

  server.addEventListener("close", () => {
    closed = true;
    clearInterval(interval);
  });
}
async function runTelemetryCycle(env) {

  console.log("Starting telemetry cycle");

  const orgs = await webexFetch(
    env,
    "/organizations?managedByPartner=true&max=100"
  );

  const items = orgs.data?.items || [];

  const batchSize = 4;
  const batches = chunkArray(items, batchSize);

  const snapshot = [];

  for (const batch of batches) {

    const results = await Promise.all(

      batch.map(async org => {

        try {

          const telemetry = await collectObservability(env, org.id);

          await storeTelemetry(env, org.id, telemetry);

          const entry = {
            orgId: org.id,
            orgName: org.displayName,
            ...telemetry
          };

          snapshot.push(entry);

          console.log("Telemetry updated", org.displayName);

          return entry;

        } catch (err) {

          console.log("Telemetry error", org.displayName, err);

          const entry = {
            orgId: org.id,
            orgName: org.displayName,
            type: "observability",
            timestamp: Date.now(),
            metrics: {
              apiLatency: 0,
              licenseCount: 0,
              deviceCount: 0
            },
            ai: {
              status: "critical",
              riskScore: 100,
              issues: [
                {
                  level: "critical",
                  message: "Telemetry collection failed"
                }
              ]
            }
          };

          snapshot.push(entry);

          return entry;

        }

      })

    );

    // pause between API bursts
    await sleep(400);

  }

  // ------------------------------------------------
  // Save partner-wide snapshot (fast dashboard load)
  // ------------------------------------------------

  try {

    await env.OBS_CACHE.put(
      "telemetry:partner_snapshot",
      JSON.stringify(snapshot),
      { expirationTtl: 300 }
    );

    console.log("Partner snapshot updated");

  } catch (err) {

    console.log("Snapshot write failed", err);

  }

}
