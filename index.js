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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const jsonHeaders = {
      "content-type": "application/json",
      "cache-control": "no-store",
    };

    /* =====================================================
       Helpers
    ===================================================== */

    function json(data, status = 200, extraHeaders = {}) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...jsonHeaders, ...extraHeaders },
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

    function cfgInt(name, def) {
      const v = env[name];
      const n = Number(v);
      return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
    }

    const SESSION_TTL_SECONDS = cfgInt("SESSION_TTL_SECONDS", 3600);

    const PIN_THROTTLE_WINDOW_SECONDS = cfgInt("PIN_THROTTLE_WINDOW_SECONDS", 900); // 15m
    const PIN_MAX_ATTEMPTS = cfgInt("PIN_MAX_ATTEMPTS", 5);
    const PIN_LOCKOUT_SECONDS = cfgInt("PIN_LOCKOUT_SECONDS", 900); // 15m

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

    async function getAccessToken() {
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

    async function getCurrentUser(token) {
      const res = await fetch("https://webexapis.com/v1/people/me", {
        headers: { Authorization: `Bearer ${token}` },
      });

      const me = await res.json();
      if (!res.ok) {
        throw new Error(`/people/me failed: ${JSON.stringify(me)}`);
      }

      const email = me.emails?.[0]?.toLowerCase();
      if (!email) throw new Error("User email not found");

      return {
        email,
        isAdmin: email.endsWith("@ussignal.com"),
      };
    }

    /* =====================================================
       Session helpers
    ===================================================== */

    async function getSession(email) {
      return await env.USER_SESSION_KV.get(KV.sessKey(email), { type: "json" });
    }

    async function setSession(email, session) {
      await env.USER_SESSION_KV.put(KV.sessKey(email), JSON.stringify(session), {
        expirationTtl: SESSION_TTL_SECONDS,
      });
    }

    async function clearSession(email) {
      await env.USER_SESSION_KV.delete(KV.sessKey(email));
    }

    /* =====================================================
       Throttling helpers (per email + per IP)
    ===================================================== */

    async function readAttempts(key) {
      const data = await env.USER_SESSION_KV.get(key, { type: "json" });
      return data || { count: 0, lockedUntil: 0, windowStart: nowMs() };
    }

    async function writeAttempts(key, data) {
      await env.USER_SESSION_KV.put(key, JSON.stringify(data), {
        expirationTtl: Math.max(PIN_THROTTLE_WINDOW_SECONDS, PIN_LOCKOUT_SECONDS),
      });
    }

    async function throttleCheckOrThrow(email, ip) {
      const kEmail = KV.attemptsKeyEmail(email);
      const kIp = KV.attemptsKeyIp(ip);

      const [aEmail, aIp] = await Promise.all([readAttempts(kEmail), readAttempts(kIp)]);

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

    async function throttleRecordFailure(email, ip) {
      const t = nowMs();
      const kEmail = KV.attemptsKeyEmail(email);
      const kIp = KV.attemptsKeyIp(ip);

      const [aEmail, aIp] = await Promise.all([readAttempts(kEmail), readAttempts(kIp)]);

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

      await Promise.all([writeAttempts(kEmail, bump(aEmail)), writeAttempts(kIp, bump(aIp))]);
    }

    async function throttleClear(email, ip) {
      // optional: clear attempts on success
      await Promise.all([
        env.USER_SESSION_KV.delete(KV.attemptsKeyEmail(email)),
        env.USER_SESSION_KV.delete(KV.attemptsKeyIp(ip)),
      ]);
    }

    /* =====================================================
       PIN map helpers (ORG_MAP_KV)
    ===================================================== */

    async function getOrgByPin(pin) {
      return await env.ORG_MAP_KV.get(KV.pinKey(pin), { type: "json" });
    }

    async function getPinByOrg(orgId) {
      return await env.ORG_MAP_KV.get(KV.orgKey(orgId), { type: "json" });
    }

    async function putPinMapping(pin, orgId, orgName) {
      // store forward + reverse
      await Promise.all([
        env.ORG_MAP_KV.put(KV.pinKey(pin), JSON.stringify({ orgId, orgName })),
        env.ORG_MAP_KV.put(KV.orgKey(orgId), JSON.stringify({ pin, orgName })),
      ]);
    }

    async function deletePinMapping(pin, orgId) {
      await Promise.all([
        env.ORG_MAP_KV.delete(KV.pinKey(pin)),
        env.ORG_MAP_KV.delete(KV.orgKey(orgId)),
      ]);
    }

    async function generateUniqueNonEasyPin() {
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
       UI: minimal modal app
    ===================================================== */

    function renderHomeHTML() {
      return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>US Signal Webex Demo</title>
  <style>
    :root{font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;}
    body{margin:0;background:#0b1220;color:#e5e7eb}
    header{padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.08);display:flex;align-items:center;gap:12px}
    .badge{font-size:12px;padding:4px 8px;border:1px solid rgba(255,255,255,.15);border-radius:999px;opacity:.9}
    main{padding:20px;max-width:1100px;margin:0 auto}
    .card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .grow{flex:1}
    button{background:#2563eb;border:0;color:white;border-radius:10px;padding:10px 12px;font-weight:600;cursor:pointer}
    button.secondary{background:rgba(255,255,255,.08)}
    button:disabled{opacity:.6;cursor:not-allowed}
    input{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:10px;color:#e5e7eb;padding:10px 12px;font-size:16px;outline:none;width:100%}
    pre{white-space:pre-wrap;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.1);padding:12px;border-radius:12px;overflow:auto}
    .muted{opacity:.8}
    /* Modal */
    .modalBackdrop{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;padding:18px}
    .modal{width:min(520px,100%);background:#0b1220;border:1px solid rgba(255,255,255,.12);border-radius:18px;padding:18px}
    .modal h2{margin:0 0 6px 0;font-size:18px}
    .modal p{margin:0 0 12px 0;opacity:.85}
    .modal .actions{display:flex;gap:10px;justify-content:flex-end;margin-top:12px}
    .error{color:#fca5a5}
    .ok{color:#86efac}
  </style>
</head>
<body>
  <header>
    <div style="font-weight:800">US Signal Webex Demo</div>
    <div class="badge" id="who">Loading…</div>
    <div class="badge" id="tenant">Tenant: —</div>
  </header>

  <main>
    <div class="row">
      <div class="card grow">
        <div class="row" style="align-items:center;justify-content:space-between">
          <div>
            <div style="font-weight:800">Organizations</div>
            <div class="muted" style="font-size:13px">Customers see only their tenant after PIN verify.</div>
          </div>
          <div class="row">
            <button class="secondary" id="btnLogout">Logout</button>
            <button id="btnReload">Reload</button>
          </div>
        </div>
        <div style="margin-top:12px">
          <pre id="out">Loading…</pre>
        </div>
      </div>
    </div>
  </main>

  <div class="modalBackdrop" id="backdrop">
    <div class="modal">
      <h2>Enter your 5-digit PIN</h2>
      <p>This demo uses a PIN to select your tenant.</p>
      <div class="row">
        <input id="pin" inputmode="numeric" maxlength="5" placeholder="•••••" />
      </div>
      <div id="msg" class="muted" style="margin-top:10px"></div>
      <div class="actions">
        <button class="secondary" id="btnCancel">Cancel</button>
        <button id="btnVerify">Verify</button>
      </div>
    </div>
  </div>

<script>
  const $ = (id)=>document.getElementById(id);

  function showModal(show){
    $("backdrop").style.display = show ? "flex" : "none";
    if(show){ $("pin").focus(); }
  }

  async function api(path, opts){
    const res = await fetch(path, { ...opts, headers: { "content-type":"application/json", ...(opts && opts.headers || {}) } });
    const txt = await res.text();
    let data = null;
    try { data = txt ? JSON.parse(txt) : null; } catch(e){ data = { raw: txt }; }
    return { ok: res.ok, status: res.status, data };
  }

  async function loadMe(){
    const r = await api("/api/me");
    if(r.ok){
      $("who").textContent = r.data.email + " (" + r.data.role + ")";
      if(r.data.orgName) $("tenant").textContent = "Tenant: " + r.data.orgName;
    } else {
      $("who").textContent = "Not authenticated";
    }
  }

  async function loadOrgs(){
    const r = await api("/api/org");
    if(r.ok){
      $("out").textContent = JSON.stringify(r.data, null, 2);
      return true;
    }
    if(r.status === 401 && r.data && (r.data.error === "pin_required" || r.data.error === "pin_required_or_expired")){
      showModal(true);
      $("msg").textContent = "PIN required.";
      return false;
    }
    $("out").textContent = JSON.stringify(r.data, null, 2);
    return false;
  }

  $("btnReload").onclick = async ()=>{ await loadMe(); await loadOrgs(); };
  $("btnLogout").onclick = async ()=>{ await api("/api/pin/logout", { method:"POST", body: JSON.stringify({}) }); await loadMe(); await loadOrgs(); };

  $("btnCancel").onclick = ()=> showModal(false);

  $("btnVerify").onclick = async ()=>{
    const pin = $("pin").value.trim();
    $("msg").textContent = "Verifying…";
    const r = await api("/api/pin/verify", { method:"POST", body: JSON.stringify({ pin }) });
    if(r.ok){
      $("msg").textContent = "✅ PIN verified. Loading orgs…";
      $("msg").className = "ok";
      showModal(false);
      await loadMe();
      await loadOrgs();
      $("pin").value = "";
      $("msg").className = "muted";
    } else {
      $("msg").textContent = (r.data && (r.data.message || r.data.error)) ? (r.data.message || r.data.error) : "PIN failed";
      $("msg").className = "error";
    }
  };

  (async ()=>{
    await loadMe();
    await loadOrgs();
  })();
</script>
</body>
</html>`;
    }

    /* =====================================================
       Routes
    ===================================================== */

    try {
      // Root UI (includes modal logic)
      if (url.pathname === "/" && request.method === "GET") {
        return text(renderHomeHTML(), 200, { "content-type": "text/html; charset=utf-8" });
      }

      // Root sanity JSON
      if (url.pathname === "/health") {
        return json({ status: "ok", service: "ussignal-webex", time: new Date().toISOString() });
      }

      // Silence favicon errors
      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      /* -----------------------------
         /api/me
         - returns role
         - returns org context if session exists
      ----------------------------- */
      if (url.pathname === "/api/me") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);
        const session = await getSession(user.email);

        return json({
          email: user.email,
          role: user.isAdmin ? "admin" : "customer",
          orgId: session?.orgId || null,
          orgName: session?.orgName || null,
          sessionExpiresInSeconds: session?.expiresAt ? Math.max(0, Math.floor((session.expiresAt - nowMs()) / 1000)) : 0,
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
        const token = await getAccessToken();
        const user = await getCurrentUser(token);
        const ip = getIP(request);

        // Admins don't need PIN; but allow admin to verify PIN for demo if desired
        const payload = await request.json().catch(() => ({}));
        const pin = String(payload.pin || "").trim();

        if (!isFiveDigitPin(pin)) {
          return json({ error: "invalid_pin_format", message: "PIN must be exactly 5 digits." }, 400);
        }

        // Throttle check
        const th = await throttleCheckOrThrow(user.email, ip);
        if (!th.allowed) {
          return json(
            { error: "too_many_attempts", message: `Too many attempts. Try again in ${th.retryAfter}s.` },
            429,
            { "retry-after": String(th.retryAfter) }
          );
        }

        const pinData = await getOrgByPin(pin);
        if (!pinData || !pinData.orgId) {
          await throttleRecordFailure(user.email, ip);
          // add small delay to slow brute forcing
          await sleep(200);
          return json({ error: "invalid_pin", message: "Invalid PIN." }, 403);
        }

        // success → clear throttles
        await throttleClear(user.email, ip);

        const session = {
          email: user.email,
          role: user.isAdmin ? "admin" : "customer",
          orgId: pinData.orgId,
          orgName: pinData.orgName,
          issuedAt: nowMs(),
          expiresAt: nowMs() + SESSION_TTL_SECONDS * 1000,
        };

        await setSession(user.email, session);

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
        const token = await getAccessToken();
        const user = await getCurrentUser(token);
        await clearSession(user.email);
        return json({ status: "ok" });
      }

      /* -----------------------------
         /api/org
         - Admin: returns all orgs
         - Customer: requires session; returns only matching org
      ----------------------------- */
      if (url.pathname === "/api/org") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        const session = await getSession(user.email);

        // customers require session (PIN)
        if (!user.isAdmin) {
          if (!session || !session.orgId) {
            return json({ error: "pin_required_or_expired", message: "PIN required." }, 401);
          }
          // session expiry check (KV TTL should handle, but keep a hard check)
          if (session.expiresAt && session.expiresAt <= nowMs()) {
            await clearSession(user.email);
            return json({ error: "pin_required_or_expired", message: "PIN required." }, 401);
          }
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

        const filtered = orgData.items.filter((o) => o.id === session.orgId);
        return json(filtered);
      }

      /* -----------------------------
         /api/admin/seed-pins (GET)
         Admin-only: fetch JSON and seed ORG_MAP_KV
         Supports 2 JSON formats:
           A) { "12345": { orgId, orgName } , ... }   // pin->org
           B) { "<orgId>": { pin, orgName }, ... }    // org->pin
      ----------------------------- */
      if (url.pathname === "/api/admin/seed-pins" && request.method === "GET") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);

        if (!user.isAdmin) return json({ error: "admin_only" }, 403);

        const seedUrl =
          env.PIN_SEED_URL ||
          "https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/org-pin-map.json";

        const res = await fetch(seedUrl, { headers: { "cache-control": "no-store" } });
        if (!res.ok) throw new Error(`Failed to fetch org-pin-map.json (${res.status})`);

       const raw = await res.json();
let written = 0;
let skipped = 0;

for (const [key, value] of Object.entries(raw)) {
  // Expect keys like "PIN_39571"
  if (!key.startsWith("PIN_")) {
    skipped++;
    continue;
  }

  const pin = key.replace("PIN_", "").trim();

  if (!/^\d{5}$/.test(pin)) {
    skipped++;
    continue;
  }

  if (!value?.orgName) {
    skipped++;
    continue;
  }

  // 🔑 orgId strategy:
  // Use normalized orgName as stable ID if no explicit orgId exists
  const orgId =
    value.orgId ||
    value.orgName.toLowerCase().replace(/[^a-z0-9]/g, "");

  // ✅ WRITE FORWARD + REVERSE MAPPINGS
  await Promise.all([
    env.ORG_MAP_KV.put(
      `pin:${pin}`,
      JSON.stringify({
        orgId,
        orgName: value.orgName,
      })
    ),
    env.ORG_MAP_KV.put(
      `org:${orgId}`,
      JSON.stringify({
        pin,
        orgName: value.orgName,
      })
    ),
  ]);

  written++;
}

return json({
  status: "ok",
  pinsLoaded: written,
  skipped
});

      /* -----------------------------
         /api/admin/pin/rotate (POST)
         Admin-only: rotate PIN for an org
         Body:
           { "orgId": "...", "orgName": "..." }   // orgName optional but recommended
         Returns:
           { oldPin, newPin, orgId, orgName }
      ----------------------------- */
      if (url.pathname === "/api/admin/pin/rotate" && request.method === "POST") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);
        if (!user.isAdmin) return json({ error: "admin_only" }, 403);

        const body = await request.json().catch(() => ({}));
        const orgId = String(body.orgId || "").trim();
        const orgName = String(body.orgName || "").trim();

        if (!orgId) return json({ error: "missing_orgId" }, 400);

        // read current mapping
        const existing = await getPinByOrg(orgId);
        const oldPin = existing?.pin || null;
        const name = orgName || existing?.orgName || "Unknown Org";

        // generate new pin
        const newPin = await generateUniqueNonEasyPin();

        // Write new mapping first
        await putPinMapping(newPin, orgId, name);

        // Best-effort delete old mapping
        if (oldPin && isFiveDigitPin(String(oldPin))) {
          await env.ORG_MAP_KV.delete(KV.pinKey(String(oldPin)));
        }

        return json({
          status: "ok",
          orgId,
          orgName: name,
          oldPin,
          newPin,
        });
      }

      /* -----------------------------
         /api/admin/pin/list (GET)
         Admin-only: returns current org->pin mappings (best-effort)
         NOTE: KV can't list keys here; so this endpoint expects you to pass orgIds if needed.
         For demo, you can skip this.
      ----------------------------- */
      if (url.pathname === "/api/admin/pin/list" && request.method === "POST") {
        const token = await getAccessToken();
        const user = await getCurrentUser(token);
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

      return json({ error: "not_found", path: url.pathname }, 404);
    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json({ error: "internal_error", message: err?.message || String(err) }, 500);
    }
  },
};
