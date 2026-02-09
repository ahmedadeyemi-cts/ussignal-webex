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

async function putPinMapping(pin, orgId, orgName, role = "customer", emails = []) {
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
   UI Shell: App Pages (Light/Dark, Role Nav, PIN modal)
===================================================== */

// Optional: set env var US_SIGNAL_LOGO_URL to your hosted logo (recommended)
const US_SIGNAL_LOGO_URL =
  env.US_SIGNAL_LOGO_URL ||
  "https://upload.wikimedia.org/wikipedia/commons/3/3f/Placeholder_view_vector.svg"; // replace ASAP

function renderAppHTML({ pageId = "dashboard", title = "US Signal Webex Portal" }) {
  const pageTitles = {
    dashboard: "Dashboard",
    licensing: "Licensing",
    maintenance: "Maintenance",
    support: "Support and Escalation",
    implementation: "Implementation and Migration",
    pstn: "PSTN Strategy",
    admin_dashboard: "Admin: Customer Overview",
    admin_licensing: "Admin: Licensing and Reports",
    admin_maintenance: "Admin: Maintenance and Scheduling",
    admin_support_model: "Admin: Support Model",
    admin_tenant_resolution: "Admin: Tenant Resolution Visualizer",
  };

  const activeTitle = pageTitles[pageId] || title;

  // Main content shells (simple, clean, professional)
  const shells = {
    dashboard: `
      <section class="card">
        <div class="h2">Customer Dashboard</div>
        <div class="muted">Tenant-scoped view. You will only see your organization once resolved.</div>
        <div class="grid3" style="margin-top:14px">
          <div class="stat"><div class="k">Organization</div><div class="v" id="orgName">Loading…</div></div>
          <div class="stat"><div class="k">Org ID</div><div class="v mono" id="orgId">Loading…</div></div>
          <div class="stat"><div class="k">Resolution</div><div class="v" id="resolution">Loading…</div></div>
        </div>
      </section>

      <section class="grid2" style="margin-top:14px">
        <div class="card">
          <div class="h3">Webex Calling Status</div>
          <div class="muted">Pulled from Webex status API.</div>
          <pre id="statusOut" class="pre">Loading…</pre>
        </div>
        <div class="card">
          <div class="h3">Organizations (API Result)</div>
          <div class="muted">Admins see all. Customers see only their tenant.</div>
          <pre id="orgOut" class="pre">Loading…</pre>
        </div>
      </section>
    `,

    licensing: `
      <section class="card">
        <div class="h2">Licensing</div>
        <div class="muted">This is an HTML shell. Next phase will wire license counts and deficit reporting.</div>

        <div class="grid2" style="margin-top:14px">
          <div class="card inner">
            <div class="h3">Customer Actions</div>
            <div class="muted">Customer must manually enter their email to receive reports.</div>

            <div class="row">
              <input id="custEmail" placeholder="your.email@company.com" />
              <button id="btnEmailLicenseMe">Email License Report</button>
            </div>

            <div class="row" style="margin-top:10px">
              <button class="secondary" id="btnDownloadLicenseCsv">Download CSV</button>
            </div>

            <div id="licenseMsg" class="muted" style="margin-top:10px"></div>
          </div>

          <div class="card inner">
            <div class="h3">License Snapshot</div>
            <div class="muted">Placeholder until license APIs are wired.</div>
            <pre class="pre">{ "total": "TBD", "used": "TBD", "available": "TBD" }</pre>
          </div>
        </div>
      </section>
    `,

    maintenance: `
      <section class="card">
        <div class="h2">Maintenance and Status</div>
        <div class="muted">Upcoming scheduled maintenances from status.webex.com API.</div>

        <div class="row" style="margin-top:14px">
          <button id="btnReloadMaint">Reload</button>
          <button class="secondary" id="btnEmailMaintMe">Email Schedule to Me</button>
          <input id="maintEmail" placeholder="your.email@company.com" />
        </div>

        <pre id="maintOut" class="pre" style="margin-top:12px">Loading…</pre>
        <div id="maintMsg" class="muted" style="margin-top:10px"></div>
      </section>
    `,

    support: `
      <section class="card">
        <div class="h2">Support and Escalation</div>
        <div class="muted">Customer-facing guidance.</div>

        <div class="grid2" style="margin-top:14px">
          <div class="card inner">
            <div class="h3">Business Hours Support</div>
            <div class="line"><b>Email:</b> <span class="mono">DLD-customercare@ussignal.com</span></div>
            <div class="line"><b>Phone:</b> <span class="mono">515-334-5755</span></div>
            <div class="muted" style="margin-top:10px">Use this during normal business hours for incidents, questions, and service requests.</div>
          </div>

          <div class="card inner">
            <div class="h3">After Hours Support</div>
            <div class="line"><b>PIN Required:</b> Yes</div>
            <div class="line"><b>OneAssist:</b> <span class="mono">844-462-3828</span></div>
            <div class="muted" style="margin-top:10px">After hours support is available through OneAssist. Keep your PIN available for verification.</div>
          </div>
        </div>
      </section>
    `,

    implementation: `
      <section class="card">
        <div class="h2">Implementation and Migration</div>
        <div class="muted">End-to-end journey from presales through cutover and optimization.</div>

        <div class="card inner" style="margin-top:14px">
          <div class="h3">Phases</div>
          <ol class="list">
            <li><b>Presales</b>: demo, requirements discovery, success criteria, initial solution design</li>
            <li><b>PSTN Selection</b>: Local Gateway, Cisco PSTN, Cloud PSTN (IntelePeer, CallTower)</li>
            <li><b>Discovery</b>: dial plan, sites, users, devices, network readiness, firewall rules, QoS</li>
            <li><b>Porting</b>: LOA, CSR, port dates, test numbers, rollback planning</li>
            <li><b>Configuration</b>: locations, trunks, routing, E911, voicemail, auto attendants, hunt groups</li>
            <li><b>Migration</b>: pilot, phased cutover, validation testing, training, go-live support</li>
            <li><b>Operations</b>: proactive monitoring, incident response, change management, reporting</li>
          </ol>
        </div>

        <div class="card inner" style="margin-top:14px">
          <div class="h3">Webex Calling Features Customers Commonly Use</div>
          <div class="chips">
            <span class="chip">Auto Attendant</span>
            <span class="chip">Hunt Groups</span>
            <span class="chip">Call Queues</span>
            <span class="chip">Voicemail</span>
            <span class="chip">E911</span>
            <span class="chip">Call Recording</span>
            <span class="chip">DECT / ATA</span>
            <span class="chip">Device Templates</span>
            <span class="chip">Analytics</span>
          </div>
        </div>
      </section>
    `,

    pstn: `
      <section class="card">
        <div class="h2">PSTN Implementation Strategy</div>
        <div class="muted">Partner may leverage one or more PSTN capabilities.</div>

        <div class="grid2" style="margin-top:14px">
          <div class="card inner">
            <div class="h3">PSTN Options</div>
            <ul class="list">
              <li>Cisco CCP Provider</li>
              <li>Partner PSTN capabilities via Local Gateway</li>
              <li>Cisco Calling Plans (PSTN)</li>
              <li>Cloud PSTN Providers (IntelePeer, CallTower)</li>
            </ul>
          </div>

          <div class="card inner">
            <div class="h3">Operational Integration</div>
            <ul class="list">
              <li>Provisioning workflows and validation</li>
              <li>Incident prevention, detection, and response aligned to SLA</li>
              <li>Escalation paths and TAC coordination</li>
              <li>Change management for routing, carrier maintenance, and cutovers</li>
            </ul>
          </div>
        </div>

        <div class="card inner" style="margin-top:14px">
          <div class="h3">Documentation Requirements</div>
          <ul class="list">
            <li>Incident prevention, detection, and response processes consistent with the Provider SLA</li>
            <li>Provisioning processes and support specific to the PSTN capabilities</li>
          </ul>
        </div>
      </section>
    `,

    admin_dashboard: `
      <section class="card">
        <div class="h2">Admin Customer Overview</div>
        <div class="muted">Admins see all customers. Search is a shell, next phase wires matching logic.</div>

        <div class="row" style="margin-top:14px">
          <input id="adminSearch" placeholder="Search by org name (partial), city, or keyword…" />
          <button id="btnAdminReload">Reload</button>
        </div>

        <pre id="adminOrgOut" class="pre" style="margin-top:12px">Loading…</pre>
      </section>
    `,

    admin_licensing: `
      <section class="card">
        <div class="h2">Admin Licensing and Reports</div>
        <div class="muted">Shell for license deficit report and email distribution.</div>

        <div class="grid2" style="margin-top:14px">
          <div class="card inner">
            <div class="h3">Send to ADMIN_EMAILS</div>
            <div class="muted">Worker env var: <span class="mono">ADMIN_EMAILS</span> contains 3 to 10 emails.</div>
            <div class="row" style="margin-top:10px">
              <button id="btnAdminSendLicenses">Email Deficit Report to ADMIN_EMAILS</button>
            </div>
            <div id="adminLicMsg" class="muted" style="margin-top:10px"></div>
          </div>

          <div class="card inner">
            <div class="h3">Generate / Export</div>
            <div class="row">
              <button class="secondary" id="btnAdminDownloadLicenses">Download Deficit CSV</button>
            </div>
            <div class="muted" style="margin-top:10px">Report generation API will be wired next.</div>
          </div>
        </div>
      </section>
    `,

    admin_maintenance: `
      <section class="card">
        <div class="h2">Admin Maintenance and Scheduling</div>
        <div class="muted">Shell for upcoming maintenances and sending schedules to ADMIN_EMAILS.</div>

        <div class="row" style="margin-top:14px">
          <button id="btnAdminReloadMaint">Reload</button>
          <button id="btnAdminEmailMaint">Email Schedule to ADMIN_EMAILS</button>
        </div>

        <pre id="adminMaintOut" class="pre" style="margin-top:12px">Loading…</pre>
        <div id="adminMaintMsg" class="muted" style="margin-top:10px"></div>
      </section>
    `,

    admin_support_model: `
      <section class="card">
        <div class="h2">Admin Support Model</div>
        <div class="muted">Internal-only explanation of support coverage, escalation, and responsibilities.</div>

        <div class="card inner" style="margin-top:14px">
          <div class="h3">Support Coverage</div>
          <ul class="list">
            <li>Business Hours: US Signal support intake via phone and email</li>
            <li>After Hours: OneAssist intake with PIN requirement</li>
            <li>Escalation: engineering triage, Cisco TAC engagement, and customer communications</li>
          </ul>
        </div>

        <div class="card inner" style="margin-top:14px">
          <div class="h3">Operational Expectations</div>
          <ul class="list">
            <li>Incident prevention, detection, response processes aligned to SLA</li>
            <li>Proactive monitoring of calling service health and status trends</li>
            <li>Change control for routing, carrier events, and Webex maintenance impacts</li>
          </ul>
        </div>
      </section>
    `,

    admin_tenant_resolution: `
      <section class="card">
        <div class="h2">Tenant Resolution Visualizer</div>
        <div class="muted">Admin-only. Shows exactly how tenant resolution occurs.</div>

        <div class="card inner" style="margin-top:14px">
          <div class="row">
            <input id="trEmail" placeholder="email@example.com" />
            <input id="trPin" placeholder="12345" />
            <input id="trOrgId" placeholder="orgId" />
            <button id="btnResolve">Resolve</button>
          </div>
          <pre id="trOut" class="pre" style="margin-top:12px">—</pre>
        </div>
      </section>
    `,
  };

  const content = shells[pageId] || `<section class="card"><div class="h2">${activeTitle}</div></section>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${activeTitle}</title>

  <style>
    :root{
      --bg: #0b1220;
      --panel: rgba(255,255,255,.04);
      --panel2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.10);
      --text: #e5e7eb;
      --muted: rgba(229,231,235,.75);
      --primary: #2563eb;
      --danger: #fca5a5;
      --ok: #86efac;
      --shadow: 0 10px 30px rgba(0,0,0,.25);
      --radius: 16px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }

    /* Light mode defaults via prefers-color-scheme, with manual override */
    @media (prefers-color-scheme: light){
      :root{
        --bg: #f6f7fb;
        --panel: #ffffff;
        --panel2: #f3f4f6;
        --border: rgba(15,23,42,.12);
        --text: #0f172a;
        --muted: rgba(15,23,42,.70);
        --shadow: 0 10px 30px rgba(2,6,23,.10);
      }
    }

    [data-theme="dark"]{
      --bg: #0b1220;
      --panel: rgba(255,255,255,.04);
      --panel2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.10);
      --text: #e5e7eb;
      --muted: rgba(229,231,235,.75);
      --shadow: 0 10px 30px rgba(0,0,0,.25);
    }

    [data-theme="light"]{
      --bg: #f6f7fb;
      --panel: #ffffff;
      --panel2: #f3f4f6;
      --border: rgba(15,23,42,.12);
      --text: #0f172a;
      --muted: rgba(15,23,42,.70);
      --shadow: 0 10px 30px rgba(2,6,23,.10);
    }

    html, body { height:100%; }
    body{
      margin:0;
      font-family: var(--sans);
      background: var(--bg);
      color: var(--text);
    }

    .wrap{
      display:grid;
      grid-template-columns: 280px 1fr;
      min-height:100vh;
    }

    .side{
      border-right: 1px solid var(--border);
      padding:18px;
      position:sticky;
      top:0;
      height:100vh;
      box-sizing:border-box;
      background: linear-gradient(180deg, var(--panel), transparent);
    }

    .brand{
      display:flex;
      align-items:center;
      gap:10px;
      padding:8px 10px;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: var(--panel);
      box-shadow: var(--shadow);
    }
    .brand img{ height:28px; width:auto; border-radius:6px; }
    .brand .b1{ font-weight:900; letter-spacing:.2px; }
    .brand .b2{ font-size:12px; color: var(--muted); margin-top:2px; }

    .nav{
      margin-top:16px;
      display:flex;
      flex-direction:column;
      gap:6px;
    }

    .nav a{
      display:flex;
      justify-content:space-between;
      align-items:center;
      padding:10px 12px;
      text-decoration:none;
      color: var(--text);
      border-radius: 12px;
      border:1px solid transparent;
    }
    .nav a:hover{
      background: var(--panel);
      border-color: var(--border);
    }
    .nav a.active{
      background: rgba(37,99,235,.14);
      border-color: rgba(37,99,235,.35);
    }
    .tag{
      font-size:12px;
      padding:2px 8px;
      border-radius:999px;
      border:1px solid var(--border);
      color: var(--muted);
    }

    .main{
      padding:18px 22px 60px 22px;
      box-sizing:border-box;
    }

    .topbar{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:12px;
      margin-bottom:16px;
    }

    .badges{ display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }
    .badge{
      font-size:12px;
      padding:6px 10px;
      border:1px solid var(--border);
      border-radius:999px;
      background: var(--panel);
      color: var(--muted);
    }

    .card{
      background: var(--panel);
      border:1px solid var(--border);
      border-radius: var(--radius);
      padding:16px;
      box-shadow: var(--shadow);
    }
    .card.inner{ box-shadow:none; background: var(--panel2); }

    .h2{ font-weight:900; font-size:18px; }
    .h3{ font-weight:800; font-size:14px; margin-bottom:8px; }
    .muted{ color: var(--muted); font-size:13px; }

    .grid2{ display:grid; grid-template-columns: 1fr 1fr; gap:14px; }
    .grid3{ display:grid; grid-template-columns: 1fr 1fr 1fr; gap:14px; }
    @media (max-width: 980px){
      .wrap{ grid-template-columns: 1fr; }
      .side{ position:relative; height:auto; }
      .grid2, .grid3{ grid-template-columns: 1fr; }
    }

    .stat{ background: var(--panel2); border:1px solid var(--border); border-radius:14px; padding:12px; }
    .stat .k{ font-size:12px; color: var(--muted); }
    .stat .v{ margin-top:6px; font-weight:800; }
    .mono{ font-family: var(--mono); }

    .row{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    input{
      flex:1;
      min-width: 240px;
      padding:10px 12px;
      border-radius:12px;
      border:1px solid var(--border);
      background: var(--panel2);
      color: var(--text);
      outline:none;
    }
    button{
      padding:10px 12px;
      border-radius:12px;
      border:0;
      background: var(--primary);
      color:white;
      font-weight:800;
      cursor:pointer;
    }
    button.secondary{
      background: transparent;
      border:1px solid var(--border);
      color: var(--text);
    }
    button:disabled{ opacity:.6; cursor:not-allowed; }

    .pre{
      white-space: pre-wrap;
      font-family: var(--mono);
      background: rgba(0,0,0,.20);
      border:1px solid var(--border);
      border-radius: 12px;
      padding:12px;
      overflow:auto;
      margin-top:10px;
    }
    @media (prefers-color-scheme: light){
      .pre{ background: rgba(15,23,42,.04); }
    }

    .list{ margin: 10px 0 0 18px; color: var(--text); }
    .list li{ margin: 8px 0; color: var(--text); }
    .line{ margin-top: 8px; }

    .chips{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
    .chip{
      font-size:12px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid var(--border);
      background: var(--panel2);
    }

    /* PIN modal */
    .modalBackdrop{
      position:fixed; inset:0;
      background: rgba(0,0,0,.55);
      display:none; align-items:center; justify-content:center;
      padding:18px;
      z-index:50;
    }
    .modal{
      width:min(520px,100%);
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: var(--shadow);
    }
    .modal .actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:12px; }
    .error{ color: var(--danger); }
    .ok{ color: var(--ok); }

    /* Floating AI shell button */
    .aiBtn{
      position:fixed;
      right:18px;
      bottom:18px;
      border-radius: 999px;
      padding: 12px 14px;
      box-shadow: var(--shadow);
      z-index:40;
    }
  </style>
</head>

<body>
  <div class="wrap" id="appRoot">
    <aside class="side">
      <div class="brand">
        <img src="${US_SIGNAL_LOGO_URL}" alt="US Signal" />
        <div>
          <div class="b1">US Signal</div>
          <div class="b2">Webex Calling Portal</div>
        </div>
      </div>

      <div class="nav" id="nav">
        <a href="/" data-id="dashboard"><span>Dashboard</span><span class="tag">Customer</span></a>
        <a href="/licensing" data-id="licensing"><span>Licensing</span><span class="tag">Customer</span></a>
        <a href="/maintenance" data-id="maintenance"><span>Maintenance</span><span class="tag">Customer</span></a>
        <a href="/support" data-id="support"><span>Support</span><span class="tag">Customer</span></a>
        <a href="/implementation" data-id="implementation"><span>Implementation</span><span class="tag">Customer</span></a>
        <a href="/pstn" data-id="pstn"><span>PSTN Strategy</span><span class="tag">Customer</span></a>

        <div style="height:8px"></div>

        <a href="/admin/dashboard" data-id="admin_dashboard" class="adminOnly"><span>Admin Overview</span><span class="tag">Admin</span></a>
        <a href="/admin/licensing" data-id="admin_licensing" class="adminOnly"><span>Admin Licensing</span><span class="tag">Admin</span></a>
        <a href="/admin/maintenance" data-id="admin_maintenance" class="adminOnly"><span>Admin Maintenance</span><span class="tag">Admin</span></a>
        <a href="/admin/support-model" data-id="admin_support_model" class="adminOnly"><span>Support Model</span><span class="tag">Admin</span></a>
        <a href="/admin/tenant-resolution" data-id="admin_tenant_resolution" class="adminOnly"><span>Tenant Resolution</span><span class="tag">Admin</span></a>

        <div style="height:10px"></div>

        <div class="row">
          <button class="secondary" id="btnTheme" type="button">Toggle Theme</button>
        </div>

        <div class="row" style="margin-top:10px">
          <button class="secondary" id="btnLogout" type="button">Logout</button>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div>
          <div class="h2">${activeTitle}</div>
          <div class="muted" id="subline">Loading identity…</div>
        </div>
        <div class="badges">
          <div class="badge" id="badgeUser">User: —</div>
          <div class="badge" id="badgeRole">Role: —</div>
          <div class="badge" id="badgeTenant">Tenant: —</div>
        </div>
      </div>

      ${content}
    </main>
  </div>

  <!-- PIN Modal -->
  <div class="modalBackdrop" id="backdrop">
    <div class="modal">
      <div class="h2">Enter your 5-digit PIN</div>
      <div class="muted" style="margin-top:6px">This portal uses a PIN session when email allowlist does not resolve your tenant.</div>
      <div class="row" style="margin-top:12px">
        <input id="pin" inputmode="numeric" maxlength="5" placeholder="12345" />
      </div>
      <div id="pinMsg" class="muted" style="margin-top:10px"></div>
      <div class="actions">
        <button class="secondary" id="btnCancel" type="button">Cancel</button>
        <button id="btnVerify" type="button">Verify</button>
      </div>
    </div>
  </div>

  <!-- AI shell button -->
  <button class="aiBtn" id="aiBtn" type="button">Ask US Signal (AI)</button>

<script>
  const PAGE_ID = ${JSON.stringify(pageId)};

  const $ = (id)=>document.getElementById(id);

  function setActiveNav() {
    const links = document.querySelectorAll(".nav a[data-id]");
    links.forEach(a => {
      if (a.getAttribute("data-id") === PAGE_ID) a.classList.add("active");
      else a.classList.remove("active");
    });
  }

  function setTheme(next){
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
  }

  function initTheme(){
    const saved = localStorage.getItem("theme");
    if(saved === "light" || saved === "dark") setTheme(saved);
  }

  function showPinModal(show){
    $("backdrop").style.display = show ? "flex" : "none";
    if(show) $("pin").focus();
  }

  async function api(path, opts){
    const res = await fetch(path, {
      ...opts,
      headers: {
        "content-type":"application/json",
        ...(opts && opts.headers || {})
      }
    });
    const txt = await res.text();
    let data = null;
    try { data = txt ? JSON.parse(txt) : null; } catch(e){ data = { raw: txt }; }
    return { ok: res.ok, status: res.status, data };
  }

  async function loadMe(){
    const r = await api("/api/me");
    if(!r.ok){
      $("subline").textContent = "Not authenticated via Zero Trust.";
      return { ok:false };
    }

    $("badgeUser").textContent = "User: " + (r.data.email || "—");
    $("badgeRole").textContent = "Role: " + (r.data.role || "—");
    $("badgeTenant").textContent = "Tenant: " + (r.data.orgName || "—");
    $("subline").textContent =
      "Resolution: " + (r.data.resolution || "none") +
      " | Session TTL: " + (r.data.sessionExpiresInSeconds || 0) + "s";

    // Hide admin links for non-admin
    const isAdmin = r.data.role === "admin";
    document.querySelectorAll(".adminOnly").forEach(el => {
      el.style.display = isAdmin ? "flex" : "none";
    });

    return { ok:true, me:r.data };
  }

  async function loadOrgs(){
    const r = await api("/api/org");
    if(r.ok){
      const out = $("orgOut") || $("adminOrgOut");
      if(out) out.textContent = JSON.stringify(r.data, null, 2);
      return { ok:true, data:r.data };
    }

    // Tenant not resolved: show PIN modal
    if(r.status === 401){
      showPinModal(true);
      const out = $("orgOut") || $("adminOrgOut");
      if(out) out.textContent = JSON.stringify(r.data, null, 2);
      return { ok:false, needsPin:true };
    }

    const out = $("orgOut") || $("adminOrgOut");
    if(out) out.textContent = JSON.stringify(r.data, null, 2);
    return { ok:false };
  }

  async function loadStatus(){
    const out = $("statusOut");
    if(!out) return;
    try{
      const res = await fetch("https://status.webex.com/api/v2/status.json", { cache:"no-store" });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }catch(e){
      out.textContent = JSON.stringify({ error: String(e) }, null, 2);
    }
  }

  async function loadMaintenance(targetId){
    const out = $(targetId);
    if(!out) return;
    try{
      const res = await fetch("https://status.webex.com/api/v2/scheduled-maintenances/upcoming.json", { cache:"no-store" });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }catch(e){
      out.textContent = JSON.stringify({ error: String(e) }, null, 2);
    }
  }

  // Page-specific wiring (still shell)
  function wireShellButtons(){
    if($("btnEmailLicenseMe")){
      $("btnEmailLicenseMe").onclick = ()=>{
        const email = ($("custEmail").value || "").trim();
        $("licenseMsg").textContent = email ? ("Queued shell action for: " + email + " (Brevo wiring next).") : "Enter an email address first.";
      };
    }
    if($("btnDownloadLicenseCsv")){
      $("btnDownloadLicenseCsv").onclick = ()=>{
        $("licenseMsg").textContent = "CSV export shell. Wiring next.";
      };
    }
    if($("btnReloadMaint")){
      $("btnReloadMaint").onclick = async ()=>{ await loadMaintenance("maintOut"); };
    }
    if($("btnEmailMaintMe")){
      $("btnEmailMaintMe").onclick = ()=>{
        const email = ($("maintEmail").value || "").trim();
        $("maintMsg").textContent = email ? ("Queued schedule email shell for: " + email + " (Brevo wiring next).") : "Enter an email address first.";
      };
    }
    if($("btnAdminReloadMaint")){
      $("btnAdminReloadMaint").onclick = async ()=>{ await loadMaintenance("adminMaintOut"); };
    }
    if($("btnAdminEmailMaint")){
      $("btnAdminEmailMaint").onclick = ()=>{
        $("adminMaintMsg").textContent = "Queued shell action to email ADMIN_EMAILS (Brevo wiring next).";
      };
    }
    if($("btnAdminSendLicenses")){
      $("btnAdminSendLicenses").onclick = ()=>{
        $("adminLicMsg").textContent = "Queued shell action to email ADMIN_EMAILS (Brevo wiring next).";
      };
    }
    if($("btnAdminDownloadLicenses")){
      $("btnAdminDownloadLicenses").onclick = ()=>{
        $("adminLicMsg").textContent = "CSV export shell. Wiring next.";
      };
    }
    if($("btnResolve")){
      $("btnResolve").onclick = async ()=>{
        const body = {
          email: ($("trEmail").value || "").trim(),
          pin: ($("trPin").value || "").trim(),
          orgId: ($("trOrgId").value || "").trim(),
        };
        const r = await api("/api/admin/resolve", { method:"POST", body: JSON.stringify(body) });
        $("trOut").textContent = JSON.stringify(r.data, null, 2);
      };
    }

    $("aiBtn").onclick = ()=>{
      alert("AI assistant shell. Next phase will wire this to a knowledge base of your portal content.");
    };
  }

  // PIN modal actions
  $("btnCancel").onclick = ()=> showPinModal(false);

  $("btnVerify").onclick = async ()=>{
    const pin = ($("pin").value || "").trim();
    $("pinMsg").textContent = "Verifying…";
    const r = await api("/api/pin/verify", { method:"POST", body: JSON.stringify({ pin }) });
    if(r.ok){
      $("pinMsg").textContent = "PIN verified. Reloading…";
      showPinModal(false);
      $("pin").value = "";
      await boot();
    } else {
      $("pinMsg").textContent = (r.data && (r.data.message || r.data.error)) ? (r.data.message || r.data.error) : "PIN failed";
      $("pinMsg").className = "error";
    }
  };

  // Top controls
  $("btnTheme").onclick = ()=>{
    const cur = localStorage.getItem("theme");
    setTheme(cur === "dark" ? "light" : "dark");
  };

  $("btnLogout").onclick = async ()=>{
    await api("/api/pin/logout", { method:"POST", body: JSON.stringify({}) });
    location.href = "/";
  };

  async function boot(){
    initTheme();
    setActiveNav();
    const me = await loadMe();

    // Fill dashboard stat placeholders if present
    if(me.ok){
      if($("orgName")) $("orgName").textContent = me.me.orgName || "—";
      if($("orgId")) $("orgId").textContent = me.me.orgId || "—";
      if($("resolution")) $("resolution").textContent = me.me.resolution || "—";
    }

    await loadOrgs();
    await loadStatus();

    // Maintenance shells
    if($("maintOut")) await loadMaintenance("maintOut");
    if($("adminMaintOut")) await loadMaintenance("adminMaintOut");

    wireShellButtons();
  }

  boot();
</script>

</body>
</html>`;
}

    /* =====================================================
       Routes
    ===================================================== */

    try {

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


      // Root UI (includes modal logic)
      if (url.pathname === "/" && request.method === "GET") {
        return text(renderHomeHTML(), 200, { "content-type": "text/html; charset=utf-8" });
      }
      /* -----------------------------
   Admin UI: Tenant Resolution Visualizer
----------------------------- */
if (url.pathname === "/admin/tenant-resolution" && request.method === "GET") {
  return text(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Tenant Resolution Inspector</title>
<style>
  body { font-family: system-ui; background:#0b1220; color:#e5e7eb; padding:20px }
  input, button { padding:10px; border-radius:8px; border:1px solid #333; background:#111827; color:#e5e7eb }
  button { background:#2563eb; font-weight:600; cursor:pointer }
  .row { display:flex; gap:10px; margin-bottom:10px }
  pre { background:#020617; padding:12px; border-radius:10px; border:1px solid #1f2937 }
  .card { border:1px solid #1f2937; border-radius:12px; padding:14px; margin-top:12px }
</style>
</head>
<body>

<h1>🧭 Tenant Resolution Visualizer</h1>
<p>Admin-only. Shows exactly how tenant resolution occurs.</p>

<div class="card">
  <div class="row">
    <input id="email" placeholder="email@example.com" />
    <input id="pin" placeholder="12345" />
    <input id="orgId" placeholder="orgId" />
    <button onclick="resolve()">Resolve</button>
  </div>
</div>

<div class="card">
  <h3>Result</h3>
  <pre id="out">—</pre>
</div>

<script>
async function resolve() {
  const body = {
    email: document.getElementById("email").value,
    pin: document.getElementById("pin").value,
    orgId: document.getElementById("orgId").value
  };

  const res = await fetch("/api/admin/resolve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  document.getElementById("out").textContent =
    JSON.stringify(data, null, 2);
}
</script>

</body>
</html>`, 200, { "content-type": "text/html; charset=utf-8" });
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
/* =====================================================
   UI PAGE ROUTES (HTML SHELLS)
   Place this block after your debug/favicon routes and before /api/me
===================================================== */

async function requireAdminOr403() {
  const token = await getAccessToken();
  const user = await getCurrentUser(token);
  if (!user.isAdmin) return { ok: false, res: json({ error: "admin_only" }, 403) };
  return { ok: true, user, token };
}

// Customer pages
if (request.method === "GET") {
  if (url.pathname === "/") {
    return text(renderAppHTML({ pageId: "dashboard" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/licensing") {
    return text(renderAppHTML({ pageId: "licensing" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/maintenance") {
    return text(renderAppHTML({ pageId: "maintenance" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/support") {
    return text(renderAppHTML({ pageId: "support" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/implementation") {
    return text(renderAppHTML({ pageId: "implementation" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/pstn") {
    return text(renderAppHTML({ pageId: "pstn" }), 200, { "content-type": "text/html; charset=utf-8" });
  }

  // Admin pages
  if (url.pathname === "/admin/dashboard") {
    const gate = await requireAdminOr403();
    if (!gate.ok) return gate.res;
    return text(renderAppHTML({ pageId: "admin_dashboard" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/admin/licensing") {
    const gate = await requireAdminOr403();
    if (!gate.ok) return gate.res;
    return text(renderAppHTML({ pageId: "admin_licensing" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/admin/maintenance") {
    const gate = await requireAdminOr403();
    if (!gate.ok) return gate.res;
    return text(renderAppHTML({ pageId: "admin_maintenance" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/admin/support-model") {
    const gate = await requireAdminOr403();
    if (!gate.ok) return gate.res;
    return text(renderAppHTML({ pageId: "admin_support_model" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
  if (url.pathname === "/admin/tenant-resolution") {
    const gate = await requireAdminOr403();
    if (!gate.ok) return gate.res;
    return text(renderAppHTML({ pageId: "admin_tenant_resolution" }), 200, { "content-type": "text/html; charset=utf-8" });
  }
}

      /* -----------------------------
         /api/me
         - returns role
         - returns org context if session exists
      ----------------------------- */
     if (url.pathname === "/api/me") {
  const token = await getAccessToken();
  const user = await getCurrentUser(token);

  // 1️⃣ Try email-based tenant resolution
  const emailOrg = await getOrgByEmail(user.email);

  // 2️⃣ Fall back to PIN session
  const session = await getSession(user.email);

  const resolvedOrg =
    emailOrg ||
    (session && session.orgId
      ? { orgId: session.orgId, orgName: session.orgName }
      : null);

  return json({
    email: user.email,
    role: user.isAdmin ? "admin" : "customer",
    orgId: resolvedOrg?.orgId || null,
    orgName: resolvedOrg?.orgName || null,
    resolution: emailOrg ? "email" : session ? "pin" : null,
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

  // customers require tenant resolution (email OR PIN)
  if (!user.isAdmin) {
    const emailOrg = await getOrgByEmail(user.email);
    if (!emailOrg && (!session || !session.orgId)) {
      return json({ error: "tenant_not_resolved" }, 401);
    }
  }

  // session expiry check
  if (session?.expiresAt && session.expiresAt <= nowMs()) {
    await clearSession(user.email);
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
const role = existing?.role || "customer";
const emails = existing?.emails || [];


        // generate new pin
        const newPin = await generateUniqueNonEasyPin();

        // Write new mapping first
        await putPinMapping(newPin, orgId, name, role, emails);

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
      /* =====================================================
   🔍 ADMIN INSPECTION ENDPOINTS (READ-ONLY)
   ===================================================== */

/* -----------------------------
   GET /api/admin/inspect/email/:email
----------------------------- */
if (url.pathname.startsWith("/api/admin/inspect/email/") && request.method === "GET") {
  const token = await getAccessToken();
  const user = await getCurrentUser(token);
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
  const token = await getAccessToken();
  const user = await getCurrentUser(token);
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
  const token = await getAccessToken();
  const user = await getCurrentUser(token);
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
  const token = await getAccessToken();
  const user = await getCurrentUser(token);
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

      /* -----------------------------
         🔎 DEBUG: seed + read a PIN
         GET /api/debug/pin-test
         TEMPORARY — remove after testing
      ----------------------------- */
      if (url.pathname === "/api/debug/pin-test") {
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

      return json({ error: "not_found", path: url.pathname }, 404);
    } catch (err) {
      console.error("🔥 Worker error:", err);
      return json({ error: "internal_error", message: err?.message || String(err) }, 500);
    }
  },
};
