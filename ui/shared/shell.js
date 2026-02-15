<script src="https://raw.githubusercontent.com/ahmedadeyemi-cts/ussignal-webex/main/ui/shared/shell.js"></script>
<script>
  // After loadMe(), call:
  window.renderShell({
    role: ME.role,
    orgName: ME.orgName,
    activePath: location.pathname
  });
(function(){
  const LOGO_URL = "https://webex.onenecklab.com/assets/ussignal-logo.jpg";

  function escapeHtml(str){
    return String(str ?? "")
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#039;");
  }

  function loadTheme(){
    const saved = localStorage.getItem("uiTheme") || "light";
    document.documentElement.setAttribute("data-theme", saved);
    const btn = document.getElementById("shellThemeBtn");
    if (btn) btn.textContent = saved === "dark" ? "Light Mode" : "Dark Mode";
  }

  function toggleTheme(){
    const cur = document.documentElement.getAttribute("data-theme") || "light";
    const next = cur === "dark" ? "light" : "dark";
    localStorage.setItem("uiTheme", next);
    loadTheme();
  }

  function navItems(role){
    const customer = [
      { href:"/customer", label:"Customer Hub", icon:"🏠" },
      { href:"/customer/licenses", label:"Licenses", icon:"🧾" },
      { href:"/customer/maintenance", label:"Maintenance", icon:"🛠️" },
      { href:"/customer/incidents", label:"Incidents", icon:"🚨" },
      { href:"/customer/status", label:"Status", icon:"🌐" },
    ];

    const admin = [
      { href:"/admin", label:"Admin Hub", icon:"🏢" },
      { href:"/admin/licenses", label:"Licenses", icon:"🧾" },
      { href:"/admin/maintenance", label:"Maintenance", icon:"🛠️" },
      { href:"/admin/support-model", label:"Support Model", icon:"🧩" },
      { href:"/admin/sow-builder", label:"SOW Builder", icon:"📄" },
      { href:"/admin/tenant-resolution", label:"Tenant Resolution", icon:"🧭" },
    ];

    return role === "admin" ? admin : customer;
  }

  function isActive(activePath, href){
    if (href === "/customer" && activePath === "/customer") return true;
    if (href === "/admin" && activePath === "/admin") return true;
    return activePath === href;
  }

  window.renderShell = function({ role, orgName, activePath }){
    // Wrap existing content into a shell
    const body = document.body;

    // Create container
    const shell = document.createElement("div");
    shell.innerHTML = `
      <style>
        :root{
          --bg:#f4f6f9;
          --card:#ffffff;
          --text:#0f172a;
          --muted:#64748b;
          --accent:#0f62fe;
          --border:rgba(0,0,0,.10);
          --shadow:0 10px 30px rgba(0,0,0,.08);
        }
        [data-theme="dark"]{
          --bg:#0b1220;
          --card:#0f172a;
          --text:#e5e7eb;
          --muted:#94a3b8;
          --accent:#3b82f6;
          --border:rgba(255,255,255,.12);
          --shadow:0 10px 30px rgba(0,0,0,.30);
        }
        body{ margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
        .shellTop{
          position:sticky; top:0; z-index:50;
          display:flex; align-items:center; justify-content:space-between; gap:14px;
          padding:14px 18px;
          background:var(--card);
          border-bottom:1px solid var(--border);
          box-shadow:0 2px 10px rgba(0,0,0,.06);
        }
        .brand{ display:flex; align-items:center; gap:12px; min-width:260px; }
        .brand img{ height:32px; width:auto; display:block; border-radius:6px; }
        .brandTitle{ font-weight:900; font-size:14px; letter-spacing:.2px; }
        .brandSub{ font-size:12px; color:var(--muted); margin-top:2px; }
        .topActions{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
        .pill{
          font-size:12px; font-weight:800;
          padding:7px 10px; border-radius:999px;
          border:1px solid var(--border);
          background:rgba(15,98,254,.08);
          color:var(--accent);
          white-space:nowrap;
        }
        .btn{
          padding:9px 12px; border-radius:10px;
          border:1px solid var(--border);
          background:transparent;
          color:var(--text);
          font-weight:800;
          cursor:pointer;
        }
        .btnPrimary{
          border:none; background:var(--accent); color:#fff;
        }
        .shellBody{ display:flex; }
        .sidebar{
          width:260px; min-height:calc(100vh - 66px);
          background:var(--card);
          border-right:1px solid var(--border);
          padding:14px;
        }
        .navItem{
          display:flex; align-items:center; gap:10px;
          padding:10px 12px;
          border-radius:12px;
          text-decoration:none;
          color:var(--text);
          font-weight:800;
          margin-bottom:8px;
          border:1px solid transparent;
        }
        .navItem:hover{ background:rgba(15,98,254,.06); border-color:rgba(15,98,254,.18); }
        .navItem.active{
          background:rgba(15,98,254,.10);
          border-color:rgba(15,98,254,.24);
          color:var(--accent);
        }
        .content{
          flex:1;
          padding:22px;
          max-width:1400px;
        }
        .contentInner{
          max-width:1400px;
          margin:auto;
        }
        @media (max-width: 980px){
          .shellBody{ flex-direction:column; }
          .sidebar{ width:auto; border-right:none; border-bottom:1px solid var(--border); }
        }
      </style>

      <div class="shellTop">
        <div class="brand">
          <img src="${LOGO_URL}" alt="US Signal" />
          <div>
            <div class="brandTitle">${role === "admin" ? "Partner Admin" : "Customer Hub"}</div>
            <div class="brandSub">${escapeHtml(orgName || "US Signal")} • Webex Partner Portal</div>
          </div>
        </div>

        <div class="topActions">
          <div class="pill" id="shellSessionPill">Session: —</div>
          <button class="btn" id="shellThemeBtn">Dark Mode</button>
          <button class="btn btnPrimary" id="shellLogoutBtn">Logout</button>
        </div>
      </div>

      <div class="shellBody">
        <div class="sidebar" id="shellNav"></div>
        <div class="content"><div class="contentInner" id="shellContentSlot"></div></div>
      </div>
    `;

    // Move existing content into slot
    const slot = shell.querySelector("#shellContentSlot");
    const existing = document.createElement("div");
    while (body.firstChild) existing.appendChild(body.firstChild);
    slot.appendChild(existing);

    // Replace body
    body.appendChild(shell);

    // Render nav
    const nav = shell.querySelector("#shellNav");
    const items = navItems(role);
    nav.innerHTML = items.map(i => `
      <a class="navItem ${isActive(activePath, i.href) ? "active" : ""}" href="${i.href}">
        <span>${i.icon}</span><span>${escapeHtml(i.label)}</span>
      </a>
    `).join("");

    // Theme
    shell.querySelector("#shellThemeBtn").addEventListener("click", toggleTheme);
    loadTheme();

    // Logout (uses your existing endpoint)
    shell.querySelector("#shellLogoutBtn").addEventListener("click", async () => {
      await fetch("/api/pin/logout", { method:"POST" });
      window.location.href = "/pin";
    });
  };

  // Optional: session pill helper
  window.shellStartSessionTimer = function(seconds){
    const pill = document.getElementById("shellSessionPill");
    if (!pill) return;

    let remaining = Number(seconds || 0);
    if (!remaining || remaining <= 0){
      pill.textContent = "Session: —";
      return;
    }

    pill.textContent = `Session: ${remaining}s`;
    setInterval(() => {
      remaining--;
      pill.textContent = `Session: ${Math.max(0, remaining)}s`;
      if (remaining <= 0) window.location.href = "/pin";
    }, 1000);
  };
})();

</script>
