const API_PORT = 18000;
const API = `${window.location.protocol}//${window.location.hostname}:${API_PORT}`;
let token = localStorage.getItem("asm_token") || null;
let me = null;               // {email, full_name, role}
let clients = [];            // [{id,name,description,active}]
let selectedClientId = "all";
let currentPage = "dominios";
let sevChart = null;
let pollTimer = null;

const ICONS = {
  dashboard: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>`,
  clients: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 21V8l9-5 9 5v13"/><path d="M9 21v-6h6v6"/></svg>`,
  domain: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>`,
  vuln: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 3 6v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10V6l-9-4Z"/><path d="M12 8v5M12 16h.01"/></svg>`,
  account: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>`,
  activity: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>`,
  plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg>`,
  edit: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>`,
  trash: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>`,
  scan: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3"/></svg>`,
  full: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 12 2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>`,
};

// ============================== Toasts ==============================
function toast(message, isError = false) {
  const stack = document.getElementById("toastStack");
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.innerText = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ============================== API ==============================
function extractErrorMessage(body) {
  const detail = body && body.detail;
  if (!detail) return "Error desconocido";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map(e => `${(e.loc||[]).join(".")}: ${e.msg}`).join(" | ");
  return JSON.stringify(detail);
}

async function api(path, opts = {}) {
  opts.headers = Object.assign({}, opts.headers, {
    "Content-Type": "application/json",
    ...(token ? {"Authorization": "Bearer " + token} : {})
  });
  const res = await fetch(API + path, opts);
  if (res.status === 401) { logout(); throw new Error("Sesión expirada"); }
  if (!res.ok) {
    let body = {}; try { body = await res.json(); } catch (_) {}
    throw new Error(extractErrorMessage(body) || res.statusText);
  }
  return res.status === 204 ? null : res.json();
}

// ============================== Auth ==============================
async function login() {
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;
  try {
    const data = await api("/auth/login", {method:"POST", body: JSON.stringify({email, password})});
    token = data.access_token;
    localStorage.setItem("asm_token", token);
    await boot();
    if (data.must_change_password) toast("Recordá cambiar tu contraseña temporal en 'Mi cuenta'.");
  } catch (e) {
    document.getElementById("loginError").innerText = e.message;
  }
}

function logout() {
  token = null; me = null;
  localStorage.removeItem("asm_token");
  document.getElementById("app").classList.add("hidden");
  document.getElementById("loginScreen").classList.remove("hidden");
}

async function boot() {
  me = await api("/users/me");
  clients = await api("/clients");
  document.getElementById("loginScreen").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  renderSidebar();
  renderUserFooter();
  goTo("dominios");
}

// ============================== Sidebar / nav ==============================
const NAV_ITEMS = [
  {id:"dashboard", label:"Dashboard", icon:"dashboard"},
  {id:"clientes", label:"Clientes", icon:"clients"},
  {id:"dominios", label:"Dominios", icon:"domain"},
  {id:"vulnerabilidades", label:"Vulnerabilidades", icon:"vuln"},
  {id:"actividad", label:"Actividad", icon:"activity", roles:["admin","client_admin"]},
  {id:"cuenta", label:"Mi cuenta", icon:"account"},
];

function renderSidebar() {
  const items = NAV_ITEMS.filter(item => !item.roles || item.roles.includes(me.role));
  document.getElementById("sidenav").innerHTML = items.map(item => `
    <a href="#" class="${item.id===currentPage?'active':''}" onclick="goTo('${item.id}');return false;">
      ${ICONS[item.icon]} ${item.label}
    </a>`).join("");
}

function renderUserFooter() {
  if (!me) return;
  const initials = (me.full_name || me.email).split(" ").map(w=>w[0]).slice(0,2).join("").toUpperCase();
  document.getElementById("userAvatar").innerText = initials;
  document.getElementById("userName").innerText = me.full_name || me.email;
  const roleLabels = {admin:"Administrador", client_admin:"Admin. de clientes", viewer_all:"Visualizador (todos)", viewer_scoped:"Visualizador"};
  document.getElementById("userRole").innerText = roleLabels[me.role] || me.role;
}

function goTo(page) {
  currentPage = page;
  renderSidebar();
  const renderers = {
    dashboard: renderDashboard, clientes: renderClientes, dominios: renderDominios,
    vulnerabilidades: renderVulnerabilidades, actividad: renderActividad, cuenta: renderCuenta,
  };
  (renderers[page] || renderDominios)();
  if (page === "dominios") ensurePolling(); else stopPolling();
}

function ensurePolling() {
  if (pollTimer) return;
  pollTimer = setInterval(livePollTick, 4000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function livePollTick() {
  if (currentPage !== "dominios") { stopPolling(); return; }
  try {
    // Trabajos recientes: reconciliación in-place (ver renderJobsList),
    // para no perder el scroll ni el detalle expandido en cada refresh.
    const jobs = selectedClientId === "all" ? await api("/scan-jobs") : await api(`/scan-jobs?client_id=${selectedClientId}`);
    const jobsList = document.getElementById("jobsList");
    if (jobsList) renderJobsList(jobs, jobsList);

    // Badges de estado + contador de subdominios + pulso visual mientras
    // el dominio está en cola/escaneando: se actualizan in-place por id,
    // para no colapsar los paneles de subdominios que el usuario haya
    // dejado abiertos.
    const domains = selectedClientId === "all" ? await api("/domains") : await api(`/clients/${selectedClientId}/domains`);
    const labels = {never_scanned:"sin escanear", queued:"en cola", scanning:"escaneando", scanned:"escaneado", error:"error"};
    domains.forEach(d => {
      const badge = document.getElementById(`status-${d.id}`);
      if (badge) {
        const cls = {never_scanned:"", queued:"queued", scanning:"scanning", scanned:"scanned", error:"error"}[d.status] || "";
        const spinner = (d.status === "queued" || d.status === "scanning") ? `<span class="spinner"></span>` : "";
        badge.className = "status-badge " + cls;
        badge.innerHTML = spinner + (labels[d.status] || d.status);
      }
      const subcount = document.getElementById(`subcount-${d.id}`);
      if (subcount && d.subdomain_count != null) subcount.innerText = d.subdomain_count;
      const card = document.getElementById(`domaincard-${d.id}`);
      if (card) card.classList.toggle("card-scanning", d.status === "queued" || d.status === "scanning");
    });

    // Paneles de subdominios que el usuario dejó abiertos: se refrescan
    // solos, con animación para los ítems recién descubiertos -- esto es
    // lo que hace que se "vea" el full-scan avanzando en vivo. Los paneles
    // de servicio ("Ver detalles") que estén abiertos se refrescan como
    // parte de este mismo refresh (ver loadSubdomainsPanel), así que no
    // hace falta un segundo query/refresh separado acá.
    const openSubPanels = document.querySelectorAll('[id^="subs-"]:not(.hidden)');
    const subRefreshes = Array.from(openSubPanels).map(el => {
      const domainId = el.id.replace("subs-", "");
      return loadSubdomainsPanel(domainId, true);
    });

    await Promise.all(subRefreshes);
  } catch (e) {
    // silencioso: un tick de polling fallido no debería interrumpir al usuario con un toast
  }
}

function clientSelectorHtml() {
  const opts = [`<option value="all">Todos los clientes</option>`]
    .concat(clients.map(c => `<option value="${c.id}" ${c.id===selectedClientId?'selected':''}>${c.name}</option>`));
  return `<select id="clientSelect" onchange="onClientSelectChange()">${opts.join("")}</select>`;
}
function onClientSelectChange() {
  selectedClientId = document.getElementById("clientSelect").value;
  goTo(currentPage);
}

// ============================== DOMINIOS ==============================
async function renderDominios() {
  const content = document.getElementById("pageContent");
  content.innerHTML = `
    <div class="page-header">
      <div><h1>Dominios</h1><p>Superficie de ataque por cliente. Desde acá se lanza el reconocimiento de subdominios.</p></div>
      <div class="header-controls">${clientSelectorHtml()}
        <button class="btn btn-primary" onclick="openNewDomainModal()">${ICONS.plus} Nuevo dominio</button>
      </div>
    </div>
    <div class="domain-grid" id="domainGrid"><div class="empty-state">Cargando...</div></div>
    <div class="panel">
      <div class="section-label">Trabajos de escaneo recientes</div>
      <div id="jobsList"><div class="empty-state">Cargando...</div></div>
    </div>`;

  try {
    const domains = selectedClientId === "all"
      ? await api("/domains")
      : (await api(`/clients/${selectedClientId}/domains`)).map(d => ({...d, client_name: clients.find(c=>c.id===selectedClientId)?.name}));

    const grid = document.getElementById("domainGrid");
    if (!domains.length) {
      grid.innerHTML = `<div class="empty-state">No hay dominios cargados todavía. Usá "+ Nuevo dominio" para empezar.</div>`;
    } else {
      grid.innerHTML = domains.map(d => domainCardHtml(d)).join("");
    }

    const jobs = selectedClientId === "all"
      ? await api("/scan-jobs")
      : await api(`/scan-jobs?client_id=${selectedClientId}`);
    renderJobsList(jobs, document.getElementById("jobsList"));
  } catch (e) {
    document.getElementById("domainGrid").innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

function domainCardHtml(d) {
  const subCount = d.subdomain_count ?? "?";
  const scanningClass = (d.status === "queued" || d.status === "scanning") ? "card-scanning" : "";
  return `
  <div class="domain-card ${scanningClass}" data-domain-id="${d.id}" id="domaincard-${d.id}">
    <div class="top-row">
      <div>
        <div class="domain-title">${ICONS.domain} ${d.name}</div>
        <div class="domain-sub">${d.client_name || ""} · <span id="subcount-${d.id}">${subCount}</span> subdominios · ${statusBadgeHtml(d.id, d.status)}</div>
      </div>
      <div class="card-icons">
        <button class="icon-btn" title="Editar" onclick="toast('Edición de dominio: próximamente')">${ICONS.edit}</button>
        <button class="icon-btn" title="Eliminar" onclick="deleteDomain('${d.id}','${d.client_id}')">${ICONS.trash}</button>
      </div>
    </div>
    <div class="domain-desc">${d.authorization_reference || "Dominio principal del cliente"}</div>
    <div class="domain-actions">
      <button class="btn btn-secondary" onclick="scanDomain('${d.id}','${d.client_id}')">${ICONS.scan} Scan domain</button>
      <button class="btn btn-primary" onclick="fullScan('${d.id}','${d.client_id}')">${ICONS.full} Full scan</button>
      <button class="link-btn" onclick="toggleSubdomains('${d.id}')">Ver subdominios</button>
    </div>
    <div id="subs-${d.id}" class="subdomain-list hidden"></div>
  </div>`;
}

function statusBadgeHtml(id, status) {
  const labels = {never_scanned:"sin escanear", queued:"en cola", scanning:"escaneando", scanned:"escaneado", error:"error"};
  const cls = {never_scanned:"", queued:"queued", scanning:"scanning", scanned:"scanned", error:"error"}[status] || "";
  const spinner = (status === "queued" || status === "scanning") ? `<span class="spinner"></span>` : "";
  return `<span class="status-badge ${cls}" id="status-${id}">${spinner}${labels[status] || status}</span>`;
}

function severityCountsHtml(j) {
  const items = [
    {k: "critical", label: "C", color: "var(--critical)", n: j.critical},
    {k: "high", label: "A", color: "var(--high)", n: j.high},
    {k: "medium", label: "M", color: "var(--medium)", n: j.medium},
    {k: "low", label: "B", color: "var(--low)", n: j.low},
    {k: "info", label: "I", color: "var(--info)", n: j.info},
  ];
  const total = items.reduce((acc, it) => acc + (it.n || 0), 0);
  // Solo tiene sentido mostrar el desglose para jobs que efectivamente
  // pueden tener vulnerabilidades asociadas (full_scan / scan_vulnerabilities).
  if (j.type !== "full_scan" && j.type !== "scan_vulnerabilities") return "";
  if (total === 0) {
    return `<span style="color:var(--muted);font-size:11.5px">sin vulnerabilidades</span>`;
  }
  return items.map(it => it.n > 0
    ? `<span style="color:${it.color};font-size:11.5px;font-weight:700;margin-right:6px">${it.label}:${it.n}</span>`
    : "").join("");
}

function jobRowContentHtml(j) {
  const typeLabels = {scan_domain:"Scan domain", scan_services:"Scan services", scan_vulnerabilities:"Scan vulns", full_scan:"Full scan"};
  const statusClass = {completed:"scanned", running:"scanning", pending:"queued", failed:"error"}[j.status] || "";
  const statusLabel = {completed:"Completado", running:"Corriendo", pending:"En cola", failed:"Falló", cancelled:"Cancelado"}[j.status] || j.status;
  const spinner = (j.status === "running" || j.status === "pending") ? `<span class="spinner"></span>` : "";
  const when = j.created_at ? new Date(j.created_at).toLocaleString() : "";
  return `
      <span class="job-type-badge">${typeLabels[j.type] || j.type}</span>
      <span class="job-target">${j.target_name || j.target_id}</span>
      ${j.client_name ? `<span style="color:var(--muted);font-size:12px">${j.client_name}</span>` : ""}
      <span class="status-badge ${statusClass}">${spinner}${statusLabel}</span>
      ${severityCountsHtml(j)}
      <span class="job-time">${when}</span>`;
}

// Renderiza/actualiza la lista de trabajos SIN destruir los nodos que ya
// existían: si reemplazáramos todo el innerHTML en cada refresh (como
// hacía antes), el navegador pierde la posición de scroll y parpadea todo
// el panel entero cada 4 segundos, aunque haya cambiado una sola palabra.
function renderJobsList(jobs, container) {
  if (!jobs.length) {
    container.innerHTML = `<div class="empty-state">Todavía no se lanzó ningún escaneo.</div>`;
    return;
  }
  if (container.querySelector(":scope > .empty-state")) container.innerHTML = "";

  const wanted = jobs.slice(0, 10);
  const wantedIds = new Set(wanted.map(j => j.id));

  // Sacar filas de trabajos que ya no están entre los 10 más recientes.
  Array.from(container.children).forEach(child => {
    const id = child.dataset.jobId;
    if (id && !wantedIds.has(id)) child.remove();
  });

  wanted.forEach((j, idx) => {
    let wrapper = document.getElementById(`jobwrap-${j.id}`);
    if (wrapper) {
      // Ya existe: actualizamos solo el contenido de adentro, sin recrear
      // el nodo -- así no se pierde el scroll ni se cierra el detalle
      // expandido de sub-tareas si estaba abierto.
      const row = wrapper.querySelector(".job-row");
      if (row) row.innerHTML = jobRowContentHtml(j);
    } else {
      wrapper = document.createElement("div");
      wrapper.id = `jobwrap-${j.id}`;
      wrapper.dataset.jobId = j.id;
      wrapper.innerHTML = `
        <div class="job-row" onclick="toggleJobTasks('${j.id}')">${jobRowContentHtml(j)}</div>
        <div id="jobtasks-${j.id}" class="job-tasks hidden"></div>`;
    }
    // Mantener el orden (más reciente primero) sin recrear nodos ya ubicados.
    const refNode = container.children[idx];
    if (refNode !== wrapper) container.insertBefore(wrapper, refNode || null);
  });
}

async function toggleJobTasks(jobId) {
  const el = document.getElementById(`jobtasks-${jobId}`);
  el.classList.toggle("hidden");
  if (el.classList.contains("hidden")) return;
  try {
    const tasks = await api(`/scan-jobs/${jobId}/tasks`);
    el.innerHTML = tasks.length ? tasks.map(t => {
      const cls = {completed:"scanned", running:"scanning", pending:"queued", failed:"error"}[t.status] || "";
      const sp = (t.status === "running" || t.status === "pending") ? `<span class="spinner"></span>` : "";
      return `<div class="job-task-row"><span class="status-badge ${cls}">${sp}${t.status}</span>
                <span>${t.worker_type}</span><span style="font-family:ui-monospace,monospace">${t.target}</span></div>`;
    }).join("") : `<div class="job-task-row">Sin sub-tareas registradas todavía.</div>`;
  } catch (e) {
    el.innerHTML = `<div class="job-task-row">Error: ${e.message}</div>`;
  }
}

// Tracking en memoria de qué IDs ya se renderizaron una vez, para poder
// animar SOLO los ítems genuinamente nuevos que aparecen durante el
// polling en vivo (si animáramos todo en cada refresh, parpadearía todo
// el panel entero cada 4 segundos, que se ve mal).
let seenSubdomainIds = {};   // domainId -> Set<subdomainId>
let seenServiceIds = {};     // subdomainId -> Set<serviceId>
let lastVulnTotal = {};      // subdomainId -> total de vulns visto la última vez (para el "bump")
let openServicePanelIds = new Set(); // ids de subdominios cuyo panel "Ver detalles" el usuario dejó abierto

async function loadSubdomainsPanel(domainId, animate = false) {
  const el = document.getElementById(`subs-${domainId}`);
  if (!el) return;
  try {
    const subs = await api(`/domains/${domainId}/subdomains`);
    if (!seenSubdomainIds[domainId]) seenSubdomainIds[domainId] = new Set();
    const seen = seenSubdomainIds[domainId];
    el.dataset.loaded = "1";

    if (!subs.length) {
      el.innerHTML = `<div class="empty-state">Sin subdominios descubiertos aún. Probá "Scan domain".</div>`;
      return;
    }
    if (el.querySelector(":scope > .empty-state")) el.innerHTML = "";

    // Reconciliación in-place: si reemplazáramos todo el innerHTML acá
    // (como se hacía antes), el navegador destruye y recrea cada fila en
    // cada refresh de polling -- eso es lo que causaba el parpadeo y que
    // se perdiera la posición de scroll cada 4 segundos. Ahora se
    // actualiza el contenido de las filas que ya existen sin tocar su
    // nodo raíz, y solo se crean nodos nuevos para subdominios
    // genuinamente nuevos.
    subs.forEach((s, idx) => {
      const rowId = `subitem-${s.id}`;
      let row = document.getElementById(rowId);
      if (row) {
        const head = row.querySelector(".subdomain-head");
        if (head) head.innerHTML = subdomainHeadInnerHtml(domainId, s);
      } else {
        const tmp = document.createElement("div");
        tmp.innerHTML = subdomainItemHtml(domainId, s).trim();
        row = tmp.firstElementChild;
        if (animate && !seen.has(s.id)) row.classList.add("flash-in");
      }
      const refNode = el.children[idx];
      if (refNode !== row) el.insertBefore(row, refNode || null);
      seen.add(s.id);

      if (openServicePanelIds.has(s.id)) {
        const svcEl = document.getElementById(`svc-${s.id}`);
        if (svcEl) svcEl.classList.remove("hidden");
        loadServiceDetailPanel(domainId, s.id, animate);
      }
    });
  } catch (e) {
    el.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

async function toggleSubdomains(domainId) {
  const el = document.getElementById(`subs-${domainId}`);
  const card = document.getElementById(`domaincard-${domainId}`);
  const opening = el.classList.contains("hidden"); // true si estaba oculto y lo vamos a abrir ahora
  el.classList.toggle("hidden");
  // Mientras el panel está abierto, la card ocupa todo el ancho del grid
  // (en vez de quedar angosta y crecer para abajo indefinidamente).
  if (card) card.classList.toggle("domain-card-expanded", opening);
  if (!opening || el.dataset.loaded) return;
  await loadSubdomainsPanel(domainId, false);
}

// Contenido interno de la fila (sin el <div class="subdomain-item"> que la
// envuelve) -- separado para poder actualizar una fila existente in-place
// sin recrear su nodo raíz.
function subdomainHeadInnerHtml(domainId, s) {
  const ips = s.ips || [];
  const ipHtml = ips.length
    ? `<span class="ip-pill" title="${ips.join(', ')}">${ips[0]}${ips.length > 1 ? ` +${ips.length - 1}` : ''}</span>`
    : `<span style="color:var(--muted);font-size:11.5px">sin IP resuelta</span>`;

  const ports = s.ports || [];
  const portsHtml = ports.length
    ? `<span class="ports-inline">${ports.map(p => `<span class="port-pill">${p}</span>`).join("")}</span>`
    : `<span style="color:var(--muted);font-size:11.5px">sin puertos detectados</span>`;

  const sevs = [
    {color: "var(--critical)", n: s.critical}, {color: "var(--high)", n: s.high},
    {color: "var(--medium)", n: s.medium}, {color: "var(--low)", n: s.low}, {color: "var(--info)", n: s.info},
  ];
  const totalVulns = sevs.reduce((a, x) => a + (x.n || 0), 0);
  const prevTotal = lastVulnTotal[s.id];
  const bump = (prevTotal !== undefined && totalVulns > prevTotal);
  lastVulnTotal[s.id] = totalVulns;

  const dotsHtml = totalVulns > 0
    ? `<span class="sevdots-inline ${bump ? 'count-bump' : ''}">${sevs.filter(x => x.n > 0).map(x =>
        `<span class="sev-dot"><span class="dot" style="background:${x.color}"></span>${x.n}</span>`).join("")}</span>`
    : (ports.length ? `<span style="color:var(--accent);font-size:11.5px">sin vulnerabilidades</span>` : "");

  const statusClass = {scanned:"scanned", queued:"queued", scanning:"scanning", error:"error"}[s.status] || "";
  return `
      🔹 <b>${s.name}</b>
      <span class="status-badge ${statusClass}">${s.status}</span>
      ${ipHtml}
      ${portsHtml}
      ${dotsHtml}
      <button class="link-btn" onclick="scanServices('${domainId}','${s.id}')">Scan services</button>
      <button class="btn btn-secondary" style="padding:4px 10px;font-size:12px" onclick="toggleServiceDetail('${domainId}','${s.id}')">Ver detalles</button>`;
}

function subdomainItemHtml(domainId, s) {
  return `
  <div class="subdomain-item" id="subitem-${s.id}" data-sub-id="${s.id}">
    <div class="subdomain-head">${subdomainHeadInnerHtml(domainId, s)}</div>
    <div id="svc-${s.id}" class="${openServicePanelIds.has(s.id) ? '' : 'hidden'}" data-domain-id="${domainId}"></div>
  </div>`;
}

function serviceRowInnerHtml(svc) {
  const sevs = [
    {color: "var(--critical)", n: svc.critical}, {color: "var(--high)", n: svc.high},
    {color: "var(--medium)", n: svc.medium}, {color: "var(--low)", n: svc.low}, {color: "var(--info)", n: svc.info},
  ];
  const dots = sevs.filter(x => x.n > 0).map(x =>
    `<span class="sev-dot"><span class="dot" style="background:${x.color}"></span>${x.n}</span>`).join("");
  return `
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;width:100%">
          🔧 <b style="color:var(--text)">${svc.port}/${svc.protocol}</b> — ${svc.product || svc.service_name || "?"} ${svc.version || ""}
          ${dots || `<span style="color:var(--accent);font-size:11px">sin vulnerabilidades</span>`}
          <button class="link-btn" onclick="scanVulns('${svc.id}')">Scan vulnerabilities</button>
        </div>
        ${svc.banner ? `<div style="color:var(--muted2);font-size:11.5px;font-family:ui-monospace,monospace;margin-left:22px">${svc.banner}</div>` : ""}`;
}

async function loadServiceDetailPanel(domainId, subId, animate = false) {
  const el = document.getElementById(`svc-${subId}`);
  if (!el) return;
  try {
    const services = await api(`/domains/${domainId}/subdomains/${subId}/services`);
    if (!seenServiceIds[subId]) seenServiceIds[subId] = new Set();
    const seen = seenServiceIds[subId];

    if (!services.length) {
      el.innerHTML = `<div class="service-row">Sin servicios detectados aún.</div>`;
      return;
    }
    if (el.querySelector(":scope > .service-row.empty-placeholder")) el.innerHTML = "";

    // Misma idea que en el panel de subdominios: actualizar filas
    // existentes in-place en vez de recrear todo, para no perder scroll
    // ni parpadear en cada refresh de polling.
    services.forEach((svc, idx) => {
      const rowId = `svcrow-${svc.id}`;
      let row = document.getElementById(rowId);
      if (row) {
        row.innerHTML = serviceRowInnerHtml(svc);
      } else {
        row = document.createElement("div");
        row.id = rowId;
        row.className = "service-row";
        row.style.cssText = "flex-direction:column;align-items:flex-start;border-bottom:1px solid var(--border);padding:8px 0";
        row.innerHTML = serviceRowInnerHtml(svc);
        if (animate && !seen.has(svc.id)) row.classList.add("flash-in");
      }
      const refNode = el.children[idx];
      if (refNode !== row) el.insertBefore(row, refNode || null);
      seen.add(svc.id);
    });
  } catch (e) {
    el.innerHTML = `<div class="service-row">Error: ${e.message}</div>`;
  }
}

async function toggleServiceDetail(domainId, subId) {
  const el = document.getElementById(`svc-${subId}`);
  const opening = el.classList.contains("hidden");
  el.classList.toggle("hidden");
  if (opening) {
    openServicePanelIds.add(subId);
    await loadServiceDetailPanel(domainId, subId, false);
  } else {
    openServicePanelIds.delete(subId);
  }
}

function openNewDomainModal() {
  const clientOptions = clients.map(c => `<option value="${c.id}">${c.name}</option>`).join("");
  showModal(`
    <h3>Nuevo dominio</h3>
    <label>Cliente</label>
    <select id="ndClient">${clientOptions}</select>
    <label>Dominio</label>
    <input id="ndName" placeholder="ejemplo.com">
    <label>Referencia de autorización (opcional)</label>
    <input id="ndRef" placeholder="Ticket / contrato que autoriza el escaneo">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="submitNewDomain()">Crear</button>
    </div>`);
}

async function submitNewDomain() {
  const client_id = document.getElementById("ndClient").value;
  const name = document.getElementById("ndName").value.trim();
  const authorization_reference = document.getElementById("ndRef").value.trim() || null;
  if (!client_id || !name) { toast("Completá cliente y dominio.", true); return; }
  try {
    await api("/domains", {method:"POST", body: JSON.stringify({client_id, name, authorization_reference})});
    closeModal();
    goTo("dominios");
  } catch (e) { toast(e.message, true); }
}

async function deleteDomain(domainId, clientId) {
  if (!confirm("¿Eliminar este dominio y todo lo descubierto debajo de él?")) return;
  try {
    await api(`/clients/${clientId}/domains/${domainId}`, {method:"DELETE"});
    goTo("dominios");
  } catch (e) { toast(e.message, true); }
}

async function autoOpenSubdomainsPanel(domainId) {
  const subsEl = document.getElementById(`subs-${domainId}`);
  if (subsEl && subsEl.classList.contains("hidden")) {
    subsEl.classList.remove("hidden");
    await loadSubdomainsPanel(domainId, false);
  }
}

async function scanDomain(domainId, clientId) {
  try {
    await api(`/clients/${clientId}/domains/${domainId}/scan`, {method:"POST"});
    toast("Escaneo de dominio encolado.");
    optimisticMarkQueued("domain", domainId);
    // Igual que Full scan: abrimos el panel de subdominios solo, para ver
    // en vivo cómo van apareciendo a medida que el recon los descubre.
    await autoOpenSubdomainsPanel(domainId);
    ensurePolling();
  } catch (e) { toast(e.message, true); }
}
async function fullScan(domainId, clientId) {
  try {
    await api(`/clients/${clientId}/domains/${domainId}/full-scan`, {method:"POST"});
    toast("Full scan encolado. Puede tardar bastante según la cantidad de subdominios.");
    optimisticMarkQueued("domain", domainId);
    // Abrimos el panel de subdominios automáticamente para que el usuario
    // vea el progreso en vivo (subdominios/servicios/vulnerabilidades
    // apareciendo) sin tener que acordarse de hacer clic en "Ver subdominios".
    await autoOpenSubdomainsPanel(domainId);
    ensurePolling();
  } catch (e) { toast(e.message, true); }
}
async function scanServices(domainId, subId) {
  try {
    await api(`/domains/${domainId}/subdomains/${subId}/scan-services`, {method:"POST"});
    toast("Escaneo de servicios encolado.");
    ensurePolling();
  } catch (e) { toast(e.message, true); }
}
async function scanVulns(serviceId) {
  try {
    await api(`/services/${serviceId}/scan-vulnerabilities`, {method:"POST"});
    toast("Escaneo de vulnerabilidades encolado.");
    ensurePolling();
  } catch (e) { toast(e.message, true); }
}

function optimisticMarkQueued(targetType, id) {
  // Actualiza el badge de estado al toque, sin esperar el próximo poll,
  // para que el click se sienta inmediato.
  const badge = document.getElementById(`status-${id}`);
  if (badge) { badge.className = "status-badge queued"; badge.innerHTML = `<span class="spinner"></span> en cola`; }
  const card = document.getElementById(`domaincard-${id}`);
  if (card) card.classList.add("card-scanning");
}

// ============================== CLIENTES ==============================
async function renderClientes() {
  const content = document.getElementById("pageContent");
  const canCreate = me.role === "admin";
  content.innerHTML = `
    <div class="page-header">
      <div><h1>Clientes</h1><p>Cuentas cuyos activos administrás en la plataforma.</p></div>
      ${canCreate ? `<button class="btn btn-primary" onclick="openNewClientModal()">${ICONS.plus} Nuevo cliente</button>` : ""}
    </div>
    <div class="domain-grid" id="clientGrid"><div class="empty-state">Cargando...</div></div>`;

  clients = await api("/clients");
  // Para mostrar el dominio principal de cada cliente en su card, sin
  // hacer N requests: traemos todos los dominios accesibles de una vez
  // (RLS ya filtra por lo que el usuario puede ver) y los agrupamos por cliente.
  let domainsByClient = {};
  try {
    const allDomains = await api("/domains");
    allDomains.forEach(d => {
      if (!domainsByClient[d.client_id]) domainsByClient[d.client_id] = d;
    });
  } catch (e) { /* si falla, simplemente no mostramos el dominio principal */ }

  document.getElementById("clientGrid").innerHTML = clients.length ? clients.map(c => {
    const mainDomain = domainsByClient[c.id];
    return `
    <div class="domain-card" style="cursor:pointer" onclick="selectClientAndGoToDomains('${c.id}')">
      <div class="domain-title">${ICONS.clients} ${c.name}</div>
      ${mainDomain ? `<div class="domain-sub">${mainDomain.name}</div>` : `<div class="domain-desc">${c.description || "Sin dominio principal cargado"}</div>`}
      <span class="status-badge ${c.active?'scanned':'error'}">${c.active?'activo':'inactivo'}</span>
    </div>`;
  }).join("") : `<div class="empty-state">No hay clientes cargados.</div>`;
}

function selectClientAndGoToDomains(clientId) {
  selectedClientId = clientId;
  goTo("dominios");
}

function openNewClientModal() {
  showModal(`
    <h3>Nuevo cliente</h3>
    <label>Nombre</label>
    <input id="ncName" placeholder="Acme Corp">
    <label>Descripción (opcional)</label>
    <input id="ncDesc" placeholder="Breve descripción del cliente">
    <label>Dominio principal (opcional)</label>
    <input id="ncDomain" placeholder="ejemplo.com">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="submitNewClient()">Crear</button>
    </div>`);
}
async function submitNewClient() {
  const name = document.getElementById("ncName").value.trim();
  const description = document.getElementById("ncDesc").value.trim() || null;
  const domainName = document.getElementById("ncDomain").value.trim();
  if (!name) { toast("El nombre es obligatorio.", true); return; }
  try {
    const client = await api("/clients", {method:"POST", body: JSON.stringify({name, description})});
    if (domainName) {
      try {
        await api("/domains", {method:"POST", body: JSON.stringify({client_id: client.id, name: domainName})});
      } catch (e) {
        toast(`Cliente creado, pero falló la carga del dominio: ${e.message}`, true);
      }
    }
    closeModal();
    clients = await api("/clients");
    // Nos vamos directo a Dominios con el cliente recién creado ya
    // seleccionado, listo para cargar más dominios o lanzar escaneos.
    selectClientAndGoToDomains(client.id);
  } catch (e) { toast(e.message, true); }
}

// Listas largas separadas por coma (típicamente CVEs de nmap "vulners",
// que puede juntar decenas en un solo string) rompían el layout: quedaban
// en un renglón interminable de ancho completo. Se truncan a unos pocos
// ítems con un botón para expandir/colapsar el resto.
let truncatedListCounter = 0;
function truncatedListHtml(rawValue, maxItems = 3) {
  if (!rawValue) return "—";
  const items = rawValue.split(",").map(s => s.trim()).filter(Boolean);
  if (items.length <= maxItems) return `<span class="wrap-cell">${items.join(", ")}</span>`;
  const uid = `trunc-${truncatedListCounter++}`;
  const shortText = items.slice(0, maxItems).join(", ");
  const fullText = items.join(", ");
  return `
    <span class="wrap-cell" id="${uid}-short">${shortText} <button class="link-btn" onclick="toggleTruncated('${uid}')">+${items.length - maxItems} más</button></span>
    <span class="wrap-cell hidden" id="${uid}-full">${fullText} <button class="link-btn" onclick="toggleTruncated('${uid}')">mostrar menos</button></span>`;
}
function toggleTruncated(uid) {
  document.getElementById(`${uid}-short`).classList.toggle("hidden");
  document.getElementById(`${uid}-full`).classList.toggle("hidden");
}

// ============================== VULNERABILIDADES ==============================
async function renderVulnerabilidades() {
  const content = document.getElementById("pageContent");
  const prevSev = document.getElementById("sevFilter")?.value || "";
  const prevStatus = document.getElementById("statusFilter")?.value || "";

  content.innerHTML = `
    <div class="page-header">
      <div><h1>Vulnerabilidades</h1><p>Hallazgos de nuclei, nmap NSE y searchsploit sobre los servicios descubiertos.</p></div>
      ${clientSelectorHtml()}
    </div>
    <div class="panel">
      <div class="filters-row">
        <select id="sevFilter" onchange="renderVulnerabilidades()">
          <option value="">Todas las severidades</option>
          <option value="critical" ${prevSev==='critical'?'selected':''}>Crítica</option>
          <option value="high" ${prevSev==='high'?'selected':''}>Alta</option>
          <option value="medium" ${prevSev==='medium'?'selected':''}>Media</option>
          <option value="low" ${prevSev==='low'?'selected':''}>Baja</option>
          <option value="info" ${prevSev==='info'?'selected':''}>Info</option>
        </select>
        <select id="statusFilter" onchange="renderVulnerabilidades()">
          <option value="">Todos los estados</option>
          <option value="open" ${prevStatus==='open'?'selected':''}>Abierto</option>
          <option value="false_positive" ${prevStatus==='false_positive'?'selected':''}>Falso positivo</option>
          <option value="remediated" ${prevStatus==='remediated'?'selected':''}>Remediado</option>
          <option value="accepted_risk" ${prevStatus==='accepted_risk'?'selected':''}>Riesgo aceptado</option>
        </select>
      </div>
      <table class="vuln-table">
        <thead><tr><th>Severidad</th><th>Título</th><th>Cliente</th><th>Activo</th><th>CVE</th><th>Fuente</th><th>Estado</th></tr></thead>
        <tbody id="vulnBody"><tr><td colspan="7" class="empty-state">Cargando...</td></tr></tbody>
      </table>
    </div>`;

  let url = "/vulnerabilities?";
  if (selectedClientId !== "all") url += `client_id=${selectedClientId}&`;
  if (prevSev) url += `severity=${prevSev}&`;
  if (prevStatus) url += `status=${prevStatus}&`;

  try {
    const vulns = await api(url);
    document.getElementById("vulnBody").innerHTML = vulns.length ? vulns.map(v => `
      <tr>
        <td><span class="sev-badge sev-${v.severity}">${v.severity}</span></td>
        <td class="wrap-cell">${v.title}</td>
        <td>${v.client_name}</td>
        <td class="wrap-cell">${v.domain_name} → ${v.subdomain_name}:${v.port}</td>
        <td class="cve-cell">${truncatedListHtml(v.cve_id)}</td>
        <td>${v.source}</td>
        <td>
          <select onchange="updateVulnStatus('${v.id}', this.value)">
            ${["open","false_positive","remediated","accepted_risk"].map(s=>`<option value="${s}" ${s===v.status?'selected':''}>${s}</option>`).join("")}
          </select>
        </td>
      </tr>`).join("") : `<tr><td colspan="7" class="empty-state">Sin hallazgos con estos filtros.</td></tr>`;
  } catch (e) {
    document.getElementById("vulnBody").innerHTML = `<tr><td colspan="7" class="empty-state">Error: ${e.message}</td></tr>`;
  }
}
async function updateVulnStatus(id, status) {
  try { await api(`/services/vulnerabilities/${id}`, {method:"PATCH", body: JSON.stringify({status})}); }
  catch (e) { toast(e.message, true); }
}

// ============================== ACTIVIDAD (audit log) ==============================
const ACTION_LABELS = {
  login: "Inicio de sesión", login_failed: "Login fallido", change_password: "Cambio de contraseña",
  create: "Creó", update: "Actualizó", delete: "Eliminó", grant_access: "Otorgó acceso",
  update_status: "Cambió estado", trigger_scan_domain: "Lanzó Scan domain",
  trigger_full_scan: "Lanzó Full scan", trigger_scan_services: "Lanzó Scan services",
  trigger_scan_vulnerabilities: "Lanzó Scan vulnerabilities",
};
const ENTITY_LABELS = {
  user: "usuario", client: "cliente", domain: "dominio", subdomain: "subdominio",
  service: "servicio", vulnerability: "vulnerabilidad", user_client_access: "acceso de usuario",
};

async function renderActividad() {
  const content = document.getElementById("pageContent");
  // OJO: hay que capturar el filtro elegido ANTES de reconstruir el HTML.
  // Si se lee document.getElementById(...).value DESPUÉS de reasignar
  // innerHTML, se está leyendo un <select> recién creado (sin la opción
  // marcada como "selected"), que siempre vuelve al valor por defecto --
  // por eso el filtro nunca "pegaba".
  const prevAction = document.getElementById("actionFilter")?.value || "";
  const prevEntity = document.getElementById("entityFilter")?.value || "";

  content.innerHTML = `
    <div class="page-header">
      <div><h1>Actividad</h1><p>Registro de operaciones de escaneo/detección de vulnerabilidades y de la aplicación web.</p></div>
      ${clientSelectorHtml()}
    </div>
    <div class="panel">
      <div class="filters-row">
        <select id="actionFilter" onchange="renderActividad()">
          <option value="">Todas las acciones</option>
          ${Object.keys(ACTION_LABELS).map(a => `<option value="${a}" ${a===prevAction?'selected':''}>${ACTION_LABELS[a]}</option>`).join("")}
        </select>
        <select id="entityFilter" onchange="renderActividad()">
          <option value="">Todas las entidades</option>
          ${Object.keys(ENTITY_LABELS).map(e => `<option value="${e}" ${e===prevEntity?'selected':''}>${ENTITY_LABELS[e]}</option>`).join("")}
        </select>
      </div>
      <table>
        <thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Entidad</th><th>Cliente</th><th>Detalle</th></tr></thead>
        <tbody id="auditBody"><tr><td colspan="6" class="empty-state">Cargando...</td></tr></tbody>
      </table>
    </div>`;

  let url = "/audit-log?limit=150&";
  if (selectedClientId !== "all") url += `client_id=${selectedClientId}&`;
  if (prevAction) url += `action=${prevAction}&`;
  if (prevEntity) url += `entity_type=${prevEntity}&`;

  try {
    const logs = await api(url);
    document.getElementById("auditBody").innerHTML = logs.length ? logs.map(l => `
      <tr>
        <td style="color:var(--muted);font-size:12px">${new Date(l.created_at).toLocaleString()}</td>
        <td>${l.user_full_name || l.user_email || "—"}</td>
        <td>${ACTION_LABELS[l.action] || l.action}</td>
        <td>${ENTITY_LABELS[l.entity_type] || l.entity_type}</td>
        <td>${l.client_name || "—"}</td>
        <td style="color:var(--muted);font-size:12px;font-family:ui-monospace,monospace">${l.metadata ? JSON.stringify(l.metadata) : ""}</td>
      </tr>`).join("") : `<tr><td colspan="6" class="empty-state">Sin actividad registrada con estos filtros.</td></tr>`;
  } catch (e) {
    document.getElementById("auditBody").innerHTML = `<tr><td colspan="6" class="empty-state">Error: ${e.message}</td></tr>`;
  }
}

// ============================== DASHBOARD ==============================
async function renderDashboard() {
  const content = document.getElementById("pageContent");
  content.innerHTML = `
    <div class="page-header">
      <div><h1>Dashboard</h1><p>Resumen de superficie de ataque y hallazgos.</p></div>
      ${clientSelectorHtml()}
    </div>
    <div class="grid-cards" id="summaryCards"><div class="empty-state">Cargando...</div></div>
    <div class="row">
      <div class="col"><div class="panel"><div class="section-label">Severidad de hallazgos abiertos</div>
        <div class="chart-wrap" id="sevChartWrap"><div class="empty-state">Cargando...</div></div></div></div>
    </div>`;

  if (selectedClientId === "all") {
    document.getElementById("summaryCards").innerHTML = `<div class="empty-state">Elegí un cliente puntual para ver el resumen detallado.</div>`;
    return;
  }
  const s = await api(`/clients/${selectedClientId}/dashboard-summary`);
  const cards = [
    {label:"Dominios", num:s.domains}, {label:"Subdominios", num:s.subdomains},
    {label:"Hosts", num:s.hosts}, {label:"Servicios", num:s.services}, {label:"Hallazgos abiertos", num:s.open_vulns},
  ];
  document.getElementById("summaryCards").innerHTML = cards.map(c =>
    `<div class="stat-card"><div class="num">${c.num}</div><div class="label">${c.label}</div></div>`).join("");

  const sevOrder = ["critical","high","medium","low","info"];
  const sevLabels = {critical:"Crítica", high:"Alta", medium:"Media", low:"Baja", info:"Info"};
  const colors = {critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#3b82f6",info:"#6b7280"};
  const data = sevOrder.map(k => s.vulns_by_severity[k] || 0);
  const total = data.reduce((a, b) => a + b, 0);
  const chartWrap = document.getElementById("sevChartWrap");

  if (sevChart) { sevChart.destroy(); sevChart = null; }

  if (total === 0) {
    // Un doughnut con todos los valores en cero no dibuja ningún arco --
    // queda solo la leyenda flotando, que se ve roto. Mejor mostrar un
    // estado vacío explícito.
    chartWrap.innerHTML = `<div class="empty-state" style="display:flex;align-items:center;gap:10px;padding:10px 0">
      <span style="color:var(--accent);font-size:20px">✓</span> Sin hallazgos abiertos para este cliente.
    </div>`;
    return;
  }

  chartWrap.innerHTML = `<canvas id="sevChart"></canvas>`;
  sevChart = new Chart(document.getElementById("sevChart"), {
    type: "doughnut",
    data: {
      labels: sevOrder.map(k => sevLabels[k]),
      datasets: [{
        data,
        backgroundColor: sevOrder.map(k => colors[k]),
        borderColor: "#131922",
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      cutout: "62%",
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#e6e8ee", usePointStyle: true, pointStyle: "circle", boxWidth: 8, padding: 14, font: {size: 12.5} },
        },
        tooltip: {
          callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.parsed}` },
        },
      },
    },
  });
}

// ============================== MI CUENTA ==============================
async function renderCuenta() {
  const content = document.getElementById("pageContent");
  content.innerHTML = `
    <div class="page-header"><div><h1>Mi cuenta</h1><p>Datos de tu usuario y cambio de contraseña.</p></div></div>
    <div class="panel" style="max-width:420px">
      <div class="section-label">Perfil</div>
      <p><b>Nombre:</b> ${me.full_name}</p>
      <p><b>Email:</b> ${me.email}</p>
      <p><b>Rol:</b> ${me.role}</p>
    </div>
    <div class="panel" style="max-width:420px">
      <div class="section-label">Cambiar contraseña</div>
      <label>Contraseña actual</label>
      <input type="password" id="curPass" style="width:100%;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 11px;margin-bottom:10px">
      <label>Contraseña nueva</label>
      <input type="password" id="newPass" style="width:100%;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 11px;margin-bottom:14px">
      <button class="btn btn-primary" onclick="submitChangePassword()">Actualizar contraseña</button>
      <p id="pwMsg" style="margin-top:10px;font-size:13px"></p>
    </div>
    ${me.role === "admin" ? `
    <div class="panel">
      <div class="top-row" style="margin-bottom:14px">
        <div class="section-label" style="margin-bottom:0">Usuarios</div>
        <button class="btn btn-primary" onclick="openNewUserModal()">${ICONS.plus} Nuevo usuario</button>
      </div>
      <table>
        <thead><tr><th>Nombre</th><th>Email</th><th>Rol</th><th>Clientes asignados</th><th>Estado</th><th></th></tr></thead>
        <tbody id="usersBody"><tr><td colspan="6" class="empty-state">Cargando...</td></tr></tbody>
      </table>
    </div>` : ""}`;

  if (me.role === "admin") await loadUsersTable();
}

const ROLE_LABELS = {admin:"Administrador", client_admin:"Tester", viewer_all:"Visualizador (todos)", viewer_scoped:"Visualizador"};

async function loadUsersTable() {
  try {
    const users = await api("/users");
    document.getElementById("usersBody").innerHTML = users.map(u => `
      <tr>
        <td>${u.full_name}</td>
        <td>${u.email}</td>
        <td>${ROLE_LABELS[u.role] || u.role}</td>
        <td style="color:var(--muted);font-size:12.5px">${(u.client_names && u.client_names.length) ? u.client_names.join(", ") : "—"}</td>
        <td><span class="status-badge ${u.active ? 'scanned' : 'error'}">${u.active ? 'activo' : 'inactivo'}</span></td>
        <td><button class="link-btn" onclick="toggleUserActive('${u.id}', ${!u.active})">${u.active ? 'Desactivar' : 'Activar'}</button></td>
      </tr>`).join("") || `<tr><td colspan="6" class="empty-state">No hay usuarios.</td></tr>`;
  } catch (e) {
    document.getElementById("usersBody").innerHTML = `<tr><td colspan="6" class="empty-state">Error: ${e.message}</td></tr>`;
  }
}

async function toggleUserActive(userId, newActive) {
  try {
    await api(`/users/${userId}?active=${newActive}`, {method: "PATCH"});
    toast(newActive ? "Usuario activado." : "Usuario desactivado.");
    await loadUsersTable();
  } catch (e) { toast(e.message, true); }
}

function openNewUserModal() {
  const clientCheckboxes = clients.map(c => `
    <label style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;color:var(--text)">
      <input type="checkbox" class="nu-client-cb" value="${c.id}"> ${c.name}
    </label>`).join("") || `<p style="color:var(--muted);font-size:13px">No hay clientes cargados todavía.</p>`;

  showModal(`
    <h3>Nuevo usuario</h3>
    <label>Nombre completo</label>
    <input id="nuName" placeholder="Juan Pérez">
    <label>Email</label>
    <input id="nuEmail" placeholder="juan@ejemplo.com">
    <label>Contraseña temporal</label>
    <input id="nuPass" type="password" placeholder="Mínimo 10 caracteres">
    <label>Rol</label>
    <select id="nuRole" style="width:100%;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 11px">
      <option value="viewer_scoped">Visualizador (solo ve resultados)</option>
      <option value="client_admin">Tester (ejecuta escaneos y ve resultados)</option>
    </select>
    <label>Clientes asignados</label>
    <div style="max-height:180px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:8px 12px">
      ${clientCheckboxes}
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="submitNewUser()">Crear</button>
    </div>`);
}

async function submitNewUser() {
  const full_name = document.getElementById("nuName").value.trim();
  const email = document.getElementById("nuEmail").value.trim();
  const temporary_password = document.getElementById("nuPass").value;
  const role = document.getElementById("nuRole").value;
  const selectedClientIds = Array.from(document.querySelectorAll(".nu-client-cb:checked")).map(cb => cb.value);

  if (!full_name || !email || !temporary_password) { toast("Completá nombre, email y contraseña.", true); return; }
  if (temporary_password.length < 10) { toast("La contraseña debe tener al menos 10 caracteres.", true); return; }
  if (!selectedClientIds.length) { toast("Asigná al menos un cliente.", true); return; }

  // "Tester" (client_admin) necesita access_level=admin para poder escanear;
  // "Visualizador" (viewer_scoped) solo necesita access_level=viewer.
  const accessLevel = role === "client_admin" ? "admin" : "viewer";
  const client_access = selectedClientIds.map(client_id => ({client_id, access_level: accessLevel}));

  try {
    await api("/users", {method: "POST", body: JSON.stringify({full_name, email, temporary_password, role, client_access})});
    toast("Usuario creado correctamente.");
    closeModal();
    await loadUsersTable();
  } catch (e) { toast(e.message, true); }
}
async function submitChangePassword() {
  const current_password = document.getElementById("curPass").value;
  const new_password = document.getElementById("newPass").value;
  const msg = document.getElementById("pwMsg");
  try {
    await api("/auth/change-password", {method:"POST", body: JSON.stringify({current_password, new_password})});
    msg.style.color = "var(--accent)"; msg.innerText = "Contraseña actualizada correctamente.";
  } catch (e) {
    msg.style.color = "var(--danger)"; msg.innerText = e.message;
  }
}

// ============================== Modal helper ==============================
function showModal(innerHtml) {
  document.getElementById("modalRoot").innerHTML = `<div class="modal-overlay" onclick="if(event.target===this)closeModal()"><div class="modal">${innerHtml}</div></div>`;
}
function closeModal() { document.getElementById("modalRoot").innerHTML = ""; }

// ============================== Init ==============================
if (token) boot().catch(() => logout());
