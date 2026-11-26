const csrfToken = document.querySelector('meta[name="x-9router-csrf"]')?.content || "";
let currentConfig = null;
let hmaInputsInitialized = false;

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

async function api(path, method = "GET", body = null) {
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET") headers["X-9Router-CSRF"] = csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

document.querySelectorAll("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`)?.classList.add("active");
    if (btn.dataset.tab === "hma") refreshHmaState();
  });
});

function renderHmaState(hma) {
  const t = hma?.tunnel || {};
  const state = t.state || "disconnected";
  const isConn = state === "connected";

  const pill = document.getElementById("tunnel-pill");
  if (pill) {
    pill.textContent = `Tunnel: ${state}${t.exit_ip ? ` (${t.exit_ip})` : ""}`;
    pill.classList.toggle("connected", isConn);
  }

  const badge = document.getElementById("hma-state-badge");
  if (badge) {
    badge.textContent = state;
    badge.className = `badge ${isConn ? "connected" : "disconnected"}`;
  }

  const licParts = [];
  if (hma?.activated) {
    licParts.push("Activated");
    if (hma.wallet_key?.last4) licParts.push(`key ...${hma.wallet_key.last4}`);
    if (hma.device_udid_masked) licParts.push(`UDID ${hma.device_udid_masked}`);
  } else {
    licParts.push("Not activated");
  }
  const licText = licParts.join(" · ");
  const licEl = document.getElementById("hma-st-license");
  if (licEl) licEl.textContent = licText;
  const licMsg = document.getElementById("hma-license-msg");
  if (licMsg) licMsg.textContent = `Current license: ${licText}`;

  const locParts = [t.country, t.city].filter(Boolean);
  const locStr = locParts.length
    ? `${locParts.join(" / ")}${t.location_key ? ` (${t.location_key})` : ""}`
    : hma?.configured_country
      ? `Configured: ${hma.configured_country}${hma.configured_city ? ` / ${hma.configured_city}` : ""}`
      : "-";

  document.getElementById("hma-st-exit-ip").textContent = t.exit_ip || "-";
  document.getElementById("hma-st-server-ip").textContent = t.server_ip || "-";
  document.getElementById("hma-st-location").textContent = locStr;
  document.getElementById("hma-st-handshake").textContent =
    t.last_handshake_age_secs != null ? `${t.last_handshake_age_secs}s ago` : "-";
  document.getElementById("hma-st-traffic").textContent =
    `${formatBytes(t.tx_bytes)} / ${formatBytes(t.rx_bytes)}`;
  document.getElementById("hma-st-dns").textContent =
    `sockets: ${t.active_sockets ?? 0} | dns: ${t.dns_latency_ms != null ? `${t.dns_latency_ms}ms` : "-"} (err ${t.dns_errors ?? 0}, drop ${t.dropped_packets ?? 0})`;
  document.getElementById("hma-st-rotation").textContent =
    `${hma?.can_rotate_now ? "Ready to switch" : "Cooldown active"} | Proxy: ${hma?.proxy_active ? "active" : "off"}`;
  document.getElementById("hma-state-json").textContent = JSON.stringify(hma, null, 2);

  if (!hmaInputsInitialized) {
    if (hma?.configured_country) {
      document.getElementById("hma-country").value = hma.configured_country;
    }
    if (hma?.configured_city) {
      document.getElementById("hma-city").value = hma.configured_city;
    }
    hmaInputsInitialized = true;
  }
}

async function refreshHmaState() {
  try {
    const hma = await api("/api/v1/hma/status");
    renderHmaState(hma);
  } catch (e) {
    console.error(e);
  }
}

async function refresh() {
  try {
    const [status, cfg, hma] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/config"),
      api("/api/v1/hma/status"),
    ]);
    currentConfig = cfg;
    renderHmaState(hma);
    document.getElementById("overview-tunnel").textContent = JSON.stringify(status.tunnel, null, 2);
    document.getElementById("overview-budget").textContent = JSON.stringify(
      { budget: status.budget, rtk_stats: status.rtk_stats },
      null,
      2,
    );
    document.getElementById("keys-status").textContent =
      `OpenAI: ${status.secrets?.openai?.configured ? `configured (...${status.secrets.openai.last4})` : "not set"} | Anthropic: ${status.secrets?.anthropic?.configured ? `configured (...${status.secrets.anthropic.last4})` : "not set"}`;
    document.getElementById("opt-free-to-paid").checked = !!cfg.fallback?.allow_free_to_paid;
    document.getElementById("cap-session").value = cfg.budget?.session_usd_cap ?? 1.0;
    document.getElementById("cap-daily").value = cfg.budget?.daily_usd_cap ?? 5.0;
    document.getElementById("rtk-enabled").checked = cfg.rtk?.enabled !== false;
    document.getElementById("rtk-caveman").value = cfg.rtk?.caveman_level || "off";
    document.getElementById("rtk-ponytail").value = cfg.rtk?.ponytail_level || "off";
    document.getElementById("rtk-custom").value = cfg.rtk?.custom_prompt || "";
    document.getElementById("opencode-snippet").textContent = JSON.stringify(
      {
        provider: {
          "9router-rs": {
            options: { baseURL: `${location.origin}/v1`, apiKey: "local-9router-rs" },
          },
        },
      },
      null,
      2,
    );
  } catch (e) {
    console.error(e);
  }
}

document.getElementById("btn-hma-refresh").onclick = async () => {
  const msg = document.getElementById("hma-msg");
  msg.textContent = "Refreshing HMA state...";
  await refresh();
  msg.textContent = `Updated at ${new Date().toLocaleTimeString()}`;
};

document.getElementById("btn-hma-countries").onclick = async () => {
  const msg = document.getElementById("hma-msg");
  msg.textContent = "Loading available HMA countries...";
  try {
    const r = await api("/api/v1/hma/countries");
    const list = document.getElementById("hma-country-list");
    list.innerHTML = "";
    const active = (r.countries || []).filter((c) => (c.state || "").toLowerCase() === "active");
    for (const c of active) {
      const opt = document.createElement("option");
      opt.value = c.country_code || c.location_key;
      opt.label = `${c.country} (${c.country_code || c.location_key})`;
      list.appendChild(opt);
    }
    msg.textContent = `Loaded ${active.length} active HMA countries into dropdown`;
  } catch (e) {
    msg.textContent = e.message;
  }
};

document.getElementById("btn-hma-activate").onclick = async () => {
  const code = document.getElementById("hma-code").value.trim();
  const msg = document.getElementById("hma-msg");
  try {
    const r = await api("/api/v1/hma/activate", "POST", { activation_code: code });
    msg.textContent = `Activated (UDID: ${r.device_udid_masked})`;
    document.getElementById("hma-code").value = "";
    await refresh();
  } catch (e) {
    msg.textContent = e.message;
  }
};

document.getElementById("btn-hma-start").onclick = async () => {
  const country = document.getElementById("hma-country").value.trim();
  const city = document.getElementById("hma-city").value.trim() || null;
  const msg = document.getElementById("hma-msg");
  msg.textContent = "Connecting...";
  try {
    const r = await api("/api/v1/hma/start", "POST", { country, city });
    msg.textContent = `Connected! Exit IP: ${r.exit_ip}`;
    await refresh();
  } catch (e) {
    msg.textContent = e.message;
  }
};

document.getElementById("btn-hma-check").onclick = async () => {
  const msg = document.getElementById("hma-msg");
  msg.textContent = "Verifying exit IP...";
  try {
    const r = await api("/api/v1/hma/check-ip", "POST", {});
    msg.textContent = `Verified Exit IP: ${r.exit_ip}`;
    await refreshHmaState();
  } catch (e) {
    msg.textContent = e.message;
  }
};

document.getElementById("btn-hma-stop").onclick = async () => {
  await api("/api/v1/hma/stop", "POST", {});
  document.getElementById("hma-msg").textContent = "Stopped";
  await refresh();
};

document.getElementById("btn-save-keys").onclick = async () => {
  const payload = {};
  const oa = document.getElementById("key-openai").value.trim();
  const an = document.getElementById("key-anthropic").value.trim();
  if (oa) payload.openai_api_key = oa;
  if (an) payload.anthropic_api_key = an;
  await api("/api/v1/secrets", "PUT", payload);
  document.getElementById("key-openai").value = "";
  document.getElementById("key-anthropic").value = "";
  await refresh();
};

document.getElementById("btn-save-fallback").onclick = async () => {
  if (!currentConfig) return;
  currentConfig.fallback.allow_free_to_paid = document.getElementById("opt-free-to-paid").checked;
  currentConfig.budget.session_usd_cap = Number(document.getElementById("cap-session").value) || 0;
  currentConfig.budget.daily_usd_cap = Number(document.getElementById("cap-daily").value) || 0;
  await api("/api/v1/config", "PUT", currentConfig);
  await refresh();
};

document.getElementById("btn-save-rtk").onclick = async () => {
  await api("/api/v1/rtk", "PUT", {
    enabled: document.getElementById("rtk-enabled").checked,
    caveman_level: document.getElementById("rtk-caveman").value,
    ponytail_level: document.getElementById("rtk-ponytail").value,
    custom_prompt: document.getElementById("rtk-custom").value,
  });
  await refresh();
};

document.getElementById("btn-import").onclick = async () => {
  const r = await api("/api/v1/import", "POST", { overwrite: false });
  document.getElementById("setup-output").textContent = JSON.stringify(r, null, 2);
  await refresh();
};

document.getElementById("btn-diag").onclick = async () => {
  const r = await api("/api/v1/diagnostics");
  document.getElementById("setup-output").textContent = JSON.stringify(r, null, 2);
};

const es = new EventSource("/api/v1/events");
const logBox = document.getElementById("live-events");
for (const name of ["tunnel_status", "request_event", "fallback_event", "rtk_stats"]) {
  es.addEventListener(name, (ev) => {
    const line = `[${name}] ${ev.data}\n`;
    logBox.textContent = (line + logBox.textContent).slice(0, 8000);
    refresh();
  });
}

refresh();
setInterval(() => {
  if (!document.hidden) refreshHmaState();
}, 5000);
