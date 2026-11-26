const csrfToken = document.querySelector('meta[name="x-9router-csrf"]')?.content || "";
let currentConfig = null;

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
  });
});

async function refresh() {
  try {
    const [status, cfg] = await Promise.all([api("/api/v1/status"), api("/api/v1/config")]);
    currentConfig = cfg;
    document.getElementById("overview-tunnel").textContent = JSON.stringify(status.tunnel, null, 2);
    document.getElementById("overview-budget").textContent = JSON.stringify({ budget: status.budget, rtk_stats: status.rtk_stats }, null, 2);
    document.getElementById("tunnel-pill").textContent = `Tunnel: ${status.tunnel?.state || "disconnected"}${status.tunnel?.exit_ip ? ` (${status.tunnel.exit_ip})` : ""}`;
    document.getElementById("keys-status").textContent = `OpenAI: ${status.secrets?.openai?.configured ? `configured (...${status.secrets.openai.last4})` : "not set"} | Anthropic: ${status.secrets?.anthropic?.configured ? `configured (...${status.secrets.anthropic.last4})` : "not set"}`;
    document.getElementById("opt-free-to-paid").checked = !!cfg.fallback?.allow_free_to_paid;
    document.getElementById("cap-session").value = cfg.budget?.session_usd_cap ?? 1.0;
    document.getElementById("cap-daily").value = cfg.budget?.daily_usd_cap ?? 5.0;
    document.getElementById("rtk-enabled").checked = cfg.rtk?.enabled !== false;
    document.getElementById("rtk-caveman").value = cfg.rtk?.caveman_level || "off";
    document.getElementById("rtk-ponytail").value = cfg.rtk?.ponytail_level || "off";
    document.getElementById("rtk-custom").value = cfg.rtk?.custom_prompt || "";
    document.getElementById("opencode-snippet").textContent = JSON.stringify({
      provider: {
        "9router-rs": {
          options: { baseURL: `${location.origin}/v1`, apiKey: "local-9router-rs" }
        }
      }
    }, null, 2);
  } catch (e) {
    console.error(e);
  }
}

document.getElementById("btn-hma-activate").onclick = async () => {
  const code = document.getElementById("hma-code").value.trim();
  const msg = document.getElementById("hma-msg");
  try {
    const r = await api("/api/v1/hma/activate", "POST", { activation_code: code });
    msg.textContent = `Activated (UDID: ${r.device_udid_masked})`;
    document.getElementById("hma-code").value = "";
    refresh();
  } catch (e) { msg.textContent = e.message; }
};

document.getElementById("btn-hma-start").onclick = async () => {
  const country = document.getElementById("hma-country").value.trim();
  const city = document.getElementById("hma-city").value.trim() || null;
  const msg = document.getElementById("hma-msg");
  msg.textContent = "Connecting...";
  try {
    const r = await api("/api/v1/hma/start", "POST", { country, city });
    msg.textContent = `Connected! Exit IP: ${r.exit_ip}`;
    refresh();
  } catch (e) { msg.textContent = e.message; }
};

document.getElementById("btn-hma-check").onclick = async () => {
  const msg = document.getElementById("hma-msg");
  try {
    const r = await api("/api/v1/hma/check-ip", "POST", {});
    msg.textContent = `Verified Exit IP: ${r.exit_ip}`;
  } catch (e) { msg.textContent = e.message; }
};

document.getElementById("btn-hma-stop").onclick = async () => {
  await api("/api/v1/hma/stop", "POST", {});
  document.getElementById("hma-msg").textContent = "Stopped";
  refresh();
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
  refresh();
};

document.getElementById("btn-save-fallback").onclick = async () => {
  if (!currentConfig) return;
  currentConfig.fallback.allow_free_to_paid = document.getElementById("opt-free-to-paid").checked;
  currentConfig.budget.session_usd_cap = Number(document.getElementById("cap-session").value) || 0;
  currentConfig.budget.daily_usd_cap = Number(document.getElementById("cap-daily").value) || 0;
  await api("/api/v1/config", "PUT", currentConfig);
  refresh();
};

document.getElementById("btn-save-rtk").onclick = async () => {
  await api("/api/v1/rtk", "PUT", {
    enabled: document.getElementById("rtk-enabled").checked,
    caveman_level: document.getElementById("rtk-caveman").value,
    ponytail_level: document.getElementById("rtk-ponytail").value,
    custom_prompt: document.getElementById("rtk-custom").value,
  });
  refresh();
};

document.getElementById("btn-import").onclick = async () => {
  const r = await api("/api/v1/import", "POST", { overwrite: false });
  document.getElementById("setup-output").textContent = JSON.stringify(r, null, 2);
  refresh();
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
