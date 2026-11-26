import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { getDataDir } from "@/lib/dataDir";
import { createProxyPool, getProxyPools, updateProxyPool } from "@/models";

const execFileAsync = promisify(execFile);

const BIN_NAME = process.platform === "win32" ? "hma-proxy.exe" : "hma-proxy";
const ALLOWED_BIND_ADDRESSES = new Set(["127.0.0.1", "0.0.0.0", "::1"]);
const COUNTRIES_CACHE_TTL_MS = 10 * 60 * 1000;

let countriesCache = { data: null, expiresAt: 0 };

export function getHmaBaseDir() {
  if (process.env.HMA_PROXY_DIR) {
    return path.resolve(process.env.HMA_PROXY_DIR);
  }
  return path.join(getDataDir(), "hma-proxy");
}

export function validateTunnelId(tunnelId) {
  if (tunnelId === undefined || tunnelId === null || tunnelId === "") {
    return "default";
  }
  if (typeof tunnelId !== "string") {
    throw new Error("Invalid tunnelId");
  }
  const clean = tunnelId.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(clean)) {
    throw new Error("tunnelId must be 1-32 lowercase alphanumeric, hyphen, or underscore characters");
  }
  return clean;
}

export function getTunnelDir(tunnelId = "default") {
  const id = validateTunnelId(tunnelId);
  const base = getHmaBaseDir();
  if (id === "default") return base;
  const resolved = path.resolve(base, "tunnels", id);
  const tunnelsRoot = path.resolve(base, "tunnels") + path.sep;
  if (!resolved.startsWith(tunnelsRoot)) {
    throw new Error("Invalid tunnel directory");
  }
  return resolved;
}

export function validateActivationCode(code) {
  if (typeof code !== "string") {
    throw new Error("Activation code is required");
  }
  const clean = code.trim();
  if (!clean || clean.length > 64 || !/^[A-Za-z0-9-]+$/.test(clean)) {
    throw new Error("Activation code must contain only letters, numbers, and hyphens");
  }
  return clean;
}

export function validateLocationArg(value, label = "location", { required = false } = {}) {
  if (value === undefined || value === null || value === "") {
    if (required) throw new Error(`${label} is required`);
    return "";
  }
  if (typeof value !== "string") {
    throw new Error(`Invalid ${label}`);
  }
  const clean = value.trim();
  if (!clean) {
    if (required) throw new Error(`${label} is required`);
    return "";
  }
  if (clean.startsWith("-") || clean.length > 64 || !/^[A-Za-z0-9 ._()-]+$/.test(clean)) {
    throw new Error(`Invalid ${label} format`);
  }
  return clean;
}

export function validatePort(value, label, { required = false, defaultPort = 0 } = {}) {
  if (value === undefined || value === null || value === "") {
    if (required) throw new Error(`${label} is required`);
    return defaultPort;
  }
  const num = Number(value);
  if (!Number.isInteger(num) || num < 1024 || num > 65535) {
    throw new Error(`${label} must be an integer between 1024 and 65535`);
  }
  return num;
}

export function validateBindAddress(bind) {
  if (!bind) return "127.0.0.1";
  const clean = String(bind).trim();
  if (!ALLOWED_BIND_ADDRESSES.has(clean)) {
    throw new Error("Bind address must be 127.0.0.1, ::1, or 0.0.0.0");
  }
  return clean;
}

function isExecutableFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return false;
    if (process.platform !== "win32") {
      fs.accessSync(filePath, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

export function resolveHmaProxyBin() {
  const candidates = [];
  if (process.env.HMA_PROXY_BIN) {
    candidates.push(process.env.HMA_PROXY_BIN);
  }
  candidates.push(path.join(getDataDir(), "bin", BIN_NAME));
  candidates.push(path.join(process.cwd(), "hma-proxy", "dist", BIN_NAME));
  candidates.push(path.join("/usr/local/bin", BIN_NAME));

  for (const candidate of candidates) {
    if (candidate && isExecutableFile(candidate)) {
      return candidate;
    }
  }

  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    const full = path.join(dir, BIN_NAME);
    if (isExecutableFile(full)) {
      return full;
    }
  }

  return null;
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function maskIdentifier(value) {
  if (!value || typeof value !== "string") return null;
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

export function sanitizeAuthState(auth) {
  if (!auth || typeof auth !== "object" || !auth.access_token) {
    return { activated: false, deviceUdid: null, updatedAt: null };
  }
  return {
    activated: true,
    deviceUdid: maskIdentifier(auth.device_udid),
    updatedAt: auth.updated_at || null,
  };
}

function ensureTunnelAuthSynced(tunnelId) {
  const baseDir = getHmaBaseDir();
  const baseAuthPath = path.join(baseDir, "state.json");
  if (!fs.existsSync(baseAuthPath)) {
    throw new Error("HMA license is not activated yet. Activate with your HMA wallet key first.");
  }
  const tunnelDir = getTunnelDir(tunnelId);
  if (tunnelDir === baseDir) return tunnelDir;

  fs.mkdirSync(tunnelDir, { recursive: true, mode: 0o700 });
  const targetAuthPath = path.join(tunnelDir, "state.json");
  fs.copyFileSync(baseAuthPath, targetAuthPath);
  try {
    fs.chmodSync(targetAuthPath, 0o600);
  } catch {
    // Ignore chmod failures on Windows
  }
  return tunnelDir;
}

async function runHmaCli(args, { dir = getHmaBaseDir(), env = {}, timeoutMs = 45000 } = {}) {
  const bin = resolveHmaProxyBin();
  if (!bin) {
    throw new Error(
      "hma-proxy binary not found. Build it with `cd hma-proxy && go build -o dist/hma-proxy ./cmd/hma-proxy` or set HMA_PROXY_BIN."
    );
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        ...env,
        HMA_PROXY_DIR: dir,
      },
    });
    return { stdout: stdout || "", stderr: stderr || "" };
  } catch (err) {
    const output = `${err?.stderr || ""}\n${err?.stdout || ""}`.trim();
    const cleaned = output
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(-3)
      .join(" | ");
    throw new Error(cleaned || err?.message || "hma-proxy command failed");
  }
}

function parseExitIpFromStatusOutput(stdout = "") {
  const match = stdout.match(/Exit IP\s*:\s*([0-9a-fA-F:.]+)/);
  return match ? match[1] : null;
}

function formatTunnelRecord(tunnelId, rt, linkedPool = null) {
  const socks5Url = rt.socks5_addr ? `socks5://${rt.socks5_addr}` : null;
  const httpUrl = rt.http_addr ? `http://${rt.http_addr}` : null;
  return {
    tunnelId,
    pid: rt.pid,
    country: rt.country,
    city: rt.city || "",
    locationKey: rt.location_key,
    serverIp: rt.server_ip,
    wgPort: rt.wg_port,
    tunnelIp: rt.tunnel_ip,
    dns: rt.dns,
    socks5Addr: rt.socks5_addr || "",
    httpAddr: rt.http_addr || "",
    socks5Url,
    httpUrl,
    startedAt: rt.started_at,
    proxyPoolId: linkedPool?.id || null,
    proxyPoolName: linkedPool?.name || null,
    proxyPoolUrl: linkedPool?.proxyUrl || null,
    exitIp: null,
  };
}

export async function listActiveTunnels({ checkIp = false } = {}) {
  const baseDir = getHmaBaseDir();
  const candidates = [{ tunnelId: "default", dir: baseDir }];

  const tunnelsRoot = path.join(baseDir, "tunnels");
  if (fs.existsSync(tunnelsRoot)) {
    try {
      for (const entry of fs.readdirSync(tunnelsRoot, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        try {
          const validId = validateTunnelId(entry.name);
          candidates.push({ tunnelId: validId, dir: path.join(tunnelsRoot, validId) });
        } catch {
          // Ignore non-conforming directories
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  let poolsByTunnel = new Map();
  try {
    const pools = await getProxyPools();
    for (const pool of pools) {
      if (pool?.hmaTunnelId) {
        poolsByTunnel.set(pool.hmaTunnelId, pool);
      }
    }
  } catch {
    // DB may not be ready in isolated unit tests
  }

  const active = [];
  for (const { tunnelId, dir } of candidates) {
    const runtimePath = path.join(dir, "runtime.json");
    const rt = readJsonSafe(runtimePath);
    if (!rt) continue;
    if (!isPidAlive(rt.pid)) {
      try {
        fs.unlinkSync(runtimePath);
      } catch {
        // Ignore cleanup errors
      }
      continue;
    }
    const record = formatTunnelRecord(tunnelId, rt, poolsByTunnel.get(tunnelId) || null);
    if (checkIp) {
      try {
        const { stdout } = await runHmaCli(["status", "--check-ip"], { dir, timeoutMs: 15000 });
        record.exitIp = parseExitIpFromStatusOutput(stdout);
      } catch {
        record.exitIp = null;
      }
    }
    active.push(record);
  }

  return active;
}

export async function getHmaStatus({ checkIp = false } = {}) {
  const bin = resolveHmaProxyBin();
  const baseDir = getHmaBaseDir();
  const auth = sanitizeAuthState(readJsonSafe(path.join(baseDir, "state.json")));
  const tunnels = await listActiveTunnels({ checkIp });

  let version = null;
  if (bin) {
    try {
      const { stdout } = await runHmaCli(["version"], { timeoutMs: 5000 });
      version = stdout.trim() || null;
    } catch {
      version = null;
    }
  }

  return {
    available: Boolean(bin),
    binaryPath: bin ? path.basename(bin) : null,
    version,
    ...auth,
    tunnels,
  };
}

export async function activateHma(activationCode) {
  const validCode = validateActivationCode(activationCode);
  const baseDir = getHmaBaseDir();
  // Pass wallet key via env var so it never appears in process argument listings (ps aux).
  await runHmaCli(["activate"], {
    dir: baseDir,
    env: { HMA_ACTIVATION_CODE: validCode },
    timeoutMs: 35000,
  });
  countriesCache = { data: null, expiresAt: 0 };
  return getHmaStatus();
}

export async function listHmaCountries({ forceRefresh = false } = {}) {
  const now = Date.now();
  if (!forceRefresh && countriesCache.data && now < countriesCache.expiresAt) {
    return countriesCache.data;
  }

  const { stdout } = await runHmaCli(["countries", "--json"], { timeoutMs: 25000 });
  const raw = JSON.parse(stdout || "[]");
  const normalized = (Array.isArray(raw) ? raw : [])
    .filter((g) => String(g?.state || "").toLowerCase() === "active")
    .map((g) => ({
      countryCode: g.country_code || "",
      country: g.country || "",
      locationKey: g.location_key || "",
      cities: (Array.isArray(g.cities) ? g.cities : [])
        .filter((c) => String(c?.state || "").toLowerCase() === "active")
        .map((c) => ({
          city: c.location_city || "",
          locationKey: c.location_key || "",
        })),
    }))
    .sort((a, b) => a.country.localeCompare(b.country));

  countriesCache = { data: normalized, expiresAt: now + COUNTRIES_CACHE_TTL_MS };
  return normalized;
}

export async function syncTunnelProxyPool(tunnel, { protocol = "http", poolName = "" } = {}) {
  const useSocks5 = protocol === "socks5" || !tunnel.httpUrl;
  const rawUrl = useSocks5 ? tunnel.socks5Url : tunnel.httpUrl;
  if (!rawUrl) {
    throw new Error("Tunnel has no reachable proxy address");
  }
  // If bound to 0.0.0.0, connect locally via 127.0.0.1 for 9Router outbound traffic.
  const proxyUrl = rawUrl.replace("://0.0.0.0:", "://127.0.0.1:");

  const locationLabel = tunnel.city ? `${tunnel.country} (${tunnel.city})` : tunnel.country || tunnel.locationKey;
  const name = poolName.trim() || `HMA VPN - ${locationLabel}`;

  const pools = await getProxyPools();
  const existing = pools.find((p) => p?.hmaTunnelId === tunnel.tunnelId);

  if (existing) {
    return updateProxyPool(existing.id, {
      name,
      proxyUrl,
      type: "hma",
      isActive: true,
      testStatus: "active",
      lastTestedAt: new Date().toISOString(),
      lastError: null,
      hmaTunnelId: tunnel.tunnelId,
      hmaLocationKey: tunnel.locationKey,
    });
  }

  return createProxyPool({
    name,
    proxyUrl,
    noProxy: "localhost,127.0.0.1",
    type: "hma",
    isActive: true,
    strictProxy: false,
    testStatus: "active",
    lastTestedAt: new Date().toISOString(),
    lastError: null,
    hmaTunnelId: tunnel.tunnelId,
    hmaLocationKey: tunnel.locationKey,
  });
}

export async function deactivateTunnelProxyPool(tunnelId) {
  try {
    const pools = await getProxyPools();
    const existing = pools.find((p) => p?.hmaTunnelId === tunnelId);
    if (!existing) return null;
    return updateProxyPool(existing.id, {
      isActive: false,
      testStatus: "unknown",
    });
  } catch {
    return null;
  }
}

export async function startHmaTunnel(options = {}) {
  const country = validateLocationArg(options.country, "country", { required: true });
  const city = validateLocationArg(options.city, "city", { required: false });
  const tunnelId = validateTunnelId(options.tunnelId);
  const socks5Port = validatePort(options.socks5Port, "socks5Port", { defaultPort: 1080 });
  const httpPort =
    options.httpPort === null || options.httpPort === 0 || options.httpPort === "0"
      ? 0
      : validatePort(options.httpPort, "httpPort", { defaultPort: 8080 });
  const bind = validateBindAddress(options.bind);
  const protocol = options.protocol === "socks5" ? "socks5" : "http";
  const autoRegisterPool = options.autoRegisterPool !== false;
  const poolName = typeof options.poolName === "string" ? options.poolName : "";

  if (httpPort > 0 && httpPort === socks5Port) {
    throw new Error("HTTP port and SOCKS5 port cannot be the same");
  }

  const tunnelDir = ensureTunnelAuthSynced(tunnelId);

  const args = ["start", "--country", country, "--socks5", String(socks5Port), "--bind", bind];
  if (city) {
    args.push("--city", city);
  }
  if (httpPort > 0) {
    args.push("--http", String(httpPort));
  }

  await runHmaCli(args, { dir: tunnelDir, timeoutMs: 45000 });

  const rt = readJsonSafe(path.join(tunnelDir, "runtime.json"));
  if (!rt || !isPidAlive(rt.pid)) {
    throw new Error("Tunnel started but runtime state could not be verified");
  }

  const tunnel = formatTunnelRecord(tunnelId, rt);
  let proxyPool = null;
  if (autoRegisterPool) {
    proxyPool = await syncTunnelProxyPool(tunnel, { protocol, poolName });
    tunnel.proxyPoolId = proxyPool?.id || null;
    tunnel.proxyPoolName = proxyPool?.name || null;
    tunnel.proxyPoolUrl = proxyPool?.proxyUrl || null;
  }

  return { tunnel, proxyPool };
}

export async function stopHmaTunnel(tunnelId = "default") {
  const validId = validateTunnelId(tunnelId);
  const tunnelDir = getTunnelDir(validId);

  if (fs.existsSync(path.join(tunnelDir, "runtime.json"))) {
    await runHmaCli(["stop"], { dir: tunnelDir, timeoutMs: 15000 });
  }

  const updatedPool = await deactivateTunnelProxyPool(validId);
  return { stopped: true, tunnelId: validId, proxyPool: updatedPool };
}
