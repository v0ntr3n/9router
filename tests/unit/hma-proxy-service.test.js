import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const mockPools = [];
vi.mock("@/models", () => ({
  getProxyPools: vi.fn(async () => [...mockPools]),
  createProxyPool: vi.fn(async (data) => {
    const record = { id: `pool-${mockPools.length + 1}`, ...data };
    mockPools.push(record);
    return record;
  }),
  updateProxyPool: vi.fn(async (id, data) => {
    const idx = mockPools.findIndex((p) => p.id === id);
    if (idx === -1) return null;
    mockPools[idx] = { ...mockPools[idx], ...data };
    return mockPools[idx];
  }),
}));

import {
  validateActivationCode,
  validateBindAddress,
  validateLocationArg,
  validatePort,
  validateTunnelId,
  sanitizeAuthState,
  getTunnelDir,
  syncTunnelProxyPool,
  deactivateTunnelProxyPool,
} from "@/lib/hmaProxy/service.js";

describe("hma-proxy service validation & security", () => {
  let tmpDir;
  const origDir = process.env.HMA_PROXY_DIR;

  beforeEach(() => {
    mockPools.length = 0;
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hma-proxy-test-"));
    process.env.HMA_PROXY_DIR = tmpDir;
  });

  afterEach(() => {
    if (origDir === undefined) delete process.env.HMA_PROXY_DIR;
    else process.env.HMA_PROXY_DIR = origDir;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("validates activation codes and rejects shell/flag characters", () => {
    expect(validateActivationCode(" ABC123-DEF456-GHI789 ")).toBe("ABC123-DEF456-GHI789");
    expect(() => validateActivationCode("")).toThrow();
    expect(() => validateActivationCode("abc; rm -rf /")).toThrow();
    expect(() => validateActivationCode("abc$(whoami)")).toThrow();
  });

  it("rejects flag injection in country/city arguments", () => {
    expect(validateLocationArg("US", "country", { required: true })).toBe("US");
    expect(validateLocationArg("US-1-NEW-YORK", "country", { required: true })).toBe("US-1-NEW-YORK");
    expect(validateLocationArg("New York", "city")).toBe("New York");
    expect(() => validateLocationArg("--foreground", "country", { required: true })).toThrow();
    expect(() => validateLocationArg("-v", "city")).toThrow();
    expect(() => validateLocationArg("US;id", "country", { required: true })).toThrow();
  });

  it("enforces valid non-privileged port bounds and bind allowlist", () => {
    expect(validatePort(1080, "socks5Port")).toBe(1080);
    expect(validatePort("8080", "httpPort")).toBe(8080);
    expect(() => validatePort(80, "httpPort")).toThrow();
    expect(() => validatePort(70000, "httpPort")).toThrow();
    expect(() => validatePort("abc", "httpPort")).toThrow();

    expect(validateBindAddress("")).toBe("127.0.0.1");
    expect(validateBindAddress("127.0.0.1")).toBe("127.0.0.1");
    expect(validateBindAddress("0.0.0.0")).toBe("0.0.0.0");
    expect(() => validateBindAddress("192.168.1.10")).toThrow();
  });

  it("prevents path traversal in tunnelId and isolates tunnel dirs", () => {
    expect(validateTunnelId("")).toBe("default");
    expect(validateTunnelId("US-East_1")).toBe("us-east_1");
    expect(() => validateTunnelId("../etc")).toThrow();
    expect(() => validateTunnelId("foo/bar")).toThrow();

    expect(getTunnelDir("default")).toBe(path.resolve(tmpDir));
    expect(getTunnelDir("us-ny")).toBe(path.join(path.resolve(tmpDir), "tunnels", "us-ny"));
  });

  it("sanitizes auth state so wallet_key and tokens are never leaked", () => {
    const sanitized = sanitizeAuthState({
      wallet_key: "SECRET-WALLET-KEY",
      access_token: "eyJhbGciOiJIUzI1NiJ9.secret",
      refresh_token: "refresh-secret",
      device_udid: "1234567890abcdef",
      updated_at: "2026-11-26T00:00:00Z",
    });

    expect(sanitized.activated).toBe(true);
    expect(sanitized.deviceUdid).toBe("1234...cdef");
    expect(JSON.stringify(sanitized)).not.toContain("SECRET-WALLET-KEY");
    expect(JSON.stringify(sanitized)).not.toContain("eyJ");
    expect(JSON.stringify(sanitized)).not.toContain("refresh-secret");
  });

  it("creates, updates, and deactivates linked Proxy Pools cleanly", async () => {
    const tunnel = {
      tunnelId: "us-1",
      country: "United States",
      city: "New York",
      locationKey: "US-1-NEW-YORK",
      httpUrl: "http://0.0.0.0:8081",
      socks5Url: "socks5://0.0.0.0:1081",
    };

    const created = await syncTunnelProxyPool(tunnel, { protocol: "http" });
    expect(created.type).toBe("hma");
    expect(created.proxyUrl).toBe("http://127.0.0.1:8081");
    expect(created.name).toBe("HMA VPN - United States (New York)");
    expect(created.isActive).toBe(true);

    // Updating the same tunnelId reuses the existing pool record instead of duplicating
    const updated = await syncTunnelProxyPool(
      { ...tunnel, country: "Germany", city: "", locationKey: "DE-1-FRANKFURT", httpUrl: "http://127.0.0.1:8082" },
      { protocol: "http" }
    );
    expect(updated.id).toBe(created.id);
    expect(updated.proxyUrl).toBe("http://127.0.0.1:8082");
    expect(mockPools.length).toBe(1);

    const deactivated = await deactivateTunnelProxyPool("us-1");
    expect(deactivated.isActive).toBe(false);
  });
});
