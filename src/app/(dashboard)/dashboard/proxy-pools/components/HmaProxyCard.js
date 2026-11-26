"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge, Button, Card, Input, Modal, Toggle } from "@/shared/components";
import { useNotificationStore } from "@/store/notificationStore";

const DEFAULT_START_FORM = {
  country: "US",
  city: "",
  tunnelId: "default",
  httpPort: "8080",
  socks5Port: "1080",
  protocol: "http",
  poolName: "",
  autoRegisterPool: true,
};

export default function HmaProxyCard({ onProxyPoolsChanged }) {
  const notify = useNotificationStore();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checkingIp, setCheckingIp] = useState(false);

  const [showActivateModal, setShowActivateModal] = useState(false);
  const [activationCode, setActivationCode] = useState("");
  const [activating, setActivating] = useState(false);

  const [showStartModal, setShowStartModal] = useState(false);
  const [startForm, setStartForm] = useState(DEFAULT_START_FORM);
  const [starting, setStarting] = useState(false);
  const [stoppingId, setStoppingId] = useState(null);

  const [countries, setCountries] = useState([]);
  const [loadingCountries, setLoadingCountries] = useState(false);

  const fetchStatus = useCallback(async ({ checkIp = false } = {}) => {
    if (checkIp) setCheckingIp(true);
    try {
      const res = await fetch(`/api/hma-proxy/status${checkIp ? "?checkIp=true" : ""}`, {
        cache: "no-store",
      });
      const data = await res.json();
      if (res.ok) {
        setStatus(data);
      }
    } catch (error) {
      console.log("Error fetching HMA proxy status:", error);
    } finally {
      setLoading(false);
      setCheckingIp(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const loadCountries = useCallback(async () => {
    if (countries.length > 0 || loadingCountries) return;
    setLoadingCountries(true);
    try {
      const res = await fetch("/api/hma-proxy/countries", { cache: "no-store" });
      const data = await res.json();
      if (res.ok && Array.isArray(data.countries)) {
        setCountries(data.countries);
      }
    } catch (error) {
      console.log("Error fetching HMA countries:", error);
    } finally {
      setLoadingCountries(false);
    }
  }, [countries.length, loadingCountries]);

  const selectedCountryObj = useMemo(
    () =>
      countries.find(
        (c) =>
          c.countryCode.toLowerCase() === startForm.country.trim().toLowerCase() ||
          c.country.toLowerCase() === startForm.country.trim().toLowerCase() ||
          c.locationKey.toLowerCase() === startForm.country.trim().toLowerCase()
      ) || null,
    [countries, startForm.country]
  );

  const openStartModal = () => {
    const activeCount = status?.tunnels?.length || 0;
    const nextTunnelId = activeCount === 0 ? "default" : `hma-${activeCount + 1}`;
    const nextHttpPort = String(8080 + activeCount);
    const nextSocksPort = String(1080 + activeCount);
    setStartForm({
      ...DEFAULT_START_FORM,
      tunnelId: nextTunnelId,
      httpPort: nextHttpPort,
      socks5Port: nextSocksPort,
    });
    setShowStartModal(true);
    loadCountries();
  };

  const handleActivate = async () => {
    if (!activationCode.trim()) return;
    setActivating(true);
    try {
      const res = await fetch("/api/hma-proxy/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ activationCode: activationCode.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus(data.status || null);
        setActivationCode("");
        setShowActivateModal(false);
        notify.success("HMA VPN license activated");
      } else {
        notify.error(data.error || "Failed to activate HMA license");
      }
    } catch {
      notify.error("Failed to activate HMA license");
    } finally {
      setActivating(false);
    }
  };

  const handleStartTunnel = async () => {
    if (!startForm.country.trim()) return;
    setStarting(true);
    try {
      const res = await fetch("/api/hma-proxy/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          country: startForm.country.trim(),
          city: startForm.city.trim(),
          tunnelId: startForm.tunnelId.trim() || "default",
          httpPort: Number(startForm.httpPort) || 0,
          socks5Port: Number(startForm.socks5Port) || 1080,
          protocol: startForm.protocol,
          poolName: startForm.poolName.trim(),
          autoRegisterPool: startForm.autoRegisterPool,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setShowStartModal(false);
        await fetchStatus();
        await onProxyPoolsChanged?.();
        notify.success(
          `HMA tunnel started (${data.tunnel?.country || startForm.country})${
            data.proxyPool ? " and synced to Proxy Pools" : ""
          }`
        );
      } else {
        notify.error(data.error || "Failed to start HMA tunnel");
      }
    } catch {
      notify.error("Failed to start HMA tunnel");
    } finally {
      setStarting(false);
    }
  };

  const handleStopTunnel = async (tunnelId) => {
    setStoppingId(tunnelId);
    try {
      const res = await fetch("/api/hma-proxy/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tunnelId }),
      });
      const data = await res.json();
      if (res.ok) {
        await fetchStatus();
        await onProxyPoolsChanged?.();
        notify.success(`Stopped HMA tunnel (${tunnelId})`);
      } else {
        notify.error(data.error || "Failed to stop HMA tunnel");
      }
    } catch {
      notify.error("Failed to stop HMA tunnel");
    } finally {
      setStoppingId(null);
    }
  };

  const tunnels = status?.tunnels || [];

  return (
    <Card>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <span className="material-symbols-outlined text-[20px] text-primary">vpn_lock</span>
          <h2 className="text-base font-semibold">HMA VPN Proxy</h2>
          {loading ? (
            <Badge variant="default">Checking...</Badge>
          ) : !status?.available ? (
            <Badge variant="error">Binary Not Found</Badge>
          ) : status?.activated ? (
            <Badge variant="success">License Activated</Badge>
          ) : (
            <Badge variant="warning">Not Activated</Badge>
          )}
          {tunnels.length > 0 && (
            <Badge variant="success">
              {tunnels.length} Running
            </Badge>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {tunnels.length > 0 && (
            <Button
              size="sm"
              variant="secondary"
              icon="public"
              loading={checkingIp}
              onClick={() => fetchStatus({ checkIp: true })}
            >
              Check Exit IP
            </Button>
          )}
          <Button
            size="sm"
            variant="secondary"
            icon="key"
            disabled={!status?.available}
            onClick={() => setShowActivateModal(true)}
          >
            {status?.activated ? "Re-Activate" : "Activate Key"}
          </Button>
          <Button
            size="sm"
            icon="play_arrow"
            disabled={!status?.available || !status?.activated}
            onClick={openStartModal}
          >
            Start HMA Tunnel
          </Button>
        </div>
      </div>

      {!loading && !status?.available && (
        <p className="mt-3 text-xs text-text-muted">
          The <code className="rounded bg-black/5 px-1 py-0.5 dark:bg-white/10">hma-proxy</code> binary
          was not found. Build it with{" "}
          <code className="rounded bg-black/5 px-1 py-0.5 dark:bg-white/10">
            cd hma-proxy &amp;&amp; go build -o dist/hma-proxy ./cmd/hma-proxy
          </code>{" "}
          (or build via Docker), then refresh.
        </p>
      )}

      {!loading && status?.available && tunnels.length === 0 && (
        <p className="mt-3 text-xs text-text-muted">
          {status.activated
            ? "No active HMA WireGuard tunnels. Start a tunnel to create a local HTTP/SOCKS5 proxy and automatically add it to your Proxy Pools."
            : "Activate your HMA license key to spin up rootless WireGuard tunnels as 9Router Proxy Pools."}
        </p>
      )}

      {tunnels.length > 0 && (
        <div className="mt-4 flex flex-col gap-2">
          {tunnels.map((tunnel) => (
            <div
              key={tunnel.tunnelId}
              className="flex flex-col gap-2 rounded-xl border border-border bg-background/60 p-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0 space-y-1 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-text-main">
                    {tunnel.country}
                    {tunnel.city ? ` (${tunnel.city})` : ""}
                  </span>
                  <Badge variant="default">{tunnel.tunnelId}</Badge>
                  <span className="text-text-muted">{tunnel.locationKey}</span>
                  {tunnel.exitIp && <Badge variant="success">Exit IP: {tunnel.exitIp}</Badge>}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-text-muted">
                  {tunnel.httpUrl && <span>HTTP: {tunnel.httpUrl}</span>}
                  {tunnel.socks5Url && <span>SOCKS5: {tunnel.socks5Url}</span>}
                  <span>WG: {tunnel.serverIp}:{tunnel.wgPort}</span>
                  {tunnel.proxyPoolName && <span>Pool: {tunnel.proxyPoolName}</span>}
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-2">
                <Button
                  size="sm"
                  variant="danger"
                  icon="stop"
                  loading={stoppingId === tunnel.tunnelId}
                  onClick={() => handleStopTunnel(tunnel.tunnelId)}
                >
                  Stop
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        isOpen={showActivateModal}
        onClose={() => !activating && setShowActivateModal(false)}
        title="Activate HMA VPN License"
      >
        <div className="space-y-4">
          <p className="text-xs text-text-muted">
            Enter your HMA activation code (wallet key). Credentials are stored locally in{" "}
            <code className="rounded bg-black/5 px-1 py-0.5 dark:bg-white/10">state.json</code> (mode
            0600) and never returned to the browser.
          </p>
          <Input
            label="HMA Activation Code"
            type="password"
            placeholder="XXXXXX-XXXXXX-XXXXXX"
            value={activationCode}
            onChange={(e) => setActivationCode(e.target.value)}
            disabled={activating}
          />
          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={activating}
              onClick={() => setShowActivateModal(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={activating}
              disabled={!activationCode.trim()}
              onClick={handleActivate}
            >
              Activate
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        isOpen={showStartModal}
        onClose={() => !starting && setShowStartModal(false)}
        title="Start HMA VPN Tunnel"
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-xs font-medium text-text-main">
              Country
              {countries.length > 0 ? (
                <select
                  value={startForm.country}
                  disabled={starting}
                  onChange={(e) =>
                    setStartForm((prev) => ({ ...prev, country: e.target.value, city: "" }))
                  }
                  className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-text-main"
                >
                  {countries.map((c) => (
                    <option key={c.locationKey || c.countryCode} value={c.countryCode || c.country}>
                      {c.country} ({c.countryCode})
                    </option>
                  ))}
                </select>
              ) : (
                <Input
                  placeholder={loadingCountries ? "Loading countries..." : "US, GB, DE, SG..."}
                  value={startForm.country}
                  onChange={(e) => setStartForm((prev) => ({ ...prev, country: e.target.value }))}
                  disabled={starting}
                />
              )}
            </label>

            <label className="flex flex-col gap-1 text-xs font-medium text-text-main">
              City (optional)
              {selectedCountryObj?.cities?.length > 0 ? (
                <select
                  value={startForm.city}
                  disabled={starting}
                  onChange={(e) => setStartForm((prev) => ({ ...prev, city: e.target.value }))}
                  className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-text-main"
                >
                  <option value="">Any city</option>
                  {selectedCountryObj.cities.map((c) => (
                    <option key={c.locationKey} value={c.city}>
                      {c.city}
                    </option>
                  ))}
                </select>
              ) : (
                <Input
                  placeholder="Optional city name"
                  value={startForm.city}
                  onChange={(e) => setStartForm((prev) => ({ ...prev, city: e.target.value }))}
                  disabled={starting}
                />
              )}
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Input
              label="HTTP Port (for 9Router)"
              type="number"
              value={startForm.httpPort}
              onChange={(e) => setStartForm((prev) => ({ ...prev, httpPort: e.target.value }))}
              disabled={starting}
            />
            <Input
              label="SOCKS5 Port"
              type="number"
              value={startForm.socks5Port}
              onChange={(e) => setStartForm((prev) => ({ ...prev, socks5Port: e.target.value }))}
              disabled={starting}
            />
            <Input
              label="Tunnel ID"
              value={startForm.tunnelId}
              onChange={(e) => setStartForm((prev) => ({ ...prev, tunnelId: e.target.value }))}
              disabled={starting}
            />
          </div>

          <Input
            label="Proxy Pool Name (optional)"
            placeholder="Auto: HMA VPN - <Country>"
            value={startForm.poolName}
            onChange={(e) => setStartForm((prev) => ({ ...prev, poolName: e.target.value }))}
            disabled={starting}
          />

          <div className="flex items-center justify-between rounded-lg border border-border px-3 py-2">
            <div>
              <div className="text-sm font-medium">Auto-register as Proxy Pool</div>
              <div className="text-xs text-text-muted">
                Creates or updates an active HTTP proxy pool ready to bind to any provider.
              </div>
            </div>
            <Toggle
              checked={startForm.autoRegisterPool}
              onChange={(checked) => setStartForm((prev) => ({ ...prev, autoRegisterPool: checked }))}
              disabled={starting}
            />
          </div>

          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={starting}
              onClick={() => setShowStartModal(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={starting}
              disabled={!startForm.country.trim()}
              onClick={handleStartTunnel}
            >
              Start Tunnel
            </Button>
          </div>
        </div>
      </Modal>
    </Card>
  );
}
