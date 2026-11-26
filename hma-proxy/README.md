# hma-proxy

Headless **HMA VPN** -> **SOCKS5** proxy CLI for Ubuntu/Linux.

Uses HMA's native `api.se-platform.com` backend + UDP Wrangler WireGuard key registration + pure-userspace `wireguard-go` netstack.

- **No `sudo` / root required**
- **No kernel WireGuard module or routing table changes** (safe on remote VPS / SSH / Docker)
- **Zero DNS leaks** (domain names are resolved inside the WireGuard tunnel)
- **Single static Linux x86_64 binary**

## Quick Start (Ubuntu)

```bash
chmod +x hma-proxy
sudo mv hma-proxy /usr/local/bin/

# 1. Activate with your HMA activation code (wallet key)
hma-proxy activate XXXXXX-XXXXXX-XXXXXX

# 2. List available countries (add --cities for city-level location keys)
hma-proxy countries
hma-proxy countries --cities

# 3. Start a background WireGuard -> SOCKS5 proxy
hma-proxy start --country US --socks5 1080

# 4. Check status (add --check-ip to verify exit IP through the proxy)
hma-proxy status
hma-proxy status --check-ip

# 5. Test with curl
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org

# 6. Stop
hma-proxy stop
```

## Build from Source

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/hma-proxy ./cmd/hma-proxy
```

## Files

State and logs are stored in `~/.config/hma-proxy/` (override with `HMA_PROXY_DIR`):

- `state.json` (mode `0600`) — activation tokens & device UDID
- `runtime.json` — active daemon PID, server, tunnel IP, SOCKS5 address
- `daemon.log` — background daemon output
