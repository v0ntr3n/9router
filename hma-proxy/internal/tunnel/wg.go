package tunnel

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"hma-proxy/internal/hma"
)

type Tunnel struct {
	Dev  *device.Device
	Net  *netstack.Net
	Info *hma.WranglerResult
}

func parseAddr(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if idx := strings.IndexByte(raw, '/'); idx != -1 {
		raw = raw[:idx]
	}
	return netip.ParseAddr(raw)
}

// Start creates a pure-userspace WireGuard tunnel using wireguard-go's netstack.
// No root privileges, no kernel module, and no host routing table modifications required.
func Start(wr *hma.WranglerResult, verbose bool) (*Tunnel, error) {
	localIP, err := parseAddr(wr.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel IP %q: %w", wr.ClientIP, err)
	}

	var dnsAddrs []netip.Addr
	if wr.DNS != "" {
		for _, part := range strings.Split(wr.DNS, ",") {
			if a, err := parseAddr(part); err == nil {
				dnsAddrs = append(dnsAddrs, a)
			}
		}
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localIP}, dnsAddrs, 1420)
	if err != nil {
		return nil, fmt.Errorf("failed to create userspace WireGuard netstack: %w", err)
	}

	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "[wg] ")

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	ipcConf := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(wr.ClientKeys.Private[:]),
		hex.EncodeToString(wr.ServerPub[:]),
		wr.ServerIP,
		wr.WGPort,
	)

	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to configure WireGuard peer: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to bring up WireGuard device: %w", err)
	}

	return &Tunnel{
		Dev:  dev,
		Net:  tnet,
		Info: wr,
	}, nil
}

func (t *Tunnel) Close() {
	if t != nil && t.Dev != nil {
		t.Dev.Close()
	}
}
