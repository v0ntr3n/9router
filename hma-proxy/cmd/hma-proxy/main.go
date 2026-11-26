package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/net/proxy"

	"hma-proxy/internal/daemon"
	"hma-proxy/internal/hma"
	"hma-proxy/internal/httpproxy"
	"hma-proxy/internal/socks5"
	"hma-proxy/internal/state"
	"hma-proxy/internal/tunnel"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "activate":
		err = cmdActivate(os.Args[2:])
	case "countries":
		err = cmdCountries(os.Args[2:])
	case "start":
		err = cmdStart(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "stop":
		err = cmdStop(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("hma-proxy %s\n", version)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`hma-proxy - Headless HMA VPN WireGuard -> SOCKS5 proxy for Linux/Ubuntu

Usage:
  hma-proxy activate [ACTIVATION_CODE]     Activate using your HMA activation code (wallet key)
  hma-proxy countries [--cities] [--json]  List available HMA countries (and cities)
  hma-proxy start [options]                Start VPN tunnel and SOCKS5 proxy
  hma-proxy status [--check-ip]            Show running proxy status
  hma-proxy stop                           Stop running proxy daemon

Start options:
  --country <code|name>   Country code, name, or location_key (e.g. US, GB, DE, US-1-NEW-YORK) [required]
  --city <name>           Optional city name within country
  --socks5 <port|addr>    SOCKS5 port (e.g. 1080) or host:port (e.g. 0.0.0.0:1080) [default: 1080]
  --http <port|addr>      Optional HTTP/HTTPS CONNECT proxy port or host:port (e.g. 8080)
  --bind <ip>             Bind address when --socks5/--http is a port number [default: 127.0.0.1]
  --user <username>       Optional SOCKS5 username
  --pass <password>       Optional SOCKS5 password
  --foreground            Run in foreground instead of daemonizing
  --verbose               Enable verbose WireGuard logging`)
}

func cmdActivate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	keyFlag := fs.String("key", "", "HMA activation code (e.g. XXXXXX-XXXXXX-XXXXXX)")
	_ = fs.Parse(args)

	walletKey := strings.TrimSpace(*keyFlag)
	if walletKey == "" && fs.NArg() > 0 {
		walletKey = strings.TrimSpace(fs.Arg(0))
	}
	if walletKey == "" {
		walletKey = strings.TrimSpace(os.Getenv("HMA_ACTIVATION_CODE"))
	}
	if walletKey == "" {
		fmt.Print("Enter HMA activation code (XXXXXX-XXXXXX-XXXXXX): ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		walletKey = strings.TrimSpace(line)
	}
	if walletKey == "" {
		return errors.New("activation code cannot be empty")
	}

	existing, _ := state.LoadAuth()
	fingerprint := hma.GenerateDeviceFingerprint()
	if existing != nil && existing.DeviceFingerprint != "" {
		fingerprint = strings.ReplaceAll(existing.DeviceFingerprint, "-", "")
	}

	client := hma.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	fmt.Println("Looking up license container ID...")
	lic, err := client.LookupLicense(ctx, walletKey)
	if err != nil {
		return err
	}
	if lic.ProductName != "" {
		fmt.Printf("Found license: %s (container %s)\n", lic.ProductName, lic.ContainerID)
	}
	containerID := lic.ContainerID

	fmt.Println("Activating license with HMA backend...")
	reg, err := client.AssociateLicense(ctx, walletKey, containerID, fingerprint)
	if err != nil {
		return err
	}

	st := &state.AuthState{
		WalletKey:         walletKey,
		ContainerID:       containerID,
		DeviceFingerprint: fingerprint,
		DeviceUDID:        reg.DeviceUDID,
		AccessToken:       reg.AccessToken,
		RefreshToken:      reg.RefreshToken,
	}
	if err := state.SaveAuth(st); err != nil {
		return fmt.Errorf("failed to save auth state: %w", err)
	}

	p, _ := state.AuthPath()
	fmt.Printf("Activated successfully! Credentials saved to %s\n", p)
	if st.DeviceUDID != "" {
		fmt.Printf("Device UDID: %s\n", st.DeviceUDID)
	}
	return nil
}

func cmdCountries(args []string) error {
	fs := flag.NewFlagSet("countries", flag.ExitOnError)
	showCities := fs.Bool("cities", false, "Show individual cities and location keys")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	client := hma.NewClient()
	accessToken := ""
	if st, err := state.LoadAuth(); err == nil && st != nil {
		accessToken = st.AccessToken
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	geos, err := client.GetGeos(ctx, accessToken)
	if errors.Is(err, hma.ErrUnauthorized) {
		// geos works without auth too; retry unauthenticated
		geos, err = client.GetGeos(ctx, "")
	}
	if err != nil {
		return err
	}

	sort.Slice(geos, func(i, j int) bool {
		return geos[i].CountryCode < geos[j].CountryCode
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(geos)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if *showCities {
		fmt.Fprintln(tw, "CODE\tCOUNTRY\tCITY\tLOCATION_KEY")
		for _, g := range geos {
			if !strings.EqualFold(g.State, "active") {
				continue
			}
			for _, c := range g.Cities {
				if !strings.EqualFold(c.State, "active") {
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.CountryCode, g.Country, c.LocationCity, c.LocationKey)
			}
		}
	} else {
		fmt.Fprintln(tw, "CODE\tCOUNTRY\tCITIES\tLOCATION_KEY")
		for _, g := range geos {
			if !strings.EqualFold(g.State, "active") {
				continue
			}
			activeCities := 0
			for _, c := range g.Cities {
				if strings.EqualFold(c.State, "active") {
					activeCities++
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", g.CountryCode, g.Country, activeCities, g.LocationKey)
		}
	}
	return tw.Flush()
}

func ensureValidToken(ctx context.Context, client *hma.Client, st *state.AuthState, forceRefresh bool) error {
	needRefresh := forceRefresh
	if !needRefresh {
		if exp, ok := hma.JWTExpiry(st.AccessToken); ok {
			if time.Until(exp) < 5*time.Minute {
				needRefresh = true
			}
		}
	}
	if !needRefresh {
		return nil
	}
	if st.RefreshToken != "" && st.DeviceUDID != "" {
		tp, err := client.RenewToken(ctx, st.DeviceUDID, st.RefreshToken)
		if err == nil {
			st.AccessToken = tp.AccessToken
			if tp.RefreshToken != "" {
				st.RefreshToken = tp.RefreshToken
			}
			return state.SaveAuth(st)
		}
	}
	// Fallback: transparently re-associate using the saved wallet key & same device fingerprint
	if st.WalletKey != "" && st.ContainerID != "" && st.DeviceFingerprint != "" {
		reg, err := client.AssociateLicense(ctx, st.WalletKey, st.ContainerID, st.DeviceFingerprint)
		if err == nil {
			if reg.DeviceUDID != "" {
				st.DeviceUDID = reg.DeviceUDID
			}
			st.AccessToken = reg.AccessToken
			if reg.RefreshToken != "" {
				st.RefreshToken = reg.RefreshToken
			}
			return state.SaveAuth(st)
		}
		return fmt.Errorf("failed to renew session (try 'hma-proxy activate'): %w", err)
	}
	if forceRefresh {
		return errors.New("access token expired and no saved session credentials available; run 'hma-proxy activate' again")
	}
	return nil
}

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	country := fs.String("country", "", "Country code, name, or location_key (e.g. US)")
	city := fs.String("city", "", "Optional city name")
	socks5Flag := fs.String("socks5", "1080", "SOCKS5 port or host:port")
	httpFlag := fs.String("http", "", "Optional HTTP/HTTPS proxy port or host:port (e.g. 8080)")
	bindFlag := fs.String("bind", "127.0.0.1", "Bind IP when --socks5/--http is a port")
	userFlag := fs.String("user", "", "Optional SOCKS5 username")
	passFlag := fs.String("pass", "", "Optional SOCKS5 password")
	foreground := fs.Bool("foreground", false, "Run in foreground")
	verbose := fs.Bool("verbose", false, "Verbose WireGuard logging")
	daemonChild := fs.Bool("daemon-child", false, "Internal flag for background daemon")
	readyFile := fs.String("ready-file", "", "Internal readiness file path")
	_ = fs.Parse(args)

	if strings.TrimSpace(*country) == "" {
		return errors.New("--country is required (e.g. hma-proxy start --country US --socks5 1080)")
	}

	listenAddr := strings.TrimSpace(*socks5Flag)
	if !strings.Contains(listenAddr, ":") {
		listenAddr = *bindFlag + ":" + listenAddr
	}
	httpListenAddr := strings.TrimSpace(*httpFlag)
	if httpListenAddr != "" && !strings.Contains(httpListenAddr, ":") {
		httpListenAddr = *bindFlag + ":" + httpListenAddr
	}

	// Check if already running
	if !*daemonChild {
		if rt, err := state.LoadRuntime(); err == nil && rt != nil {
			if daemon.IsRunning(rt.PID) {
				return fmt.Errorf("hma-proxy is already running (PID %d, %s on %s); run 'hma-proxy stop' first",
					rt.PID, rt.LocationKey, rt.Socks5Addr)
			}
			_ = state.ClearRuntime()
		}
	}

	// Verify auth exists before spawning daemon
	authSt, err := state.LoadAuth()
	if err != nil {
		return err
	}
	if authSt == nil || authSt.AccessToken == "" {
		return errors.New("not activated yet; run 'hma-proxy activate <CODE>' first")
	}

	// If not foreground and not already the daemon child, spawn detached daemon and wait for readiness
	if !*foreground && !*daemonChild {
		return spawnDaemon(args)
	}

	return runTunnelDaemon(*country, *city, listenAddr, httpListenAddr, *userFlag, *passFlag, *verbose, *readyFile)
}

func spawnDaemon(origArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	rf, err := os.CreateTemp("", "hma-proxy-ready-*.tmp")
	if err != nil {
		return err
	}
	readyPath := rf.Name()
	_ = rf.Close()
	_ = os.Remove(readyPath)
	defer os.Remove(readyPath)

	logPath, err := state.LogPath()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()

	childArgs := append([]string{"start", "--daemon-child", "--ready-file", readyPath}, origArgs...)
	cmd := exec.Command(exe, childArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	daemon.PrepareDetached(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background daemon: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(readyPath)
		if err == nil && len(raw) > 0 {
			msg := strings.TrimSpace(string(raw))
			if strings.HasPrefix(msg, "OK:") {
				rt, _ := state.LoadRuntime()
				if rt != nil {
					loc := rt.Country
					if rt.City != "" {
						loc = fmt.Sprintf("%s (%s)", rt.Country, rt.City)
					}
					fmt.Printf("hma-proxy started (PID %d)\n", rt.PID)
					fmt.Printf("  Location : %s [%s]\n", loc, rt.LocationKey)
					fmt.Printf("  Server   : %s:%d (tunnel IP %s)\n", rt.ServerIP, rt.WGPort, rt.TunnelIP)
					fmt.Printf("  SOCKS5   : %s\n", socks5.FormatProxyURL(rt.Socks5Addr))
					if rt.HTTPAddr != "" {
						fmt.Printf("  HTTP     : http://%s\n", rt.HTTPAddr)
					}
					fmt.Printf("  Log      : %s\n", logPath)
				} else {
					fmt.Printf("hma-proxy started (PID %d)\n", pid)
				}
				return nil
			}
			if strings.HasPrefix(msg, "ERR:") {
				return errors.New(strings.TrimPrefix(msg, "ERR:"))
			}
		}
		if !daemon.IsRunning(pid) {
			return fmt.Errorf("daemon exited unexpectedly; check %s", logPath)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for daemon to connect; check %s", logPath)
}

func signalReady(readyFile, msg string) {
	if readyFile == "" {
		return
	}
	_ = os.WriteFile(readyFile, []byte(msg), 0600)
}

func runTunnelDaemon(countryQuery, cityQuery, listenAddr, httpListenAddr, user, pass string, verbose bool, readyFile string) error {
	fail := func(err error) error {
		signalReady(readyFile, "ERR:"+err.Error())
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authSt, err := state.LoadAuth()
	if err != nil || authSt == nil {
		return fail(errors.New("not activated; run 'hma-proxy activate' first"))
	}

	client := hma.NewClient()
	if err := ensureValidToken(ctx, client, authSt, false); err != nil {
		return fail(err)
	}

	geos, err := client.GetGeos(ctx, authSt.AccessToken)
	if errors.Is(err, hma.ErrUnauthorized) {
		if rerr := ensureValidToken(ctx, client, authSt, true); rerr != nil {
			return fail(rerr)
		}
		geos, err = client.GetGeos(ctx, authSt.AccessToken)
	}
	if err != nil {
		return fail(err)
	}

	locKey, countryName, cityName, err := hma.ResolveLocation(geos, countryQuery, cityQuery)
	if err != nil {
		return fail(err)
	}

	servers, err := client.DiscoverWireGuard(ctx, authSt.AccessToken, locKey)
	if errors.Is(err, hma.ErrUnauthorized) {
		if rerr := ensureValidToken(ctx, client, authSt, true); rerr != nil {
			return fail(rerr)
		}
		servers, err = client.DiscoverWireGuard(ctx, authSt.AccessToken, locKey)
	}
	if err != nil {
		return fail(err)
	}

	kp, err := hma.GenerateWGKeyPair()
	if err != nil {
		return fail(err)
	}

	var wr *hma.WranglerResult
	var lastErr error
	for _, srv := range servers {
		if srv.WireGuard == nil || len(srv.WireGuard.WranglerPorts) == 0 {
			continue
		}
		for _, port := range srv.WireGuard.WranglerPorts {
			res, werr := hma.WranglerRegister(ctx, srv.IP, port, srv.WireGuard.PublicKey, authSt.AccessToken, kp)
			if werr == nil {
				wr = res
				break
			}
			lastErr = werr
		}
		if wr != nil {
			break
		}
	}
	if wr == nil {
		if lastErr == nil {
			lastErr = errors.New("no WireGuard servers with wrangler ports available")
		}
		return fail(fmt.Errorf("wrangler registration failed: %w", lastErr))
	}

	tun, err := tunnel.Start(wr, verbose)
	if err != nil {
		return fail(err)
	}
	defer tun.Close()

	srv := &socks5.Server{
		ListenAddr: listenAddr,
		Username:   user,
		Password:   pass,
		Dialer:     tun.Net,
	}
	boundAddr, err := srv.Start()
	if err != nil {
		return fail(fmt.Errorf("failed to bind SOCKS5 listener on %s: %w", listenAddr, err))
	}

	var httpSrv *httpproxy.Server
	var httpBoundAddr string
	if httpListenAddr != "" {
		httpSrv = &httpproxy.Server{
			ListenAddr: httpListenAddr,
			Username:   user,
			Password:   pass,
			Dialer:     tun.Net,
		}
		haddr, herr := httpSrv.Start()
		if herr != nil {
			_ = srv.Close()
			return fail(fmt.Errorf("failed to bind HTTP proxy listener on %s: %w", httpListenAddr, herr))
		}
		httpBoundAddr = haddr.String()
	}

	rt := &state.RuntimeState{
		PID:         os.Getpid(),
		Country:     countryName,
		City:        cityName,
		LocationKey: locKey,
		ServerIP:    wr.ServerIP,
		WGPort:      wr.WGPort,
		TunnelIP:    wr.ClientIP,
		DNS:         wr.DNS,
		Socks5Addr:  boundAddr.String(),
		HTTPAddr:    httpBoundAddr,
		StartedAt:   time.Now().UTC(),
	}
	if err := state.SaveRuntime(rt); err != nil {
		_ = srv.Close()
		if httpSrv != nil {
			_ = httpSrv.Close()
		}
		return fail(err)
	}
	defer state.ClearRuntime()

	signalReady(readyFile, "OK:"+boundAddr.String())

	if readyFile == "" {
		loc := countryName
		if cityName != "" {
			loc = fmt.Sprintf("%s (%s)", countryName, cityName)
		}
		fmt.Printf("Connected to %s [%s] via %s:%d (tunnel IP %s)\n", loc, locKey, wr.ServerIP, wr.WGPort, wr.ClientIP)
		fmt.Printf("SOCKS5 proxy listening on %s\n", socks5.FormatProxyURL(boundAddr.String()))
		if httpBoundAddr != "" {
			fmt.Printf("HTTP proxy listening on http://%s\n", httpBoundAddr)
		}
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if httpSrv != nil {
		go func() {
			_ = httpSrv.Serve(runCtx)
		}()
	}
	return srv.Serve(runCtx)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	checkIP := fs.Bool("check-ip", false, "Verify external exit IP through the SOCKS5 proxy")
	_ = fs.Parse(args)

	rt, err := state.LoadRuntime()
	if err != nil {
		return err
	}
	if rt == nil || !daemon.IsRunning(rt.PID) {
		if rt != nil {
			_ = state.ClearRuntime()
		}
		fmt.Println("Status: stopped")
		if authSt, _ := state.LoadAuth(); authSt != nil && authSt.AccessToken != "" {
			fmt.Println("License: activated")
		} else {
			fmt.Println("License: not activated (run 'hma-proxy activate')")
		}
		return nil
	}

	loc := rt.Country
	if rt.City != "" {
		loc = fmt.Sprintf("%s (%s)", rt.Country, rt.City)
	}
	uptime := time.Since(rt.StartedAt).Round(time.Second)

	fmt.Println("Status: running")
	fmt.Printf("  PID      : %d\n", rt.PID)
	fmt.Printf("  Location : %s [%s]\n", loc, rt.LocationKey)
	fmt.Printf("  Server   : %s:%d\n", rt.ServerIP, rt.WGPort)
	fmt.Printf("  Tunnel IP: %s (DNS: %s)\n", rt.TunnelIP, rt.DNS)
	fmt.Printf("  SOCKS5   : %s\n", socks5.FormatProxyURL(rt.Socks5Addr))
	if rt.HTTPAddr != "" {
		fmt.Printf("  HTTP     : http://%s\n", rt.HTTPAddr)
	}
	fmt.Printf("  Uptime   : %s\n", uptime)

	if *checkIP {
		ip, err := fetchExitIP(rt.Socks5Addr)
		if err != nil {
			fmt.Printf("  Exit IP  : error (%v)\n", err)
		} else {
			fmt.Printf("  Exit IP  : %s\n", ip)
		}
	}
	return nil
}

func fetchExitIP(socksAddr string) (string, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return "", errors.New("socks5 dialer does not support DialContext")
	}
	hc := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: cd.DialContext,
		},
	}
	resp, err := hc.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func cmdStop(args []string) error {
	rt, err := state.LoadRuntime()
	if err != nil {
		return err
	}
	if rt == nil {
		fmt.Println("hma-proxy is not running")
		return nil
	}
	if !daemon.IsRunning(rt.PID) {
		_ = state.ClearRuntime()
		fmt.Println("hma-proxy is not running (cleaned up stale state)")
		return nil
	}

	if err := daemon.StopProcess(rt.PID, 5*time.Second); err != nil {
		return fmt.Errorf("failed to stop PID %d: %w", rt.PID, err)
	}
	_ = state.ClearRuntime()
	fmt.Printf("hma-proxy stopped (PID %d)\n", rt.PID)
	return nil
}
