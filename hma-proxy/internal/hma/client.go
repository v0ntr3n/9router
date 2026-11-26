package hma

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	BaseURL        = "https://api.se-platform.com"
	ClientVersion  = "5.10.0"
	ClientType     = "hma101"
	ClientName     = "GVPN"
	ClientAPIKey   = "DECE424681E71043331A3DB13CB0905E03EB605478F1584055ED0EECE80A3E01"
	TenantID       = "3bfdc5ab-a90f-4503-8349-34d0991d33a3"
	ClientLocale   = "en-US"
	SDKVersion     = "win-5.10.0"
	PlatformID     = "win-x86-64"
	OSType         = "Windows 10 Pro"
	OSVersion      = "10.0.19045"
)

var (
	ErrUnauthorized = errors.New("unauthorized (token expired or invalid)")
)

type Client struct {
	HTTP    *http.Client
	BaseURL string
}

func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
		BaseURL: BaseURL,
	}
}

func (c *Client) setBaseHeaders(req *http.Request) {
	req.Header.Set("SE-Client-Version", ClientVersion)
	req.Header.Set("SE-Client-Type", ClientType)
	req.Header.Set("SE-Client-Name", ClientName)
	req.Header.Set("SE-Client-API-Key", ClientAPIKey)
	req.Header.Set("X-NLok-Tenant-ID", TenantID)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
}

func (c *Client) setDeviceHeaders(req *http.Request) {
	req.Header.Set("SE-Client-Locale", ClientLocale)
	req.Header.Set("SE-SDK-Version", SDKVersion)
	req.Header.Set("SE-Platform-ID", PlatformID)
	req.Header.Set("SE-Operating-System-Type", OSType)
	req.Header.Set("SE-Operating-System-Version", OSVersion)
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RegistrationInfo struct {
	DeviceUDID   string
	AccessToken  string
	RefreshToken string
}

type City struct {
	LocationKey  string `json:"location_key"`
	LocationCity string `json:"location_city"`
	State        string `json:"state"`
	Popular      bool   `json:"popular,omitempty"`
}

type Geo struct {
	CountryCode string `json:"country_code"`
	LocationKey string `json:"location_key"`
	Country     string `json:"country"`
	State       string `json:"state"`
	Cities      []City `json:"cities"`
}

type WireGuardMeta struct {
	PublicKey         string   `json:"public_key"`
	WranglerPorts     PortList `json:"wrangler_ports"`
	WranglerPortsPQ   PortList `json:"wrangler_ports_pq,omitempty"`
	WranglerPQHost    string   `json:"wrangler_pq_host,omitempty"`
	WranglerPQAPIPath string   `json:"wrangler_pq_api_path,omitempty"`
}

type DiscoveredServer struct {
	IP        string        `json:"ip"`
	Protocol  string        `json:"protocol"`
	Distance  float64       `json:"distance"`
	Geo       struct {
		LocationKey string `json:"location_key"`
		Country     string `json:"country"`
		City        string `json:"location_city"`
	} `json:"geo"`
	WireGuard *WireGuardMeta `json:"wireguard,omitempty"`
}

// PortList handles JSON port values that may be either a single integer or an array of integers.
type PortList []uint16

func (p *PortList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '[' {
		var list []uint16
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		*p = list
		return nil
	}
	var single uint16
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*p = []uint16{single}
	return nil
}

func GenerateDeviceFingerprint() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type LicenseLookup struct {
	ContainerID string
	ProductName string
	ExpiresMS   int64
}

// LookupLicense queries Avast/Privax license backend for the real container_id (license id)
// associated with a wallet_key. Required before calling /aladdin/v1/authorization/associate-license.
func (c *Client) LookupLicense(ctx context.Context, walletKey string) (*LicenseLookup, error) {
	walletKey = strings.TrimSpace(walletKey)
	rawBody, err := json.Marshal(map[string][]string{
		"walletKeys": {walletKey},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://my-win.avast.com/v1/query/get-exact-application-licenses", bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}
	var devID [32]byte
	_, _ = rand.Read(devID[:])
	var appID [16]byte
	_, _ = rand.Read(appID[:])
	appID[6] = (appID[6] & 0x0f) | 0x40
	appID[8] = (appID[8] & 0x3f) | 0x80
	appUUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", appID[0:4], appID[4:6], appID[6:8], appID[8:10], appID[10:16])

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Vaar-Version", "0")
	req.Header.Set("Vaar-Header-App-Id", appUUID)
	req.Header.Set("Vaar-Header-Device-Id", hex.EncodeToString(devID[:]))
	req.Header.Set("Vaar-Header-Device-Platform", "WIN")
	req.Header.Set("Vaar-Header-App-Product-Brand", "PRIVAX")
	req.Header.Set("Vaar-Header-App-Product-Edition", "HMA_VPN_CONSUMER")
	req.Header.Set("Vaar-Header-App-Product-Mode", "PAID")
	req.Header.Set("Vaar-Header-App-Build-Version", ClientVersion)
	req.Header.Set("Vaar-Header-App-IPM-Product", "78")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("license lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatAPIError(resp.StatusCode, body)
	}

	var entries []struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
		Product struct {
			Name string `json:"name"`
		} `json:"product"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse license lookup response: %w", err)
	}
	if len(entries) == 0 || entries[0].ID == "" {
		return nil, fmt.Errorf("no HMA license found for activation code %s", walletKey)
	}
	return &LicenseLookup{
		ContainerID: strings.ReplaceAll(entries[0].ID, "-", ""),
		ProductName: entries[0].Product.Name,
		ExpiresMS:   entries[0].Expires,
	}, nil
}

func formatAPIError(status int, body []byte) error {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err == nil {
		if msg, ok := parsed["message"].(string); ok && msg != "" {
			if code, ok2 := parsed["code"]; ok2 {
				return fmt.Errorf("HMA API error (HTTP %d, code %v): %s", status, code, msg)
			}
			return fmt.Errorf("HMA API error (HTTP %d): %s", status, msg)
		}
		if errObj, ok := parsed["error"].(map[string]any); ok {
			return fmt.Errorf("HMA API error (HTTP %d): %v", status, errObj)
		}
	}
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}
	return fmt.Errorf("HMA API error (HTTP %d): %s", status, snippet)
}

// AssociateLicense exchanges an HMA activation code (wallet_key) for device credentials & tokens.
// Endpoint verified from VpnSvc.exe: POST /aladdin/v1/authorization/associate-license
func (c *Client) AssociateLicense(ctx context.Context, walletKey, containerID, deviceFingerprint string) (*RegistrationInfo, error) {
	walletKey = strings.TrimSpace(walletKey)
	containerID = strings.ReplaceAll(strings.TrimSpace(containerID), "-", "")

	payload := map[string]string{
		"wallet_key":         walletKey,
		"container_id":       containerID,
		"device_fingerprint": deviceFingerprint,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/aladdin/v1/authorization/associate-license", bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}
	c.setBaseHeaders(req)
	c.setDeviceHeaders(req)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("associate-license request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatAPIError(resp.StatusCode, body)
	}

	// Response can have fields directly at root, under "data", or split into "token" and "credentials"
	// (verified from sub_14024B8C0 in VpnSvc.exe).
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("failed to parse associate-license response: %w", err)
	}
	if dataRaw, ok := root["data"]; ok {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(dataRaw, &inner); err == nil {
			root = inner
		}
	}

	info := &RegistrationInfo{}

	if tokRaw, ok := root["token"]; ok {
		var tp TokenPair
		if err := json.Unmarshal(tokRaw, &tp); err == nil {
			info.AccessToken = tp.AccessToken
			info.RefreshToken = tp.RefreshToken
		}
	}
	if credRaw, ok := root["credentials"]; ok {
		var cred struct {
			DeviceUDID string `json:"device_udid"`
		}
		if err := json.Unmarshal(credRaw, &cred); err == nil && cred.DeviceUDID != "" {
			info.DeviceUDID = cred.DeviceUDID
		}
	}

	// Fallback to flat fields
	if info.AccessToken == "" {
		if raw, ok := root["access_token"]; ok {
			_ = json.Unmarshal(raw, &info.AccessToken)
		}
	}
	if info.RefreshToken == "" {
		if raw, ok := root["refresh_token"]; ok {
			_ = json.Unmarshal(raw, &info.RefreshToken)
		}
	}
	if info.DeviceUDID == "" {
		if raw, ok := root["device_udid"]; ok {
			_ = json.Unmarshal(raw, &info.DeviceUDID)
		}
	}

	if info.AccessToken == "" {
		return nil, fmt.Errorf("associate-license succeeded but access_token missing in response: %s", string(body))
	}
	return info, nil
}

// RenewToken refreshes an expired access_token using the refresh_token and device_udid.
// Endpoint verified from VpnSvc.exe: POST /elysium/v1/renew
// Authorization: Basic base64("nsv:" + device_udid)
func (c *Client) RenewToken(ctx context.Context, deviceUDID, refreshToken string) (*TokenPair, error) {
	payload := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/elysium/v1/renew", bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}
	c.setBaseHeaders(req)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	basic := base64.StdEncoding.EncodeToString([]byte("nsv:" + deviceUDID))
	req.Header.Set("Authorization", "Basic "+basic)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token renew request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, formatAPIError(resp.StatusCode, body))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatAPIError(resp.StatusCode, body)
	}

	var tp TokenPair
	if err := json.Unmarshal(body, &tp); err != nil {
		return nil, fmt.Errorf("failed to parse renew response: %w", err)
	}
	if tp.AccessToken == "" {
		var wrapper struct {
			Data TokenPair `json:"data"`
		}
		if err := json.Unmarshal(body, &wrapper); err == nil && wrapper.Data.AccessToken != "" {
			tp = wrapper.Data
		}
	}
	if tp.AccessToken == "" {
		return nil, fmt.Errorf("renew succeeded but access_token missing in response")
	}
	return &tp, nil
}

// GetGeos fetches the list of available HMA countries and cities.
// Endpoint verified from VpnSvc.exe: GET /discovery/v12/geos
func (c *Client) GetGeos(ctx context.Context, accessToken string) ([]Geo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/discovery/v12/geos", nil)
	if err != nil {
		return nil, err
	}
	c.setBaseHeaders(req)
	req.Header.Set("SE-Client-Locale", ClientLocale)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("geos request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatAPIError(resp.StatusCode, body)
	}

	var parsed struct {
		Data struct {
			Geos []Geo `json:"geos"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse geos response: %w", err)
	}
	return parsed.Data.Geos, nil
}

// DiscoverWireGuard discovers WireGuard servers for a given location_key.
// Endpoint verified from VpnSvc.exe: GET /discovery/v9/discover?location_key=<key>&protocol=wireguard
func (c *Client) DiscoverWireGuard(ctx context.Context, accessToken, locationKey string) ([]DiscoveredServer, error) {
	u, err := url.Parse(c.BaseURL + "/discovery/v9/discover")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if locationKey != "" {
		q.Set("location_key", locationKey)
	}
	q.Set("protocol", "wireguard")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	c.setBaseHeaders(req)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatAPIError(resp.StatusCode, body)
	}

	var parsed struct {
		Data struct {
			IPs []DiscoveredServer `json:"ips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse discover response: %w", err)
	}

	var out []DiscoveredServer
	for _, s := range parsed.Data.IPs {
		if strings.EqualFold(s.Protocol, "wireguard") && s.WireGuard != nil && s.WireGuard.PublicKey != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no wireguard servers found for location %q", locationKey)
	}
	return out, nil
}

// JWTExpiry parses the "exp" claim from a JWT access token without verifying the signature.
func JWTExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// ResolveLocation matches a user-supplied country (ISO code, country name, or exact location_key)
// and optional city name against the geos list.
func ResolveLocation(geos []Geo, countryQuery, cityQuery string) (locationKey, countryName, cityName string, err error) {
	cq := strings.TrimSpace(countryQuery)
	if cq == "" {
		return "", "", "", errors.New("country is required")
	}
	cityQ := strings.TrimSpace(cityQuery)

	// 1. Check if cq is already an exact city location_key
	for _, g := range geos {
		for _, c := range g.Cities {
			if strings.EqualFold(c.LocationKey, cq) && strings.EqualFold(c.State, "active") {
				return c.LocationKey, g.Country, c.LocationCity, nil
			}
		}
	}

	// 2. Match country by code, location_key, or name
	var matched *Geo
	for i := range geos {
		g := &geos[i]
		if !strings.EqualFold(g.State, "active") {
			continue
		}
		if strings.EqualFold(g.CountryCode, cq) || strings.EqualFold(g.LocationKey, cq) || strings.EqualFold(g.Country, cq) {
			matched = g
			break
		}
	}
	if matched == nil {
		// Partial substring match on country name
		low := strings.ToLower(cq)
		for i := range geos {
			g := &geos[i]
			if strings.EqualFold(g.State, "active") && strings.Contains(strings.ToLower(g.Country), low) {
				matched = g
				break
			}
		}
	}
	if matched == nil {
		return "", "", "", fmt.Errorf("country %q not found (run 'hma-proxy countries' to list available countries)", countryQuery)
	}

	// 3. Pick city if requested, otherwise pick first active city (or country location_key if no cities)
	if cityQ != "" {
		lowCity := strings.ToLower(cityQ)
		for _, c := range matched.Cities {
			if !strings.EqualFold(c.State, "active") {
				continue
			}
			if strings.EqualFold(c.LocationCity, cityQ) || strings.EqualFold(c.LocationKey, cityQ) || strings.Contains(strings.ToLower(c.LocationCity), lowCity) {
				return c.LocationKey, matched.Country, c.LocationCity, nil
			}
		}
		return "", "", "", fmt.Errorf("city %q not found in %s", cityQuery, matched.Country)
	}

	// Prefer popular active city, else first active city, else country location_key
	for _, c := range matched.Cities {
		if strings.EqualFold(c.State, "active") && c.Popular {
			return c.LocationKey, matched.Country, c.LocationCity, nil
		}
	}
	for _, c := range matched.Cities {
		if strings.EqualFold(c.State, "active") {
			return c.LocationKey, matched.Country, c.LocationCity, nil
		}
	}
	return matched.LocationKey, matched.Country, "", nil
}
