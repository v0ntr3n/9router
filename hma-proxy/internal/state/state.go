package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type AuthState struct {
	WalletKey         string    `json:"wallet_key"`
	ContainerID       string    `json:"container_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	DeviceUDID        string    `json:"device_udid"`
	AccessToken       string    `json:"access_token"`
	RefreshToken      string    `json:"refresh_token"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RuntimeState struct {
	PID         int       `json:"pid"`
	Country     string    `json:"country"`
	City        string    `json:"city,omitempty"`
	LocationKey string    `json:"location_key"`
	ServerIP    string    `json:"server_ip"`
	WGPort      uint16    `json:"wg_port"`
	TunnelIP    string    `json:"tunnel_ip"`
	DNS         string    `json:"dns"`
	Socks5Addr  string    `json:"socks5_addr"`
	HTTPAddr    string    `json:"http_addr,omitempty"`
	StartedAt   time.Time `json:"started_at"`
}

func Dir() (string, error) {
	if custom := os.Getenv("HMA_PROXY_DIR"); custom != "" {
		return custom, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "hma-proxy"), nil
}

func ensureDir() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0700); err != nil {
		return "", err
	}
	return d, nil
}

func AuthPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "state.json"), nil
}

func RuntimePath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "runtime.json"), nil
}

func LogPath() (string, error) {
	d, err := ensureDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "daemon.log"), nil
}

func LoadAuth() (*AuthState, error) {
	p, err := AuthPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var st AuthState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func SaveAuth(st *AuthState) error {
	d, err := ensureDir()
	if err != nil {
		return err
	}
	st.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(d, "state.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, "state.json"))
}

func LoadRuntime() (*RuntimeState, error) {
	p, err := RuntimePath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var rt RuntimeState
	if err := json.Unmarshal(raw, &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func SaveRuntime(rt *RuntimeState) error {
	d, err := ensureDir()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(d, "runtime.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, "runtime.json"))
}

func ClearRuntime() error {
	p, err := RuntimePath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
