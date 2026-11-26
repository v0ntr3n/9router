package hma

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type WGKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateWGKeyPair() (*WGKeyPair, error) {
	var kp WGKeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, err
	}
	// Standard WireGuard / Curve25519 clamping
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return &kp, nil
}

type WranglerResult struct {
	ClientIP   string
	DNS        string
	WGPort     uint16
	ServerIP   string
	ServerPub  [32]byte
	ClientKeys *WGKeyPair
}

type wranglerResponse struct {
	StatusCode int      `json:"sc"`
	StatusText string   `json:"st"`
	ClientIP   string   `json:"ctip"`
	ClientDNS  string   `json:"cdns"`
	WGPorts    PortList `json:"wgps"`
}

// WranglerRegister performs the HMA/Avast UDP Wrangler key registration handshake.
// Wire format verified from VpnSvc.exe (sub_14025B4D0 / sub_14025B660 / sub_14025B8C0 / sub_14025BB40 / sub_14025C240):
//   Request plaintext JSON: {"at":"<access_token>","ac":1,"cores":1}
//   Request UDP packet:     nonce[24] || client_pubkey[32] || be16(len(ciphertext)) || crypto_box_easy(plaintext)
//   Response UDP packet:    nonce[24] || server_pubkey[32] || be16(len(ciphertext)) || crypto_box_easy(response_json)
func WranglerRegister(ctx context.Context, serverIP string, wranglerPort uint16, serverPubB64 string, accessToken string, kp *WGKeyPair) (*WranglerResult, error) {
	rawServerPub, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil || len(rawServerPub) != 32 {
		return nil, fmt.Errorf("invalid server wireguard public key")
	}
	var serverPub [32]byte
	copy(serverPub[:], rawServerPub)

	// Build request JSON matching sub_14025B660
	reqPayload, err := json.Marshal(map[string]any{
		"at":    accessToken,
		"ac":    1,
		"cores": 1,
	})
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	ciphertext := box.Seal(nil, reqPayload, &nonce, &serverPub, &kp.Private)
	if len(ciphertext) > 65535 {
		return nil, errors.New("wrangler ciphertext exceeds uint16")
	}

	pkt := make([]byte, 58+len(ciphertext))
	copy(pkt[0:24], nonce[:])
	copy(pkt[24:56], kp.Public[:])
	binary.BigEndian.PutUint16(pkt[56:58], uint16(len(ciphertext)))
	copy(pkt[58:], ciphertext)

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverIP, fmt.Sprintf("%d", wranglerPort)))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("wrangler UDP dial failed: %w", err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	var n int
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		deadline := time.Now().Add(3 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)

		if _, err := conn.Write(pkt); err != nil {
			lastErr = err
			continue
		}
		n, err = conn.Read(buf)
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("wrangler UDP exchange failed (%s:%d): %w", serverIP, wranglerPort, lastErr)
	}
	if n < 58+box.Overhead {
		return nil, fmt.Errorf("wrangler reply too short: %d bytes", n)
	}

	var respNonce [24]byte
	var respPub [32]byte
	copy(respNonce[:], buf[0:24])
	copy(respPub[:], buf[24:56])
	respLen := int(binary.BigEndian.Uint16(buf[56:58]))
	if 58+respLen > n {
		return nil, fmt.Errorf("wrangler reply truncated: header len=%d, received=%d", respLen, n-58)
	}

	plaintext, ok := box.Open(nil, buf[58:58+respLen], &respNonce, &respPub, &kp.Private)
	if !ok {
		return nil, errors.New("wrangler reply decryption/authentication failed")
	}

	var parsed wranglerResponse
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse wrangler JSON: %w (raw: %s)", err, string(plaintext))
	}
	if parsed.StatusCode < 200 || parsed.StatusCode >= 300 {
		return nil, fmt.Errorf("wrangler rejected request (sc=%d): %s", parsed.StatusCode, parsed.StatusText)
	}
	if parsed.ClientIP == "" || len(parsed.WGPorts) == 0 {
		return nil, fmt.Errorf("wrangler response missing ctip or wgps: %s", string(plaintext))
	}

	return &WranglerResult{
		ClientIP:   parsed.ClientIP,
		DNS:        parsed.ClientDNS,
		WGPort:     parsed.WGPorts[0],
		ServerIP:   serverIP,
		ServerPub:  serverPub,
		ClientKeys: kp,
	}, nil
}
