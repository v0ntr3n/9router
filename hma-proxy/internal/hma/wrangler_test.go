package hma

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func TestWranglerRoundTrip(t *testing.T) {
	serverKeys, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		if n < 58+box.Overhead {
			errCh <- err
			return
		}
		var reqNonce [24]byte
		var reqPub [32]byte
		copy(reqNonce[:], buf[0:24])
		copy(reqPub[:], buf[24:56])
		ctLen := int(binary.BigEndian.Uint16(buf[56:58]))
		plain, ok := box.Open(nil, buf[58:58+ctLen], &reqNonce, &reqPub, &serverKeys.Private)
		if !ok {
			errCh <- err
			return
		}

		var reqMap map[string]any
		if err := json.Unmarshal(plain, &reqMap); err != nil {
			errCh <- err
			return
		}
		if reqMap["at"] != "test-token-123" || reqMap["ac"] != float64(1) {
			errCh <- err
			return
		}

		respJSON := []byte(`{"sc":200,"st":"OK","ctip":"10.64.0.42/32","cdns":"10.64.0.1","wgps":[51820,443]}`)
		var respNonce [24]byte
		_, _ = rand.Read(respNonce[:])
		ct := box.Seal(nil, respJSON, &respNonce, &reqPub, &serverKeys.Private)
		pkt := make([]byte, 58+len(ct))
		copy(pkt[0:24], respNonce[:])
		copy(pkt[24:56], serverKeys.Public[:])
		binary.BigEndian.PutUint16(pkt[56:58], uint16(len(ct)))
		copy(pkt[58:], ct)
		_, err = pc.WriteTo(pkt, addr)
		errCh <- err
	}()

	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := WranglerRegister(
		ctx,
		"127.0.0.1",
		uint16(udpAddr.Port),
		base64.StdEncoding.EncodeToString(serverKeys.Public[:]),
		"test-token-123",
		clientKeys,
	)
	if err != nil {
		t.Fatalf("WranglerRegister failed: %v", err)
	}
	if serverErr := <-errCh; serverErr != nil {
		t.Fatalf("mock wrangler server error: %v", serverErr)
	}
	if res.ClientIP != "10.64.0.42/32" || res.DNS != "10.64.0.1" || res.WGPort != 51820 {
		t.Fatalf("unexpected wrangler result: %+v", res)
	}
}

func TestResolveLocation(t *testing.T) {
	geos := []Geo{
		{
			CountryCode: "US",
			LocationKey: "US",
			Country:     "United States",
			State:       "active",
			Cities: []City{
				{LocationKey: "US-1-NEW-YORK", LocationCity: "New York", State: "active", Popular: true},
				{LocationKey: "US-2-MIAMI", LocationCity: "Miami", State: "active"},
			},
		},
	}

	loc, country, city, err := ResolveLocation(geos, "us", "")
	if err != nil || loc != "US-1-NEW-YORK" || country != "United States" || city != "New York" {
		t.Fatalf("unexpected result: %q %q %q %v", loc, country, city, err)
	}

	loc, _, city, err = ResolveLocation(geos, "US", "miami")
	if err != nil || loc != "US-2-MIAMI" || city != "Miami" {
		t.Fatalf("unexpected city result: %q %q %v", loc, city, err)
	}
}
