// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestBuildConnectionMap(t *testing.T) {
	cfg := config.ClientConfig{
		ProtocolType: "SOCKS5",
		Domains: []string{
			"a.example.com",
			"b.example.com",
		},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
			{IP: "2001:4860:4860::8888", Port: 5353},
		},
	}

	c := New(cfg, nil, nil)
	c.BuildConnectionMap()

	if got, want := len(c.Connections()), 4; got != want {
		t.Fatalf("unexpected connection count: got=%d want=%d", got, want)
	}

	first := c.Connections()[0]
	if first.Domain == "" || first.Resolver == "" || first.Key == "" {
		t.Fatalf("connection fields should be populated: %+v", first)
	}
	if !first.IsValid {
		t.Fatalf("connections should start valid")
	}
	if first.Resolver == "2001:4860:4860::8888" && first.ResolverLabel != "[2001:4860:4860::8888]:5353" {
		t.Fatalf("unexpected ipv6 resolver label: got=%q", first.ResolverLabel)
	}
	if c.Balancer().ValidCount() != 4 {
		t.Fatalf("unexpected valid connection count: got=%d want=%d", c.Balancer().ValidCount(), 4)
	}
}

func TestResetRuntimeState(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	c.sessionID = 11
	c.sessionCookie = 22
	c.enqueueSeq = 33

	c.ResetRuntimeState(false)
	if c.sessionID != 0 || c.enqueueSeq != 0 {
		t.Fatalf("reset should clear session id and enqueue seq: sid=%d enqueue=%d", c.sessionID, c.enqueueSeq)
	}
	if c.sessionCookie != 22 {
		t.Fatalf("reset without cookie reset should preserve session cookie: got=%d", c.sessionCookie)
	}

	c.ResetRuntimeState(true)
	if c.sessionCookie != 0 {
		t.Fatalf("reset with cookie reset should clear session cookie: got=%d", c.sessionCookie)
	}
}

func TestSetConnectionValidityKeepsClientAndBalancerInSync(t *testing.T) {
	cfg := config.ClientConfig{
		Domains: []string{"a.example.com"},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
		},
	}

	c := New(cfg, nil, nil)
	c.BuildConnectionMap()
	key := c.Connections()[0].Key

	if !c.SetConnectionValidity(key, false) {
		t.Fatal("SetConnectionValidity returned false")
	}
	if c.Connections()[0].IsValid {
		t.Fatal("client connection validity was not updated")
	}
	if got := c.Balancer().ValidCount(); got != 0 {
		t.Fatalf("unexpected valid count after disable: got=%d want=0", got)
	}

	if !c.SetConnectionValidity(key, true) {
		t.Fatal("SetConnectionValidity returned false when re-enabling")
	}
	if !c.Connections()[0].IsValid {
		t.Fatal("client connection validity was not restored")
	}
	if got := c.Balancer().ValidCount(); got != 1 {
		t.Fatalf("unexpected valid count after enable: got=%d want=1", got)
	}
}
