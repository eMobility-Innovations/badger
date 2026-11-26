package badger

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func newTrustIPBadger(t *testing.T, trustIP []string) *Badger {
	t.Helper()
	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		&Config{DisableForwardAuth: true, DisableDefaultCFIPs: true, TrustIP: trustIP}, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return handler.(*Badger)
}

// Traefik builds one instance per router that references the middleware and hands every
// instance the same trustip list. With 955 entries and 672 routers the list was parsed
// 641,760 times on every configuration reload, in the plugin interpreter.
func TestTrustIPListIsParsedOncePerDistinctList(t *testing.T) {
	list := make([]string, 0, 955)
	for i := 0; i < 955; i++ {
		list = append(list, fmt.Sprintf("10.%d.%d.0/24", i/250, i%250))
	}
	before := trustIPParses
	first := newTrustIPBadger(t, list)
	for i := 0; i < 671; i++ {
		newTrustIPBadger(t, append([]string(nil), list...))
	}
	last := newTrustIPBadger(t, append([]string(nil), list...))
	if got := trustIPParses - before; got != 1 {
		t.Fatalf("an identical trustip list was parsed %d times across 673 instances, want 1", got)
	}
	if len(first.trustIP) != 955 || len(last.trustIP) != 955 {
		t.Fatalf("trustIP lengths %d and %d, want 955", len(first.trustIP), len(last.trustIP))
	}
	if first.trustIP[954].String() != "10.3.204.0/24" || last.trustIP[0].String() != "10.0.0.0/24" {
		t.Fatalf("parsed networks are wrong: %s, %s", first.trustIP[954], last.trustIP[0])
	}
}

func TestDistinctTrustIPListsStayDistinct(t *testing.T) {
	a := newTrustIPBadger(t, []string{"192.0.2.0/24"})
	b := newTrustIPBadger(t, []string{"198.51.100.0/24", "203.0.113.0/24"})
	if len(a.trustIP) != 1 || len(b.trustIP) != 2 || a.trustIP[0].String() != "192.0.2.0/24" || b.trustIP[1].String() != "203.0.113.0/24" {
		t.Fatalf("lists leaked into each other: %v / %v", a.trustIP, b.trustIP)
	}
}

// The default Cloudflare ranges are appended per instance; that must never grow the shared list.
func TestDefaultCFIPsDoNotLeakIntoTheSharedList(t *testing.T) {
	list := []string{"192.0.2.0/24"}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	withDefaults, err := New(context.Background(), next, &Config{DisableForwardAuth: true, TrustIP: list}, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(withDefaults.(*Badger).trustIP) <= 1 {
		t.Fatal("default Cloudflare ranges were not appended")
	}
	if plain := newTrustIPBadger(t, list); len(plain.trustIP) != 1 {
		t.Fatalf("an instance without the defaults has %d trusted networks, want 1", len(plain.trustIP))
	}
}

func TestInvalidTrustIPStillFailsAndIsNotCached(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for i := 0; i < 2; i++ {
		if _, err := New(context.Background(), next, &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true, TrustIP: []string{"192.0.2.0/24", "not-a-cidr"}}, "test"); err == nil {
			t.Fatalf("attempt %d: an invalid trustip entry was accepted", i)
		}
	}
}

func TestTrustIPCacheDoesNotGrowWithoutBound(t *testing.T) {
	for i := 0; i < 4*trustIPCacheLimit; i++ {
		newTrustIPBadger(t, []string{fmt.Sprintf("10.200.%d.0/24", i)})
	}
	if len(trustIPCache) > trustIPCacheLimit {
		t.Fatalf("the cache holds %d lists, limit %d", len(trustIPCache), trustIPCacheLimit)
	}
	if got := newTrustIPBadger(t, []string{"10.200.0.0/24"}); len(got.trustIP) != 1 || got.trustIP[0].String() != "10.200.0.0/24" {
		t.Fatalf("an evicted list did not parse again correctly: %v", got.trustIP)
	}
}
