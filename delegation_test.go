package badger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthoritativeIngressDelegatesOnlyBoundRequests(t *testing.T) {
	for _, mode := range []string{"allowed", "stricter", "tampered", "not-authoritative"} {
		t.Run(mode, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://app.example.test/", nil)
			request.RemoteAddr = "192.0.2.7:1234"
			request.Header.Set(xForwardFor, "10.0.0.1, 203.0.113.9")
			config := &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true}
			if mode == "stricter" {
				config.IdentityProfile = "stricter"
				config.IdentityGeneration = "2"
			}
			called := false
			consumer, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Header.Get(xRealIP) != "203.0.113.9" {
					t.Error("delegated client changed")
				}
				w.WriteHeader(204)
			}), config, "generated-consumer")
			if err != nil {
				t.Fatal(err)
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "tampered" {
					r.Header.Set(xForwardFor, "10.0.0.1")
				}
				consumer.ServeHTTP(w, r)
			})
			ingressConfig := &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true,
				TrustedProxyIPs: []string{"192.0.2.7/32"}, AuthoritativeIngress: mode != "not-authoritative",
				IdentityProfile: "ingress", IdentityGeneration: "1", IdentityScope: "test"}
			ingress, err := New(context.Background(), next, ingressConfig, "ingress")
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			ingress.ServeHTTP(recorder, request)
			if called != (mode == "allowed") {
				t.Fatalf("delegation mode %s served=%v", mode, called)
			}
			if mode != "allowed" && recorder.Code != 400 {
				t.Fatalf("delegation denial status=%d", recorder.Code)
			}
		})
	}
}
