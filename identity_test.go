package badger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIdentityBoundary(t *testing.T) {
	for _, test := range []struct {
		name, peer, xff, vendor, expected string
	}{
		{"direct", "203.0.113.9:1234", "10.0.0.1", "10.0.0.2", "203.0.113.9"},
		{"cdn", "198.51.100.2:1234", "10.0.0.1", "203.0.113.9", "203.0.113.9"},
		{"proxy", "192.0.2.7:1234", "10.0.0.1, 203.0.113.9, 198.51.100.2", "10.0.0.2", "203.0.113.9"},
		{"ipv6", "[2001:db8:1::7]:1234", "2001:db8:3::9, 2001:db8:2::2", "", "2001:db8:3::9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://app.example.test:8443/", nil)
			request.RemoteAddr = test.peer
			request.Header.Set("X-Forwarded-For", test.xff)
			request.Header.Set("CF-Connecting-IP", test.vendor)
			config := &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true,
				TrustIP:         []string{"198.51.100.0/24", "2001:db8:2::/64"},
				TrustedProxyIPs: []string{"192.0.2.7/32", "2001:db8:1::7/128"}}
			called := false
			handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.RemoteAddr != test.peer {
					t.Error("transport identity changed")
				}
				if r.Header.Get("X-Real-Ip") != test.expected || r.Header.Get("X-Forwarded-For") != test.expected {
					t.Fatalf("client headers: %v", r.Header)
				}
			}), config, "test")
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if !called || recorder.Code != 200 {
				t.Fatalf("allowed control was not served: %d", recorder.Code)
			}
		})
	}
}

func TestRepeatedMiddlewarePreservesCanonicalClient(t *testing.T) {
	request := httptest.NewRequest("GET", "http://app.example.test:8443/", nil)
	request.RemoteAddr = "192.0.2.7:1234"
	request.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Port", "8443")
	called := false
	inner, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get(xRealIP) != "203.0.113.9" || r.Header.Get(xForwardProto) != "https" || r.Header.Get("X-Forwarded-Port") != "8443" {
			t.Fatalf("normalized context lost: %v", r.Header)
		}
	}), &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true, TrustedProxyIPs: []string{"192.0.2.7/32"}}, "inner")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := New(context.Background(), inner, &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true,
		TrustedProxyIPs: []string{"192.0.2.7/32"}}, "outer")
	if err != nil {
		t.Fatal(err)
	}
	outer.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("allowed nested control was not served")
	}
}

func TestStricterMiddlewareCannotInheritWeakerTrust(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		request := httptest.NewRequest("GET", "http://app.example.test/", nil)
		request.RemoteAddr = "192.0.2.7:1234"
		request.Header.Set(xForwardFor, "10.0.0.1, 203.0.113.9")
		innerConfig := &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true}
		if allowed {
			innerConfig.TrustedProxyIPs = []string{"192.0.2.7/32"}
		}
		called := false
		inner, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(204)
		}), innerConfig, "stricter")
		if err != nil {
			t.Fatal(err)
		}
		outer, err := New(context.Background(), inner, &Config{DisableForwardAuth: true,
			DisableDefaultCFIPs: true, TrustedProxyIPs: []string{"192.0.2.7/32"}}, "outer")
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		outer.ServeHTTP(recorder, request)
		if called != allowed {
			t.Fatalf("cross-profile authority: served=%v allowed=%v", called, allowed)
		}
		if !allowed && recorder.Code != 400 {
			t.Fatalf("stricter boundary status %d", recorder.Code)
		}
	}
}

func TestBroadPrivateAndGlobalProxyTrustRejected(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "192.168.0.0/16", "fc00::/7"} {
		_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			&Config{DisableForwardAuth: true, TrustedProxyIPs: []string{cidr}}, "test")
		if err == nil {
			t.Fatalf("accepted unsafe trust %s", cidr)
		}
	}
}

func TestCustomAssertionIsConsumedAndNeverForwarded(t *testing.T) {
	for _, peer := range []string{"203.0.113.9:1234", "192.0.2.7:1234", "198.51.100.2:1234"} {
		for _, header := range []string{"Vendor-Client-IP", "X-Forwarded-For", "X-Real-IP"} {
			t.Run(peer+"/"+header, func(t *testing.T) {
				request := httptest.NewRequest("GET", "http://app.example.test/", nil)
				request.RemoteAddr = peer
				request.Header.Set(xForwardFor, "203.0.113.9")
				request.Header.Set(header, "203.0.113.9")
				if peer != "198.51.100.2:1234" {
					request.Header.Set(header, "10.0.0.1")
				}
				if peer == "192.0.2.7:1234" && header == "X-Forwarded-For" {
					request.Header.Set(header, "10.0.0.1, 203.0.113.9")
				}
				called := false
				handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					if header == "Vendor-Client-IP" && r.Header.Get(header) != "" {
						t.Error("raw custom assertion forwarded")
					}
					if r.Header.Get(xForwardFor) != "203.0.113.9" || r.Header.Get(xRealIP) != "203.0.113.9" {
						t.Error("canonical client headers lost")
					}
				}), &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true,
					TrustIP: []string{"198.51.100.0/24"}, TrustedProxyIPs: []string{"192.0.2.7/32"},
					CustomIPHeader: header}, "test")
				if err != nil {
					t.Fatal(err)
				}
				handler.ServeHTTP(httptest.NewRecorder(), request)
				if !called {
					t.Error("allowed control was not served")
				}
			})
		}
	}
}

func TestAmbiguousAssertionsAndForgedPublicContext(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) {
			r.Header.Add("X-Forwarded-For", "203.0.113.9")
			r.Header.Add("X-Forwarded-For", "10.0.0.1")
		},
		func(r *http.Request) { r.Header.Set("X-Forwarded-For", "invalid") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.test") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "ftp") },
	} {
		request := httptest.NewRequest("GET", "http://app.example.test/", nil)
		request.RemoteAddr = "192.0.2.7:1234"
		mutate(request)
		handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("invalid assertion reached application")
		}), &Config{DisableForwardAuth: true, DisableDefaultCFIPs: true,
			TrustedProxyIPs: []string{"192.0.2.7/32"}, AllowedHosts: []string{"app.example.test"}}, "test")
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != 400 {
			t.Fatalf("status %d", recorder.Code)
		}
	}
}
