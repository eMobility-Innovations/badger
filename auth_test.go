package badger

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authConfig(url string) *Config {
	return &Config{APIBaseUrl: url, UserSessionCookieName: "lab_session", ResourceSessionRequestParam: "session",
		AccessTokenQueryParam: "access", AccessTokenIDHeader: "X-Token-Id", AccessTokenHeader: "X-Token",
		DisableDefaultCFIPs: true}
}

func TestAuthProtocolAndRedirectCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, path, method, raw string
		data                    map[string]interface{}
		status                  int
		cookie, tls             bool
	}{
		{"valid", "/?session=x&access=y&keep=z", "POST", "", map[string]interface{}{
			"valid": true, "userId": "user-1", "username": "known", "email": "known@example.test",
			"name": "Known", "role": "reader", "virtualApiKeyId": "key-1"}, 204, false, true},
		{"valid-keep", "/?session=x&access=y", "POST", "", map[string]interface{}{"valid": true, "dontStripSession": true}, 204, false, false},
		{"access-redirect", "/?access=y&keep=z", "GET", "", map[string]interface{}{"valid": true}, 302, true, false},
		{"access-only-redirect", "/?access=y", "GET", "", map[string]interface{}{"valid": true}, 302, true, false},
		{"denied", "/", "GET", "", map[string]interface{}{"valid": false}, 401, false, false},
		{"challenge", "/", "GET", "", map[string]interface{}{"headerAuthChallenged": true}, 401, false, false},
		{"challenge-redirect", "/", "GET", "", map[string]interface{}{"headerAuthChallenged": true, "redirectUrl": "https://login.example.test/"}, 401, false, false},
		{"redirect-stays-302", "/?keep=z", "GET", "", map[string]interface{}{"redirectUrl": "https://login.example.test/", "redirectPermanent": true}, 302, false, false},
		{"client-error-default", "/", "GET", "", map[string]interface{}{"clientError": map[string]interface{}{"body": "denied"}}, 401, false, false},
		{"client-error-explicit", "/", "GET", "", map[string]interface{}{"clientError": map[string]interface{}{"body": "denied", "statusCode": 403, "contentType": "text/plain"}}, 403, false, false},
		{"bad-json", "/", "GET", "bad", nil, 500, false, false},
		{"bad-upstream", "/", "GET", "status", nil, 500, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input VerifyBody
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				if input.RequestIP == nil || *input.RequestIP != "203.0.113.9" || (strings.HasSuffix(r.URL.Path, "verify-session") && input.BadgerVersion != "1.7.0") {
					t.Error("auth request lost canonical client or support version")
				}
				if test.raw == "status" {
					w.WriteHeader(503)
					return
				}
				if test.raw == "bad" {
					w.Write([]byte("invalid"))
					return
				}
				if test.cookie {
					w.Header().Set("Set-Cookie", "lab_session=new; HttpOnly")
				}
				test.data["responseHeaders"] = map[string]string{"X-Lab-Auth": "checked"}
				json.NewEncoder(w).Encode(map[string]interface{}{"data": test.data})
			}))
			defer api.Close()
			request := httptest.NewRequest(test.method, "http://app.example.test"+test.path, nil)
			request.RemoteAddr = "203.0.113.9:1234"
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			request.Header.Set("Cookie", "lab_session=fixture; keep=yes")
			request.Header.Set("Remote-User", "forged")
			request.Header.Set("X-Token", "fixture")
			request.Header.Set("X-Token-Id", "fixture-id")
			called := false
			handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if test.name == "valid" {
					if r.Header.Get("Remote-User") != "known" || r.Header.Get("Remote-User-Id") != "user-1" {
						t.Error("auth claims not authoritative")
					}
					if r.URL.Query().Has("access") || r.URL.Query().Has("session") || strings.Contains(r.Header.Get("Cookie"), "lab_session") || r.Header.Get("X-Token") != "" {
						t.Error("session material reached origin")
					}
					if r.Header.Get("Cookie") != "keep=yes" {
						t.Error("unrelated cookie lost")
					}
				}
				if test.name == "valid-keep" && !r.URL.Query().Has("access") {
					t.Error("dontStripSession ignored")
				}
				w.WriteHeader(204)
			}), authConfig(api.URL), "test")
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status %d, expected %d: %s", recorder.Code, test.status, recorder.Body.String())
			}
			if called != (test.status == 204) {
				t.Error("auth boundary crossed incorrectly")
			}
			if test.name == "redirect-stays-302" && recorder.Header().Get("Location") != "https://login.example.test/" {
				t.Error("redirect target changed")
			}
		})
	}
}

func TestExchangeSessionProtocol(t *testing.T) {
	for _, mode := range []string{"cookie-query", "cookie-only", "fallthrough", "invalid", "network"} {
		t.Run(mode, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "verify-session") {
					json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]bool{"valid": true}})
					return
				}
				var input ExchangeSessionBody
				json.NewDecoder(r.Body).Decode(&input)
				if input.RequestIP == nil || *input.RequestIP != "203.0.113.9" {
					t.Error("exchange lost canonical client")
				}
				if mode == "invalid" {
					w.Write([]byte("invalid"))
					return
				}
				data := map[string]interface{}{}
				if strings.HasPrefix(mode, "cookie") {
					data["cookie"] = "lab_session=new"
					data["responseHeaders"] = map[string]string{"X-Lab": "exchange"}
				}
				json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
			}))
			defer api.Close()
			if mode == "network" {
				api.Close()
			}
			path := "http://app.example.test/?session=fixture"
			if mode == "cookie-query" {
				path += "&keep=yes"
			}
			request := httptest.NewRequest("GET", path, nil)
			request.RemoteAddr = "203.0.113.9:1234"
			handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), authConfig(api.URL), "test")
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			expected := 302
			if mode == "fallthrough" {
				expected = 204
			}
			if mode == "invalid" || mode == "network" {
				expected = 500
			}
			if recorder.Code != expected {
				t.Fatalf("status %d, expected %d", recorder.Code, expected)
			}
			if strings.HasPrefix(mode, "cookie") && (recorder.Header().Get("Set-Cookie") == "" || strings.Contains(recorder.Header().Get("Location"), "session=")) {
				t.Error("exchange redirect/cookie contract broken")
			}
		})
	}
}

func TestConfigValidationAndIdentityErrors(t *testing.T) {
	for _, config := range []*Config{CreateConfig(), {APIBaseUrl: "http://example.test"},
		{APIBaseUrl: "http://example.test", UserSessionCookieName: "x"},
		{DisableForwardAuth: true, TrustIP: []string{"invalid"}},
		{DisableForwardAuth: true, TrustedProxyIPs: []string{"invalid"}}} {
		if _, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test"); err == nil {
			t.Error("invalid config admitted")
		}
	}
	config := authConfig("http://127.0.0.1:0")
	config.DisableDefaultCFIPs = false
	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://app.example.test/", nil)
	request.RemoteAddr = "203.0.113.9:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 500 {
		t.Error("unreachable auth must fail closed")
	}
}
