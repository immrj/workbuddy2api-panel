package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/panelauth"
)

func passwordPanel(t *testing.T, allowAPIKey bool) *Panel {
	t.Helper()
	hash, err := panelauth.HashPasswordWithParams("correct-password", panelauth.HashParams{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := panelauth.New(panelauth.Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: hash,
		SessionTTL:   0,
		AllowAPIKey:  allowAPIKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Version: "test", APIKey: "legacy-key", PanelAuth: svc})
}

func loginPanel(t *testing.T, p *Panel) (*http.Cookie, string) {
	t.Helper()
	body := `{"username":"admin","password":"correct-password"}`
	req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a cookie")
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.CSRFToken == "" {
		t.Fatal("login returned empty csrf token")
	}
	return cookies[0], out.CSRFToken
}

func TestPasswordAuthLoginAndCSRF(t *testing.T) {
	p := passwordPanel(t, false)

	// 未登录：受保护接口 401，状态端点只报告未认证且不泄露用户名。
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/api/logs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous logs code=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/api/auth/session", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("status leaked auth details: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 错误密码统一 401。
	bad := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"wrong"}`))
	bad.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login code=%d", rec.Code)
	}

	cookie, csrf := loginPanel(t, p)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/panel" {
		t.Fatalf("cookie flags = %+v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/panel/api/logs", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session logs code=%d body=%s", rec.Code, rec.Body.String())
	}

	// POST 无 CSRF：必须在进入 handler 前 403。
	req = httptest.NewRequest(http.MethodPost, "/panel/api/config", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "invalid_csrf_token") {
		t.Fatalf("missing csrf code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 带 CSRF 后通过鉴权层；handler 因未注入 SaveConfig 返回 501。
	req = httptest.NewRequest(http.MethodPost, "/panel/api/config", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("valid csrf code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 退出后旧 Cookie 立即失效。
	req = httptest.NewRequest(http.MethodPost, "/panel/api/auth/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout code=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/panel/api/logs", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after logout code=%d", rec.Code)
	}
}

func TestPasswordAuthAPIKeyFallbackSwitch(t *testing.T) {
	for _, allow := range []bool{false, true} {
		p := passwordPanel(t, allow)
		req := httptest.NewRequest(http.MethodGet, "/panel/api/logs", nil)
		req.Header.Set("Authorization", "Bearer legacy-key")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		want := http.StatusUnauthorized
		if allow {
			want = http.StatusOK
		}
		if rec.Code != want {
			t.Fatalf("allow=%v code=%d want=%d", allow, rec.Code, want)
		}
	}
}

func TestPasswordModeKeepsPasswordAsPrimaryLogin(t *testing.T) {
	p := passwordPanel(t, true)
	req := httptest.NewRequest(http.MethodGet, "/panel/api/auth/session", nil)
	req.Header.Set("Authorization", "Bearer legacy-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d", rec.Code)
	}
	var out struct {
		Authenticated bool   `json:"authenticated"`
		AllowAPIKey   bool   `json:"allow_api_key"`
		Method        string `json:"method"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Authenticated || !out.AllowAPIKey || out.Method != "password" {
		t.Fatalf("status=%+v", out)
	}
}

func TestPasswordAuthDoesNotBypassWhenNoGatewayKeys(t *testing.T) {
	hash, err := panelauth.HashPasswordWithParams("correct-password", panelauth.HashParams{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := panelauth.New(panelauth.Config{
		Enabled: true, Username: "admin", PasswordHash: hash, AllowAPIKey: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := New(Config{PanelAuth: svc})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/api/logs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty gateway key table bypassed password auth: code=%d", rec.Code)
	}
}

func TestLegacyAuthStatusUsesAPIKey(t *testing.T) {
	p := newTestPanel()
	req := httptest.NewRequest(http.MethodGet, "/panel/api/auth/session", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d", rec.Code)
	}
	var out struct {
		Authenticated bool   `json:"authenticated"`
		Method        string `json:"method"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Authenticated || out.Method != "api_key" {
		t.Fatalf("status=%+v", out)
	}
}

func TestPasswordAuthSecureCookieBehindProxy(t *testing.T) {
	p := passwordPanel(t, false)
	body := `{"username":"admin","password":"correct-password"}`
	req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].Secure {
		t.Fatalf("expected Secure cookie behind TLS proxy, got %+v", cookies)
	}
}

func TestPasswordAuthRateLimitHTTP(t *testing.T) {
	p := passwordPanel(t, false)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d code=%d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"correct-password"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit code=%d retry=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
}
