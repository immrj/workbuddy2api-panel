package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func primeModelCache(t *testing.T, ids ...string) {
	t.Helper()
	infos := make([]upstream.ModelInfo, 0, len(ids))
	for _, id := range ids {
		infos = append(infos, upstream.ModelInfo{ID: id})
	}
	dynamicModelsCache.Lock()
	dynamicModelsCache.ids = infos
	dynamicModelsCache.fetched = time.Now()
	dynamicModelsCache.lastFail = time.Time{}
	dynamicModelsCache.Unlock()
	t.Cleanup(func() {
		dynamicModelsCache.Lock()
		dynamicModelsCache.ids = nil
		dynamicModelsCache.fetched = time.Time{}
		dynamicModelsCache.lastFail = time.Time{}
		dynamicModelsCache.Unlock()
	})
}

func modelIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode models: %v (body=%s)", err, rec.Body.String())
	}
	out := make([]string, 0, len(resp.Data))
	for _, m := range resp.Data {
		out = append(out, m.ID)
	}
	return out
}

// TestModelsAllowedByAPIKey 每个密钥只看到自己的白名单；空白名单仍看全部。
// 过滤发生在动态目录缓存之后，不能把某个 Key 的结果写回全局缓存。
func TestModelsAllowedByAPIKey(t *testing.T) {
	primeModelCache(t, "glm-5.2", "deepseek-v3")
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		return http.StatusOK, `{"data":[]}`, false
	})
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "prod", Key: "sk-prod", Enabled: true, AllowedModels: []string{"cn:glm-5.2"}},
		{Name: "qa", Key: "sk-qa", Enabled: true, AllowedModels: []string{"cn:deepseek-v3"}},
		{Name: "admin", Key: "sk-admin", Enabled: true},
	}})
	h := NewHandler(Config{Pool: p, Upstream: up, Live: live})

	get := func(key string) []string {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("key %s: code=%d body=%s", key, rec.Code, rec.Body.String())
		}
		return modelIDs(t, rec)
	}

	if got := strings.Join(get("sk-prod"), ","); got != "cn:glm-5.2" {
		t.Fatalf("prod models=%s want cn:glm-5.2", got)
	}
	if got := strings.Join(get("sk-qa"), ","); got != "cn:deepseek-v3" {
		t.Fatalf("qa models=%s want cn:deepseek-v3", got)
	}
	if got := strings.Join(get("sk-admin"), ","); got != "cn:glm-5.2,cn:deepseek-v3" {
		t.Fatalf("admin models=%s want full catalog", got)
	}

	// 热更新白名单：下一个请求立即按新集合过滤，且不会污染其他 Key。
	live.Store(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "prod", Key: "sk-prod", Enabled: true, AllowedModels: []string{"cn:deepseek-v3"}},
		{Name: "qa", Key: "sk-qa", Enabled: true, AllowedModels: []string{"cn:deepseek-v3"}},
		{Name: "admin", Key: "sk-admin", Enabled: true},
	}})
	if got := strings.Join(get("sk-prod"), ","); got != "cn:deepseek-v3" {
		t.Fatalf("prod hot reload models=%s want cn:deepseek-v3", got)
	}
	if got := strings.Join(get("sk-admin"), ","); got != "cn:glm-5.2,cn:deepseek-v3" {
		t.Fatalf("admin models changed after prod reload: %s", got)
	}
}

// TestChatModelAllowlistBlocksBeforeUpstream 点名调用在选号/上游之前拦截：
// 被拒绝的模型不消耗账号，不产生 fake upstream 调用；cn: 精确白名单也拒绝
// global: 同名的跨域调用。裸名按 cn 口径匹配。
func TestChatModelAllowlistBlocksBeforeUpstream(t *testing.T) {
	var calls int
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		calls++
		return http.StatusOK, sseOK, true
	})
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: "sk-prod", Enabled: true,
		AllowedModels: []string{"cn:glm-5.2"},
	}}})
	h := NewHandler(Config{Pool: p, Upstream: up, Live: live})

	post := func(model string) *httptest.ResponseRecorder {
		body := `{"model":"` + model + `","stream":true,"messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer sk-prod")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for _, model := range []string{"deepseek-v3", "global:glm-5.2"} {
		rec := post(model)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("model %q: code=%d want 403, body=%s", model, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "model_not_allowed") {
			t.Fatalf("model %q: body missing model_not_allowed: %s", model, rec.Body.String())
		}
	}
	if calls != 0 {
		t.Fatalf("denied models reached upstream %d times", calls)
	}

	for _, model := range []string{"glm-5.2", "cn:glm-5.2"} {
		rec := post(model)
		if rec.Code != http.StatusOK {
			t.Fatalf("model %q: code=%d want 200, body=%s", model, rec.Code, rec.Body.String())
		}
	}
	if calls != 2 {
		t.Fatalf("allowed models upstream calls=%d want 2", calls)
	}

	// 热更新后旧模型立即被拒，不能等到重启。
	live.Store(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: "sk-prod", Enabled: true,
		AllowedModels: []string{"cn:deepseek-v3"},
	}}})
	rec := post("glm-5.2")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("after hot reload code=%d want 403, body=%s", rec.Code, rec.Body.String())
	}
	if calls != 2 {
		t.Fatalf("hot-reload denied model reached upstream: calls=%d", calls)
	}
}

// TestModelAllowlistDisablesCrossRealmFallback 裸名默认走 cn，但 Key 只允许
// cn:glm-5.2 时不能让 pool.cross_domain_fallback 把它偷偷送到 global 域。
func TestModelAllowlistDisablesCrossRealmFallback(t *testing.T) {
	var calls int
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		calls++
		return http.StatusOK, sseOK, true
	})
	up.ChatBaseGlobal = "https://fake-global.example"
	up.BillingBaseGlobal = "https://fake-global.example"
	g := &auth.Auth{UID: "g1", AccessToken: "at-g1", ExpiresAt: 9999999999}
	if _, err := auth.BackfillRealmFor(g, "global"); err != nil {
		t.Fatal(err)
	}
	p := testPoolWith(g)
	p.SetCrossDomainFallback(true)
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: "sk-prod", Enabled: true,
		AllowedModels: []string{"cn:glm-5.2"},
	}}})
	h := NewHandler(Config{Pool: p, Upstream: up, Live: live})

	body := `{"model":"glm-5.2","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-prod")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cn-only key should stay on cn and report no healthy account, code=%d body=%s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no_healthy_account") {
		t.Fatalf("body should be no_healthy_account: %s", rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("cn-only key reached global upstream %d times", calls)
	}
}
