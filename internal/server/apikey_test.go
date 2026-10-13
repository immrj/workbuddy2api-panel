package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/httpauth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
)

// newKeyedHandler 造一个只关心鉴权的 Handler：Live 与静态密钥表都可控。
// 走 NewHandler 而不是裸 struct：mux 是在构造时装配的，裸 struct 会在
// ServeHTTP 时对 nil mux 崩溃。
func newKeyedHandler(live *livecfg.Holder, staticKey string, staticKeys []httpauth.APIKey) *Handler {
	return NewHandler(Config{Live: live, APIKey: staticKey, APIKeys: staticKeys})
}

// get 直接打鉴权中间件（而不是 /v1/models 路由）——那些路由要 Pool 与 Upstream，
// 与本文件要验的东西无关，装一堆 nil 依赖只会把测试变成脆弱的替身。
func get(h *Handler, rawKey string) int {
	r := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	if rawKey != "" {
		r.Header.Set("Authorization", "Bearer "+rawKey)
	}
	w := httptest.NewRecorder()
	h.withAuth(func(http.ResponseWriter, *http.Request) {})(w, r)
	return w.Code
}

// TestEmptyLiveTableDisablesAuth 是"删光密钥 = 关闭鉴权"的回归护栏。
//
// 这条曾经被写错过：loadKeys 原本用 len(live.APIKeys) > 0 判断是否该用运行时
// 快照，于是"空表"（=用户关掉了鉴权）会被误判成"没配置"，落回启动期的静态密钥。
// 结果磁盘上空表、面板也认（面板按 Live != nil 判），唯独网关还在用旧密钥 401——
// 两边分裂且无任何报错。判据必须是 Live 是否存在，而不是表里有没有东西。
func TestEmptyLiveTableDisablesAuth(t *testing.T) {
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "prod", Key: "sk-prod-key-value", Enabled: true},
	}})
	h := newKeyedHandler(live, "sk-startup-key-value", nil)

	if got := get(h, "sk-prod-key-value"); got != http.StatusOK {
		t.Fatalf("启用中的密钥应通过，得到 %d", got)
	}

	// 模拟面板保存：删光所有密钥
	live.Store(livecfg.Snapshot{APIKeys: nil})

	if got := get(h, ""); got != http.StatusOK {
		t.Fatalf("密钥表清空后应等于关闭鉴权，匿名请求得到 %d（期望 200）", got)
	}
	if got := get(h, "sk-prod-key-value"); got != http.StatusOK {
		t.Fatalf("关闭鉴权后旧密钥不应再 401，得到 %d", got)
	}
}

// TestLiveTableShadowsStatic 运行时快照一旦存在就完全接管，静态密钥不再兜底。
func TestLiveTableShadowsStatic(t *testing.T) {
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "only", Key: "sk-runtime-only", Enabled: true},
	}})
	h := newKeyedHandler(live, "sk-static-old", nil)

	if got := get(h, "sk-runtime-only"); got != http.StatusOK {
		t.Fatalf("运行时密钥应通过，得到 %d", got)
	}
	if got := get(h, "sk-static-old"); got != http.StatusUnauthorized {
		t.Fatalf("静态密钥已被接管，应 401，得到 %d", got)
	}
}

// TestStaticFallbackWhenNoLive 未装配 Live 时（单测 fixture 的常见形态）
// 必须仍能用静态单键鉴权。
func TestStaticFallbackWhenNoLive(t *testing.T) {
	h := newKeyedHandler(nil, "sk-static-key", nil)

	if got := get(h, "sk-static-key"); got != http.StatusOK {
		t.Fatalf("静态单键应通过，得到 %d", got)
	}
	if got := get(h, "wrong"); got != http.StatusUnauthorized {
		t.Fatalf("错误密钥应 401，得到 %d", got)
	}
}

// TestWithAuthBackfillsMaskedKeyIntoEvent 鉴权成功后的日志回填契约（AC-2）。
//
// 三件事一起钉住：
//  1. 名称回填（身份，供与 usage 的 by_api_key 关联）；
//  2. api_key 落的是**掩码**而不是明文——归档会被备份/传阅，明文凭证不能进去；
//  3. 密钥维度**独立于** logging.request_client_info 开关：关掉来源 IP 采集后
//     密钥仍要填充。用户要的是"谁用哪把密钥调的"，不该被另一个隐私开关连坐。
func TestWithAuthBackfillsMaskedKeyIntoEvent(t *testing.T) {
	const fullKey = "sk-prod-super-secret-value"
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "prod", Key: fullKey, Enabled: true},
	}})
	// RecordClientInfo=false：模拟"关掉来源 IP/UA 记录"的部署
	h := NewHandler(Config{Live: live, RecordClientInfo: false})

	tr := &requestTrace{id: "req-test", start: time.Now()}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer "+fullKey)
	r = r.WithContext(context.WithValue(r.Context(), requestTraceKey{}, tr))

	w := httptest.NewRecorder()
	h.withAuth(func(http.ResponseWriter, *http.Request) {})(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("鉴权应通过，得到 %d", w.Code)
	}

	e := tr.event(http.StatusOK)

	if e.APIKeyName != "prod" {
		t.Fatalf("名称应回填为 prod，实际 %q", e.APIKeyName)
	}
	if want := logfmt.MaskKey(fullKey); e.APIKey != want {
		t.Fatalf("api_key 应为掩码 %q，实际 %q", want, e.APIKey)
	}
	if e.APIKey == fullKey {
		t.Fatal("api_key 落了明文")
	}
	if strings.Contains(e.APIKey, "super-secret") {
		t.Fatalf("掩码里不应出现密钥中部内容：%q", e.APIKey)
	}
	if e.ClientIP != "" || e.UserAgent != "" {
		t.Fatalf("记录来源开关关闭时 client_ip/user_agent 应为空，实际 %q / %q", e.ClientIP, e.UserAgent)
	}
}

// TestWithAuthLeavesEventEmptyWhenNoKeyConfigured 未启用鉴权（空表）时不该凭空
// 造出一个密钥身份：日志里出现 "默认" 会让人以为有把密钥在用。
func TestWithAuthLeavesEventEmptyWhenNoKeyConfigured(t *testing.T) {
	live := livecfg.New(livecfg.Snapshot{APIKeys: nil}) // 空表 = 不鉴权
	h := NewHandler(Config{Live: live})

	tr := &requestTrace{id: "req-test", start: time.Now()}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r = r.WithContext(context.WithValue(r.Context(), requestTraceKey{}, tr))

	w := httptest.NewRecorder()
	h.withAuth(func(http.ResponseWriter, *http.Request) {})(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("空表应放行，得到 %d", w.Code)
	}

	e := tr.event(http.StatusOK)
	if e.APIKey != "" || e.APIKeyName != "" {
		t.Fatalf("未启用鉴权时不应有密钥身份，实际 %q / %q", e.APIKey, e.APIKeyName)
	}
}
