// auth.go 面板用户名密码登录、会话状态与退出接口。
package panel

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/httpauth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/panelauth"
)

const maxLoginBody = 8 << 10

func methodNeedsCSRF(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (p *Panel) sessionFromRequest(r *http.Request) (panelauth.Session, bool) {
	if p.cfg.PanelAuth == nil {
		return panelauth.Session{}, false
	}
	c, err := r.Cookie(panelauth.CookieName)
	if err != nil || c.Value == "" {
		return panelauth.Session{}, false
	}
	return p.cfg.PanelAuth.Authenticate(c.Value)
}

func (p *Panel) apiKeyFallbackKeys() []httpauth.APIKey {
	if p.cfg.PanelAuth == nil || !p.cfg.PanelAuth.AllowAPIKey() {
		return nil
	}
	keys := p.apiKeys()
	if !httpauth.HasEnabled(keys) {
		return nil
	}
	return keys
}

// authSession 公开的轻量状态端点：用于页面启动时决定显示密码登录还是旧密钥弹窗。
// 未认证时只暴露"是否配置了面板登录"和是否允许 API Key 兼容，不暴露用户名/哈希。
func (p *Panel) authSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if p.cfg.PanelAuth != nil && p.cfg.PanelAuth.Enabled() {
		if sess, ok := p.sessionFromRequest(r); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"configured":    true,
				"authenticated": true,
				"method":        "password",
				"username":      sess.Username,
				"csrf_token":    sess.CSRFToken,
				"expires_at":    sess.ExpiresAt.UTC().Format(time.RFC3339),
				"allow_api_key": len(p.apiKeyFallbackKeys()) > 0,
			})
			return
		}
		// 注意：这里故意不拿 Authorization 自动建立“已登录”状态。password 模式
		// 下用户名密码是主入口；allow_api_key 只是 /panel/api/* 的脚本兼容通道，
		// 用户仍可在登录弹窗里显式输入密钥进入。
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":    true,
			"authenticated": false,
			"method":        "password",
			"allow_api_key": len(p.apiKeyFallbackKeys()) > 0,
		})
		return
	}

	keys := p.apiKeys()
	required := httpauth.HasEnabled(keys)
	if !required {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":    false,
			"authenticated": true,
			"method":        "none",
			"allow_api_key": false,
		})
		return
	}
	if _, ok := httpauth.VerifyAnyBearer(r, keys); ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":    false,
			"authenticated": true,
			"method":        "api_key",
			"allow_api_key": true,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":    false,
		"authenticated": false,
		"method":        "api_key",
		"allow_api_key": true,
	})
}

func (p *Panel) authLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if p.cfg.PanelAuth == nil || !p.cfg.PanelAuth.Enabled() {
		writeErr(w, http.StatusNotFound, "panel_auth_disabled")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxLoginBody))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if body.Username == "" || body.Password == "" {
		writeErr(w, http.StatusBadRequest, "username_and_password_required")
		return
	}
	client := authClientIP(r)
	token, sess, err := p.cfg.PanelAuth.Login(body.Username, body.Password, client)
	if err != nil {
		var rl *panelauth.RateLimitError
		if errors.As(err, &rl) {
			sec := int(rl.RetryAfter.Round(time.Second) / time.Second)
			if sec < 1 {
				sec = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(sec))
			log.Printf("panel: 登录限流 client=%s", client)
			writeErr(w, http.StatusTooManyRequests, "too_many_login_attempts")
			return
		}
		if !errors.Is(err, panelauth.ErrInvalidCredentials) {
			log.Printf("panel: 登录内部错误 client=%s: %v", client, err)
			writeErr(w, http.StatusInternalServerError, "login_failed")
			return
		}
		log.Printf("panel: 登录失败 client=%s", client)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	http.SetCookie(w, panelauth.NewCookie(token, sess.ExpiresAt, requestIsHTTPS(r)))
	log.Printf("panel: 用户 %q 登录成功 client=%s", sess.Username, client)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"username":   sess.Username,
		"csrf_token": sess.CSRFToken,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (p *Panel) authLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if p.cfg.PanelAuth != nil {
		if c, err := r.Cookie(panelauth.CookieName); err == nil {
			p.cfg.PanelAuth.Logout(c.Value)
		}
	}
	http.SetCookie(w, panelauth.ClearCookie())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Scheme")), "https")
}

// authClientIP 登录限流用的客户端标识。刻意只取 TCP 对端：X-Forwarded-For
// 可由客户端伪造，不能作为限流键；反代部署下按代理 IP + 用户名限流仍有效。
func authClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return host
}
