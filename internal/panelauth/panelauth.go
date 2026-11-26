// Package panelauth 管理面板的独立用户名密码认证、内存会话与登录限流。
//
// 该包只服务 /panel/*，不参与网关 /v1/* 的 API Key 校验。会话使用不透明随机
// token，服务端保存到期时间；Cookie 只放 token，不放用户名、密码或签名载荷。
package panelauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// CookieName 面板会话 Cookie 名。Path 固定 /panel，浏览器不会把它带到 /v1/*。
	CookieName = "wb2api_panel_session"

	defaultSessionTTL = 12 * time.Hour
	loginWindow       = 15 * time.Minute
	maxLoginFailures  = 5
	loginBlockTime    = 15 * time.Minute
	// 每个 Argon2id 验证会分配 64 MiB；限制并发，避免公开登录端点被并发请求打爆内存。
	maxConcurrentVerifications = 2
)

var (
	// ErrInvalidCredentials 用户名或密码错误。调用方只回通用文案，不区分是哪一项错。
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// RateLimitError 登录尝试过多。
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return "too many login attempts" }

// Config 面板认证配置。
type Config struct {
	Enabled      bool
	Username     string
	PasswordHash string
	SessionTTL   time.Duration
	AllowAPIKey  bool
}

// Session 服务端会话快照。
type Session struct {
	Username  string
	CSRFToken string
	ExpiresAt time.Time
}

type attempt struct {
	firstFailure time.Time
	failures     int
	blockedUntil time.Time
}

// Service 并发安全的面板认证器。
type Service struct {
	mu       sync.Mutex
	cfg      Config
	sessions map[string]Session
	attempts map[string]attempt
	now      func() time.Time
	verifyCh chan struct{}
}

// New 构建认证器。Enabled=false 时保留空服务，便于运行期热启用。
func New(cfg Config) (*Service, error) {
	s := &Service{
		sessions: make(map[string]Session),
		attempts: make(map[string]attempt),
		now:      time.Now,
		verifyCh: make(chan struct{}, maxConcurrentVerifications),
	}
	if _, err := s.Update(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Update 热更新认证配置。密码或用户名变化时清空全部会话与限流计数；
// 仅调整 TTL / API Key 兼容开关时保留现有会话。
func (s *Service) Update(cfg Config) (bool, error) {
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.PasswordHash = strings.TrimSpace(cfg.PasswordHash)
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.Enabled {
		if cfg.Username == "" {
			return false, errors.New("panel_auth.username 不能为空")
		}
		if len(cfg.Username) > 64 {
			return false, errors.New("panel_auth.username 长度不能超过 64")
		}
		if strings.ContainsAny(cfg.Username, "\r\n\x00") {
			return false, errors.New("panel_auth.username 含非法控制字符")
		}
		if cfg.PasswordHash == "" {
			return false, errors.New("panel_auth.password_hash 不能为空")
		}
		if err := ValidateHash(cfg.PasswordHash); err != nil {
			return false, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invalidated := s.cfg.Username != cfg.Username ||
		s.cfg.PasswordHash != cfg.PasswordHash ||
		(s.cfg.Enabled && !cfg.Enabled)
	s.cfg = cfg
	if invalidated {
		s.sessions = make(map[string]Session)
		s.attempts = make(map[string]attempt)
	}
	return invalidated, nil
}

// Enabled 是否启用用户名密码登录。
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Enabled
}

// AllowAPIKey 是否允许旧 Bearer API Key 访问面板。
func (s *Service) AllowAPIKey() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Enabled && s.cfg.AllowAPIKey
}

// Login 校验用户名密码并创建会话。clientKey 用于登录限流（通常是客户端 IP）。
func (s *Service) Login(username, password, clientKey string) (string, Session, error) {
	now := s.now()
	username = strings.TrimSpace(username)
	key := strings.ToLower(username) + "\x00" + clientKey

	s.mu.Lock()
	s.cleanupLocked(now)
	if a, ok := s.attempts[key]; ok && now.Before(a.blockedUntil) {
		retry := a.blockedUntil.Sub(now)
		s.mu.Unlock()
		return "", Session{}, &RateLimitError{RetryAfter: retry}
	}
	cfg := s.cfg
	s.mu.Unlock()

	// 用户名比对与密码校验都保持固定形状：即使用户名不对也照常跑一次 Argon2id，
	// 避免响应耗时泄露账号是否存在。
	userOK := constantTimeEqual(username, cfg.Username)
	select {
	case s.verifyCh <- struct{}{}:
	default:
		// 验证槽已满时直接拒绝，不让大量公开登录请求无限排队占住连接。
		return "", Session{}, &RateLimitError{RetryAfter: time.Second}
	}
	passOK := verifyPassword(password, cfg.PasswordHash)
	<-s.verifyCh
	if !cfg.Enabled || !userOK || !passOK {
		s.recordFailure(key, now)
		return "", Session{}, ErrInvalidCredentials
	}

	token, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	s.mu.Lock()
	// 验证 Argon2id 期间配置可能被热更新（例如轮换密码）。若凭据已变化，
	// 不能用旧密码创建新会话；否则密码轮换会留下一个短暂的绕过窗口。
	if s.cfg.Username != cfg.Username ||
		s.cfg.PasswordHash != cfg.PasswordHash ||
		s.cfg.Enabled != cfg.Enabled {
		s.mu.Unlock()
		return "", Session{}, ErrInvalidCredentials
	}
	sess := Session{
		Username:  s.cfg.Username,
		CSRFToken: csrf,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	delete(s.attempts, key)
	s.sessions[token] = sess
	s.mu.Unlock()
	return token, sess, nil
}

// Authenticate 按 Cookie token 取会话；过期会话顺手删除。
func (s *Service) Authenticate(token string) (Session, bool) {
	if s == nil || token == "" {
		return Session{}, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if !now.Before(sess.ExpiresAt) {
		delete(s.sessions, token)
		return Session{}, false
	}
	return sess, true
}

// Logout 删除会话。不存在也视为成功。
func (s *Service) Logout(token string) {
	if s == nil || token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// VerifyCSRF 校验会话绑定的 CSRF token。
func (s *Service) VerifyCSRF(sess Session, token string) bool {
	if sess.CSRFToken == "" || token == "" {
		return false
	}
	return constantTimeEqual(token, sess.CSRFToken)
}

// NewCookie 生成面板会话 Cookie。
func NewCookie(token string, expires time.Time, secure bool) *http.Cookie {
	ttl := time.Until(expires)
	if ttl <= 0 {
		ttl = time.Second
	}
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/panel",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl / time.Second),
		Expires:  expires,
	}
}

// ClearCookie 返回立即过期 Cookie。
func ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/panel",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	}
}

func (s *Service) recordFailure(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[key]
	if a.firstFailure.IsZero() || now.Sub(a.firstFailure) > loginWindow {
		a = attempt{firstFailure: now}
	}
	a.failures++
	if a.failures >= maxLoginFailures {
		a.blockedUntil = now.Add(loginBlockTime)
	}
	s.attempts[key] = a
}

func (s *Service) cleanupLocked(now time.Time) {
	for token, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
	for key, a := range s.attempts {
		if !a.blockedUntil.IsZero() {
			if now.Before(a.blockedUntil) {
				continue
			}
			delete(s.attempts, key)
			continue
		}
		if now.Sub(a.firstFailure) > loginWindow {
			delete(s.attempts, key)
		}
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// constantTimeEqual 先摘要再比较，长度差异也会被吸收，避免按字符串长度提前返回。
func constantTimeEqual(a, b string) bool {
	da := sha256.Sum256([]byte(a))
	db := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}
