// Package keyquota 记录 API 密钥每日已结算积分，供网关做轻量额度判断。
//
// 这里刻意只记录“上游已经返回 usage.credit”的消费，不在请求前预估或预留额度：
// 因此达到上限后，下一条请求会被拒绝，但触发上限的那一条请求仍可能把额度小幅
// 超出。要保证严格不超需要另做请求级预留或单密钥串行。
//
// 账本按密钥值的 SHA-256 指纹归属，而不是按可变的展示名：面板改名不会重置当天
// 用量，替换密钥值则会自然得到一份新额度。落盘文件不含密钥明文。
package keyquota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	fileVersion   = 1
	flushInterval = 2 * time.Second
	dayLayout     = "2006-01-02"
)

type entry struct {
	Day     string  `json:"day"`
	Credits float64 `json:"credits"`
}

type file struct {
	Version int              `json:"version"`
	Saved   string           `json:"saved"`
	Keys    map[string]entry `json:"keys"`
}

// Ledger 并发安全的每日密钥积分账本。
type Ledger struct {
	mu      sync.Mutex
	path    string
	entries map[string]entry
	dirty   bool

	writeMu sync.Mutex
	startMu sync.Mutex
	started bool

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New 创建账本。path 为空时仅保存在内存，供测试或无持久化场景使用。
func New(path string) *Ledger {
	l := &Ledger{
		path:    path,
		entries: map[string]entry{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if path != "" {
		if err := l.load(); err != nil {
			log.Printf("[keyquota] 读取 %s 失败（从零开始）: %v", path, err)
		}
	}
	return l
}

// Start 启动防抖落盘。path 为空时不启动后台 goroutine。
func (l *Ledger) Start() {
	if l == nil || l.path == "" {
		return
	}
	l.startMu.Lock()
	if l.started {
		l.startMu.Unlock()
		return
	}
	l.started = true
	l.startMu.Unlock()

	go func() {
		defer close(l.done)
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				l.flush(true)
				return
			case <-t.C:
				l.flush(false)
			}
		}
	}()
}

// Stop 停止后台循环并做最后一次落盘。未 Start 时仅同步保存一次。
func (l *Ledger) Stop() {
	if l == nil {
		return
	}
	l.startMu.Lock()
	started := l.started
	l.startMu.Unlock()
	if !started {
		l.Save()
		return
	}
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
}

// Fingerprint 返回密钥值的稳定、不可逆归属标识。
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NextReset 返回 now 所在本地自然日的下一日 00:00。
func NextReset(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}

// Used 返回密钥在当前本地自然日的已结算积分。
func (l *Ledger) Used(secret string, now time.Time) float64 {
	return l.UsedID(Fingerprint(secret), now)
}

// UsedID 返回指定指纹在当前本地自然日的已结算积分。
func (l *Ledger) UsedID(id string, now time.Time) float64 {
	if l == nil || id == "" {
		return 0
	}
	day := now.Format(dayLayout)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[id]
	if !ok || e.Day != day {
		if ok {
			delete(l.entries, id)
			l.dirty = true
		}
		return 0
	}
	return e.Credits
}

// Settle 把一次已结算积分记到密钥名下。
func (l *Ledger) Settle(secret string, now time.Time, credits float64) {
	l.SettleID(Fingerprint(secret), now, credits)
}

// SettleID 把一次已结算积分记到指定指纹名下。
func (l *Ledger) SettleID(id string, now time.Time, credits float64) {
	if l == nil || id == "" || credits <= 0 || math.IsNaN(credits) || math.IsInf(credits, 0) {
		return
	}
	day := now.Format(dayLayout)
	l.mu.Lock()
	e, ok := l.entries[id]
	if !ok || e.Day != day {
		e = entry{Day: day}
	}
	e.Credits += credits
	l.entries[id] = e
	l.dirty = true
	l.mu.Unlock()
}

// Save 立即落盘。
func (l *Ledger) Save() {
	l.flush(true)
}

func (l *Ledger) load() error {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	for id, e := range f.Keys {
		if id == "" || e.Day == "" || e.Credits < 0 || math.IsNaN(e.Credits) || math.IsInf(e.Credits, 0) {
			continue
		}
		l.entries[id] = e
	}
	log.Printf("[keyquota] 已恢复 %d 个密钥额度账本（%s）", len(l.entries), l.path)
	return nil
}

func (l *Ledger) flush(force bool) {
	if l == nil || l.path == "" {
		return
	}
	l.mu.Lock()
	if !l.dirty && !force {
		l.mu.Unlock()
		return
	}
	f := file{
		Version: fileVersion,
		Saved:   time.Now().Format(time.RFC3339),
		Keys:    make(map[string]entry, len(l.entries)),
	}
	for id, e := range l.entries {
		f.Keys[id] = e
	}
	l.dirty = false
	l.mu.Unlock()

	l.writeMu.Lock()
	defer l.writeMu.Unlock()

	raw, err := json.Marshal(f)
	if err != nil {
		l.markDirty()
		log.Printf("[keyquota] 序列化失败: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		l.markDirty()
		log.Printf("[keyquota] 建目录失败: %v", err)
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		l.markDirty()
		log.Printf("[keyquota] 写临时文件失败: %v", err)
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		l.markDirty()
		log.Printf("[keyquota] 原子替换失败: %v", err)
	}
}

func (l *Ledger) markDirty() {
	l.mu.Lock()
	l.dirty = true
	l.mu.Unlock()
}
