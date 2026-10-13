// Package livecfg 运行期可变配置的并发安全持有者。
//
// 背景：进程启动时读入的配置是普通字段（读多写零），但管理面板允许在线改配置，
// 于是少量"可热生效"的字段需要有并发安全的读写点。此处用不可变快照 + atomic 指针：
// 读方 Load 拿到一致视图，写方 Store 整体替换，无锁无数据竞争。
//
// 只承载**读路径深、热改需求强**的少数字段；池参数/排程参数等各有既有 setter
// （pool.SetBreaker、scheduler.Reconfigure 等），不重复收编到这里。
package livecfg

import (
	"sync/atomic"
	"time"
)

// APIKey 一条鉴权密钥（与 httpauth.APIKey 同形，让本包不必依赖网关包）。
type APIKey struct {
	Name    string
	Key     string
	Enabled bool
}

// Snapshot 一次读取的不可变配置视图。
type Snapshot struct {
	APIKeys              []APIKey      // 网关/面板共同鉴权密钥表；无启用项 = 不鉴权
	SoftCooldown         time.Duration // 429 软冷却基数（<=0 时调用方回退内置默认）
	SanitizeFingerprints bool          // 出站请求体指纹脱敏
	RecordClientInfo     bool          // 请求日志是否记录调用来源（客户端 IP / UA）
}

// Holder 原子持有当前快照。
type Holder struct {
	p atomic.Pointer[Snapshot]
}

// New 以初始快照构建。
func New(s Snapshot) *Holder {
	h := &Holder{}
	h.Store(s)
	return h
}

// Load 返回当前快照（Holder 为 nil 或从未 Store 时返回零值快照，调用方无需判空）。
//
// APIKeys 切片**在返回前拷贝**：Snapshot 是值拷贝（*s），但切片头会让读者与
// Holder 内部共享同一块底层数组——面板渲染密钥列表时若对返回值做 sort.Slice，
// 就会与每个并发请求的数据竞争。拷贝必须在 Load 侧：Store 收到的切片可能已被
// 别处持有，替它拷贝保护不了读者；只有读者侧拷贝才能兑现"快照不可变"。
func (h *Holder) Load() Snapshot {
	if h == nil {
		return Snapshot{}
	}
	s := h.p.Load()
	if s == nil {
		return Snapshot{}
	}
	out := *s
	if len(s.APIKeys) > 0 {
		out.APIKeys = make([]APIKey, len(s.APIKeys))
		copy(out.APIKeys, s.APIKeys)
	}
	return out
}

// Store 整体替换快照。
func (h *Holder) Store(s Snapshot) { h.p.Store(&s) }
