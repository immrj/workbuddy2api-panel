// Package httpauth 网关与面板共用的 Bearer 鉴权原语。
//
// 单独成包的原因：server（/v1/*、/status）与 panel（/panel/api/*）两处鉴权
// 必须完全同口径——此前各自复制了一份"字符串直接比较"的实现，既容易漂移，
// 又都带计时侧信道。统一到这里后，口径只有一份，且天然常量时间比较。
package httpauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// bearerPrefix 认证方案前缀（大小写敏感，与 HTTP 规范及既有实现一致）。
const bearerPrefix = "Bearer "

// VerifyBearer 校验请求头是否携带正确的 Bearer 密钥。
//
// key 为空表示"未启用鉴权"，恒返回 true（调用方据此放行）。
// 比较用 SHA-256 摘要 + subtle.ConstantTimeCompare：
//   - 常量时间，不因前缀匹配长度而泄露信息；
//   - 先摘要再比较，长度差异被吸收进摘要（不会因长度不同提前返回）；
//   - 摘要本身不可逆，即便有侧信道也拿不到密钥原文。
func VerifyBearer(r *http.Request, key string) bool {
	if key == "" {
		return true
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, bearerPrefix) {
		// 缺头/方案不对：仍走一次摘要比较，保持耗时形状一致。
		subtle.ConstantTimeCompare(digest(""), digest(key))
		return false
	}
	tok := authz[len(bearerPrefix):]
	return subtle.ConstantTimeCompare(digest(tok), digest(key)) == 1
}

// digest 返回 s 的 SHA-256（定长 32 字节，供常量时间比较）。
func digest(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// APIKey 一条网关密钥。
//
// Name 是用户自取的展示名（"prod" / "staging"），**不是机密**：它会进请求日志与
// 用量维度，用于回答"这条请求是谁发起的"。Key 才是机密，只在面板配置页明文展示，
// 进日志一律经 logfmt.MaskKey 掩码。
type APIKey struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

// VerifyAnyBearer 在候选密钥表中校验 Bearer，返回命中的那一条。
//
// 语义与单键版 VerifyBearer 对齐：**没有任何 enabled 密钥 = 未启用鉴权**，恒放行
// （保持既有 api_key == "" 的行为，改造不得让"不鉴权"这条路退化）。
//
// 为什么循环里不 break（时序考量）：
//
//	每轮循环的工作量（一次 SHA-256 + 一次 ConstantTimeCompare）与被比较的内容无关，
//	所以 trip count 恒等于表长，**命中第几个不会通过耗时体现出来**——这正是
//	不 break 的收益：省掉"命中即返回"引入的耗时差异。
//	代价是未命中与命中都要扫全表。对 N 个密钥（人工维护，量级为个位数到几十）
//	完全可以接受，换来的是与单键实现同口径的抗侧信道特性。
//	表为空时提前返回 O(1) 不会造成问题：「是否启用鉴权」本来就是公开信息
//	（README 记载、面板登录页会提示、/healthz 的 service 字段可判别），
//	攻击者无需靠计时侧信道去猜它。
func VerifyAnyBearer(r *http.Request, table []APIKey) (APIKey, bool) {
	if !HasEnabled(table) {
		return APIKey{}, true
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, bearerPrefix) {
		// 缺头/方案不对：仍走满一轮比较，保持耗时形状一致。
		for _, k := range table {
			if !k.Enabled {
				continue
			}
			subtle.ConstantTimeCompare(digest(""), digest(k.Key))
		}
		return APIKey{}, false
	}
	tok := authz[len(bearerPrefix):]
	var found *APIKey
	for i := range table {
		k := &table[i]
		if !k.Enabled {
			continue
		}
		// 命中不 break：继续比较剩余候选，使耗时与命中位置无关（见上）。
		if subtle.ConstantTimeCompare(digest(tok), digest(k.Key)) == 1 {
			found = k
		}
	}
	if found == nil {
		return APIKey{}, false
	}
	return *found, true
}

// HasEnabled 表中是否存在启用的密钥。空表 / 全禁用 = 未启用鉴权。
func HasEnabled(table []APIKey) bool {
	for i := range table {
		if table[i].Enabled {
			return true
		}
	}
	return false
}
