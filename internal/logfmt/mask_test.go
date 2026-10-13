package logfmt

import "testing"

func TestMaskKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		// len<=6：前 3 与后 3 会重叠（len=6 时掩码与原文完全相同），一律只出 4 星
		{"a", "****"},
		{"abc", "****"},
		{"abcdef", "****"},
		// 正常长度：首 3 + 固定 4 星 + 末 3
		{"abcdefg", "abc****efg"},
		{"sk-abc1234xyz", "sk-****xyz"},
		{"sk-prod-abcdef123456", "sk-****456"},
	}
	for _, c := range cases {
		if got := MaskKey(c.in); got != c.want {
			t.Fatalf("MaskKey(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// TestMaskKeyNeverLeaksShortKeys 短密钥必须全掩码。
//
// 安全回归点：若边界写成 len<6，len==6 的密钥掩码后与原文完全相同，等于把明文
// 写进归档和面板——"看起来有星号"反而更危险，因为没人会再意识到它没被掩码。
func TestMaskKeyNeverLeaksShortKeys(t *testing.T) {
	for _, k := range []string{"a", "ab", "abc", "abcd", "abcde", "abcdef"} {
		got := MaskKey(k)
		if got == k {
			t.Fatalf("MaskKey(%q) 未掩码，等于泄露明文", k)
		}
		for i := 0; i < len(got); i++ {
			if got[i] != '*' {
				t.Fatalf("MaskKey(%q)=%q 含明文字符", k, got)
			}
		}
	}
}

// TestMaskKeyStarCountIsFixed 星号数恒为 4，**与密钥长度无关**。
//
// 这是本次改动的核心不变量：变形前是 len-6，会把密钥长度直接暴露在日志里
// （15 星 vs 1 星一眼看出密钥多长）。固定 4 星既消掉这个泄露，也让日志那一列
// 天然对齐。回归点：任何人把它改回 strings.Repeat("*", len(k)-6) 都必须 FAIL。
func TestMaskKeyStarCountIsFixed(t *testing.T) {
	for _, k := range []string{"abcdefg", "abcdefgh", "sk-short123", "sk-a-very-long-key-value-here-1234567890"} {
		got := MaskKey(k)
		stars := 0
		for _, c := range got {
			if c == '*' {
				stars++
			}
		}
		if stars != 4 {
			t.Fatalf("MaskKey(%q)=%q 星号数 %d，期望固定 4", k, got, stars)
		}
	}
}

// TestMaskKeyHidesLength 掩码不得暴露密钥长度：长度不同的密钥，掩码长度必须相同
// （首 3 + 4 星 + 末 3 = 常量宽度）。
func TestMaskKeyHidesLength(t *testing.T) {
	short := MaskKey("abcdefg")                               // 7 位
	long := MaskKey("sk-" + string(make([]byte, 40)) + "xyz") // 46 位
	if len(short) != len(long) {
		t.Fatalf("掩码宽度应恒定，短=%d 长=%d（长度被泄露）", len(short), len(long))
	}
	if len(short) != 10 {
		t.Fatalf("掩码宽度应为 3+4+3=10，实际 %d", len(short))
	}
}
