package logfmt

import "testing"

func TestMaskKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"a", "*"},
		{"abc", "***"},
		{"abcdef", "******"},               // len==6：前3+后3 会覆盖全文，必须全掩码
		{"abcdefg", "abc*efg"},             // len==7：恰好一个星号，尾部是末 3 位
		{"sk-abc1234xyz", "sk-*******xyz"}, // len 13 → 13-6=7 个星号
	}
	for _, c := range cases {
		if got := MaskKey(c.in); got != c.want {
			t.Fatalf("MaskKey(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// TestMaskKeyNeverLeaksShortKeys 短密钥必须全掩码。
//
// 这是安全回归点：若边界写成 len<6，len==6 的密钥（如 "sk-1234"）掩码后与原文
// 完全相同，等于把明文写进归档和面板——"看起来有星号"反而更危险，因为没人会
// 再意识到它没被掩码。
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

// TestMaskKeyStarCount 正常长度的星号数量 = len-6（保证长度信息不被刻意保留，
// 也不被放大）。
func TestMaskKeyStarCount(t *testing.T) {
	for _, k := range []string{"abcdefg", "abcdefgh", "abcdefghi"} {
		got := MaskKey(k)
		want := len(k) - 6
		stars := 0
		for _, c := range got {
			if c == '*' {
				stars++
			}
		}
		if stars != want {
			t.Fatalf("MaskKey(%q)=%q 星号数 %d，期望 %d", k, got, stars, want)
		}
	}
}
