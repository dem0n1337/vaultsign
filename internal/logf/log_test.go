package logf

import "testing"

func TestRedact(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"token hvs.CAESIabcDEF123_-xyz", "token hvs.***REDACTED***"},
		{"hvb.AAAAAQ123", "hvb.***REDACTED***"},
		{"hvr.recovery999", "hvr.***REDACTED***"},
		{"legacy s.0123456789abcdefghij token", "legacy s.***REDACTED*** token"},
		{"no secrets here", "no secrets here"},
		{"short s.tooshort stays", "short s.tooshort stays"},
	}
	for _, c := range cases {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
