package idna

import (
	"strings"
	"testing"
)

// TestToALabels checks the U-label to A-label conversion against known
// punycode vectors.
//
// checklist: DKIM-EAI-02
func TestToALabels(t *testing.T) {
	for in, want := range map[string]string{
		"example.test":          "example.test",
		"bücher.example":        "xn--bcher-kva.example",
		"BÜCHER.example":        "xn--bcher-kva.example",
		"münchen.bücher.de":     "xn--mnchen-3ya.xn--bcher-kva.de",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"例え.テスト":                "xn--r8jz45g.xn--zckzah",
		"b\xffcher.example":     "b\xffcher.example",
	} {
		if got := ToALabels(in); got != want {
			t.Errorf("ToALabels(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("ü", 64) + ".example"
	if got := ToALabels(long); got != long {
		t.Errorf("over-long label converted: %q", got)
	}
}
