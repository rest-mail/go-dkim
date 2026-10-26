package grammar

import (
	"sort"
	"strings"
	"testing"
	"unicode"
)

// FuzzParseTagList checks the tag-list parsers on any input: neither panics; a
// list the strict parser accepts has no whitespace but FWS, only valid names
// and values, the lenient parser reads it the same way, and writing it back
// out parses to the same tags.
//
// checklist: DKIM-TAG-01 DKIM-TAG-08 DKIM-VER-16
func FuzzParseTagList(f *testing.F) {
	for _, seed := range []string{
		"v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=AAAA; b=BBBB",
		"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		" a = b c ;\r\n\tb=x\r\n y ; c=", "a=1; a=2", "=x", "a", ";;", "1a=b", "a_1=b", "a=\x01", "a=b;", "i\f=1", "a=b;\v",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lenient := ParseTagList(s)
		strict, err := ParseTagListStrict(s)
		if err != nil {
			return
		}
		for _, r := range s {
			if unicode.IsSpace(r) && r != ' ' && r != '\t' && r != '\r' && r != '\n' {
				t.Fatalf("accepted %q, which holds %U, whitespace that is not FWS", s, r)
			}
		}
		keys := make([]string, 0, len(strict))
		for k, v := range strict {
			if !validTagName(k) || !validTagValue(v) || strings.Contains(v, ";") {
				t.Fatalf("accepted tag %q=%q", k, v)
			}
			if lenient[k] != v {
				t.Fatalf("lenient parse has %q=%q, strict %q", k, lenient[k], v)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+"="+strict[k])
		}
		again, err := ParseTagListStrict(strings.Join(parts, "; "))
		if err != nil || len(again) != len(strict) {
			t.Fatalf("written back as %q: %v, %v", strings.Join(parts, "; "), again, err)
		}
		for k, v := range strict {
			if again[k] != v {
				t.Fatalf("tag %s: %q written back reads %q", k, v, again[k])
			}
		}
	})
}

// TestDomainAligned pins the alignment predicate directly: equality and true
// subdomains (on a dot boundary) align; unrelated domains, a bare suffix that
// is not on a dot boundary, and empty inputs do not. Comparison is
// case-insensitive.
//
// checklist: DKIM-SIG-07
func TestDomainAligned(t *testing.T) {
	cases := []struct {
		idomain, d string
		want       bool
	}{
		{"example.test", "example.test", true},
		{"sub.example.test", "example.test", true},
		{"deep.sub.example.test", "example.test", true},
		{"EXAMPLE.test", "example.TEST", true},
		{"evil.example", "example.test", false},
		{"example.test.evil.example", "example.test", false}, // d= is a prefix, not a parent
		{"notexample.test", "example.test", false},           // suffix but not on a dot boundary
		{"", "example.test", false},
		{"example.test", "", false},
	}
	for _, c := range cases {
		if got := DomainAligned(c.idomain, c.d); got != c.want {
			t.Errorf("domainAligned(%q,%q)=%v want %v", c.idomain, c.d, got, c.want)
		}
	}
}

// TestIdentityDomain pins the i= domain extraction: the domain is everything
// after the LAST "@" (a quoted local part may itself contain "@"), and a value
// with no "@" is malformed.
//
// checklist: DKIM-SIG-07
func TestIdentityDomain(t *testing.T) {
	if d, ok := IdentityDomain("user@example.test"); !ok || d != "example.test" {
		t.Errorf("identityDomain simple: got %q,%v", d, ok)
	}
	if d, ok := IdentityDomain(`"weird@local"@example.test`); !ok || d != "example.test" {
		t.Errorf("identityDomain last-@: got %q,%v", d, ok)
	}
	if _, ok := IdentityDomain("no-at-sign"); ok {
		t.Error("i= without @ should be reported malformed")
	}
}

// TestHeaderListCoversFrom pins the h= coverage predicate directly: from is
// matched case-insensitively and ignoring surrounding whitespace; a list that
// never names from (or an empty list) is not covered.
//
// checklist: DKIM-VER-07
func TestHeaderListCoversFrom(t *testing.T) {
	cases := []struct {
		hTag string
		want bool
	}{
		{"from:to:subject", true},
		{"to:from:date", true},
		{"to:subject: From ", true}, // whitespace + uppercase
		{"to:subject:date", false},
		{"fromish:to", false}, // substring but not the field
		{"", false},
	}
	for _, c := range cases {
		if got := HeaderListCoversFrom(c.hTag); got != c.want {
			t.Errorf("headerListCoversFrom(%q)=%v want %v", c.hTag, got, c.want)
		}
	}
}

// TestFirstTagName pins the ordering helper directly: it returns the name of the
// first tag in a DKIM tag-list record, ignoring the ABNF's optional leading
// folding whitespace and empty leading segments, and "" when there is no tag.
//
// checklist: DKIM-KEY-01
func TestFirstTagName(t *testing.T) {
	cases := []struct{ rec, want string }{
		{"v=DKIM1; k=rsa; p=AAA", "v"},
		{"k=rsa; v=DKIM1; p=AAA", "k"},
		{"  v=DKIM1; p=AAA", "v"},
		{"; v=DKIM1", "v"},
		{"p=AAA", "p"},
		{"", ""},
		{"   ", ""},
		{"p; v=DKIM1", ""},
	}
	for _, c := range cases {
		if got := FirstTagName(c.rec); got != c.want {
			t.Errorf("firstTagName(%q) = %q, want %q", c.rec, got, c.want)
		}
	}
}

// TestParseTimeTag pins the RFC 6376 §3.5 timestamp ABNF (1*12DIGIT) directly:
// digits only, non-empty, at most 12 digits; anything else is an error.
//
// checklist: DKIM-SIG-10 DKIM-SIG-13
func TestParseTimeTag(t *testing.T) {
	good := map[string]int64{"0": 0, "1000000000": 1000000000, "999999999999": 999999999999}
	for in, want := range good {
		if got, err := ParseTimeTag(in); err != nil || got != want {
			t.Errorf("parseTimeTag(%q)=%d,%v want %d,nil", in, got, err, want)
		}
	}
	for _, bad := range []string{"", " ", "-1", "+1", "1e6", "12.5", "abc", "1000000000000"} {
		if _, err := ParseTimeTag(bad); err == nil {
			t.Errorf("parseTimeTag(%q) should error", bad)
		}
	}
}
