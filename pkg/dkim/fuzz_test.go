package dkim

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// validResults are the six results Verify may report.
var validResults = []string{ResultPass, ResultFail, ResultNeutral, ResultNone, ResultTempError, ResultPermError}

// FuzzSignatureHeader verifies a fixed message under any DKIM-Signature value,
// with a valid key published: the verifier never panics, reports one of the
// six results with a reason, and reports d= and s= only from a well-formed
// tag-list.
//
// checklist: DKIM-VER-06 DKIM-VER-16
func FuzzSignatureHeader(f *testing.F) {
	raw := "From: a@example.test\r\nTo: b@example.test\r\nSubject: s\r\n\r\nbody\r\n"
	val, err := Sign([]byte(raw), SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey, Time: 1792000000})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		val, " v=1; a=rsa-sha256; d=example.test; s=s; h=from; bh=; b=", "v=1; l=-1", "l=99999999999999999999999",
		"v=1; a=ed25519-sha256; d=example.test; s=s; h=from:from:from; bh=AAAA; b=AAAA; x=1; t=2",
		"v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.test; s=s; i=@sub.example.test; q=dns/txt; h=from; bh=AAAA; b=AAAA",
	} {
		f.Add(seed)
	}
	headers, body := SplitMessage([]byte(raw))
	rec := keyRecord(f, edKey)
	resolver := func(context.Context, string) ([]string, error) { return []string{rec}, nil }
	f.Fuzz(func(t *testing.T, value string) {
		sig := Header{Name: "DKIM-Signature", Value: value, Raw: "DKIM-Signature:" + value}
		for _, r := range []VerifyResult{
			VerifySignature(context.Background(), sig, headers, body, resolver),
			VerifySignatureBare(context.Background(), sig, headers, body, resolver),
		} {
			if !slices.Contains(validResults, r.Result) || r.Reason == "" {
				t.Fatalf("result %+v", r)
			}
			if _, err := ParseTagListStrict(value); err != nil && (r.Domain != "" || r.Selector != "") {
				t.Fatalf("malformed tag-list reported d=%q s=%q", r.Domain, r.Selector)
			}
		}
	})
}

// FuzzCanonicalization checks properties of the canonicalizers on any header
// field and body: canonicalizing a canonical form changes nothing, and the
// relaxed forms hold no folding, no runs of whitespace and no whitespace at
// line ends, with relaxed header names in lower case.
//
// checklist: DKIM-CANON-06 DKIM-CANON-07 DKIM-CANON-08
func FuzzCanonicalization(f *testing.F) {
	f.Add("Subject", " Y\t\r\n\tZ  ", " C \r\nD \t E\r\n\r\n\r\n")
	f.Add("B ", " x", "")
	f.Add("X-Long", strings.Repeat(" a\t", 40), "line\rbare CR\nbare LF\r\n \r\n")
	f.Fuzz(func(t *testing.T, name, value, body string) {
		headers, b := SplitMessage([]byte(name + ":" + value + "\r\n\r\n" + body))
		for _, h := range headers {
			c := CanonicalizeHeader(h, "relaxed")
			if strings.ContainsAny(c, "\r\n\t") || strings.Contains(c, "  ") || strings.HasSuffix(c, " ") {
				t.Fatalf("relaxed header %q", c)
			}
			n, v, ok := strings.Cut(c, ":")
			if !ok || n != strings.ToLower(n) || strings.HasPrefix(v, " ") {
				t.Fatalf("relaxed header %q", c)
			}
			if again := CanonicalizeHeader(Header{Name: n, Value: v, Raw: c}, "relaxed"); again != c {
				t.Fatalf("relaxed header not idempotent: %q then %q", c, again)
			}
			if CanonicalizeHeader(h, "simple") != h.Raw {
				t.Fatalf("simple header changed %q", h.Raw)
			}
		}
		for _, canon := range []string{"simple", "relaxed"} {
			c := CanonicalizeBody(b, canon)
			if again := CanonicalizeBody(c, canon); again != c {
				t.Fatalf("%s body not idempotent: %q then %q", canon, c, again)
			}
			if c != "" && !strings.HasSuffix(c, "\r\n") || strings.HasSuffix(c, "\r\n\r\n") {
				t.Fatalf("%s body %q does not end in exactly one CRLF", canon, c)
			}
			if canon == "relaxed" {
				for _, line := range strings.Split(c, "\r\n") {
					if strings.ContainsAny(line, "\t\r\n") || strings.Contains(line, "  ") || strings.HasSuffix(line, " ") {
						t.Fatalf("relaxed body line %q", line)
					}
				}
			}
		}
	})
}

// FuzzSignVerify signs any message that has a From field, in every
// canonicalization, and checks the signature verifies: the signer and the
// verifier canonicalize alike whatever the input.
//
// checklist: DKIM-SIGN-09 DKIM-VER-01
func FuzzSignVerify(f *testing.F) {
	f.Add("To: b@example.test\r\nSubject:  x \r\n", " body \r\n\r\n")
	f.Add("Cc: c\r\n folded\r\nCc: d\r\nDKIM-Signature: junk", "")
	f.Add("no colon line\r\n\tcontinued\r\nX:", "a\rb\nc")
	rec := keyRecord(f, edKey)
	resolver := func(context.Context, string) ([]string, error) { return []string{rec}, nil }
	f.Fuzz(func(t *testing.T, headers, body string) {
		raw := []byte("From: a@example.test\r\n" + headers + "\r\n\r\n" + body)
		for _, c := range diffCanons {
			val, err := Sign(raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey, HeaderCanon: c[0], BodyCanon: c[1]})
			if err != nil {
				t.Fatal(err)
			}
			signed := append([]byte("DKIM-Signature: "+val+"\r\n"), raw...)
			if r := Verify(context.Background(), signed, resolver); r[0].Result != ResultPass {
				t.Fatalf("%s/%s: %+v", c[0], c[1], r[0])
			}
		}
	})
}
