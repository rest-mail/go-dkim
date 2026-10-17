package dkim

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"slices"
	"sort"
	"strings"
	"testing"
)

// validResults are the six results Verify may report.
var validResults = []string{ResultPass, ResultFail, ResultNeutral, ResultNone, ResultTempError, ResultPermError}

// FuzzParseTagList checks the tag-list parsers on any input: neither panics; a
// list the strict parser accepts has only valid names and values, the lenient
// parser reads it the same way, and writing it back out parses to the same
// tags.
//
// checklist: DKIM-TAG-01 DKIM-VER-16
func FuzzParseTagList(f *testing.F) {
	for _, seed := range []string{
		"v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=AAAA; b=BBBB",
		"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		" a = b c ;\r\n\tb=x\r\n y ; c=", "a=1; a=2", "=x", "a", ";;", "1a=b", "a_1=b", "a=\x01", "a=b;",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lenient := ParseTagList(s)
		strict, err := ParseTagListStrict(s)
		if err != nil {
			return
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

// FuzzKeyRecord fetches a key from any key record: the verifier never panics,
// and a key it accepts is well formed, an RSA key of at least 1024 bits or a
// 32-byte Ed25519 key, from a record that is a valid tag-list.
//
// checklist: DKIM-KEY-14
func FuzzKeyRecord(f *testing.F) {
	for _, seed := range []string{
		keyRecord(f, edKey), keyRecord(f, rsaKey(f, 1024)), "v=DKIM1; p=", "v=DKIM2; p=AAAA", "k=ed25519; p=AAAA",
		"v=DKIM1; h=sha1; k=rsa; s=email:*; t=y:s; n=note; p=AAAA", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rec string) {
		resolver := func(context.Context, string) ([]string, error) { return []string{rec}, nil }
		for _, keyType := range []string{"rsa", "ed25519"} {
			pub, _, res := fetchKey(context.Background(), "s", "example.test", keyType, "sha256", resolver)
			if res != "" {
				if pub != nil || res != ResultPermError {
					t.Fatalf("result %q with key %v", res, pub)
				}
				continue
			}
			if _, err := ParseTagListStrict(rec); err != nil {
				t.Fatalf("key from a malformed record: %v", err)
			}
			switch k := pub.(type) {
			case *rsa.PublicKey:
				if keyType != "rsa" || k.N.BitLen() < 1024 {
					t.Fatalf("accepted %d-bit RSA key for %s", k.N.BitLen(), keyType)
				}
			case ed25519.PublicKey:
				if keyType != "ed25519" || len(k) != ed25519.PublicKeySize {
					t.Fatalf("accepted %d-byte Ed25519 key for %s", len(k), keyType)
				}
			default:
				t.Fatalf("key of type %T", pub)
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
