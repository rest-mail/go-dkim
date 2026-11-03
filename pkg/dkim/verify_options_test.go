package dkim

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// multiSigned returns a message carrying n DKIM-Signature fields, each by its
// own selector sel0..sel<n-1> over the same fields and body, and a resolver
// that serves every key and counts the lookups it answers.
func multiSigned(t *testing.T, n int) ([]byte, TXTResolver, *atomic.Int64) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := RecordValue(publicPEM(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	const body = "Many signatures.\r\n"
	var sigs strings.Builder
	keys := map[string]bool{}
	for i := range n {
		sel := fmt.Sprintf("sel%d", i)
		keys[RecordName(sel, "example.test")] = true
		raw := signTestMessage(t, priv, "example.test", sel, "relaxed", "relaxed", fields(), body)
		sigs.WriteString(string(raw[:strings.Index(string(raw), "\r\n")+2]))
	}
	var msg strings.Builder
	msg.WriteString(sigs.String())
	for _, f := range fields() {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n" + body)

	lookups := &atomic.Int64{}
	resolver := func(_ context.Context, name string) ([]string, error) {
		lookups.Add(1)
		if keys[name] {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return []byte(msg.String()), resolver, lookups
}

// Verify checks at most DefaultMaxSignatures signatures, from the top down; the
// rest are reported, in header order, as neutral and not checked, and cost no
// DNS lookup. MaxSignatures changes the cap and a negative one removes it.
//
// checklist: DKIM-VER-24
func TestVerifyLimitsSignatures(t *testing.T) {
	const n = 12
	raw, resolver, lookups := multiSigned(t, n)

	for _, tc := range []struct {
		name    string
		verify  func() []VerifyResult
		checked int
	}{
		{"default", func() []VerifyResult { return Verify(context.Background(), raw, resolver) }, DefaultMaxSignatures},
		{"zero is default", func() []VerifyResult {
			return VerifyWithOptions(context.Background(), raw, resolver, VerifyOptions{})
		}, DefaultMaxSignatures},
		{"two", func() []VerifyResult {
			return VerifyWithOptions(context.Background(), raw, resolver, VerifyOptions{MaxSignatures: 2})
		}, 2},
		{"no limit", func() []VerifyResult {
			return VerifyWithOptions(context.Background(), raw, resolver, VerifyOptions{MaxSignatures: -1})
		}, n},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups.Store(0)
			results := tc.verify()
			if got := lookups.Load(); got != int64(tc.checked) {
				t.Errorf("DNS lookups = %d, want %d", got, tc.checked)
			}
			if len(results) != n {
				t.Fatalf("got %d results, want one per signature (%d)", len(results), n)
			}
			for i, r := range results {
				if r.Domain != "example.test" || r.Selector != fmt.Sprintf("sel%d", i) {
					t.Errorf("result %d reports d=%s s=%s, want header order", i, r.Domain, r.Selector)
				}
				if i < tc.checked {
					if r.Result != ResultPass {
						t.Errorf("result %d: %s (%s), want pass", i, r.Result, r.Reason)
					}
					continue
				}
				if r.Result != ResultNeutral || !strings.Contains(r.Reason, "not checked") ||
					!strings.Contains(r.Reason, fmt.Sprint(tc.checked)) {
					t.Errorf("result %d: %s (%s), want neutral, not checked, naming the limit", i, r.Result, r.Reason)
				}
			}
		})
	}
}

// A message with no more signatures than the cap is verified exactly as before:
// every signature is checked.
//
// checklist: DKIM-VER-24
func TestVerifyAtSignatureLimit(t *testing.T) {
	raw, resolver, lookups := multiSigned(t, DefaultMaxSignatures)
	results := Verify(context.Background(), raw, resolver)
	if len(results) != DefaultMaxSignatures || lookups.Load() != DefaultMaxSignatures {
		t.Fatalf("got %d results and %d lookups, want %d of each", len(results), lookups.Load(), DefaultMaxSignatures)
	}
	for i, r := range results {
		if r.Result != ResultPass {
			t.Errorf("result %d: %s (%s), want pass", i, r.Result, r.Reason)
		}
	}
}

// A host can require fields besides From in every signature's h=; a signature
// leaving one out is a permerror naming it, decided before any DNS lookup.
// Without a list only From is required, as before.
//
// checklist: DKIM-VER-08
func TestVerifyRequiredHeaders(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := publicPEM(t, priv)
	// Signs From, To, Subject, Date and Message-ID; not Reply-To or Cc.
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	keyResolver := testKeyResolver(t, pubPEM, "sel", "example.test")
	var lookups int
	resolver := func(ctx context.Context, name string) ([]string, error) {
		lookups++
		return keyResolver(ctx, name)
	}

	for _, tc := range []struct {
		name     string
		required []string
		want     string
		reason   string
	}{
		{"none", nil, ResultPass, ""},
		{"covered, any case", []string{"Subject", "DATE", " message-id ", ""}, ResultPass, ""},
		{"from listed again", []string{"from"}, ResultPass, ""},
		{"one missing", []string{"Subject", "Reply-To"}, ResultPermError, "required header field reply-to not signed"},
		{"first missing named", []string{"CC", "Reply-To"}, ResultPermError, "required header field cc not signed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := VerifyOptions{RequiredHeaders: tc.required}
			lookups = 0
			results := VerifyWithOptions(context.Background(), raw, resolver, opts)
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			r := results[0]
			if r.Result != tc.want || !strings.Contains(r.Reason, tc.reason) {
				t.Errorf("VerifyWithOptions: %s (%s), want %s (%s)", r.Result, r.Reason, tc.want, tc.reason)
			}
			if tc.want == ResultPermError && lookups != 0 {
				t.Errorf("a missing required field cost %d DNS lookups, want 0", lookups)
			}

			headers, body := SplitMessage(raw)
			single := VerifySignatureWithOptions(context.Background(), headers[0], headers, body, resolver, opts)
			if single != r {
				t.Errorf("VerifySignatureWithOptions = %+v, want %+v", single, r)
			}
		})
	}

	// The defaults are unchanged: Verify and VerifySignature require From only.
	if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPass {
		t.Errorf("Verify = %+v, want one pass", r)
	}
	headers, body := SplitMessage(raw)
	if r := VerifySignature(context.Background(), headers[0], headers, body, resolver); r.Result != ResultPass {
		t.Errorf("VerifySignature = %+v, want pass", r)
	}
	// The option is DKIM policy; the bare mechanism never applies it.
	if r := VerifySignatureBare(context.Background(), headers[0], headers, body, resolver); r.Result != ResultPass {
		t.Errorf("VerifySignatureBare = %+v, want pass", r)
	}
}
