package dkim

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

// auditMessage signs the exact tag text, including deliberately malformed tags.
// It assembles the header hash directly, so malformed inputs have valid crypto
// and cannot pass a test merely because a post-signing edit broke the hash.
func auditMessage(t *testing.T, optional string) string {
	t.Helper()
	const raw = "From: Alice <alice@example.test>\r\nSubject: audit\r\n\r\nBody.\r\n"
	bodyHash := sha256.Sum256([]byte("Body.\r\n"))
	value := "v=1; a=ed25519-sha256; d=example.test; s=audit; " + optional +
		"h=from:subject; bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]) + "; b="
	hashed := sha256.Sum256([]byte("From: Alice <alice@example.test>\r\nSubject: audit\r\nDKIM-Signature: " + value))
	sig := ed25519.Sign(edKey, hashed[:])
	return "DKIM-Signature: " + value + base64.StdEncoding.EncodeToString(sig) + "\r\n" + raw
}

func auditResolver(_ context.Context, name string) ([]string, error) {
	if name != "audit._domainkey.example.test" {
		return nil, fmt.Errorf("unexpected lookup %q", name)
	}
	return []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edKey.Public().(ed25519.PublicKey))}, nil
}

// TestOptionalTagsDoNotDefaultWhenEmpty exercises §3.2's distinction between
// absent and empty with cryptographically intact signatures. Invalid optional
// values must fail before key retrieval, while omission and valid c= forms pass.
//
// checklist: DKIM-TAG-09
func TestOptionalTagsDoNotDefaultWhenEmpty(t *testing.T) {
	for _, tag := range []string{"c", "i", "t", "x", "l", "q"} {
		t.Run(tag, func(t *testing.T) {
			lookups := 0
			resolver := func(ctx context.Context, name string) ([]string, error) {
				lookups++
				return auditResolver(ctx, name)
			}
			got := Verify(context.Background(), []byte(auditMessage(t, tag+"=; ")), resolver)
			if len(got) != 1 || got[0].Result != ResultPermError || lookups != 0 {
				t.Fatalf("empty %s=: %+v, lookups=%d; want permerror before DNS", tag, got, lookups)
			}
		})
	}
	for _, optional := range []string{"", "c=simple; ", "c=simple/simple; ", "i=@example.test; ", "t=1; "} {
		got := Verify(context.Background(), []byte(auditMessage(t, optional)), auditResolver)
		if len(got) != 1 || got[0].Result != ResultPass {
			t.Errorf("valid %q: %+v", optional, got)
		}
	}
	for _, c := range []string{"simple/", "/simple", "simple/simple/relaxed"} {
		got := Verify(context.Background(), []byte(auditMessage(t, "c="+c+"; ")), auditResolver)
		if len(got) != 1 || got[0].Result != ResultPermError {
			t.Errorf("malformed c=%s: %+v", c, got)
		}
	}
}

// TestSignedExistingSignatureValues covers the rule that another signature's
// b= is ordinary signed content. The current signature must never select itself
// from h=, even when an earlier signature signs a later one in the header block.
//
// checklist: DKIM-HASH-06
func TestSignedExistingSignatureValues(t *testing.T) {
	raw := buildRaw("Body.\r\n")
	opt := SignOptions{Domain: "example.test", Selector: "audit", PrivateKey: edKey}
	old, err := Sign([]byte(raw), opt)
	if err != nil {
		t.Fatal(err)
	}
	raw = "DKIM-Signature: " + old + "\r\n" + raw
	opt.Headers = []string{"from", "dkim-signature"}
	newer, err := Sign([]byte(raw), opt)
	if err != nil {
		t.Fatal(err)
	}
	signed := "DKIM-Signature: " + newer + "\r\n" + raw
	// Both header orders are valid: selecting the current signature would break
	// the new signature when it is physically below the one it covers.
	reversed := "DKIM-Signature: " + old + "\r\nDKIM-Signature: " + newer + "\r\n" + buildRaw("Body.\r\n")
	for _, msg := range []string{signed, reversed} {
		got := Verify(context.Background(), []byte(msg), auditResolver)
		if len(got) != 2 || got[0].Result != ResultPass || got[1].Result != ResultPass {
			t.Fatalf("signed signature/order: %+v", got)
		}
	}
	// Flip only the covered signature's b=, retaining valid base64 syntax.
	at := strings.LastIndex(raw, "b=") + 2
	replacement := byte('A')
	if raw[at] == replacement {
		replacement = 'B'
	}
	tampered := raw[:at] + string(replacement) + raw[at+1:]
	got := Verify(context.Background(), []byte("DKIM-Signature: "+newer+"\r\n"+tampered), auditResolver)
	if len(got) != 2 || got[0].Result != ResultFail || got[1].Result != ResultFail {
		t.Fatalf("changed other b=: %+v; want both fail", got)
	}
}

// TestFailureStopsOnlyThatSignature checks syntax refusal without DNS, TEMPFAIL
// output retaining d=, continuation to a good signature, and diagnostic reasons.
//
// checklist: DKIM-VER-18 DKIM-VER-19
func TestFailureStopsOnlyThatSignature(t *testing.T) {
	good := auditMessage(t, "")
	for _, temporary := range []bool{false, true} {
		t.Run(fmt.Sprint(temporary), func(t *testing.T) {
			bad := "DKIM-Signature: v=2; d=example.test; s=bad\r\n"
			want, wantQueries := ResultPermError, 1
			if temporary {
				bad = strings.SplitN(auditMessage(t, ""), "\r\n", 2)[0] + "\r\n"
				want, wantQueries = ResultTempError, 2
			}
			queries := 0
			resolver := func(ctx context.Context, name string) ([]string, error) {
				queries++
				if temporary && queries == 1 {
					return nil, &net.DNSError{Err: "timeout", IsTimeout: true}
				}
				return auditResolver(ctx, name)
			}
			got := Verify(context.Background(), []byte(bad+good), resolver)
			if len(got) != 2 || got[0].Result != want || got[1].Result != ResultPass || queries != wantQueries {
				t.Fatalf("results=%+v queries=%d", got, queries)
			}
			for _, result := range got {
				if result.Domain != "example.test" || result.Reason == "" {
					t.Errorf("missing domain/reason: %+v", result)
				}
			}
		})
	}
}

// TestBodyLengthBoundAfterCanonicalization uses signed, unchanged l= tags.
// The bound is the canonicalized octet count, not the input size; zero remains
// valid, and the 76-digit grammar limit applies even to leading zeroes.
//
// checklist: DKIM-VER-20 DKIM-SIG-08
func TestBodyLengthBoundAfterCanonicalization(t *testing.T) {
	const raw = "From: a@example.test\r\n\r\nA  B \t\r\n\r\n"
	cases := []struct{ canon, length, want string }{
		{"simple", "0", ResultPass}, {"simple", "8", ResultPass}, {"simple", "9", ResultPermError},
		{"relaxed", "0", ResultPass}, {"relaxed", "5", ResultPass}, {"relaxed", "6", ResultPermError},
		{"relaxed", strings.Repeat("0", 75) + "5", ResultPass},
		{"relaxed", strings.Repeat("0", 76) + "5", ResultPermError},
	}
	for _, tc := range cases {
		t.Run(tc.canon+"/"+tc.length, func(t *testing.T) {
			msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=audit; c=simple/"+tc.canon+"; h=from; l="+tc.length, "simple", tc.canon, raw)
			got := Verify(context.Background(), []byte(msg), auditResolver)
			if len(got) != 1 || got[0].Result != tc.want {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}

// TestAbsentAUIDUsesSigningDomain tests the default @d identity with a t=s key:
// absent and explicit @d succeed, whereas an explicit subdomain is refused.
//
// checklist: DKIM-VER-21
func TestAbsentAUIDUsesSigningDomain(t *testing.T) {
	resolver := func(ctx context.Context, name string) ([]string, error) {
		records, err := auditResolver(ctx, name)
		if err != nil {
			return nil, err
		}
		return []string{records[0] + "; t=s"}, nil
	}
	for _, tc := range []struct{ optional, want string }{
		{"", ResultPass}, {"i=@example.test; ", ResultPass},
		{"i=@sub.example.test; ", ResultPermError},
	} {
		got := Verify(context.Background(), []byte(auditMessage(t, tc.optional)), resolver)
		if len(got) != 1 || got[0].Result != tc.want || got[0].Domain != "example.test" {
			t.Errorf("%q: %+v; want %s for example.test", tc.optional, got, tc.want)
		}
	}
}
