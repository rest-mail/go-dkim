package dkim

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"
)

// ── Canonicalization anchored to RFC 6376 §3.4.5 worked example ──────────
//
// These assertions pin the canonicalizers to the outputs the RFC itself
// publishes, independently of any crypto — so a body/header canon bug can't
// hide behind a self-consistent sign/verify round-trip.

func TestRelaxedHeaderCanon_RFCExample(t *testing.T) {
	// "A: X" and the folded "B : Y<TAB>CRLF<TAB>Z  " from §3.4.5.
	a := Header{Name: "A", Value: " X", Raw: "A: X"}
	if got := CanonicalizeHeader(a, "relaxed"); got != "a:X" {
		t.Errorf("relaxed A: got %q want %q", got, "a:X")
	}
	b := Header{Name: "B", Value: " Y\t\r\n\tZ  ", Raw: "B : Y\t\r\n\tZ  "}
	if got := CanonicalizeHeader(b, "relaxed"); got != "b:Y Z" {
		t.Errorf("relaxed B: got %q want %q", got, "b:Y Z")
	}
}

func TestSimpleHeaderCanon_Unchanged(t *testing.T) {
	b := Header{Name: "B", Value: " Y\t\r\n\tZ  ", Raw: "B : Y\t\r\n\tZ  "}
	if got := CanonicalizeHeader(b, "simple"); got != "B : Y\t\r\n\tZ  " {
		t.Errorf("simple header should be byte-identical, got %q", got)
	}
}

func TestBodyCanon_RFCExample(t *testing.T) {
	body := " C \r\nD \t E\r\n\r\n\r\n"
	if got := CanonicalizeBody(body, "relaxed"); got != " C\r\nD E\r\n" {
		t.Errorf("relaxed body: got %q want %q", got, " C\r\nD E\r\n")
	}
	if got := CanonicalizeBody(body, "simple"); got != " C \r\nD \t E\r\n" {
		t.Errorf("simple body: got %q want %q", got, " C \r\nD \t E\r\n")
	}
}

func TestBodyCanon_Empty(t *testing.T) {
	if got := CanonicalizeBody("", "simple"); got != "\r\n" {
		t.Errorf("simple empty body should be CRLF, got %q", got)
	}
	if got := CanonicalizeBody("", "relaxed"); got != "" {
		t.Errorf("relaxed empty body should be empty, got %q", got)
	}
}

// ── removeBValue ─────────────────────────────────────────────────────────

func TestRemoveBValue(t *testing.T) {
	in := "v=1; a=rsa-sha256; bh=ABC; h=from:to; b=SIGDATA=="
	want := "v=1; a=rsa-sha256; bh=ABC; h=from:to; b="
	if got := RemoveBValue(in); got != want {
		t.Errorf("removeBValue: got %q want %q", got, want)
	}
	// b= not last, and bh= must be untouched.
	in2 := "v=1; b=SIG; bh=HASH; s=sel"
	want2 := "v=1; b=; bh=HASH; s=sel"
	if got := RemoveBValue(in2); got != want2 {
		t.Errorf("removeBValue mid: got %q want %q", got, want2)
	}
}

// ── Sign/verify round-trip ──────────────────────────────────────────────

// signTestMessage is an independent reference signer used only by tests: it
// assembles a DKIM-Signature over the given header fields + body and returns a
// full raw message with the signature prepended.
func signTestMessage(t *testing.T, priv *rsa.PrivateKey, d, s, hcanon, bcanon string, fields []string, body string) []byte {
	t.Helper()

	bodyHash := sha256.Sum256([]byte(CanonicalizeBody(body, bcanon)))
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	// h= = field names in order.
	var names []string
	hdrs := make([]Header, 0, len(fields))
	for _, f := range fields {
		eq := strings.IndexByte(f, ':')
		hdrs = append(hdrs, Header{Name: strings.TrimSpace(f[:eq]), Value: f[eq+1:], Raw: f})
		names = append(names, strings.ToLower(strings.TrimSpace(f[:eq])))
	}
	hlist := strings.Join(names, ":")

	sigVal := " v=1; a=rsa-sha256; c=" + hcanon + "/" + bcanon +
		"; d=" + d + "; s=" + s + "; h=" + hlist + "; bh=" + bh + "; b="

	// Build the data to sign: each named header, then the sig header (b= empty).
	var sb strings.Builder
	for _, h := range hdrs {
		sb.WriteString(CanonicalizeHeader(h, hcanon))
		sb.WriteString("\r\n")
	}
	sigHdr := Header{Name: "DKIM-Signature", Value: sigVal, Raw: "DKIM-Signature:" + sigVal}
	sb.WriteString(CanonicalizeHeader(sigHdr, hcanon))

	hashed := sha256.Sum256([]byte(sb.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(sig)

	var msg strings.Builder
	msg.WriteString("DKIM-Signature:" + sigVal + b64 + "\r\n")
	for _, f := range fields {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

func testKeyResolver(t *testing.T, pubPEM, selector, domain string) TXTResolver {
	t.Helper()
	txt, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatalf("RecordValue: %v", err)
	}
	want := RecordName(selector, domain)
	return func(_ context.Context, name string) ([]string, error) {
		if name == want {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

func fields() []string {
	return []string{
		"From: Alice <alice@example.test>",
		"To: Bob <bob@rcpt.test>",
		"Subject: DKIM round trip",
		"Date: " + time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC).Format(time.RFC1123Z),
		"Message-ID: <rt-1@example.test>",
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := publicPEM(t, priv)

	for _, canon := range []struct{ h, b string }{
		{"relaxed", "relaxed"},
		{"simple", "simple"},
		{"relaxed", "simple"},
		{"simple", "relaxed"},
	} {
		t.Run(canon.h+"/"+canon.b, func(t *testing.T) {
			raw := signTestMessage(t, priv, "example.test", "sel", canon.h, canon.b, fields(), "Hello DKIM world.\r\nSecond line.\r\n")
			resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

			results := Verify(context.Background(), raw, resolver)
			if len(results) != 1 {
				t.Fatalf("want 1 result, got %d", len(results))
			}
			if results[0].Result != ResultPass {
				t.Errorf("want pass, got %s (%s)", results[0].Result, results[0].Reason)
			}
			if results[0].Domain != "example.test" || results[0].Selector != "sel" {
				t.Errorf("d/s mismatch: %+v", results[0])
			}
		})
	}
}

func TestVerify_BodyTamperFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Original body.\r\n")
	// Flip the body after signing.
	tampered := strings.Replace(string(raw), "Original body.", "Tampered body!", 1)

	results := Verify(context.Background(), []byte(tampered), testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 || results[0].Result != ResultFail {
		t.Fatalf("want fail on body tamper, got %+v", results)
	}
	if results[0].Reason != "body hash mismatch" {
		t.Errorf("want body hash mismatch, got %q", results[0].Reason)
	}
}

func TestVerify_HeaderTamperFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	// Change a signed header (Subject) after signing → body hash still ok, sig fails.
	tampered := strings.Replace(string(raw), "Subject: DKIM round trip", "Subject: Evil replacement", 1)

	results := Verify(context.Background(), []byte(tampered), testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 || results[0].Result != ResultFail {
		t.Fatalf("want fail on header tamper, got %+v", results)
	}
	if results[0].Reason != "signature verification failed" {
		t.Errorf("want signature verification failed, got %q", results[0].Reason)
	}
}

func TestVerify_NoSignature(t *testing.T) {
	raw := "From: a@example.test\r\nSubject: plain\r\n\r\nno dkim here\r\n"
	results := Verify(context.Background(), []byte(raw), func(_ context.Context, _ string) ([]string, error) {
		t.Fatal("resolver should not be called with no signature")
		return nil, nil
	})
	if len(results) != 0 {
		t.Errorf("want no results, got %+v", results)
	}
}

func TestVerify_NoKeyPermError(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	// Resolver reports NXDOMAIN for everything.
	nx := func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	results := Verify(context.Background(), raw, nx)
	if len(results) != 1 || results[0].Result != ResultPermError {
		t.Fatalf("want permerror on missing key, got %+v", results)
	}
}

func TestVerify_DNSTempError(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	temp := func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	results := Verify(context.Background(), raw, temp)
	if len(results) != 1 || results[0].Result != ResultTempError {
		t.Fatalf("want temperror on DNS failure, got %+v", results)
	}
}

func TestVerify_RevokedKeyPermError(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	revoked := func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=DKIM1; k=rsa; p="}, nil // empty p = revoked
	}
	results := Verify(context.Background(), raw, revoked)
	if len(results) != 1 || results[0].Result != ResultPermError {
		t.Fatalf("want permerror on revoked key, got %+v", results)
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	other, _ := rsa.GenerateKey(rand.Reader, 1024)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	// Publish the WRONG public key.
	results := Verify(context.Background(), raw, testKeyResolver(t, publicPEM(t, other), "sel", "example.test"))
	if len(results) != 1 || results[0].Result != ResultFail {
		t.Fatalf("want fail with wrong key, got %+v", results)
	}
}

// injectTag splices an extra "key=value; " tag into the DKIM-Signature of a raw
// message, right after the a= tag, without disturbing any other bytes.
func injectTag(t *testing.T, raw []byte, key, value string) []byte {
	t.Helper()
	const anchor = "a=rsa-sha256;"
	s := string(raw)
	if !strings.Contains(s, anchor) {
		t.Fatalf("anchor %q not found in signature", anchor)
	}
	return []byte(strings.Replace(s, anchor, anchor+" "+key+"="+value+";", 1))
}

// TestVerify_NegativeBodyLength pins the RFC 6376 §3.5 l= tag ABNF (1*76DIGIT):
// a negative body-length count is attacker-controlled and reaches the body-hash
// step before any crypto, so it must be rejected as a syntactically invalid
// signature (PERMFAIL) — never allowed to slice the body with a negative bound,
// which panics ("slice bounds out of range [:-1]") and crashes the verifier.
func TestVerify_NegativeBodyLength(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Hello DKIM world.\r\n")
	raw = injectTag(t, raw, "l", "-1")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on negative l=, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if results[0].Reason != "invalid l= tag" {
		t.Errorf("want reason %q, got %q", "invalid l= tag", results[0].Reason)
	}
}

// TestVerify_PlusBodyLength covers the other non-digit sign form the ABNF
// forbids: a leading "+" must be rejected exactly like a leading "-".
func TestVerify_PlusBodyLength(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Hello DKIM world.\r\n")
	raw = injectTag(t, raw, "l", "+5")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 || results[0].Result != ResultPermError || results[0].Reason != "invalid l= tag" {
		t.Fatalf("want permerror invalid l= tag on l=+5, got %+v", results)
	}
}

// TestVerify_BodyLengthExceedsBody guards the other slice bound: an l= count far
// larger than the canonicalized body must not slice past the end (which would
// also panic). The whole available body is used, so the injected tag simply
// breaks the signature — the result is a clean failure, not a crash.
func TestVerify_BodyLengthExceedsBody(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "short body\r\n")
	raw = injectTag(t, raw, "l", "999999999")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultFail {
		t.Errorf("want fail (no panic) on oversized l=, got %s (%s)", results[0].Result, results[0].Reason)
	}
}

// ── d=/i= identity alignment (RFC 6376 §6.1.1 / §3.5) ────────────────────

// signWithIdentity signs a message exactly like signTestMessage (relaxed/
// relaxed) but adds an explicit i= (AUID) tag to the signature — the tag is
// part of the signed data, so the resulting signature verifies as far as the
// crypto is concerned. It is the fixture for the alignment tests: without an
// alignment check a signature valid for d= can assert an i= in any domain and
// still pass.
func signWithIdentity(t *testing.T, priv *rsa.PrivateKey, d, s, iTag string, fields []string, body string) []byte {
	t.Helper()
	const hcanon, bcanon = "relaxed", "relaxed"

	bodyHash := sha256.Sum256([]byte(CanonicalizeBody(body, bcanon)))
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	var names []string
	hdrs := make([]Header, 0, len(fields))
	for _, f := range fields {
		eq := strings.IndexByte(f, ':')
		hdrs = append(hdrs, Header{Name: strings.TrimSpace(f[:eq]), Value: f[eq+1:], Raw: f})
		names = append(names, strings.ToLower(strings.TrimSpace(f[:eq])))
	}
	hlist := strings.Join(names, ":")

	sigVal := " v=1; a=rsa-sha256; c=" + hcanon + "/" + bcanon +
		"; d=" + d + "; s=" + s + "; i=" + iTag + "; h=" + hlist + "; bh=" + bh + "; b="

	var sb strings.Builder
	for _, h := range hdrs {
		sb.WriteString(CanonicalizeHeader(h, hcanon))
		sb.WriteString("\r\n")
	}
	sigHdr := Header{Name: "DKIM-Signature", Value: sigVal, Raw: "DKIM-Signature:" + sigVal}
	sb.WriteString(CanonicalizeHeader(sigHdr, hcanon))

	hashed := sha256.Sum256([]byte(sb.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(sig)

	var msg strings.Builder
	msg.WriteString("DKIM-Signature:" + sigVal + b64 + "\r\n")
	for _, f := range fields {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

// TestVerify_UnalignedIdentityRejected is the red-green anchor for issue #5:
// the message is signed correctly for d=example.test but asserts an AUID
// (i=mallory@evil.example) in an unrelated domain. Before the fix the verifier
// ignores i= entirely and returns pass (the AUID-spoofing vuln); RFC 6376
// §6.1.1 requires PERMFAIL (domain mismatch) because evil.example is neither
// example.test nor a subdomain of it.
func TestVerify_UnalignedIdentityRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithIdentity(t, priv, "example.test", "sel", "mallory@evil.example", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on unaligned i=, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "not aligned") {
		t.Errorf("want a domain-mismatch reason, got %q", results[0].Reason)
	}
}

// TestVerify_AlignedIdentityVerifies keeps the legitimate cases passing: an i=
// whose domain is exactly d=, a subdomain of d=, or (empty local part) equal to
// d= must still verify.
func TestVerify_AlignedIdentityVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

	for _, iTag := range []string{
		"user@example.test",     // exactly d=
		"user@sub.example.test", // subdomain of d=
		"user@EXAMPLE.TEST",     // case-insensitive match of d=
		"@example.test",         // empty local part, domain == d=
	} {
		t.Run(iTag, func(t *testing.T) {
			raw := signWithIdentity(t, priv, "example.test", "sel", iTag, fields(), "Body.\r\n")
			results := Verify(context.Background(), raw, resolver)
			if len(results) != 1 {
				t.Fatalf("want 1 result, got %d", len(results))
			}
			if results[0].Result != ResultPass {
				t.Errorf("want pass on aligned i=%s, got %s (%s)", iTag, results[0].Result, results[0].Reason)
			}
		})
	}
}

// TestDomainAligned pins the alignment predicate directly: equality and true
// subdomains (on a dot boundary) align; unrelated domains, a bare suffix that
// is not on a dot boundary, and empty inputs do not. Comparison is
// case-insensitive.
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
		if got := domainAligned(c.idomain, c.d); got != c.want {
			t.Errorf("domainAligned(%q,%q)=%v want %v", c.idomain, c.d, got, c.want)
		}
	}
}

// TestIdentityDomain pins the i= domain extraction: the domain is everything
// after the LAST "@" (a quoted local part may itself contain "@"), and a value
// with no "@" is malformed.
func TestIdentityDomain(t *testing.T) {
	if d, ok := identityDomain("user@example.test"); !ok || d != "example.test" {
		t.Errorf("identityDomain simple: got %q,%v", d, ok)
	}
	if d, ok := identityDomain(`"weird@local"@example.test`); !ok || d != "example.test" {
		t.Errorf("identityDomain last-@: got %q,%v", d, ok)
	}
	if _, ok := identityDomain("no-at-sign"); ok {
		t.Error("i= without @ should be reported malformed")
	}
}

// ── From must be signed (RFC 6376 §5.4 / §6.1.1) ─────────────────────────

// signOmittingFrom signs a message (relaxed/relaxed) whose h= tag deliberately
// omits the From field even though the message carries a From header. The
// signature is cryptographically valid over the headers it does name, so before
// the "From must be signed" check it verifies as pass — leaving the displayed
// author identity outside the hash so From can be swapped (or the message
// replayed under a new author) without breaking the signature. It is the
// red-green fixture for issue #6.
func signOmittingFrom(t *testing.T, priv *rsa.PrivateKey, d, s, body string) []byte {
	t.Helper()
	const hcanon, bcanon = "relaxed", "relaxed"

	// From is present in the message but excluded from the signed field set.
	fromHdr := "From: Alice <alice@example.test>"
	signedFields := []string{
		"To: Bob <bob@rcpt.test>",
		"Subject: unsigned-from attack",
		"Date: " + time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC).Format(time.RFC1123Z),
	}

	bodyHash := sha256.Sum256([]byte(CanonicalizeBody(body, bcanon)))
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	var names []string
	hdrs := make([]Header, 0, len(signedFields))
	for _, f := range signedFields {
		eq := strings.IndexByte(f, ':')
		hdrs = append(hdrs, Header{Name: strings.TrimSpace(f[:eq]), Value: f[eq+1:], Raw: f})
		names = append(names, strings.ToLower(strings.TrimSpace(f[:eq])))
	}
	hlist := strings.Join(names, ":") // e.g. "to:subject:date" — no from

	sigVal := " v=1; a=rsa-sha256; c=" + hcanon + "/" + bcanon +
		"; d=" + d + "; s=" + s + "; h=" + hlist + "; bh=" + bh + "; b="

	var sb strings.Builder
	for _, h := range hdrs {
		sb.WriteString(CanonicalizeHeader(h, hcanon))
		sb.WriteString("\r\n")
	}
	sigHdr := Header{Name: "DKIM-Signature", Value: sigVal, Raw: "DKIM-Signature:" + sigVal}
	sb.WriteString(CanonicalizeHeader(sigHdr, hcanon))

	hashed := sha256.Sum256([]byte(sb.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(sig)

	var msg strings.Builder
	msg.WriteString("DKIM-Signature:" + sigVal + b64 + "\r\n")
	msg.WriteString(fromHdr + "\r\n") // present in the message, absent from h=
	for _, f := range signedFields {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

// TestVerify_FromNotSignedRejected is the red-green anchor for issue #6: the
// message is signed correctly but its h= tag (to:subject:date) never names the
// From field. Before the fix the verifier hashes only what h= lists and returns
// pass, so the unsigned From can be forged under a valid signature. RFC 6376
// §6.1.1 requires PERMFAIL ("From field not signed") when h= does not cover
// from.
func TestVerify_FromNotSignedRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signOmittingFrom(t, priv, "example.test", "sel", "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror when h= omits from, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "From") {
		t.Errorf("want a From-not-signed reason, got %q", results[0].Reason)
	}
}

// TestVerify_FromSignedVerifies keeps the legitimate case passing: a signature
// whose h= includes From (as fields() does) must still verify. It pins that the
// §6.1.1 check rejects only the missing-From case and does not disturb a normal
// signature. (Case-insensitive matching of "from" is pinned directly by
// TestHeaderListCoversFrom, which avoids mutating the signed h= bytes.)
func TestVerify_FromSignedVerifies(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := publicPEM(t, priv)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

	// Normal signature (fields() lists From first in h=).
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPass {
		t.Fatalf("want pass with From in h=, got %+v", r)
	}
}

// TestHeaderListCoversFrom pins the h= coverage predicate directly: from is
// matched case-insensitively and ignoring surrounding whitespace; a list that
// never names from (or an empty list) is not covered.
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
		if got := headerListCoversFrom(c.hTag); got != c.want {
			t.Errorf("headerListCoversFrom(%q)=%v want %v", c.hTag, got, c.want)
		}
	}
}

// publicPEM renders a private key's public half exactly as GenerateKey does
// (PKIX SubjectPublicKeyInfo), which is what RecordValue consumes.
func publicPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
