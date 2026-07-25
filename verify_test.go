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

// ── Duplicate tags invalidate the tag-list (RFC 6376 §3.2) ───────────────

// signWithDuplicateTag signs a message (relaxed/relaxed) whose DKIM-Signature
// value carries the SAME tag name twice. The signature is computed over the
// exact bytes — duplicate included — so with a last-wins parser every check
// passes and the crypto verifies: the message returns pass even though RFC 6376
// §3.2 says a tag-list with a repeated tag name is entirely invalid ("if a tag
// name does occur more than once, the entire tag-list is invalid"). It is the
// red-green fixture for issue #7. dupPrefix is spliced in ahead of the genuine
// tags (e.g. "s=bogus; ") so a first-wins verifier would resolve the tag
// differently from a last-wins one — the verdict divergence the RFC forbids.
func signWithDuplicateTag(t *testing.T, priv *rsa.PrivateKey, d, s, dupPrefix string, fields []string, body string) []byte {
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
		"; " + dupPrefix + "d=" + d + "; s=" + s + "; h=" + hlist + "; bh=" + bh + "; b="

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

// TestVerify_DuplicateTagRejected is the red-green anchor for issue #7: the
// signature is cryptographically valid but its tag-list repeats s= (s=bogus …
// s=sel). Before the fix the parser silently keeps the last value, every check
// passes and the verifier returns pass — while a first-wins verifier would look
// up s=bogus and disagree, the cross-implementation divergence RFC 6376 §3.2
// forbids. The fix rejects the duplicate at parse time and returns PERMFAIL.
func TestVerify_DuplicateTagRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithDuplicateTag(t, priv, "example.test", "sel", "s=bogus; ", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on duplicate tag, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "duplicate") {
		t.Errorf("want a duplicate-tag reason, got %q", results[0].Reason)
	}
}

// TestVerify_DuplicateTagInKeyRecordRejected covers the second parse path named
// in issue #7: the DNS key record repeats p= (a bogus value first, the genuine
// key second). A last-wins parser keeps the valid key and the message verifies;
// RFC 6376 §3.2 makes the whole record invalid, so the key must be rejected and
// the result is PERMFAIL (no usable key).
func TestVerify_DuplicateTagInKeyRecordRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	valid, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	validP := strings.TrimPrefix(valid, "v=DKIM1; k=rsa; ") // "p=<base64 DER>"
	rec := "v=DKIM1; k=rsa; p=BOGUS; " + validP             // two p= tags
	resolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{rec}, nil
	}

	results := Verify(context.Background(), raw, resolver)
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on duplicate-tag key record, got %s (%s)", results[0].Result, results[0].Reason)
	}
}

// ── Key-record h= acceptable hash algorithms (RFC 6376 §3.6.1 / §6.1.2) ──

// keyRecordWithHashTag renders a valid DKIM key record for the given public PEM
// and appends an h= tag listing algs (e.g. "sha1" or "sha1:sha256"), yielding
// the TXT value a resolver publishes for a key that restricts which hash
// algorithms it may be used with.
func keyRecordWithHashTag(t *testing.T, pubPEM, algs string) string {
	t.Helper()
	rec, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rec + "; h=" + algs
}

// keyRecordResolver returns a resolver publishing rec at selector/domain and
// NXDOMAIN elsewhere — the key-record analogue of testKeyResolver, but for a
// caller-supplied record value.
func keyRecordResolver(selector, domain, rec string) TXTResolver {
	want := RecordName(selector, domain)
	return func(_ context.Context, name string) ([]string, error) {
		if name == want {
			return []string{rec}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// TestVerify_KeyHashAlgorithmNotAllowedRejected is the red-green anchor for
// issue #8: the message is signed correctly with rsa-sha256, but the key record
// published in DNS carries h=sha1 — declaring sha1 the ONLY hash algorithm the
// domain permits with this key. RFC 6376 §3.6.1 makes h= the per-key list of
// acceptable hash algorithms, and §6.1.2 requires the verifier to ignore a key
// record whose h= does not include the signature's hash algorithm, leading to
// PERMFAIL. Before the fix the h= tag was never read, so an rsa-sha256
// signature verified against an h=sha1 key — an algorithm-downgrade acceptance
// avenue by which a key the domain published for sha1 only accepts a stronger
// (or any other) algorithm it never authorized. The fix skips the record; with
// no other usable record the verifier PERMFAILs.
func TestVerify_KeyHashAlgorithmNotAllowedRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	rec := keyRecordWithHashTag(t, pubPEM, "sha1") // key permits sha1 only
	results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("rsa-sha256 signature against an h=sha1 key must PERMFAIL, got %s (%s)",
			results[0].Result, results[0].Reason)
	}
}

// TestVerify_KeyHashAlgorithmAllowedVerifies confirms the h= enforcement does
// not over-reach: when the key record's h= list DOES include the signature's
// hash algorithm — on its own, within a longer list, in either order, with the
// folding whitespace §3.6.1 permits around the colon, and alongside an
// unrecognized algorithm that §3.6.1 says to ignore rather than let veto the
// match — verification still passes.
func TestVerify_KeyHashAlgorithmAllowedVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	for _, algs := range []string{"sha256", "sha1:sha256", "sha256:sha1", "sha1 : sha256", "sha256:x-future-hash"} {
		t.Run(algs, func(t *testing.T) {
			rec := keyRecordWithHashTag(t, pubPEM, algs)
			results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
			if len(results) != 1 || results[0].Result != ResultPass {
				t.Fatalf("h=%q includes sha256; want pass, got %+v", algs, results)
			}
		})
	}
}

// TestKeyRecordAllowsHash pins the h= list-matching helper directly: the
// signature's hash name must appear in the key record's colon-separated h= list,
// matched case-insensitively with surrounding folding whitespace ignored, and an
// unrecognized entry must neither match nor suppress a later valid one.
func TestKeyRecordAllowsHash(t *testing.T) {
	allow := []struct{ hTag, alg string }{
		{"sha256", "sha256"},
		{"SHA256", "sha256"},
		{"sha1:sha256", "sha256"},
		{"sha256:sha1", "sha1"},
		{" sha1 : sha256 ", "sha256"},
		{"x-unknown:sha256", "sha256"},
	}
	for _, c := range allow {
		if !keyRecordAllowsHash(c.hTag, c.alg) {
			t.Errorf("keyRecordAllowsHash(%q, %q) = false, want true", c.hTag, c.alg)
		}
	}
	deny := []struct{ hTag, alg string }{
		{"sha1", "sha256"},
		{"sha256", "sha1"},
		{"sha1:sha512", "sha256"},
		{"x-unknown", "sha256"},
		{"", "sha256"},
	}
	for _, c := range deny {
		if keyRecordAllowsHash(c.hTag, c.alg) {
			t.Errorf("keyRecordAllowsHash(%q, %q) = true, want false", c.hTag, c.alg)
		}
	}
}

// ── Key-record version v= (RFC 6376 §3.6.1 / §6.1.2) ────────────────────

// TestVerify_KeyRecordWrongVersionRejected is the red-green anchor for issue
// #11: the message is signed correctly, but the key record published in DNS
// advertises v=DKIM2 — an unknown key-record version. RFC 6376 §3.6.1 defines
// the key record's v= tag (default "DKIM1") and requires that, when present, it
// equal "DKIM1"; §6.1.2 makes a verifier ignore a record with any other version.
// Before the fix the v= tag was never read, so a v=DKIM2 record was used exactly
// as a DKIM1 record and the signature verified — a domain's future/parallel key
// scheme silently honored under DKIM1 rules. The fix skips the record; with no
// other usable record the verifier PERMFAILs. (This is the DNS KEY record's v=,
// distinct from the DKIM-Signature header's v= enforced at §3.5 / issue #14.)
func TestVerify_KeyRecordWrongVersionRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	valid, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	rec := strings.Replace(valid, "v=DKIM1", "v=DKIM2", 1) // wrong key-record version
	results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("v=DKIM2 key record must PERMFAIL, got %s (%s)", results[0].Result, results[0].Reason)
	}
}

// TestVerify_KeyRecordVersionNotFirstRejected covers §3.6.1's ordering rule: a
// key record's v= tag, when present, MUST be the FIRST tag in the record. Here
// the value is the correct "DKIM1" but it appears after k=, so the record is
// malformed and MUST NOT be used. Before the fix v= was never inspected, so this
// record (a valid DKIM1 key by value) verified; the fix skips it and the
// verifier PERMFAILs.
func TestVerify_KeyRecordVersionNotFirstRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	valid, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	validP := strings.TrimPrefix(valid, "v=DKIM1; k=rsa; ") // "p=<base64 DER>"
	rec := "k=rsa; v=DKIM1; " + validP                      // v= present but not first
	results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("key record with a non-first v= must PERMFAIL, got %s (%s)", results[0].Result, results[0].Reason)
	}
}

// TestVerify_KeyRecordVersionAcceptedVerifies is the green guard: the v=
// enforcement must not over-reach. A record that omits v= entirely (default
// DKIM1, §3.6.1) and one that carries v=DKIM1 as its first tag (case-sensitive,
// as the RFC requires) both remain usable and the signature verifies.
func TestVerify_KeyRecordVersionAcceptedVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	valid, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	absentV := strings.TrimPrefix(valid, "v=DKIM1; ") // "k=rsa; p=<base64 DER>"

	for _, c := range []struct{ name, rec string }{
		{"present-DKIM1-first", valid},
		{"absent", absentV},
	} {
		t.Run(c.name, func(t *testing.T) {
			results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", c.rec))
			if len(results) != 1 || results[0].Result != ResultPass {
				t.Fatalf("record %q must verify; want pass, got %+v", c.rec, results)
			}
		})
	}
}

// TestFirstTagName pins the ordering helper directly: it returns the name of the
// first tag in a DKIM tag-list record, ignoring the ABNF's optional leading
// folding whitespace and empty leading segments, and "" when there is no tag.
func TestFirstTagName(t *testing.T) {
	cases := []struct{ rec, want string }{
		{"v=DKIM1; k=rsa; p=AAA", "v"},
		{"k=rsa; v=DKIM1; p=AAA", "k"},
		{"  v=DKIM1; p=AAA", "v"},
		{"; v=DKIM1", "v"},
		{"p=AAA", "p"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := firstTagName(c.rec); got != c.want {
			t.Errorf("firstTagName(%q) = %q, want %q", c.rec, got, c.want)
		}
	}
}

// ── Signature expiration x= / timestamp t= (RFC 6376 §3.5 / §6.1.1) ──────

// signWithTiming signs a message (relaxed/relaxed) exactly like signTestMessage
// but splices timing tags (timing, e.g. "t=1000000000; x=1000000001; ") into
// the signed tag-list just before h=. Because the tags are part of the signed
// data the crypto verifies, so any rejection comes from the timing semantics
// themselves — not a broken signature. It is the fixture for the expiration
// tests: without an x= check an expired signature (x= in the past) still
// verifies as pass.
func signWithTiming(t *testing.T, priv *rsa.PrivateKey, d, s, timing string, fields []string, body string) []byte {
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
		"; d=" + d + "; s=" + s + "; " + timing + "h=" + hlist + "; bh=" + bh + "; b="

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

// TestVerify_ExpiredSignatureRejected is the red-green anchor for issue #9: the
// message is signed correctly but carries t=1000000000; x=1000000001 — an
// expiration in 2001. Before the fix the verifier never reads x=, so the crypto
// passes and it returns pass, letting an old captured message be replayed
// indefinitely despite the signer's explicit expiry. RFC 6376 §6.1.1 lets a
// verifier treat an expired signature as invalid; the fix PERMFAILs it.
func TestVerify_ExpiredSignatureRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithTiming(t, priv, "example.test", "sel", "t=1000000000; x=1000000001; ", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on expired x=, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "expired") {
		t.Errorf("want an expired reason, got %q", results[0].Reason)
	}
}

// withFixedNow pins the package clock to a fixed instant for the duration of a
// test (restored on cleanup), so the x= expiry boundary is exercised
// deterministically rather than against the wall clock.
func withFixedNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = prev })
}

// TestVerify_NonExpiredSignatureVerifies keeps the legitimate case passing: a
// signature whose x= lies in the future (relative to the injected clock) must
// still verify. It pins that the §6.1.1 expiry check rejects only expired
// signatures and leaves a live one untouched.
func TestVerify_NonExpiredSignatureVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	// now = 2001-09-09T01:46:40Z (Unix 1000000000); x= one hour later.
	withFixedNow(t, time.Unix(1000000000, 0))
	raw := signWithTiming(t, priv, "example.test", "sel", "t=999999999; x=1000003600; ", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPass {
		t.Errorf("want pass on non-expired x=, got %s (%s)", results[0].Result, results[0].Reason)
	}
}

// TestVerify_ExpirationBoundary pins the RFC 6376 §6.1.1 boundary: a signature
// is expired when now is AT OR AFTER x=, and live strictly before it.
func TestVerify_ExpirationBoundary(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")
	raw := signWithTiming(t, priv, "example.test", "sel", "x=1000000000; ", fields(), "Body.\r\n")

	t.Run("now==x is expired", func(t *testing.T) {
		withFixedNow(t, time.Unix(1000000000, 0))
		if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPermError {
			t.Fatalf("now==x should PERMFAIL (expired), got %+v", r)
		}
	})
	t.Run("now<x is live", func(t *testing.T) {
		withFixedNow(t, time.Unix(999999999, 0))
		if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPass {
			t.Fatalf("now<x should pass, got %+v", r)
		}
	})
}

// TestVerify_ExpirationNotAfterTimestampRejected pins RFC 6376 §3.5: when both
// t= and x= are present, x= MUST be greater than t=. An x= <= t= is malformed
// and PERMFAILs regardless of the current time — the check runs ahead of the
// expiry comparison, so x==t is rejected as malformed, not merely "expired".
func TestVerify_ExpirationNotAfterTimestampRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")
	// now well before x=, so an accidental expiry path cannot mask the x<=t reject.
	withFixedNow(t, time.Unix(1000000000, 0))

	for _, timing := range []string{
		"t=2000000000; x=2000000000; ", // x == t
		"t=2000000001; x=2000000000; ", // x < t
	} {
		t.Run(timing, func(t *testing.T) {
			raw := signWithTiming(t, priv, "example.test", "sel", timing, fields(), "Body.\r\n")
			if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPermError {
				t.Fatalf("want permerror on x<=t, got %+v", r)
			}
		})
	}
}

// TestVerify_InvalidExpirationTagRejected pins the RFC 6376 §3.5 x= ABNF
// (1*12DIGIT): a non-numeric or over-long x= is syntactically invalid and
// PERMFAILs rather than being silently ignored.
func TestVerify_InvalidExpirationTagRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

	for _, bad := range []string{"notanumber", "-1", "+5", "1e6", "9999999999999"} {
		t.Run(bad, func(t *testing.T) {
			raw := signWithTiming(t, priv, "example.test", "sel", "x="+bad+"; ", fields(), "Body.\r\n")
			r := Verify(context.Background(), raw, resolver)
			if len(r) != 1 || r[0].Result != ResultPermError {
				t.Fatalf("want permerror on invalid x=%q, got %+v", bad, r)
			}
			if !strings.Contains(r[0].Reason, "x=") {
				t.Errorf("want an x= reason, got %q", r[0].Reason)
			}
		})
	}
}

// TestParseTimeTag pins the RFC 6376 §3.5 timestamp ABNF (1*12DIGIT) directly:
// digits only, non-empty, at most 12 digits; anything else is an error.
func TestParseTimeTag(t *testing.T) {
	good := map[string]int64{"0": 0, "1000000000": 1000000000, "999999999999": 999999999999}
	for in, want := range good {
		if got, err := parseTimeTag(in); err != nil || got != want {
			t.Errorf("parseTimeTag(%q)=%d,%v want %d,nil", in, got, err, want)
		}
	}
	for _, bad := range []string{"", " ", "-1", "+1", "1e6", "12.5", "abc", "1000000000000"} {
		if _, err := parseTimeTag(bad); err == nil {
			t.Errorf("parseTimeTag(%q) should error", bad)
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

// ── Unpadded base64 tolerance (RFC 6376 §2.10 / §3.5) — issue #10 ─────────
//
// RFC 6376's base64string ABNF makes the trailing "=" padding OPTIONAL, so a
// conformant signer or key record may emit unpadded base64. verify.go must
// decode bh=, b= and key p= tolerantly and MUST NOT reject an otherwise-valid
// signature with a spurious "invalid base64" PERMFAIL merely because the
// padding is absent.

// signTestMessageUnpadded is signTestMessage (relaxed/relaxed) with the base64
// padding stripped from the two signature-carried base64 values: bh= (which is
// part of the signed header bytes, so the signature is computed over the
// unpadded form) and b= (the signature itself, not self-covered). A SHA-256
// digest is 32 bytes and a 1024-bit RSA signature is 128 bytes — both ≡ 2
// (mod 3) — so each canonical encoding carries exactly one "=" that this strips,
// yielding values whose length is not a multiple of four. The produced
// signature is cryptographically valid; only its base64 encoding is unpadded.
func signTestMessageUnpadded(t *testing.T, priv *rsa.PrivateKey, d, s string, fields []string, body string) []byte {
	t.Helper()
	const hcanon, bcanon = "relaxed", "relaxed"

	bodyHash := sha256.Sum256([]byte(CanonicalizeBody(body, bcanon)))
	bh := strings.TrimRight(base64.StdEncoding.EncodeToString(bodyHash[:]), "=")

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
	b64 := strings.TrimRight(base64.StdEncoding.EncodeToString(sig), "=")

	var msg strings.Builder
	msg.WriteString("DKIM-Signature:" + sigVal + b64 + "\r\n")
	for _, f := range fields {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

// unpaddedKeyResolver serves the signer's public key as a normal DKIM TXT record
// but with the trailing "=" padding stripped from its p= value (p= is the last
// tag, so trimming the record's trailing "=" trims only the p= padding).
func unpaddedKeyResolver(t *testing.T, pubPEM, selector, domain string) TXTResolver {
	t.Helper()
	txt, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatalf("RecordValue: %v", err)
	}
	unpadded := strings.TrimRight(txt, "=")
	if unpadded == txt {
		t.Fatalf("key p= carried no padding to strip; pick a key size whose DER length is not a multiple of 3")
	}
	want := RecordName(selector, domain)
	return func(_ context.Context, name string) ([]string, error) {
		if name == want {
			return []string{unpadded}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// TestVerify_UnpaddedBase64Accepted is the issue #10 regression: a signature or
// key record whose base64 values omit the optional "=" padding must still
// verify. On the pre-fix strict-padded decoder each subtest PERMFAILs with a
// spurious "invalid base64"; padded inputs must keep verifying unchanged.
func TestVerify_UnpaddedBase64Accepted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := publicPEM(t, priv)
	body := "Hello DKIM world.\r\nSecond line.\r\n"

	t.Run("unpadded bh= and b=", func(t *testing.T) {
		raw := signTestMessageUnpadded(t, priv, "example.test", "sel", fields(), body)
		results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
		if len(results) != 1 {
			t.Fatalf("want 1 result, got %d", len(results))
		}
		if results[0].Result != ResultPass {
			t.Fatalf("unpadded bh=/b= must verify, got %s (%s)", results[0].Result, results[0].Reason)
		}
	})

	t.Run("unpadded key p=", func(t *testing.T) {
		// 1032-bit key: its SubjectPublicKeyInfo DER length is not a multiple of
		// 3, so the canonical p= base64 carries padding to strip (a 1024/2048-bit
		// key's DER length is a multiple of 3 and would need none). The signature
		// itself stays padded — only the published key record is unpadded.
		kpriv, kerr := rsa.GenerateKey(rand.Reader, 1032)
		if kerr != nil {
			t.Fatal(kerr)
		}
		raw := signTestMessage(t, kpriv, "example.test", "sel", "relaxed", "relaxed", fields(), body)
		results := Verify(context.Background(), raw, unpaddedKeyResolver(t, publicPEM(t, kpriv), "sel", "example.test"))
		if len(results) != 1 {
			t.Fatalf("want 1 result, got %d", len(results))
		}
		if results[0].Result != ResultPass {
			t.Fatalf("unpadded key p= must verify, got %s (%s)", results[0].Result, results[0].Reason)
		}
	})

	t.Run("padded still verifies (regression)", func(t *testing.T) {
		raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), body)
		results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
		if len(results) != 1 || results[0].Result != ResultPass {
			t.Fatalf("padded base64 must still verify, got %+v", results)
		}
	})
}

// TestDecodeBase64Tag exercises the tolerant decoder that all three verify.go
// base64 sites (bh=, b=, key p=) share, over the shapes RFC 6376 §2.10 / §3.5
// permit: padded and unpadded (length ≡ 2 and ≡ 3 mod 4), values carrying folding
// whitespace, and genuinely invalid input that must still be rejected.
func TestDecodeBase64Tag(t *testing.T) {
	// Inputs chosen so the canonical encoding needs padding: 4 bytes ≡ 1 (mod 3)
	// → 2 pad chars (encoded length ≡ 3 mod 4); 5 bytes ≡ 2 (mod 3) → 1 pad char
	// (encoded length ≡ 2 mod 4). 3 bytes needs none (length ≡ 0 mod 4).
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"one pad char (len%4==2)", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}},
		{"two pad chars (len%4==3)", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"no pad needed (len%4==0)", []byte{0xDE, 0xAD, 0xBE}},
		{"empty", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			padded := base64.StdEncoding.EncodeToString(tc.raw)
			unpadded := strings.TrimRight(padded, "=")

			for label, in := range map[string]string{
				"padded":              padded,
				"unpadded":            unpadded,
				"unpadded + FWS fold": insertFWS(unpadded),
				"padded + FWS fold":   insertFWS(padded),
			} {
				got, err := decodeBase64Tag(in)
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", label, err)
				}
				if !bytesEqual(got, tc.raw) {
					t.Fatalf("%s: decoded %x, want %x", label, got, tc.raw)
				}
			}
		})
	}

	// Genuinely invalid base64 must still be rejected (not silently accepted).
	for _, bad := range []string{"!!!!", "AB=C", "ABCDE"} { // last is length ≡ 1 mod 4
		if _, err := decodeBase64Tag(bad); err == nil {
			t.Errorf("decodeBase64Tag(%q) accepted invalid input, want error", bad)
		}
	}
}

// insertFWS splices a CRLF+space fold into the middle of a base64 string to model
// a value folded across lines (RFC 6376 permits FWS within base64string).
func insertFWS(s string) string {
	if len(s) < 2 {
		return s
	}
	mid := len(s) / 2
	return s[:mid] + "\r\n " + s[mid:]
}

// ── Signature v= version tag is REQUIRED and MUST be 1 (RFC 6376 §3.5) — issue #14 ──
//
// RFC 6376 §3.5 lists v= as the first, REQUIRED tag of a DKIM-Signature and
// specifies its value MUST be "1". A signature lacking v= is malformed and must
// PERMFAIL — it must NOT be accepted merely because a wrong-version guard only
// fired when v= was present. (This is the signature header's v=, distinct from
// the key record's v=DKIM1, which is issue #11.)

// signWithVersionTag signs a message (relaxed/relaxed) exactly like
// signTestMessage but lets the caller control the leading v= tag of the
// DKIM-Signature. versionTag is spliced verbatim at the front of the tag-list
// (e.g. "v=1; ", "v=2; ", or "" to omit v= entirely) and is part of the signed
// data, so the produced signature is cryptographically valid over whatever
// version tag — or none — the caller chose. This isolates the version-tag
// semantics from the crypto: any rejection comes from the v= check itself, not a
// broken signature.
func signWithVersionTag(t *testing.T, priv *rsa.PrivateKey, d, s, versionTag string, fields []string, body string) []byte {
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

	sigVal := " " + versionTag + "a=rsa-sha256; c=" + hcanon + "/" + bcanon +
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
	for _, f := range fields {
		msg.WriteString(f + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

// TestVerify_MissingVersionRejected is the red-green anchor for issue #14: the
// message is signed correctly but its DKIM-Signature carries NO v= tag. Before
// the fix the version guard only rejected a WRONG version (v= present but != 1)
// and the required-tag loop never listed v=, so an absent v= slipped through the
// `!= ""` short-circuit and the signature was accepted (pass) — even though RFC
// 6376 §3.5 makes v= REQUIRED. The fix treats a missing v= as a malformed
// signature and PERMFAILs.
func TestVerify_MissingVersionRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithVersionTag(t, priv, "example.test", "sel", "", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on missing v=, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "required tag v") {
		t.Errorf("want a missing-version reason, got %q", results[0].Reason)
	}
}

// TestVerify_WrongVersionRejected pins the other half of RFC 6376 §3.5: v= MUST
// equal "1". A signature declaring v=2 is an unsupported version and PERMFAILs.
// This case was already caught by the version guard before issue #14; the test
// guards that the missing-v fix does not regress it.
func TestVerify_WrongVersionRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithVersionTag(t, priv, "example.test", "sel", "v=2; ", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("want permerror on v=2, got %s (%s)", results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "version") {
		t.Errorf("want an unsupported-version reason, got %q", results[0].Reason)
	}
}

// TestVerify_VersionOneVerifies keeps the legitimate case passing: a signature
// with v=1 (through the same helper) must still verify, pinning that the §3.5 v=
// enforcement rejects only the missing/wrong-version cases and leaves a
// conformant signature untouched.
func TestVerify_VersionOneVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithVersionTag(t, priv, "example.test", "sel", "v=1; ", fields(), "Body.\r\n")

	results := Verify(context.Background(), raw, testKeyResolver(t, pubPEM, "sel", "example.test"))
	if len(results) != 1 || results[0].Result != ResultPass {
		t.Fatalf("want pass with v=1, got %+v", results)
	}
}

// ── Bare (policy-free) verification for ARC (RFC 8617 §4.1.2) — issue #33 ──
//
// VerifySignatureBare is the policy-free cryptographic primitive: it selects the
// h= headers, canonicalizes per c=, hashes per a=/l=, and RSA-verifies b= against
// the d=/s= key — and NOTHING else. It applies none of the RFC 6376
// DKIM-Signature POLICY that VerifySignature layers on top (v= required, From
// signed, i= alignment, timing, key t=s/s= flags). It exists so a layered scheme
// can verify a signature that is structurally a DKIM-Signature but governed by
// its own policy: an ARC-Message-Signature is versionless by design (RFC 8617
// §4.1.2) and carries no author-alignment semantics, so an ARC verifier checks
// the AMS mechanism here and then enforces RFC 8617 itself.
//
// These tests pin the SEAM: the same signature that VerifySignatureBare accepts
// on mechanism, VerifySignature rejects on the DKIM policy it violates — and that
// VerifySignature's strictness is unchanged is covered by every other test here.

// splitToSig splits a raw message and returns the DKIM-Signature header together
// with the full header block and body — the exact inputs the per-signature
// primitives consume — so a test can drive VerifySignature / VerifySignatureBare
// directly.
func splitToSig(t *testing.T, raw []byte) (Header, []Header, string) {
	t.Helper()
	headers, body := SplitMessage(raw)
	for _, h := range headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			return h, headers, body
		}
	}
	t.Fatal("no DKIM-Signature header in message")
	return Header{}, nil, ""
}

// TestVerifySignatureBare_VersionlessSeam is the core red-green anchor for issue
// #33: a correctly signed VERSIONLESS signature (the ARC-Message-Signature shape,
// RFC 8617 §4.1.2 — no v= tag) verifies through the bare mechanism primitive, yet
// the SAME signature PERMFAILs through VerifySignature because RFC 6376 §3.5 makes
// v= a required DKIM policy tag. This is the seam that lets ARC reuse go-dkim's
// crypto path without inheriting its DKIM policy.
func TestVerifySignatureBare_VersionlessSeam(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithVersionTag(t, priv, "example.test", "sel", "", fields(), "Body.\r\n")
	sig, headers, body := splitToSig(t, raw)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

	if res := VerifySignatureBare(context.Background(), sig, headers, body, resolver); res.Result != ResultPass {
		t.Errorf("bare: versionless signature must verify, got %s (%s)", res.Result, res.Reason)
	}
	res := VerifySignature(context.Background(), sig, headers, body, resolver)
	if res.Result != ResultPermError {
		t.Errorf("VerifySignature: versionless must PERMFAIL (v= required), got %s (%s)", res.Result, res.Reason)
	}
	if !strings.Contains(res.Reason, "required tag v") {
		t.Errorf("VerifySignature: want a missing-version reason, got %q", res.Reason)
	}
}

// TestVerifySignatureBare_IgnoresIdentityAlignment pins that i=/d= alignment (RFC
// 6376 §6.1.1) is DKIM POLICY, not mechanism: a cryptographically valid signature
// whose i= domain is unaligned with d= verifies through the bare primitive but
// PERMFAILs through VerifySignature.
func TestVerifySignatureBare_IgnoresIdentityAlignment(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithIdentity(t, priv, "example.test", "sel", "mallory@evil.example", fields(), "Body.\r\n")
	sig, headers, body := splitToSig(t, raw)
	resolver := testKeyResolver(t, pubPEM, "sel", "example.test")

	if res := VerifySignatureBare(context.Background(), sig, headers, body, resolver); res.Result != ResultPass {
		t.Errorf("bare must not enforce i= alignment; want pass, got %s (%s)", res.Result, res.Reason)
	}
	if res := VerifySignature(context.Background(), sig, headers, body, resolver); res.Result != ResultPermError {
		t.Errorf("VerifySignature must enforce i= alignment; want permerror, got %s (%s)", res.Result, res.Reason)
	}
}

// TestVerifySignatureBare_IgnoresKeyPolicyFlags pins that the key record's t=s
// (no-subdomain) and s= (service-type) flags (RFC 6376 §3.6.1) are DKIM POLICY,
// not mechanism: a valid signature verifies through the bare primitive even when
// those flags would make VerifySignature PERMFAIL.
func TestVerifySignatureBare_IgnoresKeyPolicyFlags(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)

	// t=s no-subdomain flag vs a subdomain i=.
	raw := signWithIdentity(t, priv, "example.test", "sel", "user@sub.example.test", fields(), "Body.\r\n")
	sig, headers, body := splitToSig(t, raw)
	tsResolver := keyRecordResolver("sel", "example.test", keyRecordWithFlags(t, pubPEM, "s"))
	if res := VerifySignatureBare(context.Background(), sig, headers, body, tsResolver); res.Result != ResultPass {
		t.Errorf("bare must not enforce key t=s flag; want pass, got %s (%s)", res.Result, res.Reason)
	}
	if res := VerifySignature(context.Background(), sig, headers, body, tsResolver); res.Result != ResultPermError {
		t.Errorf("VerifySignature must enforce key t=s flag; want permerror, got %s (%s)", res.Result, res.Reason)
	}

	// s= service-type flag that does not permit email.
	raw2 := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	sig2, headers2, body2 := splitToSig(t, raw2)
	svcResolver := keyRecordResolver("sel", "example.test", keyRecordWithService(t, pubPEM, "tlsa"))
	if res := VerifySignatureBare(context.Background(), sig2, headers2, body2, svcResolver); res.Result != ResultPass {
		t.Errorf("bare must not enforce key s= service flag; want pass, got %s (%s)", res.Result, res.Reason)
	}
	if res := VerifySignature(context.Background(), sig2, headers2, body2, svcResolver); res.Result != ResultPermError {
		t.Errorf("VerifySignature must enforce key s= service flag; want permerror, got %s (%s)", res.Result, res.Reason)
	}
}

// ── Key-record t=s no-subdomain flag (RFC 6376 §3.6.1) ───────────────────

// keyRecordWithFlags renders a valid DKIM key record for the given public PEM
// and appends a t= tag carrying flags (e.g. "s" or "y:s"), yielding the TXT
// value a resolver publishes for a key whose policy flags the verifier must
// apply against the signature.
func keyRecordWithFlags(t *testing.T, pubPEM, flags string) string {
	t.Helper()
	rec, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rec + "; t=" + flags
}

// TestVerify_KeyTSFlagRejectsSubdomainIdentity is the red-green anchor for issue
// #13: the message is signed correctly for d=example.test and carries an AUID in
// a subdomain (i=user@sub.example.test) — which the general d=/i= alignment
// check admits — but the key record published in DNS sets t=s. RFC 6376 §3.6.1
// makes the "s" flag forbid subdomaining: any signature's i= domain MUST equal
// d= exactly. Before the fix the t= flag was never read, so the subdomain AUID
// verified in defiance of the key's published policy. The fix PERMFAILs.
func TestVerify_KeyTSFlagRejectsSubdomainIdentity(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithIdentity(t, priv, "example.test", "sel", "user@sub.example.test", fields(), "Body.\r\n")

	rec := keyRecordWithFlags(t, pubPEM, "s") // key forbids subdomaining
	results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("subdomain i= against a t=s key must PERMFAIL, got %s (%s)",
			results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "t=s") {
		t.Errorf("want a t=s no-subdomain reason, got %q", results[0].Reason)
	}
}

// TestVerify_KeyTSFlagAllowsExactIdentity guards the boundary: t=s must not
// over-reach. When the key sets t=s (in a list "y:s", to also exercise flag-list
// parsing) but the signature's i= domain equals d= exactly — or i= is absent, so
// its §3.5 default "@"+d equals d — verification still passes.
func TestVerify_KeyTSFlagAllowsExactIdentity(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	rec := keyRecordWithFlags(t, pubPEM, "y:s")
	resolver := keyRecordResolver("sel", "example.test", rec)

	for _, iTag := range []string{
		"user@example.test", // exactly d=
		"user@EXAMPLE.TEST", // case-insensitive match of d=
		"@example.test",     // empty local part, domain == d=
	} {
		t.Run(iTag, func(t *testing.T) {
			raw := signWithIdentity(t, priv, "example.test", "sel", iTag, fields(), "Body.\r\n")
			results := Verify(context.Background(), raw, resolver)
			if len(results) != 1 || results[0].Result != ResultPass {
				t.Fatalf("i=%s with t=s key should pass, got %+v", iTag, results)
			}
		})
	}

	// i= absent: default AUID is "@"+d, exactly aligned, so t=s is satisfied.
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")
	if r := Verify(context.Background(), raw, resolver); len(r) != 1 || r[0].Result != ResultPass {
		t.Fatalf("absent i= with t=s key should pass, got %+v", r)
	}
}

// TestVerify_NoTSFlagAllowsSubdomainIdentity guards the default: absent the t=s
// flag, a subdomain AUID (i=user@sub.example.test) remains permitted per RFC
// 6376 §3.6.1 — the fix must not narrow the default subdomain-allowed behavior.
func TestVerify_NoTSFlagAllowsSubdomainIdentity(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signWithIdentity(t, priv, "example.test", "sel", "user@sub.example.test", fields(), "Body.\r\n")

	// Plain key record (no t=), and one whose t= lists only unrelated flags.
	for _, rec := range []string{
		mustRecord(t, pubPEM),
		keyRecordWithFlags(t, pubPEM, "y"), // testing flag, not s
	} {
		results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
		if len(results) != 1 || results[0].Result != ResultPass {
			t.Fatalf("subdomain i= without t=s should pass, got %+v", results)
		}
	}
}

func mustRecord(t *testing.T, pubPEM string) string {
	t.Helper()
	rec, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestParseKeyFlags pins the flag-list parser directly: the "s" (no-subdomain)
// flag is recognized alone, within a colon-separated list, in either case, with
// surrounding folding whitespace ignored; unrecognized flags (e.g. "y") neither
// set it nor suppress a sibling "s".
func TestParseKeyFlags(t *testing.T) {
	set := []string{"s", "S", "y:s", "s:y", " y : s ", "s:x-future"}
	for _, tt := range set {
		if !parseKeyFlags(tt).NoSubdomain {
			t.Errorf("parseKeyFlags(%q).NoSubdomain = false, want true", tt)
		}
	}
	unset := []string{"", "y", "y:x-future", "subdomain"}
	for _, tt := range unset {
		if parseKeyFlags(tt).NoSubdomain {
			t.Errorf("parseKeyFlags(%q).NoSubdomain = true, want false", tt)
		}
	}
}

// ── Key-record s= service type (RFC 6376 §3.6.1) ─────────────────────────

// keyRecordWithService renders a valid DKIM key record for the given public PEM
// and appends an s= tag carrying svcs (e.g. "email", "tlsa", or "email:tlsa"),
// yielding the TXT value a resolver publishes for a key whose service-type list
// restricts which services the key may be used for.
func keyRecordWithService(t *testing.T, pubPEM, svcs string) string {
	t.Helper()
	rec, err := RecordValue(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rec + "; s=" + svcs
}

// TestVerify_KeyServiceTypeNotEmailRejected is the red-green anchor for issue
// #12: the message is signed correctly, but the key record published in DNS
// carries s=tlsa — declaring the ONLY service type the domain permits with this
// key, and it is not email. RFC 6376 §3.6.1 makes s= the per-key colon-separated
// list of service types the key may be used for (default "*", all); a verifier
// evaluating an email signature must use the key only if the list contains
// "email" or "*". Before the fix the s= tag was never read, so a key restricted
// to tlsa still verified an email signature — the key was used for a service the
// domain never authorized it for. The fix PERMFAILs.
func TestVerify_KeyServiceTypeNotEmailRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	rec := keyRecordWithService(t, pubPEM, "tlsa") // key permits tlsa only, not email
	results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Result != ResultPermError {
		t.Errorf("email signature against an s=tlsa key must PERMFAIL, got %s (%s)",
			results[0].Result, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "service") {
		t.Errorf("want a service-type reason, got %q", results[0].Reason)
	}
}

// TestVerify_KeyServiceTypeEmailVerifies confirms the s= enforcement does not
// over-reach: when the key record's s= list DOES cover email — via the "email"
// service on its own, the wildcard "*", email alongside another service, in
// either order, with the folding whitespace §3.6.1 permits around the colon, and
// alongside an unrecognized service type that §3.6.1 says to ignore rather than
// let veto the match — verification still passes. Absent s= (default "*") is
// covered separately below.
func TestVerify_KeyServiceTypeEmailVerifies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := publicPEM(t, priv)
	raw := signTestMessage(t, priv, "example.test", "sel", "relaxed", "relaxed", fields(), "Body.\r\n")

	for _, svcs := range []string{"email", "*", "email:tlsa", "tlsa:email", "email : tlsa", "*:tlsa", "email:x-future-svc"} {
		t.Run(svcs, func(t *testing.T) {
			rec := keyRecordWithService(t, pubPEM, svcs)
			results := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec))
			if len(results) != 1 || results[0].Result != ResultPass {
				t.Fatalf("s=%q covers email; want pass, got %+v", svcs, results)
			}
		})
	}

	// s= absent: default is "*" (all services), so an email signature verifies.
	rec := mustRecord(t, pubPEM)
	if r := Verify(context.Background(), raw, keyRecordResolver("sel", "example.test", rec)); len(r) != 1 || r[0].Result != ResultPass {
		t.Fatalf("absent s= (default *) should pass, got %+v", r)
	}
}

// TestKeyRecordAllowsService pins the s= list-matching helper directly: email is
// permitted when the colon-separated list contains "email" or the wildcard "*",
// matched case-insensitively with surrounding folding whitespace ignored, and an
// unrecognized service type must neither match nor suppress a sibling "email"/"*".
// An empty list permits nothing.
func TestKeyRecordAllowsService(t *testing.T) {
	allow := []struct{ sTag string }{
		{"email"},
		{"EMAIL"},
		{"*"},
		{"email:tlsa"},
		{"tlsa:email"},
		{" tlsa : email "},
		{"*:tlsa"},
		{"x-unknown:email"},
	}
	for _, c := range allow {
		if !keyRecordAllowsService(c.sTag) {
			t.Errorf("keyRecordAllowsService(%q) = false, want true", c.sTag)
		}
	}
	deny := []struct{ sTag string }{
		{"tlsa"},
		{"notemail"},
		{"tlsa:x-unknown"},
		{""},
	}
	for _, c := range deny {
		if keyRecordAllowsService(c.sTag) {
			t.Errorf("keyRecordAllowsService(%q) = true, want false", c.sTag)
		}
	}
}
