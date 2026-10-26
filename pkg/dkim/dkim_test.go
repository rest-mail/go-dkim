package dkim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/rest-mail/go-dkim/pkg/dkim/internal/grammar"
)

// TestParseTagListStrict pins the RFC 6376 §3.2 strict tag-list parser: a
// well-formed list parses (with a trailing ";" permitted), while a repeated tag
// name, a non-empty segment lacking "=", or an empty tag name are all rejected.
//
// checklist: DKIM-TAG-01 DKIM-TAG-04
func TestParseTagListStrict(t *testing.T) {
	// A well-formed list parses; keys and value ends are trimmed.
	got, err := ParseTagListStrict("v=1; a=rsa-sha256 ; d=example.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["v"] != "1" || got["a"] != "rsa-sha256" || got["d"] != "example.test" {
		t.Errorf("parsed map wrong: %#v", got)
	}

	// A trailing ";" leaves an empty final segment, which the ABNF permits.
	if _, err := ParseTagListStrict("v=1; a=rsa-sha256;"); err != nil {
		t.Errorf("trailing ';' should be allowed, got %v", err)
	}

	// A repeated tag name invalidates the whole list (§3.2).
	if _, err := ParseTagListStrict("s=bogus; d=example.test; s=sel"); err == nil {
		t.Error("duplicate tag name must be rejected")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want a duplicate error, got %v", err)
	}

	// A non-empty segment lacking '=' is a malformed tag-spec.
	if _, err := ParseTagListStrict("v=1; garbage; d=example.test"); err == nil {
		t.Error("segment without '=' must be rejected")
	}

	// An empty tag name ("=value") is malformed (tag-name = ALPHA *ALNUMPUNC).
	if _, err := ParseTagListStrict("v=1; =oops"); err == nil {
		t.Error("empty tag name must be rejected")
	}
}

// TestParseTagListStrictFWS checks that folding whitespace is the only
// whitespace a tag-list may hold (RFC 6376 §3.2, RFC 5322 §3.2.2): SP, HTAB and
// a CRLF fold around a name, "=", a value and ";" still parse, while a form
// feed, a vertical tab, U+0085 or U+00A0 — before or after a tag name, before
// "=", or in a value — is refused with an error naming it, so "i\f=1" is not
// read as "i=1".
//
// checklist: DKIM-TAG-08
func TestParseTagListStrictFWS(t *testing.T) {
	for _, s := range []string{"i=1", " i = 1 ;", "\ti\t=\t1\t", "\r\n i\r\n\t=\r\n 1\r\n\t;\r\n a=b"} {
		if tags, err := ParseTagListStrict(s); err != nil || tags["i"] != "1" {
			t.Errorf("%q: got %q, %v; want i=1", s, tags, err)
		}
	}
	for _, ws := range []rune{'\f', '\v', '\u0085', '\u00a0'} {
		w := string(ws)
		for _, s := range []string{w + "i=1", "i" + w + "=1", "i=" + w + "1", "i=1" + w + "2", "i=1" + w, "i=1;" + w} {
			_, err := ParseTagListStrict(s)
			if err == nil {
				t.Errorf("%q accepted", s)
			} else if !strings.Contains(err.Error(), fmt.Sprintf("%U", ws)) {
				t.Errorf("%q: error %q does not name %U", s, err, ws)
			}
		}
	}
	// The lenient parser does not read such a name as the bare one either.
	if v, ok := ParseTagList("i\f=1")["i"]; ok {
		t.Errorf("ParseTagList read i\\f=1 as i=%q", v)
	}
}

// TestWireWhitespaceIsFWS checks that the code reading tag names, the ":"
// lists of h= and s=, the i= and d= domains and the t= timestamp trims only
// folding whitespace (RFC 6376 §3.2, §3.5, §3.6.1), so other whitespace stays
// part of the text and does not match.
//
// checklist: DKIM-TAG-08
func TestWireWhitespaceIsFWS(t *testing.T) {
	if got := StripWSP(" \tA\r\nB\f\u00a0"); got != "AB\f\u00a0" {
		t.Errorf("StripWSP = %q", got)
	}
	if got := RemoveBValue("v=1; b\f=keep; b =drop"); got != "v=1; b\f=keep; b =" {
		t.Errorf("RemoveBValue = %q", got)
	}
	if got := grammar.FirstTagName("\r\n v =DKIM1"); got != "v" {
		t.Errorf("firstTagName with FWS = %q", got)
	}
	if got := grammar.FirstTagName("\u00a0v=DKIM1"); got != "\u00a0v" {
		t.Errorf("firstTagName with U+00A0 = %q", got)
	}
	if !grammar.ListContains(" sha1 :\r\n\tsha256 ", "sha256") || grammar.ListContains("sha256\v", "sha256") {
		t.Error("listContains trims something other than FWS")
	}
	if !grammar.HeaderListCoversFrom("to : from") || grammar.HeaderListCoversFrom("to:from\f") {
		t.Error("headerListCoversFrom trims something other than FWS")
	}
	if !grammar.DomainAligned(" mail.example.test", "example.test ") || grammar.DomainAligned("example.test\u0085", "example.test") {
		t.Error("domainAligned trims something other than FWS")
	}
	if _, err := grammar.ParseTimeTag("\f1700000000"); err == nil {
		t.Error("parseTimeTag accepted a form feed")
	}
	if got := BuildSignedHeaders(" from \f", []Header{{Name: "From", Value: " a", Raw: "From: a"}}, Header{Name: "S", Value: "b=x", Raw: "S:b=x"}, "relaxed"); got != "s:b=" {
		t.Errorf("BuildSignedHeaders signed \"from\\f\" as From: %q", got)
	}
}

// checklist: DKIM-KEY-09
func TestRecordName(t *testing.T) {
	if got := RecordName("default", "mail3.test"); got != "default._domainkey.mail3.test" {
		t.Errorf("RecordName = %q", got)
	}
	if got := RecordName("", "acme.example"); got != "default._domainkey.acme.example" {
		t.Errorf("empty selector should default: %q", got)
	}
}

// checklist: DKIM-ALG-05 DKIM-ALG-07 DKIM-KEY-17
func TestGenerateKeyAndRecordRoundTrip(t *testing.T) {
	if _, _, err := GenerateKey(1024); err == nil {
		t.Error("GenerateKey(1024) succeeded; RFC 8301 asks for at least 2048 bits")
	}
	priv, pub, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Private PEM must parse as an RSA key.
	pb, _ := pem.Decode([]byte(priv))
	if pb == nil || pb.Type != "RSA PRIVATE KEY" {
		t.Fatalf("bad private PEM block: %+v", pb)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	rec, err := RecordValue(pub)
	if err != nil {
		t.Fatalf("RecordValue: %v", err)
	}
	if !strings.HasPrefix(rec, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("record value has wrong prefix: %q", rec)
	}

	// The p= payload must decode to the public half of the generated key.
	b64 := strings.TrimPrefix(rec, "v=DKIM1; k=rsa; p=")
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("p= is not valid base64: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("p= is not a valid public key: %v", err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatal("p= is not an RSA public key")
	}
	if rsaPub.E != 65537 {
		t.Errorf("public exponent %d, want 65537", rsaPub.E)
	}
	if rsaPub.N.Cmp(privKey.N) != 0 || rsaPub.E != privKey.E {
		t.Error("record public key does not match generated private key")
	}
}

// checklist: DKIM-KEY-10
func TestRecordFragmentChunks(t *testing.T) {
	// Short value → single quoted string.
	short := RecordFragment("default._domainkey.d.test", "v=DKIM1; k=rsa; p=abc")
	if short != `txt-record=default._domainkey.d.test,"v=DKIM1; k=rsa; p=abc"` {
		t.Errorf("short fragment wrong: %s", short)
	}

	// A value longer than 255 chars must split into multiple <=255 strings
	// whose concatenation reproduces the original.
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400)
	frag := RecordFragment("n", long)
	quoted := frag[len("txt-record=n,"):]
	parts := strings.Split(quoted, ",")
	if len(parts) < 2 {
		t.Fatalf("expected multiple chunks, got %d: %s", len(parts), frag)
	}
	var joined string
	for _, p := range parts {
		s := strings.TrimPrefix(strings.TrimSuffix(p, `"`), `"`)
		if len(s) > 255 {
			t.Errorf("chunk exceeds 255 chars: %d", len(s))
		}
		joined += s
	}
	if joined != long {
		t.Error("chunks do not reassemble to the original value")
	}

	// An empty value is one empty string.
	if got := RecordFragment("n", ""); got != `txt-record=n,""` {
		t.Errorf("empty fragment wrong: %s", got)
	}
}

// checklist: DKIM-KEY-17
func TestRecordValueRejectsBadInput(t *testing.T) {
	if _, err := RecordValue("not a pem"); err == nil {
		t.Error("expected error for non-PEM input")
	}
	// A valid PEM block that isn't a public key.
	junk := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))
	if _, err := RecordValue(junk); err == nil {
		t.Error("expected error for non-key PEM")
	}
	// A public key of a type DKIM has no algorithm for.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if _, err := RecordValue(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))); err == nil {
		t.Error("expected error for an ECDSA key")
	}
}
