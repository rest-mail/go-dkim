package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	keyMu   sync.Mutex
	rsaKeys = map[int]*rsa.PrivateKey{}
	edKey   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
)

// rsaKey returns an RSA key of the given size, generated once per test run.
func rsaKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	if k := rsaKeys[bits]; k != nil {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeys[bits] = k
	return k
}

// keyRecord renders the DNS key record for a signer's public key.
func keyRecord(t testing.TB, signer crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := RecordValue(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// signAndVerify signs raw with opt, prepends the field, and verifies it with
// opt's key published at opt's selector and domain.
func signAndVerify(t *testing.T, raw string, opt SignOptions) (string, []VerifyResult) {
	t.Helper()
	val, err := Sign([]byte(raw), opt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed := "DKIM-Signature: " + val + "\r\n" + raw
	resolver := recordResolver(map[string]string{RecordName(opt.Selector, opt.Domain): keyRecord(t, opt.PrivateKey)})
	return signed, Verify(context.Background(), []byte(signed), resolver)
}

// sigTags returns the tags of the first DKIM-Signature field of msg.
func sigTags(t *testing.T, msg string) map[string]string {
	t.Helper()
	headers, _ := SplitMessage([]byte(msg))
	for _, h := range headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			tags, err := ParseTagListStrict(h.Value)
			if err != nil {
				t.Fatal(err)
			}
			return tags
		}
	}
	t.Fatal("no DKIM-Signature")
	return nil
}

// hList returns the h= names of a signature, trimmed.
func hList(tags map[string]string) []string {
	var names []string
	for _, n := range strings.Split(tags["h"], ":") {
		names = append(names, strings.TrimSpace(n))
	}
	return names
}

// TestSignAlgorithm checks that an RSA key signs with rsa-sha256, and that the
// signature is RSASSA-PKCS1-v1_5 over the whole SHA-256 hash of the header
// data, checked here with crypto/rsa rather than the package's own verifier.
//
// checklist: DKIM-ALG-01 DKIM-ALG-04
func TestSignAlgorithm(t *testing.T) {
	key := rsaKey(t, 2048)
	raw := buildRaw("body\r\n")
	val, err := Sign([]byte(raw), SignOptions{Domain: "example.test", Selector: "s", PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	signed := "DKIM-Signature: " + val + "\r\n" + raw
	tags := sigTags(t, signed)
	if tags["a"] != "rsa-sha256" {
		t.Fatalf("a=%s, want rsa-sha256", tags["a"])
	}
	headers, _ := SplitMessage([]byte(signed))
	data := BuildSignedHeaders(tags["h"], headers[1:], headers[0], "relaxed")
	sum := sha256.Sum256([]byte(data))
	b, _ := decodeBase64Tag(tags["b"])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], b); err != nil {
		t.Errorf("b= is not PKCS#1 v1.5 over the SHA-256 hash: %v", err)
	}
}

// fakeSigner is a crypto.Signer with any public key, for keys Sign must refuse
// before it signs.
type fakeSigner struct{ pub crypto.PublicKey }

func (f fakeSigner) Public() crypto.PublicKey { return f.pub }
func (f fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, io.ErrUnexpectedEOF
}

// TestSignRejectsShortRSAKey checks that Sign refuses an RSA key under 1024
// bits, and other key types it has no algorithm for.
//
// checklist: DKIM-ALG-06
func TestSignRejectsShortRSAKey(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 1022) // a 1023-bit modulus
	opt := SignOptions{Domain: "example.test", Selector: "s", PrivateKey: fakeSigner{&rsa.PublicKey{N: n, E: 65537}}}
	if _, err := Sign([]byte(buildRaw("x\r\n")), opt); err == nil || !strings.Contains(err.Error(), "1024") {
		t.Errorf("1023-bit key: got %v, want a key-size error", err)
	}
	opt.PrivateKey = fakeSigner{"not a key"}
	if _, err := Sign([]byte(buildRaw("x\r\n")), opt); err == nil {
		t.Error("Sign accepted an unsupported key type")
	}
	// A signer that fails is reported, not ignored.
	opt.PrivateKey = fakeSigner{edKey.Public()}
	if _, err := Sign([]byte(buildRaw("x\r\n")), opt); err == nil {
		t.Error("Sign hid the signer's error")
	}
}

// TestEd25519RoundTrip signs with an Ed25519 key, in every canonicalization,
// and checks the result verifies.
//
// checklist: DKIM-ALG-10 DKIM-ALG-11
func TestEd25519RoundTrip(t *testing.T) {
	for _, c := range [][2]string{{"simple", "simple"}, {"simple", "relaxed"}, {"relaxed", "simple"}, {"relaxed", "relaxed"}} {
		signed, results := signAndVerify(t, buildRaw("Hello\r\n"), SignOptions{
			Domain: "example.test", Selector: "ed", PrivateKey: edKey, HeaderCanon: c[0], BodyCanon: c[1],
		})
		if tags := sigTags(t, signed); tags["a"] != "ed25519-sha256" {
			t.Errorf("a=%s, want ed25519-sha256", tags["a"])
		}
		if len(results) != 1 || results[0].Result != ResultPass {
			t.Errorf("%s/%s: got %+v, want pass", c[0], c[1], results)
		}
	}
}

// TestEd25519SignsHash checks RFC 8463's construction directly: the b= value
// is a PureEdDSA signature of the SHA-256 hash of the header data, not of the
// data itself.
//
// checklist: DKIM-ALG-12
func TestEd25519SignsHash(t *testing.T) {
	signed, _ := signAndVerify(t, buildRaw("x\r\n"), SignOptions{Domain: "example.test", Selector: "ed", PrivateKey: edKey})
	tags := sigTags(t, signed)
	headers, _ := SplitMessage([]byte(signed))
	data := BuildSignedHeaders(tags["h"], headers[1:], headers[0], "relaxed")
	sum := sha256.Sum256([]byte(data))
	b, _ := decodeBase64Tag(tags["b"])
	pub := edKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, sum[:], b) {
		t.Error("b= is not an Ed25519 signature of the SHA-256 hash")
	}
	if ed25519.Verify(pub, []byte(data), b) {
		t.Error("b= signs the data itself, not its hash")
	}
}

// TestSignTags checks the tags Sign emits: v=1, a=, c=, d=, s=, t= when given,
// h=, bh= and b=, and never i=, l=, x= or z=. h= never names the
// DKIM-Signature field being created, even when the message already has one.
//
// checklist: DKIM-SIGN-01 DKIM-SIGN-10 DKIM-SIGN-14
func TestSignTags(t *testing.T) {
	raw := "DKIM-Signature: v=1; a=rsa-sha256; d=other.test; s=x; h=from; bh=; b=\r\n" + buildRaw("body\r\n")
	signed, results := signAndVerify(t, raw, SignOptions{
		Domain: "example.test", Selector: "s1", PrivateKey: rsaKey(t, 2048), HeaderCanon: "simple", Time: 1784775188,
	})
	tags := sigTags(t, signed)
	want := map[string]string{"v": "1", "a": "rsa-sha256", "c": "simple/relaxed", "d": "example.test", "s": "s1", "t": "1784775188"}
	for k, v := range want {
		if tags[k] != v {
			t.Errorf("%s=%q, want %q", k, tags[k], v)
		}
	}
	for _, k := range []string{"h", "bh", "b"} {
		if tags[k] == "" {
			t.Errorf("no %s= tag", k)
		}
	}
	for _, k := range []string{"i", "l", "x", "z", "q"} {
		if _, ok := tags[k]; ok {
			t.Errorf("unexpected %s= tag", k)
		}
	}
	if slices.Contains(hList(tags), "dkim-signature") {
		t.Errorf("h= names DKIM-Signature: %s", tags["h"])
	}
	if results[0].Result != ResultPass {
		t.Errorf("got %+v, want pass", results[0])
	}

	// Without Time there is no t=.
	signed, _ = signAndVerify(t, buildRaw("body\r\n"), SignOptions{Domain: "example.test", Selector: "s1", PrivateKey: edKey})
	if _, ok := sigTags(t, signed)["t"]; ok {
		t.Error("t= emitted without Time")
	}
}

// TestDefaultSignedHeaders checks the default header set: RFC 6376 §5.4.1's
// list, From first, and none of the fields it says to leave out because they
// change in transit.
//
// checklist: DKIM-SIGN-04 DKIM-SIGN-05
func TestDefaultSignedHeaders(t *testing.T) {
	for _, name := range []string{
		"from", "reply-to", "subject", "date", "to", "cc", "resent-date", "resent-from", "resent-to", "resent-cc",
		"in-reply-to", "references", "list-id", "list-help", "list-unsubscribe", "list-subscribe", "list-post",
		"list-owner", "list-archive",
	} {
		if !slices.Contains(DefaultSignedHeaders, name) {
			t.Errorf("DefaultSignedHeaders lacks %s", name)
		}
	}
	for _, name := range []string{"return-path", "received", "comments", "keywords", "dkim-signature"} {
		if slices.Contains(DefaultSignedHeaders, name) || slices.Contains(DefaultOversignedHeaders, name) {
			t.Errorf("default sets include %s", name)
		}
	}
	for _, name := range []string{"from", "to", "cc", "subject", "reply-to", "date", "message-id", "content-type", "mime-version"} {
		if !slices.Contains(DefaultOversignedHeaders, name) {
			t.Errorf("DefaultOversignedHeaders lacks %s", name)
		}
	}

	raw := "Return-Path: <a@example.test>\r\nReceived: from x by y\r\nList-Id: <l.example.test>\r\n" + buildRaw("body\r\n")
	signed, results := signAndVerify(t, raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey})
	h := hList(sigTags(t, signed))
	if h[0] != "from" || !slices.Contains(h, "list-id") || slices.Contains(h, "received") || slices.Contains(h, "return-path") {
		t.Errorf("default h=%v", h)
	}
	if results[0].Result != ResultPass {
		t.Errorf("got %+v, want pass", results[0])
	}
}

// TestOversigning checks that an oversigned field is listed once more than
// the message carries it (once when it is absent), that adding a copy after
// signing breaks the signature, and that adding a field that is signed but not
// oversigned does not, since the verifier picks fields from the bottom up.
//
// checklist: DKIM-SIGN-06 DKIM-SIGN-07 DKIM-SIGN-15
func TestOversigning(t *testing.T) {
	raw := buildRaw("body\r\n") // From, To, Subject, Date, Message-ID, MIME-Version, Content-Type; no Cc
	signed, results := signAndVerify(t, raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey})
	if results[0].Result != ResultPass {
		t.Fatalf("got %+v, want pass", results[0])
	}
	h := hList(sigTags(t, signed))
	count := func(name string) (n int) {
		for _, x := range h {
			if x == name {
				n++
			}
		}
		return n
	}
	for name, want := range map[string]int{"from": 2, "to": 2, "subject": 2, "cc": 1, "reply-to": 1, "list-id": 0, "sender": 0} {
		if got := count(name); got != want {
			t.Errorf("h= lists %s %d times, want %d (h=%v)", name, got, want, h)
		}
	}

	resolver := recordResolver(map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)})
	head, body, _ := strings.Cut(signed, "\r\n\r\n")
	for added, want := range map[string]string{
		"From: Mallory <m@evil.example>": ResultFail, // oversigned and present
		"Cc: m@evil.example":             ResultFail, // oversigned and absent
		"Reply-To: m@evil.example":       ResultFail,
		"Sender: m@evil.example":         ResultPass, // signed if present, but absent and not oversigned
		"X-Mailer: test":                 ResultPass,
	} {
		for _, msg := range []string{
			added + "\r\n" + head + "\r\n\r\n" + body, // above the signature
			head + "\r\n" + added + "\r\n\r\n" + body, // below every other field
		} {
			if r := Verify(context.Background(), []byte(msg), resolver); r[0].Result != want {
				t.Errorf("%s added: got %s, want %s", added, r[0].Result, want)
			}
		}
	}

	// Oversign alone, without Headers: only the oversigned names are signed.
	signed, results = signAndVerify(t, raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey, Oversign: []string{"From"}})
	if h := hList(sigTags(t, signed)); !slices.Equal(h, []string{"from", "from"}) || results[0].Result != ResultPass {
		t.Errorf("Oversign only: h=%v result %+v", h, results[0])
	}
	// Headers alone: nothing oversigned.
	signed, _ = signAndVerify(t, raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey, Headers: []string{"from", "to"}})
	if h := hList(sigTags(t, signed)); !slices.Equal(h, []string{"from", "to"}) {
		t.Errorf("Headers only: h=%v", h)
	}
}

// TestMultipleInstancesBottomUp checks that a signed field the message carries
// several times is listed once per instance, so every instance is signed,
// bottom to top: changing any of them breaks the signature.
//
// checklist: DKIM-SIGN-08
func TestMultipleInstancesBottomUp(t *testing.T) {
	raw := "Received: <A>\r\nReceived: <B>\r\nReceived: <C>\r\n" + buildRaw("body\r\n")
	signed, results := signAndVerify(t, raw, SignOptions{
		Domain: "example.test", Selector: "s", PrivateKey: edKey, Headers: []string{"from", "received"},
	})
	if h := hList(sigTags(t, signed)); !slices.Equal(h, []string{"from", "received", "received", "received"}) {
		t.Fatalf("h=%v", h)
	}
	if results[0].Result != ResultPass {
		t.Fatalf("got %+v, want pass", results[0])
	}
	resolver := recordResolver(map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)})
	for _, which := range []string{"<A>", "<B>", "<C>"} {
		msg := strings.Replace(signed, which, "<X>", 1)
		if r := Verify(context.Background(), []byte(msg), resolver); r[0].Result != ResultFail {
			t.Errorf("changing Received %s: got %s, want fail", which, r[0].Result)
		}
	}
	// Swapping two instances changes the bottom-up order, which is signed.
	msg := strings.Replace(strings.Replace(signed, "<A>", "<tmp>", 1), "<C>", "<A>", 1)
	msg = strings.Replace(msg, "<tmp>", "<C>", 1)
	if r := Verify(context.Background(), []byte(msg), resolver); r[0].Result != ResultFail {
		t.Errorf("reordering Received: got %s, want fail", r[0].Result)
	}
}

// TestSignFolds checks that the signature field is folded so that no line,
// "DKIM-Signature: " included, is longer than 78 characters, even with a
// 4096-bit key and a long h= list, and that it still verifies in both header
// canonicalizations (simple hashes the folds as they are).
//
// checklist: DKIM-ALG-08 DKIM-SIGN-13
func TestSignFolds(t *testing.T) {
	raw := "Cc: a@example.test\r\nReply-To: b@example.test\r\nList-Id: <l.example.test>\r\n" + buildRaw("body\r\n")
	for _, key := range []crypto.Signer{rsaKey(t, 4096), rsaKey(t, 1024), edKey} {
		for _, hc := range []string{"simple", "relaxed"} {
			signed, results := signAndVerify(t, raw, SignOptions{
				Domain: "a-rather-long-subdomain.of-an-example-domain.example.test", Selector: "selector-2026-10",
				PrivateKey: key, HeaderCanon: hc, Time: 1784775188,
			})
			field, _, _ := strings.Cut(signed, "\r\nCc:")
			for _, line := range strings.Split(field, "\r\n") {
				if len(line) > 78 {
					t.Errorf("%s: line of %d characters: %q", hc, len(line), line)
				}
				if strings.HasSuffix(line, " ") {
					t.Errorf("%s: line ends in a space: %q", hc, line)
				}
			}
			if results[0].Result != ResultPass {
				t.Errorf("%s: got %+v, want pass", hc, results[0])
			}
		}
	}
}

// TestSignDoesNotChangeMessage checks that signing leaves the caller's message
// bytes untouched (canonicalization works on a copy), and that existing
// DKIM-Signature fields are kept and still verify after a new signature is
// prepended.
//
// checklist: DKIM-CANON-03 DKIM-SIGN-02 DKIM-SIGN-12 DKIM-SIGN-17
func TestSignDoesNotChangeMessage(t *testing.T) {
	raw := []byte("From:  A <a@example.test> \r\nSubject:\tHi  there\r\n\r\nBody  with   spaces \r\n\r\n")
	orig := bytes.Clone(raw)
	first, err := Sign(raw, SignOptions{Domain: "example.test", Selector: "one", PrivateKey: edKey})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, orig) {
		t.Fatal("Sign changed the message")
	}
	once := append([]byte("DKIM-Signature: "+first+"\r\n"), raw...)
	second, err := Sign(once, SignOptions{Domain: "example.test", Selector: "two", PrivateKey: rsaKey(t, 2048)})
	if err != nil {
		t.Fatal(err)
	}
	twice := append([]byte("DKIM-Signature: "+second+"\r\n"), once...)
	resolver := recordResolver(map[string]string{
		"one._domainkey.example.test": keyRecord(t, edKey),
		"two._domainkey.example.test": keyRecord(t, rsaKey(t, 2048)),
	})
	results := Verify(context.Background(), twice, resolver)
	if len(results) != 2 || results[0].Result != ResultPass || results[1].Result != ResultPass {
		t.Errorf("got %+v, want two passes", results)
	}
}

// TestSignRejectsBadOptions checks Sign's other refusals: a missing domain,
// selector or key, a domain or selector that is not an A-label DNS name, an
// unknown canonicalization, and a header name that is not a field name.
//
// checklist: DKIM-SIG-05 DKIM-SIGN-16
func TestSignRejectsBadOptions(t *testing.T) {
	raw := []byte(buildRaw("x\r\n"))
	ok := SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey}
	if _, err := Sign(raw, ok); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	for name, mutate := range map[string]func(*SignOptions){
		"no domain":         func(o *SignOptions) { o.Domain = "" },
		"no key":            func(o *SignOptions) { o.PrivateKey = nil },
		"U-label domain":    func(o *SignOptions) { o.Domain = "bücher.example" },
		"empty label":       func(o *SignOptions) { o.Domain = "example..test" },
		"space in selector": func(o *SignOptions) { o.Selector = "a b" },
		"long label":        func(o *SignOptions) { o.Selector = strings.Repeat("a", 64) },
		"long name":         func(o *SignOptions) { o.Domain = strings.Repeat("a.", 127) + "test" },
		"header canon":      func(o *SignOptions) { o.HeaderCanon = "nofws" },
		"body canon":        func(o *SignOptions) { o.BodyCanon = "Relaxed" },
		"header name":       func(o *SignOptions) { o.Headers = []string{"from", "bad:name"} },
		"oversign name":     func(o *SignOptions) { o.Oversign = []string{"from", ""} },
	} {
		opt := ok
		mutate(&opt)
		if _, err := Sign(raw, opt); err == nil {
			t.Errorf("%s: Sign succeeded", name)
		}
	}
	if _, err := Sign([]byte("To: b@example.test\r\n\r\nbody\r\n"), ok); err == nil || !strings.Contains(err.Error(), "no From") {
		t.Errorf("message without From: %v", err)
	}
	if !validDNSName("xn--bcher-kva.example") || !validDNSName("_s1.sel-2") {
		t.Error("A-label names rejected")
	}
}
