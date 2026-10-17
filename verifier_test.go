package dkim

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// signWithTags signs raw with a DKIM-Signature carrying exactly the given tags,
// with bh= and b= appended, hashing the header with canonicalization hc and the
// body with bc (truncated to l= when tags has one). It is independent of the
// tags' own c=, so a test can sign a field Sign would never produce and check
// how the verifier reads it.
func signWithTags(t *testing.T, key crypto.Signer, tags, hc, bc, raw string) string {
	t.Helper()
	headers, body := SplitMessage([]byte(raw))
	canon := CanonicalizeBody(body, bc)
	if l := ParseTagList(tags)["l"]; l != "" {
		n, _ := strconv.Atoi(l)
		canon = canon[:min(n, len(canon))]
	}
	sum := sha256.Sum256([]byte(canon))
	value := " " + tags + "; bh=" + base64.StdEncoding.EncodeToString(sum[:]) + "; b="
	sig := Header{Name: "DKIM-Signature", Value: value, Raw: "DKIM-Signature:" + value}
	hashed := sha256.Sum256([]byte(BuildSignedHeaders(ParseTagList(tags)["h"], headers, sig, hc)))
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := key.(ed25519.PrivateKey); ok {
		opts = crypto.Hash(0)
	}
	b, err := key.Sign(rand.Reader, hashed[:], opts)
	if err != nil {
		t.Fatal(err)
	}
	return "DKIM-Signature:" + value + base64.StdEncoding.EncodeToString(b) + "\r\n" + raw
}

// verifyOne verifies msg with the given key records and returns its single
// result.
func verifyOne(t *testing.T, msg string, records map[string]string) VerifyResult {
	t.Helper()
	results := Verify(context.Background(), []byte(msg), recordResolver(records))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	return results[0]
}

const simpleMsg = "From: A <a@example.test>\r\nTo: b@example.test\r\nSubject:  Hello   there \r\n\r\nBody  text \r\n\r\n"

// TestRSASHA1Refused checks that an rsa-sha1 signature, historic since RFC
// 8301, is a permanent error, while the same message signed with rsa-sha256
// passes.
//
// checklist: DKIM-ALG-03
func TestRSASHA1Refused(t *testing.T) {
	key := rsaKey(t, 2048)
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, key)}
	msg := signWithTags(t, key, "v=1; a=rsa-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	if r := verifyOne(t, msg, records); r.Result != ResultPass {
		t.Fatalf("rsa-sha256: %+v", r)
	}
	msg = strings.Replace(msg, "a=rsa-sha256", "a=rsa-sha1", 1)
	if r := verifyOne(t, msg, records); r.Result != ResultPermError || !strings.Contains(r.Reason, "RFC 8301") {
		t.Errorf("rsa-sha1: got %+v, want permerror citing RFC 8301", r)
	}
}

// TestUnknownAlgorithm checks that a signature with an unknown algorithm, or a
// known one spelled in another case, is a permanent error.
//
// checklist: DKIM-TAG-03 DKIM-ALG-13
func TestUnknownAlgorithm(t *testing.T) {
	for _, a := range []string{"rsa-sha512", "RSA-SHA256", "ed448-sha256", "hmac-sha256"} {
		msg := signWithTags(t, edKey, "v=1; a="+a+"; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
		if r := verifyOne(t, msg, nil); r.Result != ResultPermError || !strings.Contains(r.Reason, "unsupported algorithm") {
			t.Errorf("a=%s: got %+v, want permerror", a, r)
		}
	}
}

// rsaRecordOfSize renders a key record for an RSA public key of the given size
// (the modulus need not be a real key: the record must be refused before it is
// used).
func rsaRecordOfSize(t *testing.T, bits int) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// TestVerifyShortRSAKeyRejected checks that a key record holding an RSA key
// under 1024 bits is not usable, so its signatures are a permanent error, not
// merely a failed check.
//
// checklist: DKIM-ALG-09
func TestVerifyShortRSAKeyRejected(t *testing.T) {
	msg := signWithTags(t, rsaKey(t, 1024), "v=1; a=rsa-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	for _, bits := range []int{512, 1023} {
		r := verifyOne(t, msg, map[string]string{"s._domainkey.example.test": rsaRecordOfSize(t, bits)})
		if r.Result != ResultPermError {
			t.Errorf("%d-bit key: got %+v, want permerror", bits, r)
		}
	}
	// FetchKey, which ARC uses, refuses it too.
	_, _, res := FetchKey(context.Background(), "s", "example.test", "sha256",
		recordResolver(map[string]string{"s._domainkey.example.test": rsaRecordOfSize(t, 512)}))
	if res != ResultPermError {
		t.Errorf("FetchKey of a 512-bit key: %q, want permerror", res)
	}
}

// TestUnknownCanonicalization checks that an unknown header or body
// canonicalization, or a known one in another case, is a permanent error.
//
// checklist: DKIM-CANON-02
func TestUnknownCanonicalization(t *testing.T) {
	for _, c := range []string{"nowsp/simple", "simple/nofws", "Relaxed/relaxed", "relaxed/Simple"} {
		msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; c="+c+"; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
		if r := verifyOne(t, msg, nil); r.Result != ResultPermError || !strings.Contains(r.Reason, "canonicalization") {
			t.Errorf("c=%s: got %+v, want permerror", c, r)
		}
	}
}

// TestCanonDefaults checks c='s defaults: absent, both halves are simple; with
// only the header algorithm given, the body is simple. The message has extra
// whitespace in a header and the body, so the wrong algorithm would not
// verify.
//
// checklist: DKIM-CANON-01 DKIM-CANON-04
func TestCanonDefaults(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	for _, c := range []struct{ tag, hc, bc string }{
		{"", "simple", "simple"},
		{"c=relaxed; ", "relaxed", "simple"},
		{"c=simple; ", "simple", "simple"},
		{"c=relaxed/relaxed; ", "relaxed", "relaxed"},
		{"c=simple/relaxed; ", "simple", "relaxed"},
	} {
		tags := "v=1; a=ed25519-sha256; " + c.tag + "d=example.test; s=s; h=from:subject"
		if r := verifyOne(t, signWithTags(t, edKey, tags, c.hc, c.bc, simpleMsg), records); r.Result != ResultPass {
			t.Errorf("%q signed %s/%s: got %+v, want pass", c.tag, c.hc, c.bc, r)
		}
		other := map[string]string{"simple": "relaxed", "relaxed": "simple"}
		if r := verifyOne(t, signWithTags(t, edKey, tags, other[c.hc], c.bc, simpleMsg), records); r.Result != ResultFail {
			t.Errorf("%q signed with the other header algorithm: got %+v, want fail", c.tag, r)
		}
		if r := verifyOne(t, signWithTags(t, edKey, tags, c.hc, other[c.bc], simpleMsg), records); r.Result != ResultFail {
			t.Errorf("%q signed with the other body algorithm: got %+v, want fail", c.tag, r)
		}
	}
}

// TestRequiredTags checks that a signature missing any of the tags the
// mechanism needs, or with an empty h=, is a permanent error, found before any
// key is fetched.
//
// checklist: DKIM-SIG-03 DKIM-VER-06
func TestRequiredTags(t *testing.T) {
	full := map[string]string{"v": "1", "a": "rsa-sha256", "b": "AAAA", "bh": "AAAA", "d": "example.test", "h": "from", "s": "s"}
	headers, body := SplitMessage([]byte(simpleMsg))
	noDNS := func(context.Context, string) ([]string, error) {
		t.Error("a key was fetched for an invalid signature")
		return nil, errors.New("unexpected")
	}
	for missing := range full {
		var parts []string
		for k, v := range full {
			if k != missing {
				parts = append(parts, k+"="+v)
			}
		}
		value := " " + strings.Join(parts, "; ")
		r := VerifySignature(context.Background(), Header{Name: "DKIM-Signature", Value: value, Raw: "DKIM-Signature:" + value}, headers, body, noDNS)
		if r.Result != ResultPermError || !strings.Contains(r.Reason, "missing required tag "+missing) {
			t.Errorf("without %s=: got %+v", missing, r)
		}
	}
}

// TestTagNamesCaseSensitive checks that tag names are case-sensitive: "D=" is
// not d=, and "B=" is an unknown tag that is hashed like any other rather than
// blanked like b=.
//
// checklist: DKIM-TAG-02
func TestTagNamesCaseSensitive(t *testing.T) {
	headers, body := SplitMessage([]byte(simpleMsg))
	value := " v=1; a=rsa-sha256; b=AAAA; bh=AAAA; D=example.test; h=from; s=s"
	r := VerifySignature(context.Background(), Header{Name: "DKIM-Signature", Value: value, Raw: "DKIM-Signature:" + value}, headers, body, nil)
	if r.Result != ResultPermError || !strings.Contains(r.Reason, "missing required tag d") {
		t.Errorf("D=: got %+v, want permerror for a missing d=", r)
	}
	if got := RemoveBValue("v=1; B=keep; b=drop"); got != "v=1; B=keep; b=" {
		t.Errorf("RemoveBValue blanked B=: %q", got)
	}
}

// TestTagValueWhitespace checks that whitespace around a value is not part of
// it and whitespace inside one is kept, folding included.
//
// checklist: DKIM-TAG-05
func TestTagValueWhitespace(t *testing.T) {
	tags, err := ParseTagListStrict(" a = one two ;\r\n\tb=x\r\n y ; c=")
	if err != nil {
		t.Fatal(err)
	}
	if tags["a"] != "one two" || tags["b"] != "x\r\n y" || tags["c"] != "" {
		t.Errorf("got %q", tags)
	}
}

// TestUnknownTagsIgnored checks that unknown signature tags are hashed (a
// changed value breaks the signature) but otherwise ignored, and that unknown
// key record tags are ignored.
//
// checklist: DKIM-TAG-06 DKIM-SIG-01 DKIM-HASH-03 DKIM-KEY-18
func TestUnknownTagsIgnored(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey) + "; n=notes here; g=*; future=1"}
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from; z=From:a@example.test; x_extra=1; B=keep", "simple", "simple", simpleMsg)
	if r := verifyOne(t, msg, records); r.Result != ResultPass {
		t.Fatalf("got %+v, want pass", r)
	}
	for _, change := range [][2]string{{"x_extra=1", "x_extra=2"}, {"B=keep", "B=kept"}} {
		if r := verifyOne(t, strings.Replace(msg, change[0], change[1], 1), records); r.Result != ResultFail {
			t.Errorf("changing %s: got %+v, want fail", change[0], r)
		}
	}
}

// TestDomainSelectorSyntax checks that a signature whose d= or s= is not a DNS
// name in A-label form is a permanent error and sends no query.
//
// checklist: DKIM-SIG-05
func TestDomainSelectorSyntax(t *testing.T) {
	headers, body := SplitMessage([]byte(simpleMsg))
	noDNS := func(context.Context, string) ([]string, error) {
		t.Error("a key was fetched for an invalid name")
		return nil, errors.New("unexpected")
	}
	for _, ds := range [][2]string{{"bücher.example", "s"}, {"example..test", "s"}, {"example.test", "a b"}, {"example.test", "s\x00"}} {
		value := " v=1; a=rsa-sha256; b=AAAA; bh=AAAA; d=" + ds[0] + "; h=from; s=" + ds[1]
		r := VerifySignatureBare(context.Background(), Header{Name: "DKIM-Signature", Value: value, Raw: "DKIM-Signature:" + value}, headers, body, noDNS)
		if r.Result != ResultPermError {
			t.Errorf("d=%q s=%q: got %+v, want permerror", ds[0], ds[1], r)
		}
	}
}

// TestHeaderNamesCaseInsensitive checks that h= names match header fields
// whatever their case, and that the h= list of a verified signature may carry
// whitespace around its colons.
//
// checklist: DKIM-SIG-06 DKIM-VER-09
func TestHeaderNamesCaseInsensitive(t *testing.T) {
	msg := "FROM: A <a@example.test>\r\nsubject: Hi\r\n\r\nbody\r\n"
	signed := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=From :\r\n SUBJECT", "simple", "simple", msg)
	if r := verifyOne(t, signed, map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}); r.Result != ResultPass {
		t.Errorf("got %+v, want pass", r)
	}
	if r := verifyOne(t, strings.Replace(signed, "subject: Hi", "subject: Bye", 1), map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}); r.Result != ResultFail {
		t.Errorf("a changed lower-case subject: got %+v, want fail", r)
	}
}

// TestQueryMethod checks q=: absent or listing dns/txt (with unknown methods
// ignored), the key is fetched; listing only unknown methods, it is a
// permanent error.
//
// checklist: DKIM-SIG-09
func TestQueryMethod(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	for q, want := range map[string]string{"": ResultPass, "q=dns/txt; ": ResultPass, "q=x-ldap/v1 : dns/txt; ": ResultPass, "q=x-ldap/v1; ": ResultPermError, "q=DNS/TXT; ": ResultPermError} {
		msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; "+q+"d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
		if r := verifyOne(t, msg, records); r.Result != want {
			t.Errorf("%q: got %+v, want %s", q, r, want)
		}
	}
}

// TestKeyTypes checks key selection by type: k= defaults to rsa, a key of
// another type than the signature's algorithm is not suitable, an unknown k=
// makes the record ignored, and a later suitable record is still found.
//
// checklist: DKIM-TAG-03 DKIM-KEY-03 DKIM-KEY-15
func TestKeyTypes(t *testing.T) {
	rsaK := rsaKey(t, 2048)
	rsaMsg := signWithTags(t, rsaK, "v=1; a=rsa-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	edMsg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	rsaRec, edRec := keyRecord(t, rsaK), keyRecord(t, edKey)
	noK := strings.Replace(rsaRec, " k=rsa;", "", 1)
	for _, c := range []struct {
		name, msg string
		records   []string
		want      string
	}{
		{"rsa, no k=", rsaMsg, []string{noK}, ResultPass},
		{"rsa signature, ed25519 key", rsaMsg, []string{edRec}, ResultPermError},
		{"ed25519 signature, rsa key", edMsg, []string{rsaRec}, ResultPermError},
		{"ed25519 signature, no k=", edMsg, []string{strings.Replace(edRec, " k=ed25519;", "", 1)}, ResultPermError},
		{"unknown k=", rsaMsg, []string{strings.Replace(rsaRec, "k=rsa", "k=dsa", 1)}, ResultPermError},
		{"k=RSA", rsaMsg, []string{strings.Replace(rsaRec, "k=rsa", "k=RSA", 1)}, ResultPermError},
		{"unknown k= then rsa", rsaMsg, []string{strings.Replace(rsaRec, "k=rsa", "k=dsa", 1), rsaRec}, ResultPass},
		{"ed25519 key in SPKI under k=rsa", edMsg, []string{"k=rsa; p=" + edSPKI(t)}, ResultPermError},
	} {
		resolver := func(context.Context, string) ([]string, error) { return c.records, nil }
		if r := Verify(context.Background(), []byte(c.msg), resolver); r[0].Result != c.want {
			t.Errorf("%s: got %+v, want %s", c.name, r[0], c.want)
		}
	}
}

// publicPEMOf PEM-encodes a public key as a SubjectPublicKeyInfo.
func publicPEMOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// edSPKI returns the test Ed25519 key as base64 SubjectPublicKeyInfo.
func edSPKI(t *testing.T) string {
	der, err := x509.MarshalPKIXPublicKey(edKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// TestRSAPublicKeyFormats checks that an RSA p= is accepted both as the
// RSAPublicKey RFC 6376 §3.6.1 names and as the SubjectPublicKeyInfo its
// Appendix C and most publishers use, and that an RSA key in a k=ed25519
// record is not.
//
// checklist: DKIM-ALG-14 DKIM-KEY-16 DKIM-KEY-17
func TestRSAPublicKeyFormats(t *testing.T) {
	key := rsaKey(t, 2048)
	msg := signWithTags(t, key, "v=1; a=rsa-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	pkcs1 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for rec, want := range map[string]string{
		"v=DKIM1; k=rsa; p=" + pkcs1:                                   ResultPass,
		"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(spki): ResultPass,
		"v=DKIM1; k=ed25519; p=" + pkcs1:                               ResultPermError,
	} {
		if r := verifyOne(t, msg, map[string]string{"s._domainkey.example.test": rec}); r.Result != want {
			t.Errorf("%.40s: got %+v, want %s", rec, r, want)
		}
	}
	rec, err := RecordValue(publicPEMOf(t, edKey.Public()))
	if err != nil || rec != "v=DKIM1; k=ed25519; p="+base64.StdEncoding.EncodeToString(edKey.Public().(ed25519.PublicKey)) {
		t.Errorf("Ed25519 RecordValue = %q, %v", rec, err)
	}
	if len(strings.TrimPrefix(rec, "v=DKIM1; k=ed25519; p=")) != 44 {
		t.Errorf("Ed25519 p= is not 44 characters: %q", rec)
	}
}

// TestMultipleKeyRecords checks that with several records at the selector,
// unusable ones are skipped and a usable one is found.
//
// checklist: DKIM-KEY-11
func TestMultipleKeyRecords(t *testing.T) {
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	resolver := func(context.Context, string) ([]string, error) {
		return []string{"v=spf1 -all", "v=DKIM1; p=", "k=ed25519; p=AAAA", keyRecord(t, edKey)}, nil
	}
	if r := Verify(context.Background(), []byte(msg), resolver); r[0].Result != ResultPass {
		t.Errorf("got %+v, want pass", r[0])
	}
}

// TestMalformedKeyRecords checks that malformed key records are ignored, so
// the signature is a permanent error, and never crash the verifier.
//
// checklist: DKIM-KEY-14 DKIM-VER-16
func TestMalformedKeyRecords(t *testing.T) {
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	good := strings.TrimPrefix(keyRecord(t, edKey), "v=DKIM1; k=ed25519; p=")
	for _, rec := range []string{
		"", ";", "=", "p", "v=DKIM1", "k=ed25519", "k=ed25519; p=" + good + "; p=" + good,
		"k=ed25519; p=!!!!", "k=ed25519; p=" + good[:20], "k=ed25519; p=" + good + "AAAA",
		"k=ed25519; 1p=" + good, "k=ed25519; p=" + good + "; n=\x01", "k=ed25519; v=DKIM1; p=" + good,
		"v=DKIM2; k=ed25519; p=" + good, "k=rsa; p=" + good,
	} {
		if r := verifyOne(t, msg, map[string]string{"s._domainkey.example.test": rec}); r.Result != ResultPermError {
			t.Errorf("record %q: got %+v, want permerror", rec, r)
		}
	}
}

// TestKeyLookupName checks the key is looked up as a TXT record at
// <selector>._domainkey.<domain>, once.
//
// checklist: DKIM-KEY-09
func TestKeyLookupName(t *testing.T) {
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=Mail.Example.test; s=sel.2026; h=from", "simple", "simple", simpleMsg)
	var names []string
	resolver := func(_ context.Context, name string) ([]string, error) {
		names = append(names, name)
		return []string{keyRecord(t, edKey)}, nil
	}
	if r := Verify(context.Background(), []byte(msg), resolver); r[0].Result != ResultPass {
		t.Errorf("got %+v, want pass", r[0])
	}
	if len(names) != 1 || names[0] != "sel.2026._domainkey.Mail.Example.test" {
		t.Errorf("queried %q", names)
	}
}

// TestVerifyResultFields checks each result carries the signature's d= and
// s=, an RFC 8601 result, and a reason.
//
// checklist: DKIM-VER-02
func TestVerifyResultFields(t *testing.T) {
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	for _, c := range []struct{ msg, want string }{
		{msg, ResultPass},
		{strings.Replace(msg, "Body  text", "Body text!", 1), ResultFail},
		{strings.Replace(msg, "v=1", "v=2", 1), ResultPermError},
	} {
		r := verifyOne(t, c.msg, records)
		if r.Domain != "example.test" || r.Selector != "s" || r.Result != c.want || r.Reason == "" {
			t.Errorf("got %+v, want %s with d=, s= and a reason", r, c.want)
		}
	}
}

// TestMultipleSignaturesIndependent checks that each signature is verified on
// its own: a broken one does not stop the next, and the order of the fields
// changes no verdict.
//
// checklist: DKIM-VER-03 DKIM-VER-04
func TestMultipleSignaturesIndependent(t *testing.T) {
	good := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from", "simple", "simple", simpleMsg)
	goodField, _, _ := strings.Cut(good, "\r\nFrom:")
	bad := strings.Replace(goodField, "d=example.test", "d=other.test", 1)
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	for _, order := range [][2]string{{bad, goodField}, {goodField, bad}} {
		msg := order[0] + "\r\n" + order[1] + "\r\n" + simpleMsg
		results := Verify(context.Background(), []byte(msg), recordResolver(records))
		verdict := map[string]string{}
		for _, r := range results {
			verdict[r.Domain] = r.Result
		}
		if len(results) != 2 || verdict["example.test"] != ResultPass || verdict["other.test"] != ResultPermError {
			t.Errorf("got %+v", results)
		}
	}
}

// TestBareLineEndingsNormalized checks that bare LF and CR line endings are
// read as CRLF, both when signing and when verifying.
//
// checklist: DKIM-CANON-10
func TestBareLineEndingsNormalized(t *testing.T) {
	lf := strings.ReplaceAll(simpleMsg, "\r\n", "\n")
	val, err := Sign([]byte(lf), SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey, HeaderCanon: "simple", BodyCanon: "simple"})
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	signed := "DKIM-Signature: " + val + "\r\n" + simpleMsg
	for _, msg := range []string{signed, strings.ReplaceAll(signed, "\r\n", "\n"), strings.ReplaceAll(signed, "\r\n", "\r")} {
		if r := verifyOne(t, msg, records); r.Result != ResultPass {
			t.Errorf("got %+v, want pass", r)
		}
	}
}

// TestBodyLength checks l=: only that many octets of the canonicalized body
// are hashed, so text appended after them does not break the signature, while
// a change within them does.
//
// checklist: DKIM-SIG-08 DKIM-HASH-01
func TestBodyLength(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; h=from; l=6", "simple", "simple", simpleMsg)
	if r := verifyOne(t, msg, records); r.Result != ResultPass {
		t.Fatalf("got %+v, want pass", r)
	}
	if r := verifyOne(t, strings.TrimSuffix(msg, "\r\n\r\n")+"\r\nappended\r\n", records); r.Result != ResultPass {
		t.Errorf("appended text: got %+v, want pass", r)
	}
	if r := verifyOne(t, strings.Replace(msg, "Body  text", "Bxdy  text", 1), records); r.Result != ResultFail {
		t.Errorf("changed signed text: got %+v, want fail", r)
	}
}

// TestSimpleCanonBFirst checks that b= is blanked wherever it appears in the
// signature field, as its first tag included, under simple header
// canonicalization. The signed data is built by hand here, not with
// BuildSignedHeaders.
//
// checklist: DKIM-HASH-02 DKIM-HASH-04
func TestSimpleCanonBFirst(t *testing.T) {
	sum := sha256.Sum256([]byte("body\r\n"))
	rest := "v=1; a=ed25519-sha256; c=simple/simple; d=example.test; s=s; h=from:to; bh=" + base64.StdEncoding.EncodeToString(sum[:])
	from, to := "From: A <a@example.test>", "To:  b@example.test "
	data := from + "\r\n" + to + "\r\n" + "DKIM-Signature: b=; " + rest
	hashed := sha256.Sum256([]byte(data))
	b := base64.StdEncoding.EncodeToString(ed25519.Sign(edKey, hashed[:]))
	msg := "DKIM-Signature: b=" + b + "; " + rest + "\r\n" + from + "\r\n" + to + "\r\n\r\nbody\r\n"
	if r := verifyOne(t, msg, map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}); r.Result != ResultPass {
		t.Errorf("got %+v, want pass", r)
	}
}

// TestIdentitySyntax checks that an i= whose domain is not in A-label form is
// a permanent error even when it ends in d=.
//
// checklist: DKIM-SIG-05 DKIM-SIG-07
func TestIdentitySyntax(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	for i, want := range map[string]string{"@example.test": ResultPass, "user@sub.example.test": ResultPass, "@bücher.example.test": ResultPermError, "@a..example.test": ResultPermError} {
		msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; i="+i+"; s=s; h=from", "simple", "simple", simpleMsg)
		if r := verifyOne(t, msg, records); r.Result != want {
			t.Errorf("i=%s: got %+v, want %s", i, r, want)
		}
	}
}

// TestAttachmentsSigned checks that the whole body is signed, MIME parts and
// their transfer encoding included: changing an attachment breaks the
// signature.
//
// checklist: DKIM-HASH-05
func TestAttachmentsSigned(t *testing.T) {
	raw := crlf(`From: a@example.test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain

See attached.
--b1
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

AAECAwQFBgcICQ==
--b1--
`)
	signed, results := signAndVerify(t, raw, SignOptions{Domain: "example.test", Selector: "s", PrivateKey: edKey})
	if results[0].Result != ResultPass {
		t.Fatalf("got %+v, want pass", results[0])
	}
	if r := verifyOne(t, strings.Replace(signed, "AAECAwQFBgcICQ==", "AAECAwQFBgcICg==", 1), map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}); r.Result != ResultFail {
		t.Errorf("changed attachment: got %+v, want fail", r)
	}
}

// TestMalformedHeaderLines checks that lines in the header that are not
// header fields (no colon, or a name with whitespace or control characters in
// it) are not taken as fields, and that their continuation lines are not
// glued onto the field above.
//
// checklist: DKIM-CANON-11
func TestMalformedHeaderLines(t *testing.T) {
	headers, body := SplitMessage([]byte(" orphan continuation\r\nFrom: a@example.test\r\nnot a field\r\n continued\r\nBad Name: x\r\n\tmore\r\nSubject : ok\r\n folded\r\n\r\nbody"))
	if len(headers) != 2 || headers[0].Raw != "From: a@example.test" || headers[1].Name != "Subject" || headers[1].Value != " ok\r\n folded" {
		t.Errorf("headers %q", headers)
	}
	if body != "body" {
		t.Errorf("body %q", body)
	}
	if h, b := SplitMessage([]byte("From: a\r\n")); len(h) != 1 || b != "" {
		t.Errorf("message without a body: %q %q", h, b)
	}
	// A message that starts with an empty line has no header fields at all.
	if h, b := SplitMessage([]byte("\r\nFrom: a\r\n\r\nbody")); len(h) != 0 || b != "From: a\r\n\r\nbody" {
		t.Errorf("empty header section: %q %q", h, b)
	}
	if h, b := SplitMessage(nil); len(h) != 0 || b != "" {
		t.Errorf("empty message: %q %q", h, b)
	}
}

// TestParsePrivateKey checks ParsePrivateKey reads RSA keys in PKCS#1 and
// PKCS#8 form and refuses anything else.
//
// checklist: DKIM-ALG-01
func TestParsePrivateKey(t *testing.T) {
	key := rsaKey(t, 2048)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	edPKCS8, _ := x509.MarshalPKCS8PrivateKey(edKey)
	for _, block := range []*pem.Block{
		{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		{Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		got, err := ParsePrivateKey(string(pem.EncodeToMemory(block)))
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: %v", block.Type, err)
		}
	}
	for _, bad := range []string{"", "not PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPKCS8}))} {
		if _, err := ParsePrivateKey(bad); err == nil {
			t.Errorf("accepted %.30q", bad)
		}
	}
}

// TestHashBytes checks HashBytes returns the whole digest of the hash asked
// for, never truncated.
//
// checklist: DKIM-ALG-04
func TestHashBytes(t *testing.T) {
	if got := HashBytes(crypto.SHA256, []byte("abc")); len(got) != 32 || base64.StdEncoding.EncodeToString(got) != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Errorf("SHA-256 %x", got)
	}
	if got := HashBytes(crypto.SHA1, []byte("abc")); len(got) != 20 {
		t.Errorf("SHA-1 %x", got)
	}
}

// TestInvalidTagValues checks that a signature whose t=, bh= or b= cannot be
// decoded is a permanent error.
//
// checklist: DKIM-SIG-13 DKIM-VER-06
func TestInvalidTagValues(t *testing.T) {
	records := map[string]string{"s._domainkey.example.test": keyRecord(t, edKey)}
	msg := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=example.test; s=s; t=1792000000; h=from", "simple", "simple", simpleMsg)
	for old, bad := range map[string]string{"t=1792000000": "t=17920000x0", "bh=": "bh=!!!!", "b=": "b=@@@@"} {
		if r := verifyOne(t, strings.Replace(msg, old, bad, 1), records); r.Result != ResultPermError {
			t.Errorf("%s: got %+v, want permerror", bad, r)
		}
	}
}

// TestBuildSignedHeadersSkipsEmptyNames checks that empty names in an h= list
// (a doubled or trailing colon) select no field.
//
// checklist: DKIM-HASH-02
func TestBuildSignedHeadersSkipsEmptyNames(t *testing.T) {
	headers, _ := SplitMessage([]byte(simpleMsg))
	sig := Header{Name: "DKIM-Signature", Value: " b=x", Raw: "DKIM-Signature: b=x"}
	if a, b := BuildSignedHeaders("from::to:", headers, sig, "relaxed"), BuildSignedHeaders("from:to", headers, sig, "relaxed"); a != b {
		t.Errorf("%q != %q", a, b)
	}
}
