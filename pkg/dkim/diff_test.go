package dkim

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"strings"
	"testing"

	msgauth "github.com/emersion/go-msgauth/dkim"
)

// The differential tests check this package against another implementation,
// github.com/emersion/go-msgauth/dkim (MIT): a message one signs must verify
// with the other, in both directions, for every canonicalization and both key
// types. go-msgauth is a test-only dependency; the library does not import it.

// diffMessages are messages whose canonicalization is easy to get wrong.
var diffMessages = map[string]string{
	"plain": "From: Alice <alice@example.test>\r\nTo: bob@example.test\r\nSubject: Hello\r\n" +
		"Date: Fri, 16 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@example.test>\r\n\r\nHello, world.\r\n",
	"whitespace": "From:   Alice  <alice@example.test>  \r\nTo:\tbob@example.test\t\r\nSubject: \t lots   of\t\tspace \r\n" +
		"\r\n  leading\r\ntrailing  \t\r\n\t\r\nruns  of \t space\r\n \r\n\r\n\r\n",
	"folded":           "From: Alice\r\n <alice@example.test>\r\nSubject: a\r\n\tfolded\r\n   subject \r\nTo: b@example.test,\r\n c@example.test\r\n\r\nbody\r\n",
	"empty body":       "From: a@example.test\r\nSubject: nothing\r\n\r\n",
	"no final CRLF":    "From: a@example.test\r\nSubject: x\r\n\r\nlast line without CRLF",
	"only blank lines": "From: a@example.test\r\n\r\n\r\n\r\n \r\n\t\r\n",
	"repeated": "Received: by a\r\nReceived: by b\r\nFrom: a@example.test\r\nTo: one@example.test\r\n" +
		"To: two@example.test\r\nSubject: s\r\n\r\nbody\r\n",
	"utf-8": "From: =?utf-8?q?J=C3=B6rg?= <j@example.test>\r\nSubject: Grüße\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"MIME-Version: 1.0\r\n\r\nGrüße aus Köln  \r\n",
	"long header": "From: a@example.test\r\nSubject: " + strings.Repeat("word ", 150) + "\r\n\r\n" + strings.Repeat("x", 2000) + "\r\n",
}

var diffCanons = [][2]string{{"simple", "simple"}, {"simple", "relaxed"}, {"relaxed", "simple"}, {"relaxed", "relaxed"}}

// diffKeys are the two key types, by algorithm name.
func diffKeys(t *testing.T) map[string]crypto.Signer {
	return map[string]crypto.Signer{"rsa": rsaKey(t, 2048), "ed25519": edKey}
}

// msgauthVerify verifies msg with go-msgauth, serving key at
// s._domainkey.example.test, and returns the error of each signature.
func msgauthVerify(t *testing.T, msg string, key crypto.Signer) []error {
	t.Helper()
	rec := keyRecord(t, key)
	verifications, err := msgauth.VerifyWithOptions(strings.NewReader(msg), &msgauth.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			if name == "s._domainkey.example.test" {
				return []string{rec}, nil
			}
			return nil, fmt.Errorf("no record at %s", name)
		},
	})
	if err != nil {
		t.Fatalf("go-msgauth: %v", err)
	}
	errs := make([]error, len(verifications))
	for i, v := range verifications {
		errs[i] = v.Err
	}
	return errs
}

// TestDifferentialSignHereVerifyMsgauth signs each message here, with the
// default header set and oversigning, and checks go-msgauth verifies it, and
// that both reject it once an oversigned field is added.
//
// checklist: DKIM-CANON-01 DKIM-SIGN-09 DKIM-SIGN-11 DKIM-HASH-02 DKIM-VER-01
func TestDifferentialSignHereVerifyMsgauth(t *testing.T) {
	for name, raw := range diffMessages {
		for alg, key := range diffKeys(t) {
			for _, c := range diffCanons {
				val, err := Sign([]byte(raw), SignOptions{
					Domain: "example.test", Selector: "s", PrivateKey: key, HeaderCanon: c[0], BodyCanon: c[1], Time: 1792000000,
				})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				signed := "DKIM-Signature: " + val + "\r\n" + raw
				if errs := msgauthVerify(t, signed, key); len(errs) != 1 || errs[0] != nil {
					t.Errorf("%s, %s, %s/%s: go-msgauth says %v", name, alg, c[0], c[1], errs)
				}
				tampered := "From: Mallory <m@evil.example>\r\n" + signed
				if errs := msgauthVerify(t, tampered, key); len(errs) != 1 || errs[0] == nil {
					t.Errorf("%s, %s, %s/%s: go-msgauth verified a message with an added From", name, alg, c[0], c[1])
				}
				resolver := recordResolver(map[string]string{"s._domainkey.example.test": keyRecord(t, key)})
				if r := Verify(context.Background(), []byte(tampered), resolver); r[0].Result != ResultFail {
					t.Errorf("%s, %s, %s/%s: added From gave %s here", name, alg, c[0], c[1], r[0].Result)
				}
			}
		}
	}
}

// TestDifferentialMsgauthSignVerifyHere signs each message with go-msgauth,
// oversigning From and naming an absent Cc, and checks it verifies here.
//
// checklist: DKIM-ALG-02 DKIM-ALG-10 DKIM-CANON-01 DKIM-SIGN-07 DKIM-HASH-02 DKIM-VER-01
func TestDifferentialMsgauthSignVerifyHere(t *testing.T) {
	for name, raw := range diffMessages {
		for alg, key := range diffKeys(t) {
			resolver := recordResolver(map[string]string{"s._domainkey.example.test": keyRecord(t, key)})
			for _, c := range diffCanons {
				var out bytes.Buffer
				err := msgauth.Sign(&out, strings.NewReader(raw), &msgauth.SignOptions{
					Domain: "example.test", Selector: "s", Signer: key,
					HeaderCanonicalization: msgauth.Canonicalization(c[0]), BodyCanonicalization: msgauth.Canonicalization(c[1]),
					HeaderKeys: []string{"From", "To", "Subject", "Received", "Cc", "From"},
				})
				if err != nil {
					t.Fatalf("%s: go-msgauth: %v", name, err)
				}
				r := Verify(context.Background(), out.Bytes(), resolver)
				if len(r) != 1 || r[0].Result != ResultPass {
					t.Errorf("%s, %s, %s/%s: got %+v, want pass", name, alg, c[0], c[1], r)
				}
			}
		}
	}
}
