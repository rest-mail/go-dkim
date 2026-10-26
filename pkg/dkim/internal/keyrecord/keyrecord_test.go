package keyrecord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/rest-mail/go-dkim/pkg/dkim/internal/grammar"
)

// FuzzKeyRecord fetches a key from any key record: the verifier never panics,
// and a key it accepts is well formed, an RSA key of at least 1024 bits or a
// 32-byte Ed25519 key, from a record that is a valid tag-list.
//
// checklist: DKIM-KEY-14
func FuzzKeyRecord(f *testing.F) {
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	for _, seed := range []string{
		"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edKey.Public().(ed25519.PublicKey)), rsaRecord(f), "v=DKIM1; p=", "v=DKIM2; p=AAAA", "k=ed25519; p=AAAA",
		"v=DKIM1; h=sha1; k=rsa; s=email:*; t=y:s; n=note; p=AAAA", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rec string) {
		resolver := func(context.Context, string) ([]string, error) { return []string{rec}, nil }
		for _, keyType := range []string{"rsa", "ed25519"} {
			pub, _, res := Fetch(context.Background(), "s", "example.test", keyType, "sha256", resolver)
			if res != "" {
				if pub != nil || res != resultPermError {
					t.Fatalf("result %q with key %v", res, pub)
				}
				continue
			}
			if _, err := grammar.ParseTagListStrict(rec); err != nil {
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

// TestKeyRecordAllowsHash pins the h= list-matching helper directly: the
// signature's hash name must appear in the key record's colon-separated h= list,
// matched case-sensitively (RFC 6376 §3.2) with surrounding folding whitespace
// ignored, and an unrecognized entry must neither match nor suppress a later
// valid one.
//
// checklist: DKIM-TAG-03 DKIM-KEY-02
func TestKeyRecordAllowsHash(t *testing.T) {
	allow := []struct{ hTag, alg string }{
		{"sha256", "sha256"},
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
		{"SHA256", "sha256"},
	}
	for _, c := range deny {
		if keyRecordAllowsHash(c.hTag, c.alg) {
			t.Errorf("keyRecordAllowsHash(%q, %q) = true, want false", c.hTag, c.alg)
		}
	}
}

// TestParseKeyFlags pins the flag-list parser directly: the "s" (no-subdomain)
// flag is recognized alone and within a colon-separated list, case-sensitively
// (RFC 6376 §3.2), with surrounding folding whitespace ignored; unrecognized flags (e.g. "y") neither
// set it nor suppress a sibling "s".
//
// checklist: DKIM-TAG-03 DKIM-KEY-06 DKIM-KEY-08
func TestParseKeyFlags(t *testing.T) {
	set := []string{"s", "y:s", "s:y", " y : s ", "s:x-future"}
	for _, tt := range set {
		if !parseKeyFlags(tt).NoSubdomain {
			t.Errorf("parseKeyFlags(%q).NoSubdomain = false, want true", tt)
		}
	}
	unset := []string{"", "y", "y:x-future", "subdomain", "S"}
	for _, tt := range unset {
		if parseKeyFlags(tt).NoSubdomain {
			t.Errorf("parseKeyFlags(%q).NoSubdomain = true, want false", tt)
		}
	}
}

// TestKeyRecordAllowsService pins the s= list-matching helper directly: email is
// permitted when the colon-separated list contains "email" or the wildcard "*",
// matched case-sensitively (RFC 6376 §3.2) with surrounding folding whitespace ignored, and an
// unrecognized service type must neither match nor suppress a sibling "email"/"*".
// An empty list permits nothing.
//
// checklist: DKIM-TAG-03 DKIM-KEY-05
func TestKeyRecordAllowsService(t *testing.T) {
	allow := []struct{ sTag string }{
		{"email"},
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
		{"EMAIL"},
	}
	for _, c := range deny {
		if keyRecordAllowsService(c.sTag) {
			t.Errorf("keyRecordAllowsService(%q) = true, want false", c.sTag)
		}
	}
}

// rsaRecord supplies the RSA seed used by the key-record fuzzer.
func rsaRecord(t testing.TB) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}
