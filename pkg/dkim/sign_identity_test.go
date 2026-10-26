package dkim

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSignAUIDAndExpiry checks, across the options Sign takes, that it emits no
// i= and, while Expiration is unset, no x=. Without i= the AUID of every
// signature is the default "@" + d=, so each message one signer signs carries
// the same AUID (§3.5); and without x= there is no expiry to fall at or before
// t=. Each signature still verifies. TestSignExpiration covers a set x=.
//
// checklist: DKIM-SIGN-18 DKIM-SIGN-19
func TestSignAUIDAndExpiry(t *testing.T) {
	cases := []SignOptions{
		{PrivateKey: rsaKey(t, 2048)},
		{PrivateKey: edKey},
		{PrivateKey: edKey, Time: 1},
		{PrivateKey: rsaKey(t, 2048), Time: 1784775188, HeaderCanon: "simple", BodyCanon: "simple"},
		{PrivateKey: edKey, Time: 1784775188, HeaderCanon: "relaxed", BodyCanon: "simple"},
		{PrivateKey: edKey, Headers: []string{"from", "subject"}},
		{PrivateKey: edKey, Oversign: []string{"from"}, Time: 1784775188},
	}
	for i, opt := range cases {
		opt.Domain, opt.Selector = "example.test", "s1"
		for n := range 3 {
			raw := buildRaw(fmt.Sprintf("message %d of case %d\r\n", n, i))
			signed, results := signAndVerify(t, raw, opt)
			tags := sigTags(t, signed)
			for _, k := range []string{"i", "x"} {
				if v, ok := tags[k]; ok && (k == "i" || opt.Expiration == 0) {
					t.Errorf("case %d message %d: Sign emitted %s=%q", i, n, k, v)
				}
			}
			if tags["d"] != "example.test" {
				t.Errorf("case %d message %d: d=%q, want example.test", i, n, tags["d"])
			}
			if opt.Time > 0 && tags["t"] != fmt.Sprint(opt.Time) {
				t.Errorf("case %d message %d: t=%q, want %d", i, n, tags["t"], opt.Time)
			}
			if len(results) != 1 || results[0].Result != ResultPass {
				t.Errorf("case %d message %d: got %+v, want one pass", i, n, results)
			}
		}
	}
}

// TestSignHashesBodyBeforeDotStuffing checks that Sign hashes the body as
// given, before SMTP's transport-level dot-stuffing (§3.7): bh= is the hash
// of the unstuffed lines, the message verifies as the receiving SMTP server
// hands it over after removing the stuffing, and the stuffed form, which is
// not what the RFC hashes, fails the body hash.
//
// checklist: DKIM-SIGN-21
func TestSignHashesBodyBeforeDotStuffing(t *testing.T) {
	body := ".\r\n..two dots\r\n.leading dot\r\nplain\r\n"
	raw := buildRaw(body)
	opt := SignOptions{Domain: "example.test", Selector: "s1", PrivateKey: edKey, BodyCanon: "simple"}
	signed, results := signAndVerify(t, raw, opt)
	if len(results) != 1 || results[0].Result != ResultPass {
		t.Fatalf("got %+v, want one pass", results)
	}

	// Simple canonicalization leaves a body ending in one CRLF unchanged, so
	// the expected bh= is the SHA-256 of the bytes given.
	sum := sha256.Sum256([]byte(body))
	if bh, want := sigTags(t, signed)["bh"], base64.StdEncoding.EncodeToString(sum[:]); bh != want {
		t.Errorf("bh=%s, want %s (the hash of the unstuffed body)", bh, want)
	}

	// Dot-stuff the body as an SMTP client does on the wire (RFC 5321
	// §4.5.2) and verify that: the body hash must not match.
	head, _, _ := strings.Cut(signed, "\r\n\r\n")
	var stuffed strings.Builder
	for line := range strings.SplitAfterSeq(body, "\r\n") {
		if strings.HasPrefix(line, ".") {
			stuffed.WriteString(".")
		}
		stuffed.WriteString(line)
	}
	resolver := recordResolver(map[string]string{RecordName(opt.Selector, opt.Domain): keyRecord(t, opt.PrivateKey)})
	got := Verify(context.Background(), []byte(head+"\r\n\r\n"+stuffed.String()), resolver)
	if len(got) != 1 || got[0].Result != ResultFail || got[0].Reason != "body hash mismatch" {
		t.Errorf("stuffed body: got %+v, want one body-hash fail", got)
	}
}

// TestSignExpiration checks the x= tag Sign emits for SignOptions.Expiration
// (§3.5 recommends one). The value is written as given, with or without t=,
// and the signature verifies until that moment and is a permerror from it on,
// so verifiers really do stop accepting it. Sign refuses an Expiration at or
// before Time, which §3.5 says makes the signature invalid, a negative one,
// and a Time or Expiration of more than the 12 digits §3.5 allows.
//
// checklist: DKIM-SIG-16 DKIM-SIGN-19
func TestSignExpiration(t *testing.T) {
	const ts, exp = 1784775188, 1784861588
	for i, opt := range []SignOptions{
		{PrivateKey: edKey, Expiration: exp},
		{PrivateKey: edKey, Time: ts, Expiration: exp},
		{PrivateKey: edKey, Time: ts, Expiration: ts + 1},
		{PrivateKey: rsaKey(t, 2048), Time: ts, Expiration: maxTimestamp, HeaderCanon: "simple", BodyCanon: "simple"},
	} {
		opt.Domain, opt.Selector = "example.test", "s1"
		withFixedNow(t, time.Unix(opt.Expiration-1, 0))
		signed, results := signAndVerify(t, buildRaw(fmt.Sprintf("case %d\r\n", i)), opt)
		tags := sigTags(t, signed)
		if tags["x"] != fmt.Sprint(opt.Expiration) {
			t.Errorf("case %d: x=%q, want %d", i, tags["x"], opt.Expiration)
		}
		if _, ok := tags["t"]; ok != (opt.Time > 0) {
			t.Errorf("case %d: t=%q present=%v, want present=%v", i, tags["t"], ok, opt.Time > 0)
		}
		if len(results) != 1 || results[0].Result != ResultPass {
			t.Errorf("case %d: before x= got %+v, want one pass", i, results)
		}

		withFixedNow(t, time.Unix(opt.Expiration, 0))
		resolver := recordResolver(map[string]string{RecordName(opt.Selector, opt.Domain): keyRecord(t, opt.PrivateKey)})
		results = Verify(context.Background(), []byte(signed), resolver)
		if len(results) != 1 || results[0].Result != ResultPermError || !strings.Contains(results[0].Reason, "expired") {
			t.Errorf("case %d: at x= got %+v, want one expired permerror", i, results)
		}
	}

	for name, opt := range map[string]SignOptions{
		"expiration equals time":   {Time: ts, Expiration: ts},
		"expiration before time":   {Time: ts, Expiration: ts - 1},
		"negative expiration":      {Expiration: -1},
		"13-digit expiration":      {Expiration: maxTimestamp + 1},
		"13-digit time":            {Time: maxTimestamp + 1},
		"13-digit time and expiry": {Time: maxTimestamp + 1, Expiration: maxTimestamp + 2},
	} {
		opt.Domain, opt.Selector, opt.PrivateKey = "example.test", "s1", edKey
		if v, err := Sign([]byte(buildRaw("body\r\n")), opt); err == nil {
			t.Errorf("%s: Sign returned %q, want an error", name, v)
		}
	}
}
