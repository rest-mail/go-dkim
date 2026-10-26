package dkim

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

// crlf turns the LF line endings of a Go raw string into CRLF.
func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// recordResolver serves fixed TXT records by name; any other name does not
// exist.
func recordResolver(records map[string]string) TXTResolver {
	return func(_ context.Context, name string) ([]string, error) {
		if rec, ok := records[name]; ok {
			return []string{rec}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

// RFC 8463 Appendix A: a message with an ed25519-sha256 and an rsa-sha256
// signature over the same header fields, From, Subject and Date oversigned,
// and the two key records (A.2), whose strings are joined as a resolver joins
// them.
var (
	rfc8463Records = map[string]string{
		"brisbane._domainkey.football.example.com": "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		"test._domainkey.football.example.com": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" +
			"iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" +
			"DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" +
			"Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
	}
	rfc8463Message = crlf(`DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.

`)
)

// TestRFC8463Example verifies both signatures of RFC 8463's Appendix A
// against its published keys: the ed25519-sha256 one and a 1024-bit
// rsa-sha256 one, each with folded tags and FWS around the h= colons.
//
// checklist: DKIM-ALG-02 DKIM-ALG-08 DKIM-ALG-10 DKIM-ALG-14 DKIM-SIG-09 DKIM-KEY-10 DKIM-VER-01
func TestRFC8463Example(t *testing.T) {
	results := Verify(context.Background(), []byte(rfc8463Message), recordResolver(rfc8463Records))
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	for i, sel := range []string{"brisbane", "test"} {
		r := results[i]
		if r.Result != ResultPass || r.Domain != "football.example.com" || r.Selector != sel {
			t.Errorf("signature %d: got %+v, want pass for d=football.example.com s=%s", i, r, sel)
		}
	}
}

// TestRFC8463Oversigning checks the RFC's own oversigning: its signatures list
// From, Subject and Date once more than the message carries them, so a second
// copy of any of them added after signing breaks both, while a copy of an
// unsigned field does not.
//
// checklist: DKIM-SIGN-06 DKIM-SIGN-07
func TestRFC8463Oversigning(t *testing.T) {
	headers, body, _ := strings.Cut(rfc8463Message, "\r\n\r\n")
	for _, added := range []string{"From: Mallory <m@evil.example>", "Subject: Free money", "Date: Sat, 12 Jul 2003 00:00:00 +0000"} {
		msg := headers + "\r\n" + added + "\r\n\r\n" + body
		for _, r := range Verify(context.Background(), []byte(msg), recordResolver(rfc8463Records)) {
			if r.Result != ResultFail {
				t.Errorf("after adding %q: s=%s gave %s, want fail", added, r.Selector, r.Result)
			}
		}
	}
	msg := headers + "\r\nX-Unsigned: fine\r\n\r\n" + body
	for _, r := range Verify(context.Background(), []byte(msg), recordResolver(rfc8463Records)) {
		if r.Result != ResultPass {
			t.Errorf("after adding an unsigned field: s=%s gave %s, want pass", r.Selector, r.Result)
		}
	}
}

// TestRFC6376AppendixA checks the parts of RFC 6376's Appendix A example that
// hold up: its body hashes to the published bh= under simple canonicalization,
// its signature field is a well-formed tag-list, and the Appendix C key record
// (no k=, so RSA by default) is a usable key. The example's b= was not computed
// with the Appendix C key (the record is published under example.org, the
// signature names example.com), so it is not checked. The body has one space
// after "game.": the RFC's typesetting shows two, but only one gives the
// published bh=, the same value RFC 8463 publishes for this body relaxed.
//
// checklist: DKIM-CANON-07 DKIM-HASH-01 DKIM-KEY-03
func TestRFC6376AppendixA(t *testing.T) {
	body := crlf("Hi.\n\nWe lost the game. Are you hungry yet?\n\nJoe.\n")
	sum := sha256.Sum256([]byte(CanonicalizeBody(body, "simple")))
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=" {
		t.Errorf("simple body hash %s, want the published bh=", got)
	}

	sig := crlf(`v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
        4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
        KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
        4bmp/YzhwvcubU4=;`)
	tags, err := ParseTagListStrict(sig)
	if err != nil {
		t.Fatalf("Appendix A signature: %v", err)
	}
	if tags["d"] != "example.com" || tags["s"] != "brisbane" || tags["c"] != "simple/simple" {
		t.Errorf("Appendix A tags parsed wrongly: %v", tags)
	}

	rec := "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
		"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
		"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
		"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
		"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"
	resolver := recordResolver(map[string]string{"brisbane._domainkey.example.org": rec})
	if pub, _, res := FetchKey(context.Background(), "brisbane", "example.org", "sha256", resolver); res != "" || pub.N.BitLen() != 1024 {
		t.Errorf("Appendix C key record: result %q", res)
	}
}
