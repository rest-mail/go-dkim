package dkim_test

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-dkim"
)

// Example signs a message and then verifies it. It uses an in-memory DNS
// resolver so the round trip is self-contained. In production you generate the
// keypair once, sign with the private half, publish the public half as the DNS
// TXT record at <selector>._domainkey.<domain>, and let Verify resolve it over
// system DNS by passing a nil resolver.
//
// checklist: DKIM-SIGN-02 DKIM-SIGN-12
func Example() {
	// Generate a keypair. Keep the private key for signing; publish the public
	// half as the DNS record verifiers look up.
	privPEM, pubPEM, err := dkim.GenerateKey(2048)
	if err != nil {
		panic(err)
	}
	key, err := dkim.ParsePrivateKey(privPEM)
	if err != nil {
		panic(err)
	}

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: hello\r\n" +
		"Date: Thu, 23 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <1@example.com>\r\n" +
		"\r\n" +
		"Hello, world!\r\n")

	// Sign returns the DKIM-Signature field value; prepend the header yourself.
	value, err := dkim.Sign(raw, dkim.SignOptions{
		Domain:     "example.com",
		Selector:   "default",
		PrivateKey: key,
	})
	if err != nil {
		panic(err)
	}
	signed := append([]byte("DKIM-Signature: "+value+"\r\n"), raw...)

	// Serve the public key we just generated from memory, so the example needs
	// no real DNS. In production, pass nil to use the system resolver.
	txt, err := dkim.RecordValue(pubPEM)
	if err != nil {
		panic(err)
	}
	resolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{txt}, nil
	}

	results := dkim.Verify(context.Background(), signed, resolver)
	r := results[0]
	fmt.Printf("d=%s s=%s -> %s\n", r.Domain, r.Selector, r.Result)
	// Output: d=example.com s=default -> pass
}
