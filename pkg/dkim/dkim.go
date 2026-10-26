package dkim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// DefaultSelector is the selector RecordName and RecordFragment fall back to
// when none is given: "default", i.e. default._domainkey.<domain>.
const DefaultSelector = "default"

// GenerateKey creates an RSA DKIM keypair of the given size in bits and returns
// both halves PEM-encoded. The private PEM is the signing key (pass it to
// ParsePrivateKey); the public PEM feeds RecordValue to build the DNS record.
// RFC 8301 §3.2 says signers SHOULD use at least 2048 bits, so a smaller size
// is refused. The public exponent is 65537, as RFC 6376 §3.3.2 advises.
func GenerateKey(bits int) (privatePEM, publicPEM string, err error) {
	if bits < 2048 {
		return "", "", fmt.Errorf("dkim: a %d-bit key is too small; RFC 8301 asks for at least 2048 bits", bits)
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privatePEM, publicPEM, nil
}

// RecordName returns the DKIM record name <selector>._domainkey.<domain>.
func RecordName(selector, domain string) string {
	if selector == "" {
		selector = DefaultSelector
	}
	return selector + "._domainkey." + domain
}

// RecordValue renders the DKIM DNS TXT value from a PEM-encoded public key (a
// SubjectPublicKeyInfo, as GenerateKey produces). For an RSA key it is
// "v=DKIM1; k=rsa; p=<base64 DER>"; for an Ed25519 key, "v=DKIM1; k=ed25519;
// p=<base64 of the 32-byte key>" (RFC 8463 §4.2).
func RecordValue(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		// block.Bytes is the DER SubjectPublicKeyInfo — exactly what p= carries.
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(block.Bytes), nil
	case ed25519.PublicKey:
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(k), nil
	default:
		return "", fmt.Errorf("public key is neither RSA nor Ed25519")
	}
}

// RecordFragment renders a dnsmasq txt-record line for a DKIM record, splitting
// the value into <=255-char strings (the DNS TXT per-string limit) so that
// 2048-bit records — whose p= value exceeds 255 chars — stay valid:
//
//	txt-record=default._domainkey.d,"chunk1","chunk2"
func RecordFragment(name, value string) string {
	const maxLen = 255
	var chunks []string
	for i := 0; i < len(value); i += maxLen {
		end := i + maxLen
		if end > len(value) {
			end = len(value)
		}
		chunks = append(chunks, `"`+value[i:end]+`"`)
	}
	if len(chunks) == 0 {
		chunks = []string{`""`}
	}
	return "txt-record=" + name + "," + strings.Join(chunks, ",")
}
