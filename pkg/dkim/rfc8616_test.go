package dkim

import (
	"context"
	"strings"
	"testing"
)

// TestRFC8616ULabels checks RFC 8616 §5: in an internationalized message d=,
// s= and the i= domain may be U-labels (A-labels stay valid, and the forms may
// mix), the key record is looked up under the A-label name, and the i=
// local-part may carry UTF-8.
//
// checklist: DKIM-EAI-01 DKIM-EAI-02 DKIM-EAI-05
func TestRFC8616ULabels(t *testing.T) {
	const msg = "From: A <a@bücher.example>\r\nSubject: Grüße\r\n\r\nbody\r\n"
	var queried []string
	records := recordResolver(map[string]string{"xn--mnchen-3ya._domainkey.xn--bcher-kva.example": keyRecord(t, edKey)})
	resolver := func(ctx context.Context, name string) ([]string, error) {
		queried = append(queried, name)
		return records(ctx, name)
	}
	for _, tags := range []string{
		"d=bücher.example; s=münchen",
		"d=bücher.example; i=@bücher.example; s=münchen",
		"d=bücher.example; i=üser@mail.bücher.example; s=münchen",
		"d=xn--bcher-kva.example; i=@BÜCHER.example; s=münchen",
		"d=BÜCHER.example; i=@xn--bcher-kva.example; s=xn--mnchen-3ya",
	} {
		queried = nil
		signed := signWithTags(t, edKey, "v=1; a=ed25519-sha256; c=relaxed/simple; "+tags+"; h=from:subject", "relaxed", "simple", msg)
		results := Verify(context.Background(), []byte(signed), resolver)
		if len(results) != 1 || results[0].Result != ResultPass {
			t.Errorf("%s: got %+v, want pass", tags, results)
			continue
		}
		if results[0].Domain != "xn--bcher-kva.example" || results[0].Selector != "xn--mnchen-3ya" {
			t.Errorf("%s: reported d=%q s=%q, want A-labels", tags, results[0].Domain, results[0].Selector)
		}
		if len(queried) != 1 || queried[0] != "xn--mnchen-3ya._domainkey.xn--bcher-kva.example" {
			t.Errorf("%s: queried %q, want the A-label record name", tags, queried)
		}
	}

	// A U-label i= outside d= is still unaligned once both are A-labels.
	signed := signWithTags(t, edKey, "v=1; a=ed25519-sha256; d=bücher.example; i=@böcher.example; s=münchen; h=from", "simple", "simple", msg)
	if r := Verify(context.Background(), []byte(signed), resolver); len(r) != 1 || r[0].Result != ResultPermError {
		t.Errorf("unaligned U-label i=: got %+v, want permerror", r)
	}
}

// TestRFC8616HashUsesHeaderForm checks RFC 8616 §5: the hash covers the domain
// name in the form it occurs in the header, so swapping a signed U-label for
// its (equivalent) A-label breaks the signature, and the reverse too.
//
// checklist: DKIM-EAI-03
func TestRFC8616HashUsesHeaderForm(t *testing.T) {
	const msg = "From: a@bücher.example\r\n\r\nbody\r\n"
	records := map[string]string{"s._domainkey.xn--bcher-kva.example": keyRecord(t, edKey)}
	for _, swap := range [][2]string{{"bücher.example", "xn--bcher-kva.example"}, {"xn--bcher-kva.example", "bücher.example"}} {
		signed := signWithTags(t, edKey, "v=1; a=ed25519-sha256; c=relaxed/relaxed; d="+swap[0]+"; s=s; h=from", "relaxed", "relaxed", msg)
		if r := verifyOne(t, signed, records); r.Result != ResultPass {
			t.Fatalf("d=%s as signed: got %+v, want pass", swap[0], r)
		}
		changed := strings.Replace(signed, "d="+swap[0], "d="+swap[1], 1)
		if r := verifyOne(t, changed, records); r.Result != ResultFail {
			t.Errorf("d=%s rewritten to %s: got %+v, want fail", swap[0], swap[1], r)
		}
	}
}
