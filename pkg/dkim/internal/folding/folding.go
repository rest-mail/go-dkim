package folding

import (
	"strings"
)

// lineLimit is the line length the folder keeps to, RFC 5322 §2.1.1's
// recommended 78 characters.
const lineLimit = 78

// folder writes a DKIM-Signature value folded at tag and list boundaries, with
// the column counted from the start of the field ("DKIM-Signature: ").
type folder struct {
	b   strings.Builder
	col int
}

// New starts a signature value after the DKIM-Signature field name.
func New() *folder { return &folder{col: len("DKIM-Signature: ")} }

func (f *folder) String() string { return f.b.String() }

// fold starts a new continuation line.
func (f *folder) fold() {
	f.b.WriteString("\r\n ")
	f.col = 1
}

// Tag writes one tag=value, after a "; " separator unless it is the first. An
// h= list too long for one line is folded after its colons, which the h= ABNF
// allows.
func (f *folder) Tag(tag string) {
	if f.b.Len() > 0 {
		f.b.WriteByte(';')
		f.col++
		if f.col+1+len(tag) > lineLimit {
			f.fold()
		} else {
			f.b.WriteByte(' ')
			f.col++
		}
	}
	name, list, isH := strings.Cut(tag, "=")
	if name != "h" || !isH || f.col+len(tag) <= lineLimit {
		f.b.WriteString(tag)
		f.col += len(tag)
		return
	}
	f.b.WriteString("h=")
	f.col += 2
	for i, field := range strings.Split(list, ":") {
		if i > 0 {
			f.b.WriteByte(':')
			f.col++
		}
		if f.col+len(field)+1 > lineLimit {
			f.fold()
		}
		f.b.WriteString(field)
		f.col += len(field)
	}
}

// Base64 appends a base64 value, folded wherever a line fills; whitespace in
// b= is ignored (RFC 6376 §3.5).
func (f *folder) Base64(s string) {
	for s != "" {
		if f.col >= lineLimit {
			f.fold()
		}
		n := min(len(s), lineLimit-f.col)
		f.b.WriteString(s[:n])
		f.col += n
		s = s[n:]
	}
}
