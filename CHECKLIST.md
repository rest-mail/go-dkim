# RFC 6376 checklist

Inventory of the requirements [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)
places on a DKIM signer and verifier, as updated by
[RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) (algorithms and key sizes) and
[RFC 8463](https://www.rfc-editor.org/rfc/rfc8463) (Ed25519) and
[RFC 8616](https://www.rfc-editor.org/rfc/rfc8616) §5 (internationalized mail), with the tests that
cover them. This records MUST, MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED and
NOT RECOMMENDED clauses, implemented MAYs, and normative behaviour without a
keyword (level "Normative"). DNS-publisher and receiver-policy duties are
listed as n/a with reasons. An n/a can also identify an unsupported feature or
an explicit deviation; it does not mean that requirement has been satisfied.
A section number alone is RFC 6376; the others are named.

An item that does not apply to a library (because it is the receiver's policy,
say) says "n/a" and why. CI checks this file against the tests with
`go run ./internal/checklist`; the format is described in the
[README](README.md#the-rfc-checklist).

## Audit scope (2026-10-22)

The clause-inventory pass compared the following sections, including their
subsections, against the existing rows and added the omitted clauses below.
This is an inventory and executable evidence for individual assertions, not a
claim that arbitrary input has been proved conformant to every imported ABNF.

| Audited sections | Outcome / checklist areas |
|------------------|---------------------------|
| RFC 6376 §§1–1.5, 2–2.10 | Context and definitions; tag-list, FWS and base64 rules in TAG. |
| RFC 6376 §2.11 | Added QP encoding/decoding boundaries (QP-01–03); no diagnostic decoding API. |
| RFC 6376 §§3–3.1 | Selector context; key lookup covered by KEY-09. |
| RFC 6376 §§3.2–3.3.4 | TAG and ALG; added absent-versus-empty TAG-09. Historic crypto requirements are superseded explicitly. |
| RFC 6376 §§3.4–3.4.5 | CANON; existing simple/relaxed examples and copy/normalization assertions. |
| RFC 6376 §3.5 | SIG and SIGN; added trace-field ordering and timestamp/expiry recommendations, and HASH-06 for other signatures' b= values. |
| RFC 6376 §§3.6–3.6.2.2 | KEY; added publisher t=s recommendation and unique-selector TXT duty. |
| RFC 6376 §§3.7–3.11 | HASH, SIGN-21, VER-02; added explicit default AUID proof. |
| RFC 6376 §§4–4.2 | SIGN-17, VER-03/04/15; HASH-06 now checks signed signatures in either order. |
| RFC 6376 §§5–5.2 | Local signing/key-selection policy; no additional MUST/SHOULD clauses. |
| RFC 6376 §§5.3–5.6 | SIGN and HASH; added transmission of normalized bytes and modification-before-resigning host duties. |
| RFC 6376 §§6–6.1.3 | VER and KEY; added immediate per-signature termination, default AUID, canonicalized l= bound and conditional domain-blocklist configuration. |
| RFC 6376 §§6.2–6.3 | VER; added diagnostic-reason proof and actual-SDID presentation duty. |
| RFC 6376 §§7–7.10 | Registry maintenance, not runtime protocol; added IANA-01. |
| RFC 6376 §§8–8.15 | Existing KEY-14, VER-16 and SIGN-14 cover the uppercase requirements; other security advice informs caller policy. |
| RFC 6376 §9, Appendices A–F | References/examples/change history; existing RFC examples and retired g= row KEY-18; no additional signer/verifier MUST/SHOULD clauses. |
| RFC 8301 §§1–6 | All algorithm/key-size changes already in ALG-01–09/15; no extra clause found. |
| RFC 8616 §5 | Added EAI-01–05: U-labels and UTF-8 in d=, s= and i=, A-label key lookup, header-form hash; the signer recommendation is n/a. |
| RFC 8463 §§1–9, Appendix A | All algorithm/key syntax/implementation clauses already in ALG-10–14 and KEY-17; published dual-signature vector remains TestRFC8463Example. |

The configurable required-signed-header list (VER-08) remains an owner decision;
this pass adds no Verify option. Timestamp/expiry defaults and publisher/host
duties below remain explicit limitations, not implied implementation claims.

## Tag lists (§3.2, §2.10)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-TAG-01 | 3.2 | Normative | Parse tag-lists by the ABNF: a tag-name is ALPHA *ALNUMPUNC, a value is VALCHARs with internal FWS; a malformed tag-spec invalidates the list. | `TestParseTagListStrict`, `FuzzParseTagList` |
| DKIM-TAG-02 | 3.2 | MUST | Interpret tag names case-sensitively. | `TestTagNamesCaseSensitive` |
| DKIM-TAG-03 | 3.2 | MUST | Process values case-sensitively unless a tag's definition says otherwise. | `TestUnknownAlgorithm`, `TestKeyTypes`, `TestKeyRecordAllowsHash`, `TestParseKeyFlags`, `TestKeyRecordAllowsService` |
| DKIM-TAG-04 | 3.2 | MUST NOT | Duplicate tag names in one tag-list; a list with one is invalid. | `TestParseTagListStrict`, `TestVerify_DuplicateTagRejected`, `TestVerify_DuplicateTagInKeyRecordRejected` |
| DKIM-TAG-05 | 3.2 | MUST | Retain whitespace within a value; whitespace around it is not part of it. | `TestTagValueWhitespace` |
| DKIM-TAG-06 | 3.2 | MUST | Ignore unrecognized tags. | `TestUnknownTagsIgnored` |
| DKIM-TAG-07 | 2.10, 3.5 | Normative | Base64 values may be folded with FWS and may omit their padding. | `TestDecodeBase64Tag`, `TestVerify_UnpaddedBase64Accepted` |
| DKIM-TAG-08 | 3.2, 3.5, 3.6.1 | Normative | The only whitespace around tag names, "=", values, ";" and list separators is FWS (SP, HTAB, CRLF folding); any other whitespace is malformed. | `TestParseTagListStrictFWS`, `TestWireWhitespaceIsFWS`, `FuzzParseTagList` |

## Algorithms and keys (§3.3, RFC 8301, RFC 8463)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-ALG-01 | 3.3; RFC 8301 3.1 | MUST | Signers sign with rsa-sha256 (an RSA key). | `TestSignAlgorithm`, `TestParsePrivateKey` |
| DKIM-ALG-02 | RFC 8301 3.1 | MUST | Verifiers verify rsa-sha256. | `TestRFC8463Example`, `TestVerify_RoundTrip`, `TestDifferentialMsgauthSignVerifyHere` |
| DKIM-ALG-03 | RFC 8301 3.1 | MUST NOT | Use rsa-sha1 for signing or verifying; an rsa-sha1 signature has permanently failed. | `TestRSASHA1Refused` |
| DKIM-ALG-04 | 3.3.1, 3.3.2 | MUST NOT | Truncate or convert the hash: RSASSA-PKCS1-v1_5 signs the whole SHA-256 digest. | `TestSignAlgorithm`, `TestHashBytes` |
| DKIM-ALG-05 | 3.3.1, 3.3.2 | SHOULD | Signing keys use the public exponent 65537. | `TestGenerateKeyAndRecordRoundTrip` |
| DKIM-ALG-06 | RFC 8301 3.2 | MUST | Signers use RSA keys of at least 1024 bits. | `TestSignRejectsShortRSAKey` |
| DKIM-ALG-07 | RFC 8301 3.2 | SHOULD | Signers use RSA keys of at least 2048 bits (GenerateKey refuses smaller). | `TestGenerateKeyAndRecordRoundTrip` |
| DKIM-ALG-08 | RFC 8301 3.2 | MUST | Verifiers validate signatures with RSA keys of 1024 to 4096 bits. | `TestRFC8463Example`, `TestSignFolds` |
| DKIM-ALG-09 | RFC 8301 3.2 | MUST NOT | Consider signatures with RSA keys under 1024 bits valid. | `TestVerifyShortRSAKeyRejected` |
| DKIM-ALG-10 | RFC 8463 5 | MUST | Verifiers implement ed25519-sha256. | `TestRFC8463Example`, `TestEd25519RoundTrip`, `TestDifferentialMsgauthSignVerifyHere` |
| DKIM-ALG-11 | RFC 8463 5 | SHOULD | Signers implement ed25519-sha256. | `TestEd25519RoundTrip` |
| DKIM-ALG-12 | RFC 8463 3 | Normative | ed25519-sha256 signs the SHA-256 hash of the header data with PureEdDSA. | `TestEd25519SignsHash` |
| DKIM-ALG-13 | 3.3.4, 3.5 | MUST | Ignore a signature with an algorithm the verifier does not implement (PERMFAIL). | `TestUnknownAlgorithm` |
| DKIM-ALG-14 | RFC 8463 4.2 | Normative | An Ed25519 key record has k=ed25519 and p= the 32-byte key in base64 (44 characters). | `TestRFC8463Example`, `TestRSAPublicKeyFormats` |
| DKIM-ALG-15 | 3.3, 3.3.3 | MUST | Verifiers implement rsa-sha1 and validate keys of 512 to 2048 bits. | n/a: replaced by RFC 8301, which forbids rsa-sha1 (DKIM-ALG-03) and keys under 1024 bits (DKIM-ALG-09). |

## Canonicalization (§3.4, §3.8, §5.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-CANON-01 | 3.4 | MUST | Verifiers implement simple and relaxed, for the header and the body. | `TestVerify_RoundTrip`, `TestSign_VerifyRoundTrip`, `TestCanonDefaults`, `TestDifferentialSignHereVerifyMsgauth`, `TestDifferentialMsgauthSignVerifyHere` |
| DKIM-CANON-02 | 3.4 | MUST | Ignore a signature with a canonicalization the verifier does not implement (PERMFAIL). | `TestUnknownCanonicalization` |
| DKIM-CANON-03 | 3.4 | MUST NOT | Change the transmitted message: canonicalization works on a copy. | `TestSignDoesNotChangeMessage` |
| DKIM-CANON-04 | 3.5 | Normative | c= defaults to simple/simple; a c= naming only the header algorithm means a simple body. | `TestCanonDefaults` |
| DKIM-CANON-05 | 3.4.1 | MUST | Simple header canonicalization presents fields unchanged: names not case-folded, whitespace unchanged. | `TestSimpleHeaderCanon_Unchanged` |
| DKIM-CANON-06 | 3.4.2 | MUST | Relaxed header canonicalization lowercases names, unfolds, reduces WSP runs to one SP, and drops WSP at the end of the value and around the colon. | `TestRelaxedHeaderCanon_RFCExample`, `FuzzCanonicalization` |
| DKIM-CANON-07 | 3.4.3 | Normative | Simple body canonicalization drops empty lines at the end; an empty body, or one without a final CRLF, gets one CRLF. | `TestBodyCanon_RFCExample`, `TestBodyCanon_Empty`, `TestRFC6376AppendixA`, `FuzzCanonicalization` |
| DKIM-CANON-08 | 3.4.4 | MUST | Relaxed body canonicalization drops WSP at line ends (never the CRLF), reduces WSP runs to one SP, and drops empty lines at the end; an empty body stays empty. | `TestBodyCanon_RFCExample`, `TestBodyCanon_Empty`, `FuzzCanonicalization` |
| DKIM-CANON-09 | 3.4.5 | Normative | The canonicalization examples of 3.4.5 come out as shown. | `TestRelaxedHeaderCanon_RFCExample`, `TestBodyCanon_RFCExample` |
| DKIM-CANON-10 | 5.3 | MUST | Convert bare CR or LF line endings to CRLF before signing (and before verifying). | `TestBareLineEndingsNormalized` |
| DKIM-CANON-11 | 3.8 | SHOULD | Take reasonable steps to ensure the input is a valid RFC 5322 message: a header line that is not a field is not read as one. | `TestMalformedHeaderLines` |

## The DKIM-Signature field (§3.5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-SIG-01 | 3.5 | MUST | Treat the b= value as empty when hashing the field; include unknown tags in the hash but otherwise ignore them. | `TestRemoveBValue`, `TestUnknownTagsIgnored` |
| DKIM-SIG-02 | 3.5, 6.1.1 | MUST | v= is required and is 1; any other version is PERMFAIL (incompatible version). | `TestVerify_MissingVersionRejected`, `TestVerify_WrongVersionRejected`, `TestVerify_VersionOneVerifies` |
| DKIM-SIG-03 | 3.5, 6.1.1 | MUST | A signature missing a required tag (a=, b=, bh=, d=, h=, s=) is PERMFAIL. | `TestRequiredTags` |
| DKIM-SIG-04 | 3.5 | MUST | Ignore whitespace in b= and bh= when decoding them. | `TestDecodeBase64Tag`, `TestVerify_UnpaddedBase64Accepted` |
| DKIM-SIG-05 | 3.5; RFC 8616 5 | MUST | d=, s= and the domain of i= are DNS names, internationalized ones as A-labels (or U-labels, EAI-01); otherwise the signature is invalid. | `TestDomainSelectorSyntax`, `TestIdentitySyntax`, `TestSignRejectsBadOptions` |
| DKIM-SIG-06 | 3.5 | MUST | h= is not empty, and its names are compared with field names case-insensitively. | `TestHeaderNamesCaseInsensitive` |
| DKIM-SIG-07 | 3.5, 3.10, 6.1.1 | MUST | The domain of i= is d= or a subdomain of it; otherwise PERMFAIL (domain mismatch). | `TestVerify_UnalignedIdentityRejected`, `TestVerify_AlignedIdentityVerifies`, `TestDomainAligned`, `TestIdentityDomain`, `TestIdentitySyntax` |
| DKIM-SIG-08 | 3.5 | Normative | l= is 1*76DIGIT; when present, only that many octets of the canonicalized body are hashed. | `TestBodyLength`, `TestVerify_NegativeBodyLength`, `TestVerify_PlusBodyLength`, `TestVerify_BodyLengthExceedsBody`, `TestBodyLengthBoundAfterCanonicalization` |
| DKIM-SIG-09 | 3.5 | MUST | Use the q= query methods in order, ignoring unrecognized ones; dns/txt is the default and the only method defined. | `TestQueryMethod`, `TestRFC8463Example` |
| DKIM-SIG-10 | 3.5 | SHOULD | Handle t= and x= values up to at least 10^12 (well beyond 2038). | `TestParseTimeTag` |
| DKIM-SIG-11 | 3.5 | MUST | x= is greater than t=; a signature where it is not is invalid. | `TestVerify_ExpirationNotAfterTimestampRejected` |
| DKIM-SIG-12 | 3.5, 6.1.1 | MAY | Treat a signature whose x= has passed as invalid (PERMFAIL, signature expired). | `TestVerify_ExpiredSignatureRejected`, `TestVerify_NonExpiredSignatureVerifies`, `TestVerify_ExpirationBoundary` |
| DKIM-SIG-13 | 3.5, 6.1.1 | MUST | A t= or x= that is not 1*12DIGIT makes the signature invalid. | `TestVerify_InvalidExpirationTagRejected`, `TestParseTimeTag`, `TestInvalidTagValues` |

## Signing (§3.5, §3.7, §4.2, §5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-SIGN-01 | 3.5 | Normative | Emit v=1 and the required a=, b=, bh=, d=, h= and s=, with c= and t= as configured. | `TestSignTags` |
| DKIM-SIGN-02 | 3.5 | SHOULD | Prepend the DKIM-Signature field, treated like a trace field. | `Example`, `TestSignDoesNotChangeMessage` |
| DKIM-SIGN-03 | 5.4 | MUST | Sign the From field; refuse a header list or a message without one. | `TestSign_RequiresFrom` |
| DKIM-SIGN-04 | 5.4, 5.4.1 | SHOULD NOT | Sign fields likely to be changed or removed in transit (Return-Path, Received, Comments, Keywords) by default. | `TestDefaultSignedHeaders` |
| DKIM-SIGN-05 | 5.4, 5.4.1 | Normative | By default sign the fields 5.4.1 recommends (plus Message-ID, Sender and the MIME fields 5.4 advises). | `TestDefaultSignedHeaders` |
| DKIM-SIGN-06 | 5.4, 5.4.2 | MAY | Oversign: list a field once more than the message carries it, so a copy added later breaks the signature (by default From, To, Cc, Subject, Reply-To, Date, Message-ID, Content-Type and MIME-Version). | `TestOversigning`, `TestRFC8463Oversigning` |
| DKIM-SIGN-07 | 5.4 | MUST | Treat a field named in h= that the message lacks as the null string, when signing and when verifying. | `TestOversigning`, `TestRFC8463Oversigning`, `TestDifferentialMsgauthSignVerifyHere` |
| DKIM-SIGN-08 | 5.4.2 | MUST | Signing a field that occurs more than once signs the last instance first; to sign several, list the name once per instance and sign bottom to top. | `TestMultipleInstancesBottomUp` |
| DKIM-SIGN-09 | 3.7 | MUST | Compute the body hash, then the header hash, which covers bh=. | `TestDifferentialSignHereVerifyMsgauth`, `FuzzSignVerify` |
| DKIM-SIGN-10 | 3.5, 3.7, 5.4 | MUST NOT | Include the DKIM-Signature field being created in its own h=. | `TestSignTags` |
| DKIM-SIGN-11 | 5.3 | MUST | Sign the message as it is expected to reach the verifier: its raw bytes, not a reconstruction. | `TestSign_VerifyRoundTrip`, `TestDifferentialSignHereVerifyMsgauth` |
| DKIM-SIGN-12 | 5.6 | MUST | The inserted field is the one hashed with b= filled in, inserted before any other DKIM-Signature field. | `TestSignDoesNotChangeMessage`, `Example` |
| DKIM-SIGN-13 | 5.6 (RFC 5322 2.1.1) | MUST | Keep the field's lines within RFC 5322's limits (folded at 78 characters, whatever the key size). | `TestSignFolds` |
| DKIM-SIGN-14 | 3.5, 8.2 | MUST NOT | Emit an l= larger than the canonicalized body (Sign never emits l=, which 8.2 advises against). | `TestSignTags` |
| DKIM-SIGN-15 | 5.4 | MAY | Sign other fields present at the time of signing, named by the caller; a named field the message lacks is left out unless oversigned. | `TestSign_OnlySignsPresentHeaders`, `TestOversigning` |
| DKIM-SIGN-16 | 3.5 | MUST | d= and s= are DNS names, internationalized ones as A-labels. | `TestSignRejectsBadOptions` |
| DKIM-SIGN-17 | 4.2 | SHOULD NOT | Remove existing DKIM-Signature fields when signing. | `TestSignDoesNotChangeMessage` |
| DKIM-SIGN-18 | 3.5 | SHOULD | Use the same AUID (i=) for each message intended to be evaluated as one. | `TestSignAUIDAndExpiry` |
| DKIM-SIGN-19 | 3.5 | MUST | x= is greater than t=. | `TestSignAUIDAndExpiry`, `TestSignExpiration` |
| DKIM-SIGN-20 | 5.3 | SHOULD | Convert the message to a transfer encoding that survives transit (quoted-printable or base64) before signing. | n/a: the caller builds the MIME message; the library signs the bytes it is given. |
| DKIM-SIGN-21 | 3.7 | MUST | Hash the body after content-transfer encoding and before transport-level encoding (dot-stuffing). | `TestSignHashesBodyBeforeDotStuffing` |
| DKIM-SIGN-22 | 5.4.1 | SHOULD | Choose the canonicalization by the kind of mail sent. | n/a: the caller's choice, through HeaderCanon and BodyCanon (relaxed by default). |
| DKIM-SIGN-23 | 5.5 | SHOULD | An intermediary that modifies and re-signs a message checks existing signatures on input. | n/a: the library does not modify messages. |

## The hash (§3.7)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-HASH-01 | 3.7 | MUST | Hash the canonicalized body, cut to l= octets when l= is present. | `TestBodyLength`, `TestRFC6376AppendixA` |
| DKIM-HASH-02 | 3.7 | MUST | Hash the h= fields in order, each canonicalized and ended by CRLF, then the DKIM-Signature field canonicalized, with b= empty and no final CRLF. | `TestSimpleCanonBFirst`, `TestBuildSignedHeadersSkipsEmptyNames`, `TestDifferentialSignHereVerifyMsgauth`, `TestDifferentialMsgauthSignVerifyHere` |
| DKIM-HASH-03 | 3.7 | MUST | Include every tag of the field in the hash, even ones the verifier does not understand. | `TestUnknownTagsIgnored` |
| DKIM-HASH-04 | 3.7 | Normative | Empty b= wherever it is in the field, as its first tag included. | `TestRemoveBValue`, `TestSimpleCanonBFirst` |
| DKIM-HASH-05 | 3.7 | MUST | Include MIME attachments in the signed content. | `TestAttachmentsSigned` |

## Key records (§3.6, §6.1.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-KEY-01 | 3.6.1, 6.1.2 | MUST | A key record's v=, if present, is DKIM1 and the first tag; a record with another is discarded. | `TestVerify_KeyRecordWrongVersionRejected`, `TestVerify_KeyRecordVersionNotFirstRejected`, `TestVerify_KeyRecordVersionAcceptedVerifies`, `TestFirstTagName` |
| DKIM-KEY-02 | 3.6.1, 6.1.2 | MUST | When a key record's h= does not list the signature's hash algorithm, ignore the record (PERMFAIL, inappropriate hash algorithm); unrecognized algorithms are ignored. | `TestVerify_KeyHashAlgorithmNotAllowedRejected`, `TestVerify_KeyHashAlgorithmAllowedVerifies`, `TestKeyRecordAllowsHash` |
| DKIM-KEY-03 | 3.6.1 | MUST | Support the rsa key type, the default for k=; ignore records of unrecognized types. | `TestKeyTypes`, `TestRFC6376AppendixA` |
| DKIM-KEY-04 | 3.6.1, 6.1.2 | MUST | An empty p= means the key is revoked: PERMFAIL (key revoked). | `TestVerify_RevokedKeyPermError` |
| DKIM-KEY-05 | 3.6.1 | MUST | Ignore a record whose s= lists neither email nor *; ignore unrecognized service types. | `TestVerify_KeyServiceTypeNotEmailRejected`, `TestVerify_KeyServiceTypeEmailVerifies`, `TestKeyRecordAllowsService` |
| DKIM-KEY-06 | 3.6.1 | MUST | Ignore unrecognized t= flags. | `TestParseKeyFlags` |
| DKIM-KEY-07 | 3.6.1 | MUST NOT | Treat messages from a signer in testing mode (t=y) differently from unsigned mail. | n/a: the library reports each signature's result; how a result is acted on, and so what testing mode changes, is the receiver's policy. |
| DKIM-KEY-08 | 3.6.1, 3.10 | MUST | With t=s, the domain of i= is exactly d=, not a subdomain. | `TestVerify_KeyTSFlagRejectsSubdomainIdentity`, `TestVerify_KeyTSFlagAllowsExactIdentity`, `TestVerify_NoTSFlagAllowsSubdomainIdentity`, `TestParseKeyFlags` |
| DKIM-KEY-09 | 3.6.2.1, 6.1.2 | MUST | Look the key up as a DNS TXT record at selector._domainkey.domain. | `TestRecordName`, `TestKeyLookupName` |
| DKIM-KEY-10 | 3.6.2.2 | MUST | Concatenate the strings of a TXT record with no whitespace between them. | `TestRecordFragmentChunks`, `TestRFC8463Example` |
| DKIM-KEY-11 | 6.1.2 | MAY | With several key records, try them in turn until one is usable. | `TestMultipleKeyRecords` |
| DKIM-KEY-12 | 6.1.2 | MUST | When the key record does not exist, return PERMFAIL (no key for signature). | `TestVerify_NoKeyPermError` |
| DKIM-KEY-13 | 6.1.2 | MAY | When the key query fails to respond, return TEMPFAIL (key unavailable). | `TestVerify_DNSTempError` |
| DKIM-KEY-14 | 6.1.2, 8.8 | MUST | Validate key records and ignore malformed ones (PERMFAIL, key syntax error); be robust against hostile records. | `TestMalformedKeyRecords`, `TestVerify_DuplicateTagInKeyRecordRejected`, `FuzzKeyRecord` |
| DKIM-KEY-15 | 6.1.2 | MUST | A key not suitable for the a= and k= algorithms is PERMFAIL (inappropriate key algorithm). | `TestKeyTypes` |
| DKIM-KEY-16 | 3.6.1 | Normative | An rsa p= is a DER RSAPublicKey; the SubjectPublicKeyInfo of Appendix C and most published records is accepted too. | `TestRSAPublicKeyFormats` |
| DKIM-KEY-17 | 3.6.1; RFC 8463 4.2 | Normative | A published key record is v=DKIM1 first, then k= and p= the base64 key. | `TestGenerateKeyAndRecordRoundTrip`, `TestRecordValueRejectsBadInput`, `TestRSAPublicKeyFormats` |
| DKIM-KEY-18 | C.2 | MUST | Ignore the retired g= tag, like any unknown key record tag. | `TestUnknownTagsIgnored` |

## Verifying (§3.9, §4.2, §6)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-VER-01 | 6 | MUST | Produce results semantically equivalent to the steps of section 6 (shown on RFC 8463's example and against go-msgauth). | `TestRFC8463Example`, `TestDifferentialSignHereVerifyMsgauth`, `TestDifferentialMsgauthSignVerifyHere`, `FuzzSignVerify` |
| DKIM-VER-02 | 3.9, 3.11, 6.3 | MUST | Report, for each signature, its d= (SDID) and the result; a message without signatures has none. | `TestVerifyResultFields`, `TestVerify_NoSignature` |
| DKIM-VER-03 | 4.2, 6.1 | SHOULD | Evaluate signatures independently, going on to the next after one fails. | `TestMultipleSignaturesIndependent` |
| DKIM-VER-04 | 6.1 | MUST NOT | Attribute ultimate meaning to the order of the DKIM-Signature fields. | `TestMultipleSignaturesIndependent` |
| DKIM-VER-05 | 6.1 | SHOULD NOT | Treat a message with only bad signatures differently from an unsigned one. | n/a: how a result is acted on is the receiver's policy. |
| DKIM-VER-06 | 6.1.1, 8.9 | MUST | Validate the signature field meticulously; any inconsistency makes it ignored (PERMFAIL). | `TestRequiredTags`, `TestInvalidTagValues`, `FuzzSignatureHeader` |
| DKIM-VER-07 | 5.4, 6.1.1 | MUST | A signature whose h= does not cover From is PERMFAIL (From field not signed). | `TestVerify_FromNotSignedRejected`, `TestVerify_FromSignedVerifies`, `TestHeaderListCoversFrom` |
| DKIM-VER-08 | 6.1.1 | SHOULD | Make configurable the list of fields a signature must cover. | n/a: not supported; the library requires From only, as the RFC does. |
| DKIM-VER-09 | 6.1.3 | MUST | Match h= names against field names case-insensitively. | `TestHeaderNamesCaseInsensitive` |
| DKIM-VER-10 | 6.1.3 | SHOULD | A body hash that does not match is PERMFAIL (body hash did not verify), reported as fail. | `TestVerify_BodyTamperFails` |
| DKIM-VER-11 | 6.1.3 | SHOULD | A signature that does not validate is PERMFAIL (signature did not verify), reported as fail. | `TestVerify_HeaderTamperFails`, `TestVerify_WrongKeyFails`, `TestSign_TamperFails` |
| DKIM-VER-12 | 6.2 | SHOULD | Insert the verification result (Authentication-Results) above the DKIM-Signature fields. | n/a: the library writes no header fields. |
| DKIM-VER-13 | 6.3 | SHOULD NOT | Decide acceptance on the lack of a signature or an unverifiable one alone. | n/a: acting on results is the receiver's policy. |
| DKIM-VER-14 | 6.3 | SHOULD | Reject with 550/5.7.x when rejecting on a DKIM result; reply 4xx only for temporary failures (permanent ones MUST NOT). | n/a: the library sends no SMTP replies; it reports temperror and permerror apart, as that choice needs. |
| DKIM-VER-15 | 4.2 | SHOULD | Identity Assessors ignore signatures that PERMFAILed. | n/a: assessing identities is the caller's; each result says whether it passed. |
| DKIM-VER-16 | 8.9 | MUST | Be robust against malformed DKIM-Signature fields: no crash, no hang, a PERMFAIL. | `FuzzParseTagList`, `FuzzSignatureHeader`, `TestMalformedKeyRecords`, `TestVerify_NegativeBodyLength`, `TestVerify_BodyLengthExceedsBody` |
| DKIM-VER-17 | 6.1.2, 6.1.3 | Normative | Key retrieval and the hash and signature check (6.1.2, 6.1.3) run apart from the field checks of 6.1.1, so a scheme reusing them (ARC) applies its own. | `TestVerifySignatureBare_VersionlessSeam`, `TestVerifySignatureBare_IgnoresIdentityAlignment`, `TestVerifySignatureBare_IgnoresKeyPolicyFlags`, `TestVerifySignatureBareTags` |

## Additional clauses found by the section audit

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-TAG-09 | 3.2, 3.5, 6.1.1 | Normative | A present empty value is distinct from an omitted default; empty c=, i=, t=, x=, l= and q= are invalid, and c= with a slash requires both algorithms. | `TestOptionalTagsDoNotDefaultWhenEmpty` |
| DKIM-QP-01 | 2.11 | MUST | DKIM-quoted-printable producers encode controls, non-ASCII octets, DEL, SPACE and semicolon, including all value whitespace. | n/a: Sign emits no i= or z=, and RecordValue emits no n= notes; this library has no DKIM-quoted-printable encoder. |
| DKIM-QP-02 | 2.11, 3.5 | MUST | Remove inserted FWS before decoding DKIM-quoted-printable, including copied z= fields. | n/a: the verifier does not decode or expose i= local-parts, z= copied headers or n= notes; it checks the i= domain and hashes the supplied field text. No decoded diagnostics are offered. |
| DKIM-QP-03 | 2.11 | NOT RECOMMENDED | Emit characters outside the RFC 2049 mail-safe set in DKIM-quoted-printable. | n/a: no DKIM-quoted-printable encoder is implemented; Sign emits neither i= nor z= and RecordValue emits no n= notes. |
| DKIM-SIG-14 | 3.5 | SHOULD NOT | Reorder DKIM-Signature fields when handling them as trace fields. | n/a: the caller inserts/transports the returned field; Verify reports input order without rewriting the message. Prepending is covered separately by SIGN-02/12. |
| DKIM-SIG-15 | 3.5 | RECOMMENDED | Include the t= signature creation timestamp. | n/a: explicit deviation at the zero-value default; Sign emits t= only when the caller sets Time greater than zero, otherwise creation time is unknown. |
| DKIM-SIG-16 | 3.5 | RECOMMENDED | Include the x= absolute signature expiration time. | `TestSignExpiration` |
| DKIM-KEY-19 | 3.6.1 | RECOMMENDED | Publish t=s unless AUID subdomaining is required. | n/a: DNS publication policy belongs to the key owner; RecordValue emits no t= flags. Enforcing a supplied t=s is covered by KEY-08. |
| DKIM-KEY-20 | 3.6.2.2 | MUST | Publish only one TXT RR for a particular selector name. | n/a: the library renders a record but does not provision DNS RRsets. Multiple received records have undefined RFC results; the chosen verifier behaviour is covered by KEY-11. |
| DKIM-SIGN-24 | 5.3 | SHOULD | Apply local-to-CRLF normalization to the message actually transmitted, as well as the signing input. | n/a: Sign returns a field value and cannot replace the caller's transmitted message; callers must transmit the normalized bytes (CANON-10 checks hashing normalization only). |
| DKIM-SIGN-25 | 5.5 | MUST | An intermediary makes its message modifications before re-signing. | n/a: the library neither modifies nor forwards messages; the host must call Sign after finishing its edits. SIGN-23 covers checking existing signatures. |
| DKIM-HASH-06 | 3.5, 3.7, 4.2 | Normative | Other DKIM-Signature fields selected by h= are ordinary fields with their b= values intact; selection excludes the signature currently being checked. | `TestSignedExistingSignatureValues` |
| DKIM-VER-18 | 6.1 | MUST | Immediately cease processing the individual signature when returning PERMFAIL or TEMPFAIL, while allowing later signatures to be checked. | `TestFailureStopsOnlyThatSignature` |
| DKIM-VER-19 | 6.3 | SHOULD | Make the reason for verification failure available for diagnostics; the host may record it. | `TestFailureStopsOnlyThatSignature` |
| DKIM-VER-20 | 3.5, 5.3.1, 6.1.1 | MUST NOT | Accept an l= count larger than the canonicalized body's octet count; determine the bound after canonicalization. | `TestBodyLengthBoundAfterCanonicalization` |
| DKIM-VER-21 | 6.1.1 | MUST | In the absence of i=, behave as though it were @ followed by d=, including when the key requires t=s. | `TestAbsentAUIDUsesSigningDomain` |
| DKIM-VER-22 | 6.1.1 | SHOULD | If rejecting SDIDs as unacceptable signing entities, make that domain list configurable. | n/a: this optional domain-rejection mode is not implemented; Verify has no built-in unacceptable-domain list. Caller policy can filter reported Domain values. |
| DKIM-VER-23 | 6.3 | SHOULD | When a verified SDID differs from From, make the actual SDID clear to the reader. | n/a: user presentation is the consuming mail system's responsibility; VerifyResult.Domain exposes the SDID independently of From (VER-02). |
| DKIM-IANA-01 | 7 | MUST | Registry submissions include the registered name, defining document and active or historic status. | n/a: the library makes no IANA registrations; it implements the existing algorithm, tag and key registries. |

## Internationalized mail (RFC 8616 §5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-EAI-01 | RFC 8616 5 | MAY | In internationalized headers d=, s= and the i= domain may be U-labels or A-labels, in any mix; a verifier accepts both. | `TestRFC8616ULabels`, `TestIdentitySyntax` |
| DKIM-EAI-02 | RFC 8616 5 | Normative | U-labels in d= and s= are converted to A-labels for the key record lookup, and alignment compares A-labels. | `TestRFC8616ULabels`, `TestToALabels` |
| DKIM-EAI-03 | RFC 8616 5 | MUST | Computing or verifying the hash uses the domain name in the form it occurs in the header. | `TestRFC8616HashUsesHeaderForm` |
| DKIM-EAI-04 | RFC 8616 5 | SHOULD | Signers of internationalized messages represent IDNs in d=, s= and i= as U-labels. | n/a: explicit deviation; Sign takes A-label Domain and Selector only (SIGN-16), which RFC 8616 keeps valid, and cannot tell whether the message is internationalized. |
| DKIM-EAI-05 | RFC 8616 5 | Normative | dkim-safe-char and the i= local-part admit UTF-8 (UTF8-2/3/4, UTF8-non-ascii) in internationalized headers; invalid UTF-8 is still malformed. | `TestRFC8616ULabels`, `TestDomainSelectorSyntax` |
