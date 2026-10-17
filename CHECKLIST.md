# RFC 6376 checklist

Every requirement [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) places on a
DKIM signer and verifier, as updated by [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301)
(algorithms and key sizes) and [RFC 8463](https://www.rfc-editor.org/rfc/rfc8463)
(Ed25519), item by item, with the tests that cover it. The list takes in every
MUST, MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED and NOT RECOMMENDED that
applies to a signer or a verifier, the MAYs the library implements, and the
normative behaviour that carries no keyword (level "Normative"). Requirements
on DNS publishers and on how a receiver acts on a result are listed where a
reader would look for them and marked n/a. A section number alone is RFC 6376;
the others are named.

An item that does not apply to a library (because it is the receiver's policy,
say) says "n/a" and why. CI checks this file against the tests with
`go run ./internal/checklist`; the format is described in the
[README](README.md#the-rfc-checklist).

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
| DKIM-SIG-05 | 3.5 | MUST | d=, s= and the domain of i= are DNS names, internationalized ones as A-labels; otherwise the signature is invalid. | `TestDomainSelectorSyntax`, `TestIdentitySyntax`, `TestSignRejectsBadOptions` |
| DKIM-SIG-06 | 3.5 | MUST | h= is not empty, and its names are compared with field names case-insensitively. | `TestHeaderNamesCaseInsensitive` |
| DKIM-SIG-07 | 3.5, 3.10, 6.1.1 | MUST | The domain of i= is d= or a subdomain of it; otherwise PERMFAIL (domain mismatch). | `TestVerify_UnalignedIdentityRejected`, `TestVerify_AlignedIdentityVerifies`, `TestDomainAligned`, `TestIdentityDomain`, `TestIdentitySyntax` |
| DKIM-SIG-08 | 3.5 | Normative | l= is 1*76DIGIT; when present, only that many octets of the canonicalized body are hashed. | `TestBodyLength`, `TestVerify_NegativeBodyLength`, `TestVerify_PlusBodyLength`, `TestVerify_BodyLengthExceedsBody` |
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
| DKIM-SIGN-18 | 3.5 | SHOULD | Use the same AUID (i=) for each message intended to be evaluated as one. | n/a: Sign emits no i=, so the AUID is always the default "@" + d=. |
| DKIM-SIGN-19 | 3.5 | MUST | x= is greater than t=. | n/a: Sign emits no x=. |
| DKIM-SIGN-20 | 5.3 | SHOULD | Convert the message to a transfer encoding that survives transit (quoted-printable or base64) before signing. | n/a: the caller builds the MIME message; the library signs the bytes it is given. |
| DKIM-SIGN-21 | 3.7 | MUST | Hash the body after content-transfer encoding and before transport-level encoding (dot-stuffing). | n/a: the caller passes the message as it goes into DATA, encoded and not dot-stuffed; the library hashes those bytes. |
| DKIM-SIGN-22 | 5.4.1 | SHOULD | Choose the canonicalization by the kind of mail sent. | n/a: the caller's choice, through HeaderCanon and BodyCanon (relaxed by default). |
| DKIM-SIGN-23 | 5.5 | SHOULD | An intermediary that modifies a message checks its signatures and makes sure its changes do not break them. | n/a: the library does not modify messages. |

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
| DKIM-VER-17 | 6.1.2, 6.1.3 | Normative | Key retrieval and the hash and signature check (6.1.2, 6.1.3) run apart from the field checks of 6.1.1, so a scheme reusing them (ARC) applies its own. | `TestVerifySignatureBare_VersionlessSeam`, `TestVerifySignatureBare_IgnoresIdentityAlignment`, `TestVerifySignatureBare_IgnoresKeyPolicyFlags` |
