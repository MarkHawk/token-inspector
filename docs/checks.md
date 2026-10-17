# Checks

Every check token-inspector runs, grouped by input type, with what each result
means. A check reports one of four results:

- **PASS** the check succeeded.
- **WARN** not a failure on its own, but worth a look, and something a stricter
  receiver might reject.
- **FAIL** a receiver should reject the token or assertion for this reason.
- **SKIP** the check did not apply, or you did not supply what it needs (for
  example a certificate, or an expected value to compare against).

The exit status is 1 if any check failed, otherwise 0 (and 2 if the input or a
key file could not be read).

Findings that match a known identity-lab failure link to its runbook.

## SAML

**Response status.** The `StatusCode` in the response. FAIL for anything other
than `Success`, with a plain reading of the status (for example `Responder`,
`AuthnFailed`), because the login failed at the identity provider and the
service provider is not at fault.

**Encrypted assertion.** WARN when the assertion is encrypted, since only the
response envelope can be read without the service provider's private key, which
this tool never takes.

**Response signature** and **Assertion signature.** Whether the signature over
each element verifies. PASS when it verifies against the trusted certificate
(from `--metadata` or `--cert`). WARN when it verifies only against a
certificate embedded in the message, which anyone can place there, so no trust
material was supplied. FAIL when the content was changed after signing (a digest
mismatch), or when it was signed with a certificate that is not the trusted one
(a likely key rotation), or when it does not verify at all.

**Signature coverage.** Whether a valid signature actually covers the assertion
the service provider would read. FAIL when nothing is signed, when only a
different element is signed, or when duplicate element IDs or a wrapped
signature point to an XML Signature Wrapping attack. This is the check that
catches a forged assertion smuggled past a naive signature verifier.

**Signature algorithm.** FAIL for MD5. WARN for SHA-1, which is deprecated and
rejected by default by many service providers and SAML libraries. PASS for
SHA-256 and stronger.

**Signing certificate dates.** The validity dates of the certificate that
actually signed the message. FAIL if it has expired or is not yet valid. WARN if
it expires within 30 days.

**Trusted certificate dates.** The validity dates of the certificate the service
provider trusts (from `--metadata` or `--cert`), independent of what signed this
message. FAIL when every trusted certificate has expired or is not yet valid,
because a service provider that checks dates then has no usable identity
provider certificate and rejects every login, even one signed with a good new
key. When the message was signed with a different certificate, the finding says
so and points to giving the service provider the identity provider's current
certificate. SKIP without trust material.

**Certificate matches trusted.** Whether the certificate that signed the message
is the one the service provider trusts. FAIL when it is not (the identity
provider has a new signing certificate the service provider does not know
about). WARN when the fingerprints differ but the signature still verifies (the
same key in a reissued certificate). SKIP without trust material.

**Timestamp format.** FAIL if a `NotBefore` or `NotOnOrAfter` is not a valid
`xs:dateTime`.

**Not before.** Whether the assertion's `NotBefore` has passed. FAIL if it is in
the future beyond the skew allowance. WARN if it is in the future but within the
allowance.

**Not on or after.** Whether the assertion is still within its validity window,
taking the earliest of the `Conditions` and bearer `SubjectConfirmationData`
expiries. FAIL once expired beyond the skew allowance, with wording that
distinguishes clock skew from a genuinely old or replayed response. WARN if
expired but within the allowance.

**Issuer.** The response and assertion `Issuer` against `--expect-issuer` (or the
entityID from `--metadata`). FAIL on a mismatch, or if the response and assertion
issuers disagree. SKIP if no expected value was given.

**Audience.** The assertion `AudienceRestriction` against `--expect-audience`.
FAIL on a mismatch. WARN if the assertion carries no audience at all. SKIP
without an expected value.

**Destination** and **Recipient.** The response `Destination` and the
`SubjectConfirmationData` `Recipient` against the service provider's ACS URL
(`--expect-destination` / `--expect-recipient`). FAIL on a mismatch, with a hint
when they differ only by scheme, host, port or a trailing slash. WARN if a signed
response has no `Destination`. SKIP without an expected value.

**InResponseTo.** The `InResponseTo` against the service provider's AuthnRequest
ID (`--expect-in-response-to`). FAIL on a mismatch (the response answers a
different login attempt). For a response with no `InResponseTo`, FAIL if an ID was
expected (this was an identity-provider-initiated login) and SKIP otherwise.

## OIDC and JWT

**Algorithm.** The `alg` header against what the relying party expects (from
`--expect-alg`, or inferred from the keys in `--jwks`). FAIL for `none`, for an
unknown algorithm, for the wrong algorithm, and in particular for a shared-secret
algorithm (`HS256`) where an asymmetric one was expected, which is the classic
algorithm-confusion attack. WARN for a shared-secret algorithm when none was
specified.

**Key ID (kid).** Whether the header `kid` is present in `--jwks`. FAIL when it
is not (a likely key rotation with a stale cached JWKS). WARN when the header has
no `kid` at all. SKIP without a JWKS, or for a shared-secret algorithm.

**Signature.** Whether the signature verifies with a matching key from `--jwks`.
FAIL when it does not. SKIP for a shared-secret algorithm (the secret is not
taken), for an unsupported algorithm, or without a JWKS.

**Expiry (exp).** Whether the token is still within its lifetime. FAIL once
expired beyond the skew allowance, WARN if expired but within it, and for an ID
token with no `exp` at all, FAIL (an access token without one is WARN).

**Not before (nbf).** Like the SAML `NotBefore`: FAIL if in the future beyond the
skew allowance, WARN if within it, SKIP if absent (it is optional).

**Issued at (iat).** When the token was minted. A past `iat` is PASS. An `iat`
ahead of this machine's clock but within the skew allowance is PASS with a note
(it only records issue time, so a small gap is clock drift, not a token that is
not valid yet). Beyond the allowance it is FAIL.

**Timestamp format.** FAIL if `exp`, `nbf` or `iat` is not a NumericDate (seconds
since 1970).

**Issuer (iss).** Against `--expect-issuer`, compared exactly including scheme,
port, path and trailing slash. FAIL on a mismatch. SKIP without an expected
value.

**Audience (aud).** Against `--expect-audience`, or the client ID (`--client-id`)
for an ID token. FAIL when the token was issued for a different client or API.
SKIP without an expected value.

**Nonce.** For an ID token, the `nonce` against `--nonce` from the login request.
FAIL on a mismatch or when the request sent a nonce the token lacks. SKIP for a
non-ID token, or when no nonce was supplied.

**Authorised party (azp).** For an ID token, `azp` against `--client-id`. FAIL
when the token was issued to another client. WARN when there are several
audiences but no `azp`. SKIP for a non-ID token or a single audience without a
value to compare.

**Required claims.** That the claims a token of this type must carry are present
(the OIDC set for an ID token, the RFC 9068 set for an `at+jwt` access token),
plus any added with `--require-claim`. FAIL when one is missing.

**Encrypted token.** WARN when the input is an encrypted JWT (a JWE): its claims
can only be read with the relying party's private key, so nothing else can be
checked here.
