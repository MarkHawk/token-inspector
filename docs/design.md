# Design

## What it is for

A support engineer handed "SSO is broken for everyone" usually sees only the
customer's description. The cause is buried in signed XML, token claims,
certificates and clocks, split across two sides owned by different teams.
token-inspector takes one artefact (a SAML response or a JWT) and turns it into
a list of plain-English findings, so the person on the ticket can see which side
is at fault and what to change.

## Principles

**Offline by default.** The tool reads only local files: the ones you pass it,
plus an `idp-metadata.xml` or `jwks.json` sitting next to the input file when
you give no trust flag (the report says when it does this). It never follows a
JWKS or metadata URL and never contacts the issuer. That keeps it usable on a
locked-down support laptop, and it means pasting a hostile token can never
trigger outbound traffic. Trust material (`--metadata`, `--cert`, `--jwks`) is
always a local file. The test suite enforces this: a fixture fails any test
that opens a socket.

**Easy first run, explicit when it matters.** Picking up trust material from
the input's folder means a capture folder laid out the usual way just works
with no flags. It is never silent: the report names the file it used, any
explicit `--metadata`, `--cert` or `--jwks` switches it off entirely, and
`--no-discover` turns it off with no other change. A token pasted with
`--token` or read from standard input never triggers it, because there is no
folder to look in.

**One check, one finding.** A normal verification library stops at the first
problem, which is the right thing for an application but the wrong thing for
triage. Here each property (signature, coverage, certificate dates, issuer,
audience, expiry, and so on) is reported separately, with its own PASS, WARN,
FAIL or SKIP, so an engineer sees the whole picture at once rather than fixing
one error only to hit the next. The full list is in
[checks.md](checks.md).

**Explain, do not just reject.** Each failing finding says what is wrong in the
language of the problem (a rotated certificate, a clock that disagrees, an
audience meant for another client) and what to do next. Where a finding matches
a known identity-lab failure, it links to that runbook.

**Say when you cannot tell.** SKIP is a first-class result. If no metadata or
certificate was supplied, the certificate checks skip rather than guess, and the
signature check drops to a WARN that explains an embedded certificate proves
nothing on its own.

**Evaluate at a chosen moment.** `--now` lets the engineer check the token as at
the time the ticket says the login failed, not as at now, so an expiry or a
not-yet-valid window is judged against the right clock. A skew allowance
(`--skew`, default 60 seconds) keeps small clock differences out of the way.

**Safe to paste.** `--redact` masks emails, names, NameID and `sub` so a report
can go into a ticket without carrying personal data.

## Handling untrusted input

The input is, by assumption, a token from a failing or possibly hostile login.
XML is parsed with hardening against entity-expansion and external-entity
attacks. Signature coverage is checked against the element actually read, so an
assertion wrapped around a signature over a different element is caught rather
than trusted (an XML Signature Wrapping attack). The algorithm check flags a
shared-secret algorithm presented where an asymmetric one is expected, the shape
of an algorithm-confusion attack.

## Lab captures

The fixtures under `samples/lab/` are real captures from
[identity-lab](https://github.com/MarkHawk/identity-lab), a self-contained lab
that breaks single sign-on on purpose. Captures are produced by
`scripts/capture_from_lab.sh`, which signs in like a browser and keeps what
comes back. Nothing is written until it is sanitised: private addresses, home
directory paths and private keys are removed or refused, and if sanitising had
to change signed content the sidecar records that so a sanitised sample is never
mistaken for a genuinely broken signature. A repository-hygiene test re-checks
every tracked file for the same patterns, and in particular fails if any tracked
file contains a private key.

## Testing

Most fixtures are generated at a fixed reference time by
`scripts/generate_samples.py`, so results never depend on the wall clock: the
certificates, tokens and clock-skew cases are all built relative to that moment.
On top of those, the committed lab captures are run through the CLI end to end.
Each check has at least one passing and one failing sample. CI runs the whole
suite on Python 3.12 and 3.13.

## Ideas

Not built yet, recorded so they are not lost.

- **Diagnose redirect_uri mismatches from a HAR (identity-lab runbook 03).**
  The redirect-uri-mismatch scenario fails before any token is issued: the
  identity provider rejects the authorisation request with an error page, so
  there is nothing for token-inspector to read today. A browser HAR of the
  failing login, though, contains the authorisation request (with the
  `redirect_uri` the application sent) and the identity provider's error
  response. token-inspector already reads tokens out of HAR files; extending that
  to read the authorisation request and error would let it explain a
  redirect_uri mismatch (the registered value against what the application sent)
  from the same kind of capture, and point at runbook 03. The other token-less
  scenarios (a failed directory bind, a RADIUS secret mismatch) stay out of
  scope: they produce no SAML or OIDC artefact at all.

- **An opt-in online mode.** A single explicit flag could let the tool fetch the
  live JWKS or metadata to compare against what the relying party has cached. It
  would stay off by default, so the offline guarantee holds unless the engineer
  asks for it.
