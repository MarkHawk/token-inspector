# token-inspector

**token-inspector decodes a SAML response or a JWT and explains, in
plain English, why a single sign-on login is failing.** It runs fully
offline: it reads only local files and never contacts the issuer or
anything else, so it's safe on a locked-down support laptop, and a
pasted token can't trigger any network traffic.

## Try it in 1 minute

From a clone, with Python 3.12 or newer:

```
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Then see what it makes of four bundled samples:

```
token-inspector demo
```

```
token-inspector demo: 4 bundled samples, checked offline as at the time each was captured

  valid     Signed SAML response, in date   PASS  no problems found
  expired   OIDC ID token, expired 3 h ago  FAIL  likely cause: the token is simply old
  rotation  Lab capture, mid key rotation   FAIL  likely cause: key rotation, trusted cert expired
  xsw       Forged SAML response            FAIL  likely cause: signature wrapping (XSW)

Full report for one sample:  token-inspector demo <name>   e.g. token-inspector demo xsw
Try your own file:           token-inspector <file>
```

### Try a real lab capture

This SAML response was captured from
[identity-lab](https://github.com/MarkHawk/identity-lab) while the identity
provider was mid certificate rotation, and ships with the repository:

```
token-inspector samples/lab/expired-signing-cert/saml-response.xml --now 2026-10-17T13:34:20Z
```

`--now` checks the response as at the moment it was captured rather than
today, so its age is not reported as a problem; leave it out and the report
suggests the value to use.

```
Note:       Using idp-metadata.xml found next to the input
...
== Checks ==
  PASS  Response status              Success.
  FAIL  Response signature           The signature does not match the certificate from metadata
                                     idp-metadata.xml. It was made with a different certificate
                                     (included in the message), so the IdP has most likely rotated
                                     its signing certificate and the SP still trusts the old one.
  ...
  PASS  Signing certificate dates    Valid until 2036-10-17 13:34:20 UTC (another 3653 days).
  FAIL  Trusted certificate dates    The certificate the SP trusts (from metadata idp-metadata.xml)
                                     expired on 2026-10-17 13:34:16 UTC, 4 s ago. The IdP is now
                                     signing with a different certificate, so the SP must be given
                                     the IdP's current certificate.
  ...

== Likely cause ==
  The certificate the SP trusts has expired and the IdP has moved on to a new signing key, so the SP
  no longer trusts the key that signs its logins.
  First:     Give the SP the IdP's current signing certificate, or have it refresh the IdP metadata.
  Runbook:   identity-lab 01-expired-signing-cert
             https://github.com/MarkHawk/identity-lab/blob/main/runbooks/01-expired-signing-cert.md
  Explains:  Response signature, Assertion signature, Signature coverage, Trusted certificate dates,
             Certificate matches trusted

Verdict: 5 problems to fix (5 FAIL, 0 WARN, 6 PASS, 4 SKIP)
```

No trust flags were needed: it found the IdP's metadata in the same folder and
checked against it. Every check still gets its own line, and the Likely cause
section ties the five failures together into the one thing to fix.

## Common cases

Give it a file, or `-` for standard input, or paste the value with `--token`.
It works out whether the input is a SAML response or a JWT, and unwraps
base64, deflate, URLs, HAR files and SAML-tracer exports as needed.

```
# SAML response, checked against the IdP's metadata
token-inspector saml-response.xml --metadata idp-metadata.xml

# ... against the certificate the SP has pinned instead
token-inspector saml-response.xml --cert sp-pinned-cert.pem

# OIDC ID token, checked against the IdP's JWKS
token-inspector id-token.txt --jwks jwks.json

# a token pasted from a ticket, as at the moment the login failed
token-inspector --token 'eyJhbGciOi...' --now 2026-10-17T09:15:00Z

# a report safe to paste back into the ticket
token-inspector saml-response.xml --redact
```

If `idp-metadata.xml` or `jwks.json` sits next to the input file, it is used
automatically, as above; any explicit `--metadata`, `--cert` or `--jwks` takes
its place.

Checks that compare against what the SP expects (audience, destination,
nonce and so on) show as SKIP until you give the expected value, for example
`--expect-audience <SP entity ID>`. The SKIP line names the flag to add.

Exit status is 0 when no check failed, 1 when at least one did, and 2 when the
input or a key file could not be read. Every flag, including `--json` and the
full list of expected values, is in [`docs/usage.md`](docs/usage.md).

## Lab samples

The captures under [`samples/lab/`](samples/lab) are real SAML responses and
tokens taken from a running [identity-lab](https://github.com/MarkHawk/identity-lab),
a self-contained lab that reproduces single sign-on failures on purpose. Each
capture is sanitised before it is committed (no private addresses, home
directory paths or private keys), and the tool's findings link to the matching
identity-lab runbook. See [`samples/lab/README.md`](samples/lab/README.md) for
how the captures are produced.

## Documentation

- [`docs/usage.md`](docs/usage.md) every option, input format and exit code,
  and the demo subcommand.
- [`docs/checks.md`](docs/checks.md) every check, and what a pass, warning or
  failure means.
- [`docs/design.md`](docs/design.md) why the tool is built the way it is, and
  ideas not yet built.

## Development

```
python3 -m venv venv
venv/bin/pip install -r requirements-dev.txt
venv/bin/pip install -e . --no-deps
venv/bin/pytest
```

The test suite is offline: a fixture fails any test that opens a socket.

## A note on how this was built

token-inspector was written with AI-assisted tooling (Claude Code). The design
decisions, the checks and this documentation were reviewed by a person.

## Licence

MIT. See [LICENSE](LICENSE).
