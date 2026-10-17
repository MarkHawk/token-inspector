# token-inspector

Decode a SAML response or a JWT and explain, in plain English, why a single
sign-on login is failing. It runs fully offline: it reads only the files you
give it and never calls out to the issuer or anywhere else, so it is safe on a
locked-down support laptop and a pasted token cannot trigger any network
traffic.

## What it looks like

Point it at a captured SAML response, give it the certificate the service
provider trusts, and it reports every check with a verdict. This runs against a
committed sample, so you can reproduce it exactly from a clone:

```
$ token-inspector samples/lab/expired-signing-cert/saml-response.xml \
    --cert samples/lab/expired-signing-cert/sp-pinned-cert.pem \
    --expect-issuer https://idlab.home:8180/realms/idlab \
    --expect-audience https://idlab.home:8181/saml/metadata \
    --now 2026-10-17T13:34:19Z

== Checks ==
  PASS  Response status              Success.
  FAIL  Response signature           The signature does not match the certificate from certificate
                                     sp-pinned-cert.pem. It was made with a different certificate
                                     (included in the message), so the IdP has most likely rotated
                                     its signing certificate and the SP still trusts the old one.
  PASS  Signing certificate dates    Valid until 2036-10-17 13:34:20 UTC (another 3653 days).
  FAIL  Trusted certificate dates    The certificate the SP trusts (from certificate
                                     sp-pinned-cert.pem) expired on 2026-10-17 13:34:16 UTC, 3 s
                                     ago. The IdP is now signing with a different certificate, so
                                     the SP must be given the IdP's current certificate.
  FAIL  Certificate matches trusted  The IdP signed with a certificate that is not in certificate
                                     sp-pinned-cert.pem.
  ...
Verdict: 5 problems to fix (5 FAIL, 0 WARN, 10 PASS, 0 SKIP)
```

This capture was taken while the identity provider was mid-rotation: its pinned
signing certificate had expired, so it had fallen back to a freshly generated
key. The signature itself verifies against the new key, but the certificate the
service provider still trusts has lapsed, and the two no longer match. The tool
separates those facts out so the person on the ticket can see exactly what to
fix. The full story is in
[`samples/lab/expired-signing-cert/`](samples/lab/expired-signing-cert).

## Install

Needs Python 3.12 or newer. Install into a virtual environment:

```
python3 -m venv venv
venv/bin/pip install -e .
```

That puts a `token-inspector` command in `venv/bin`. Activate the environment
(`source venv/bin/activate`) if you would rather call it by name.

## Usage

Give it a file, or `-` to read from standard input, or paste the value with
`--token`. It works out whether the input is a SAML response or a JWT, and
decodes base64, deflate and JWT compact form as needed. The flags you reach for
most:

```
# SAML, checked against the IdP's metadata
token-inspector saml-response.xml --metadata idp-metadata.xml \
    --expect-issuer <IdP entity ID> \
    --expect-audience <SP entity ID> \
    --expect-destination <SP ACS URL> \
    --expect-in-response-to <AuthnRequest ID from the SP log>

# or against a single certificate the SP has pinned
token-inspector saml-response.xml --cert sp-pinned-cert.pem ...

# OIDC ID token, checked against the IdP's JWKS
token-inspector id-token.txt --jwks jwks.json \
    --expect-issuer <issuer> --client-id <client ID> --nonce <nonce from the login request>

# an access token
token-inspector access-token.txt --jwks jwks.json --token-type access --expect-issuer <issuer>
```

Other useful flags:

- `--now <ISO 8601>` evaluate the token as at a given time, for example the
  moment the ticket says the login failed, instead of now.
- `--skew <seconds>` clock skew allowance (default 60).
- `--json` machine-readable output.
- `--redact` mask emails, names, NameID and `sub` so the report can be pasted
  into a ticket.
- `--require-claim <name>` fail if a named claim is absent.

Exit status is 0 when no check failed, 1 when at least one did, and 2 when the
input or a key file could not be read. Run `token-inspector --help` for the
full list.

## Lab samples

The captures under [`samples/lab/`](samples/lab) are real SAML responses and
tokens taken from a running [identity-lab](https://github.com/MarkHawk/identity-lab),
a self-contained lab that reproduces single sign-on failures on purpose. Each
capture is sanitised before it is committed (no private addresses, home
directory paths or private keys), and the tool's findings link to the matching
identity-lab runbook. See [`samples/lab/README.md`](samples/lab/README.md) for
how the captures are produced.

## Documentation

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
