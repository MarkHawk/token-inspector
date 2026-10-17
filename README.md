# token-inspector

Decode a SAML response or a JWT and explain, in plain English, why a single
sign-on login is failing. It runs fully offline: it reads only local files and
never calls out to the issuer or anywhere else, so it is safe on a locked-down
support laptop and a pasted token cannot trigger any network traffic.

## Try it in 1 minute

From a clone, with Python 3.12 or newer:

```
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Then point it at a real capture that ships with the repository:

```
token-inspector samples/lab/expired-signing-cert/saml-response.xml
```

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
                                     expired on 2026-10-17 13:34:16 UTC, ...
  ...
Verdict: 6 problems to fix (6 FAIL, 0 WARN, 5 PASS, 4 SKIP)
```

No flags needed: it found the IdP's metadata in the same folder and checked
against it. This capture caught the identity provider mid certificate rotation.
The certificate the service provider trusts has expired, so the IdP has started
signing with a new one the SP does not know about, and the report says exactly
that. (It also flags the response as old, because it was captured in the past;
the report tells you the `--now` value to check it as at the time it was
issued.)

To see four bundled cases side by side, including a signature wrapping attack:

```
token-inspector demo
```

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
