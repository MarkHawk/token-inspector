# Usage reference

Every option token-inspector accepts. The [README](../README.md) covers the
common cases; this page is the full list. `token-inspector --help` prints the
same flags in short form.

```
token-inspector [options] [file]
token-inspector demo [name] [--json] [--redact]
```

## Input

| Option | What it does |
|---|---|
| `file` | The file to read. Omit it, or give `-`, to read standard input. |
| `--token VALUE` | The token or `SAMLResponse` value itself, instead of a file. |
| `--pick N` | Which token to inspect when the input holds several (default 1). The report says when there are others. |

The tool works out what it has been given, so you rarely need to tidy the input
first. It accepts:

- a SAML response as raw XML, base64 (the HTTP-POST binding value) or deflate
  plus base64 (the HTTP-Redirect binding value);
- a whole URL or form body carrying `SAMLResponse`, `id_token` or
  `access_token`;
- the auto-submit HTML page an IdP returns, with the `SAMLResponse` hidden
  input;
- a browser HAR file, including bearer tokens in `Authorization` headers;
- a SAML-tracer export;
- a bare JWT (compact JWS) or an encrypted JWT (compact JWE, which can be
  described but not decrypted).

The report's `Input:` line says which encoding and container it found, because
"the Redirect binding value was pasted where a POST value was expected" is a
diagnosis in its own right.

A file that is itself IdP metadata is refused with a hint to pass it with
`--metadata` instead.

## Trust material

All trust material is a local file. The tool never fetches metadata or a JWKS
from a URL.

| Option | What it does |
|---|---|
| `--metadata FILE` | IdP SAML metadata XML. Its signing certificates are trusted, and its `entityID` is used as the expected issuer when `--expect-issuer` is not given. |
| `--cert FILE` | An IdP signing certificate (PEM or DER), for example the one the SP has pinned. Repeatable. |
| `--jwks FILE` | A JWKS JSON file, for checking JWT signatures. |
| `--no-discover` | Do not pick up trust material from the input file's folder (see below). |

### Trust material found next to the input

When the input is a file and none of `--metadata`, `--cert` or `--jwks` is
given, the tool looks in the same folder as the input:

- for a SAML response, it uses `idp-metadata.xml` if there is one;
- for a JWT, it uses `jwks.json` if there is one.

The report says so on a `Note:` line, for example
`Using idp-metadata.xml found next to the input`, and the JSON output lists it
under `notes`. Any explicit trust flag switches this off entirely, so the files
you name are always the ones checked. `--no-discover` switches it off with no
other change. Input from `--token` or standard input never triggers it.

Without any trust material, signatures are still checked against the
certificate embedded in a SAML message, but the report warns that this proves
nothing about who signed it, and JWT signature checks are skipped.

## Expected values

Each of these turns a check from SKIP into PASS or FAIL. Take the values from
the SP or relying party's configuration and logs, not from the token.

| Option | Compared with |
|---|---|
| `--expect-issuer VALUE` | SAML `Issuer`, or JWT `iss`. |
| `--expect-audience VALUE` | SAML `Audience` (the SP entity ID), or JWT `aud` (client ID or API audience). |
| `--expect-destination URL` | SAML Response `Destination` (the SP's ACS URL). |
| `--expect-recipient URL` | SAML `SubjectConfirmationData` `Recipient` (the SP's ACS URL). |
| `--expect-in-response-to ID` | SAML `InResponseTo`: the AuthnRequest ID from the SP's log. |
| `--expect-alg ALG` | JWT `alg` header, for example `RS256`. |
| `--nonce VALUE` | OIDC ID token `nonce`: the one sent in the authentication request. |
| `--client-id VALUE` | OIDC client ID, for checking `azp` when there are several audiences. |
| `--token-type id\|access` | Treat a JWT as an ID token or an access token, instead of guessing. |
| `--require-claim NAME` | Fail if the named JWT claim is absent. Repeatable. |

## Time

| Option | What it does |
|---|---|
| `--now ISO8601` | Evaluate as at this time, for example the moment the ticket says the login failed. `Z` or an offset is accepted; a time with neither is taken as UTC. |
| `--skew SECONDS` | Clock skew allowance (default 60). A time that misses by more than this fails; one that misses by less usually warns. |

Without `--now`, an old capture fails its expiry check, and the report suggests
the `--now` value that would check it as at the time it was issued.

## Output

| Option | What it does |
|---|---|
| `--json` | Print the report as JSON: the decoded fields, every finding with its `check_id`, any `notes`, and a summary. |
| `--redact` | Mask emails, names, NameID and `sub`, so the report can be pasted into a ticket. |
| `--version` | Print the version and exit. |

Colour is used when writing to a terminal, and switched off when the
`NO_COLOR` environment variable is set.

## Exit status

| Code | Meaning |
|---|---|
| 0 | No check failed (there may be warnings). |
| 1 | At least one check failed. |
| 2 | The input or a key file could not be read or used. |

## The demo subcommand

```
token-inspector demo                # one-line verdict for each bundled sample
token-inspector demo xsw            # the full report for one of them
token-inspector demo xsw --json     # ... as JSON (--redact works too)
```

The demo runs four samples that ship with the package, so it works from any
install and never uses the network:

| Name | What it shows |
|---|---|
| `valid` | A signed SAML response with everything in order. |
| `expired` | An OIDC ID token that expired three hours before it was checked. |
| `rotation` | A real identity-lab capture taken while the IdP was mid certificate rotation, checked against the certificate the SP had pinned. |
| `xsw` | A SAML signature wrapping (XSW) attack: a forged assertion placed before the signed one. |

Each sample is checked as at a fixed time, so the verdicts never change. The
full report starts with a `Same as:` line giving the equivalent command with
every flag, which is a quick way to see how the options fit together.

To inspect a file that is actually called `demo`, write `./demo`.

The samples are rebuilt with `python scripts/build_demo_samples.py`.
