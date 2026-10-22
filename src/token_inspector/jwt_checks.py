"""JWT and OIDC checks.

The signature is verified directly with PyJWT's algorithm objects so that
signature, algorithm, kid and each claim can be reported separately. A
library call such as jwt.decode() stops at the first problem, which is
what an application should do but not what a support engineer needs.
"""

import datetime as dt
import json

import jwt
from jwt.exceptions import InvalidKeyError, PyJWKError

from token_inspector.common import expiry_finding, match_finding, not_before_finding
from token_inspector.findings import Finding, Status

ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "ES256K", "EdDSA"}
SYMMETRIC = {"HS256", "HS384", "HS512"}
KTY_FOR_ALG = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}

ID_TOKEN_REQUIRED = ["iss", "sub", "aud", "exp", "iat"]  # OIDC Core 1.0, section 2
ACCESS_TOKEN_REQUIRED = ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]  # RFC 9068, section 2.2

TIME_CLAIMS = ("exp", "iat", "nbf", "auth_time", "updated_at")


def _kty(alg):
    return KTY_FOR_ALG.get((alg or "")[:2])


def _time(claims, name):
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return dt.datetime.fromtimestamp(value, dt.UTC)
    except (OverflowError, OSError, ValueError):
        return None


def expected_alg_family(opts):
    """What the RP expects: --expect-alg, else whatever the JWKS keys imply."""
    if opts.expect_alg:
        return {opts.expect_alg}, f"--expect-alg {opts.expect_alg}"
    if opts.jwks:
        algs = {k.get("alg") for k in opts.jwks["keys"] if k.get("alg")}
        if algs:
            return algs, f"the keys in {opts.jwks_source}"
        ktys = {k.get("kty") for k in opts.jwks["keys"]}
        family = {a for a in ASYMMETRIC if _kty(a) in ktys}
        if family:
            return family, f"the key types in {opts.jwks_source}"
    return None, None


def run_jwt_checks(token, opts):
    if token.encrypted:
        return [encrypted_finding(token)]
    findings = [algorithm_finding(token, opts), kid_finding(token, opts), signature_finding(token, opts)]
    findings += time_findings(token, opts)
    findings += claim_findings(token, opts)
    return findings


def encrypted_finding(token):
    h = token.header
    return Finding(
        "jwt.encrypted",
        Status.WARN,
        "Encrypted token",
        f"This is an encrypted JWT (JWE, alg {h.get('alg')}, enc {h.get('enc')}). Its claims can only be read "
        "with the relying party's private key, so nothing else can be checked here.",
        "Check the relying party's own logs after decryption, or ask the IdP admin to turn off ID token "
        "encryption for this client while you troubleshoot.",
        details={"header": h},
    )


# ---------------------------------------------------------------- algorithm, kid, signature


def algorithm_finding(token, opts):
    check_id, title = "jwt.algorithm", "Algorithm"
    alg = token.header.get("alg")
    expected, source = expected_alg_family(opts)
    details = {"alg": alg, "expected": sorted(expected) if expected else None}
    if alg is None or str(alg).lower() == "none":
        return Finding(
            check_id,
            Status.FAIL,
            title,
            "The token is unsigned (alg none). A relying party must never accept it.",
            "Find out where the token came from: a real IdP never issues alg none tokens to a client. If the "
            "relying party accepted it, its JWT library is misconfigured; that is a security issue.",
            details=details,
        )
    if alg not in ASYMMETRIC | SYMMETRIC:
        return Finding(check_id, Status.FAIL, title, f"Unknown or unsupported algorithm {alg!r}.",
                       "Check the IdP's signing algorithm setting for this client.", details=details)
    if expected and alg not in expected:
        if alg in SYMMETRIC and not (expected & SYMMETRIC):
            return Finding(
                check_id,
                Status.FAIL,
                title,
                f"The token uses {alg}, a shared-secret algorithm, but {', '.join(sorted(expected))} was expected "
                f"(from {source}). A library that verified it with the IdP's public key as the secret would "
                "accept a forgery: the classic algorithm confusion attack.",
                "Check the IdP's ID token signature algorithm for this client. The relying party should pin "
                "the algorithms it accepts rather than trust the token's alg header.",
                details=details,
            )
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The token uses {alg}, but {', '.join(sorted(expected))} was expected (from {source}).",
            "Make the IdP's signing algorithm for this client match what the relying party accepts.",
            details=details,
        )
    if alg in SYMMETRIC:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"Uses {alg}, signed with a secret shared between the IdP and the client.",
            "That is allowed for ID tokens signed with the client secret, but anyone with the secret can mint "
            "tokens. Pass --expect-alg if the relying party expects an asymmetric algorithm.",
            details=details,
        )
    note = f" (as expected from {source})" if expected else ""
    return Finding(check_id, Status.PASS, title, f"Uses {alg}{note}.", details=details)


def _jwks_kids(opts):
    return [k.get("kid") for k in opts.jwks["keys"]] if opts.jwks else []


def kid_finding(token, opts):
    check_id, title = "jwt.kid", "Key ID (kid)"
    alg = token.header.get("alg")
    kid = token.header.get("kid")
    if alg is None or str(alg).lower() == "none" or alg in SYMMETRIC:
        return Finding(check_id, Status.SKIP, title, f"Not used with {alg}.")
    if kid is None:
        return Finding(
            check_id,
            Status.WARN,
            title,
            "The header has no kid, so the relying party has to try every key in the JWKS.",
            "Some libraries require a kid and reject the token. Check the IdP includes kid in the header.",
        )
    if not opts.jwks:
        return Finding(check_id, Status.SKIP, title, f"Not checked: kid is {kid!r}. Pass --jwks to check it is published.")
    kids = _jwks_kids(opts)
    if kid in kids:
        return Finding(check_id, Status.PASS, title, f"kid {kid!r} is in {opts.jwks_source}.")
    shown = ", ".join(repr(k) for k in kids) or "no kids"
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"kid {kid!r} is not in {opts.jwks_source}, which has {shown}. The IdP has probably rotated its signing "
        "key and the relying party's cached copy of the JWKS is out of date.",
        "Download the IdP's current JWKS (the jwks_uri in its discovery document) and compare. Then refresh or "
        "restart the relying party's key cache. Check the JWKS is from the right IdP and realm.",
        details={"kid": kid, "jwks_kids": kids},
    )


def _candidate_keys(token, opts):
    alg = token.header.get("alg")
    kid = token.header.get("kid")
    keys = opts.jwks["keys"]
    matching = [k for k in keys if kid is not None and k.get("kid") == kid]
    if matching:
        return matching
    return [k for k in keys if k.get("kty") == _kty(alg) and k.get("use", "sig") == "sig"]


def signature_finding(token, opts):
    check_id, title = "jwt.signature", "Signature"
    alg = token.header.get("alg")
    if alg is None or str(alg).lower() == "none":
        return Finding(check_id, Status.FAIL, title, "There is no signature (alg none).",
                       "See the algorithm result.")
    if alg in SYMMETRIC:
        return Finding(check_id, Status.SKIP, title,
                       f"Not checked: {alg} needs the shared client secret, which this tool does not take.")
    if alg not in ASYMMETRIC:
        return Finding(check_id, Status.SKIP, title, f"Not checked: unsupported algorithm {alg!r}.")
    if not opts.jwks:
        return Finding(check_id, Status.SKIP, title, "Not checked: pass --jwks with the IdP's JWKS file.")
    candidates = _candidate_keys(token, opts)
    if not candidates:
        return Finding(check_id, Status.FAIL, title, f"{opts.jwks_source} has no {_kty(alg)} signing key for {alg}.",
                       "Check the JWKS belongs to this IdP and realm.")
    algorithm = jwt.get_algorithm_by_name(alg)
    for jwk in candidates:
        try:
            key = jwt.PyJWK(jwk, algorithm=alg).key
        except (PyJWKError, InvalidKeyError, ValueError):
            continue
        if algorithm.verify(token.signing_input, key, token.signature):
            return Finding(check_id, Status.PASS, title,
                           f"Valid {alg} signature, verified with key {jwk.get('kid')!r} from {opts.jwks_source}.",
                           details={"kid": jwk.get("kid")})
    if len(candidates) == 1 and candidates[0].get("kid") == token.header.get("kid"):
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The signature does not match key {candidates[0].get('kid')!r}. The header or claims were changed "
            "after signing.",
            "Treat the token as forged or corrupted. A token cut short when it was copied fails in the same way, "
            "so check you have all of it, then check nothing between the IdP and the relying party rewrites it.",
        )
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"The signature does not verify with any of the {len(candidates)} matching keys in {opts.jwks_source}.",
        "If the kid result above failed, the IdP is signing with a key this JWKS does not have. Otherwise "
        "treat the token as forged or corrupted.",
    )


# ---------------------------------------------------------------- time


def time_findings(token, opts):
    c = token.claims
    is_id = token.token_type == "id"
    issued = _time(c, "iat")
    findings = [
        expiry_finding("jwt.time.exp", "Expiry (exp)", _time(c, "exp"), "exp", opts, issued=issued,
                       subject="The token", missing_status=Status.FAIL if is_id else Status.WARN,
                       check_lifetime=True),
        not_before_finding("jwt.time.nbf", "Not before (nbf)", _time(c, "nbf"), "nbf", opts, subject="The token"),
        not_before_finding("jwt.time.iat", "Issued at (iat)", issued, "iat", opts, subject="The token",
                           pass_text="Issued {when}.", missing_text="No iat claim.",
                           future_text="The token says it was issued in the future",
                           within_skew_status=Status.PASS),
    ]
    for name in ("exp", "nbf", "iat"):
        if name in c and _time(c, name) is None:
            findings.append(Finding(
                "jwt.time.format",
                Status.FAIL,
                "Timestamp format",
                f"{name} is {c[name]!r}, but JWT times must be a number of seconds since 1970 (NumericDate).",
                "Check the IdP or any custom claim mapper that sets this claim.",
            ))
    return findings


# ---------------------------------------------------------------- claims


def claim_findings(token, opts):
    c = token.claims
    is_id = token.token_type == "id"
    findings = [
        match_finding(
            "jwt.issuer", "Issuer (iss)", c.get("iss"), opts.expect_issuer, "--expect-issuer", "the issuer",
            "The issuer must match the relying party's configured issuer exactly, including scheme, port, path "
            "and any trailing slash. Check the IdP's public hostname and realm or tenant settings.",
        )
    ]
    expected_aud, source = opts.expect_audience, None
    if expected_aud is None and is_id and opts.client_id:
        expected_aud, source = opts.client_id, "--client-id"
    aud = c.get("aud")
    audience = match_finding(
        "jwt.audience", "Audience (aud)", aud, expected_aud, "--expect-audience", "the audience",
        "The token was issued for a different client or API. Check the client ID the relying party is "
        "configured with, and for access tokens the audience (resource) requested from the IdP.",
        source,
    )
    findings.append(audience)
    findings.append(nonce_finding(token, opts))
    findings.append(azp_finding(token, opts, audience))
    findings.append(required_claims_finding(token, opts))
    return findings


def nonce_finding(token, opts):
    check_id, title = "oidc.nonce", "Nonce"
    if token.token_type != "id":
        return Finding(check_id, Status.SKIP, title, "Not an ID token, so no nonce is expected.")
    nonce = token.claims.get("nonce")
    if opts.nonce is None:
        if nonce is None:
            return Finding(check_id, Status.SKIP, title, "No nonce claim. Pass --nonce if the login request sent one.")
        return Finding(check_id, Status.SKIP, title,
                       f"Not checked: nonce is {nonce!r}. Pass --nonce with the value from the login request.")
    if nonce is None:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            "The ID token has no nonce, but the login request sent one.",
            "Check the relying party really sends nonce in the authorisation request. A token from a refresh "
            "or a different flow has no nonce, so check where this token came from.",
        )
    if nonce == opts.nonce:
        return Finding(check_id, Status.PASS, title, "Matches the nonce sent in the login request.")
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"nonce is {nonce!r}, but the login request sent {opts.nonce!r}. The token belongs to a different "
        "login attempt.",
        "Usually the user started two logins (two tabs, the back button) or the relying party lost the session "
        "where it stored the nonce: a blocked or SameSite cookie, or a load balancer without sticky sessions.",
    )


def azp_finding(token, opts, audience=None):
    check_id, title = "oidc.azp", "Authorised party (azp)"
    if token.token_type != "id":
        return Finding(check_id, Status.SKIP, title, "Not an ID token.")
    azp = token.claims.get("azp")
    aud = token.claims.get("aud")
    aud_values = aud if isinstance(aud, list) else [aud]
    if audience is not None and audience.status == Status.FAIL and azp is not None and azp in aud_values:
        # azp just repeats the wrong audience: one cause, reported once.
        return Finding(check_id, Status.SKIP, title, "Same cause as the Audience failure above.")
    several = isinstance(aud, list) and len(aud) > 1
    if azp is None:
        if several:
            return Finding(
                check_id,
                Status.WARN,
                title,
                f"The token has {len(aud)} audiences but no azp, so it does not say which client it was "
                "issued to.",
                "OIDC expects azp when there are several audiences, and some libraries reject the token "
                "without it. Check the IdP's audience mappers for this client.",
            )
        return Finding(check_id, Status.SKIP, title, "No azp claim (optional with a single audience).")
    if opts.client_id is None:
        return Finding(check_id, Status.SKIP, title, f"Not checked: azp is {azp!r}. Pass --client-id to compare.")
    if azp == opts.client_id:
        return Finding(check_id, Status.PASS, title, f"Matches the client ID {opts.client_id!r}.")
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"azp is {azp!r}, but this client is {opts.client_id!r}. The token was issued to another client.",
        "The relying party may be using a token obtained by a different application. Check which client "
        "started the login and the client ID the relying party is configured with.",
    )


def required_claims_finding(token, opts):
    check_id, title = "oidc.required_claims", "Required claims"
    if token.token_type == "id":
        base, basis = ID_TOKEN_REQUIRED, "an OIDC ID token must contain"
    elif str(token.header.get("typ", "")).lower() in ("at+jwt", "application/at+jwt"):
        base, basis = ACCESS_TOKEN_REQUIRED, "an RFC 9068 access token must contain"
    else:
        base, basis = [], None
    extra = [n for n in opts.required_claims if n not in base]
    required = base + extra
    if not required:
        return Finding(check_id, Status.SKIP, title,
                       "No standard required claims for this token type. Use --require-claim to add some.")
    missing = [name for name in required if name not in token.claims]
    if not missing:
        return Finding(check_id, Status.PASS, title, f"All present: {', '.join(required)}.")
    reasons = []
    std = [n for n in missing if n in base]
    own = [n for n in missing if n not in base]
    if std:
        reasons.append(f"{', '.join(std)}, which {basis}")
    if own:
        reasons.append(f"{', '.join(own)}, which you asked for with --require-claim")
    return Finding(
        check_id,
        Status.FAIL,
        title,
        "Missing " + "; and ".join(reasons) + ".",
        "Check the IdP's claim mappers or scopes for this client. A claim that comes only with a certain "
        "scope is missing when the relying party does not request that scope.",
        details={"missing": missing},
    )


# ---------------------------------------------------------------- decoded view


def _show(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(", ", ": "))
    return value


def describe_jwt(token):
    sections = [("Header", [(k, _show(v)) for k, v in token.header.items()])]
    if token.encrypted:
        return sections
    rows = []
    for name, value in token.claims.items():
        when = _time(token.claims, name) if name in TIME_CLAIMS else None
        rows.append((name, when if when is not None else _show(value)))
    kind = "ID token" if token.token_type == "id" else "access token"
    sections.insert(0, ("Token", [("Type", f"{kind} ({token.type_reason})"),
                                  ("Signature", f"{len(token.signature)} bytes" if token.signature else "none")]))
    sections.append(("Claims", rows))
    return sections
