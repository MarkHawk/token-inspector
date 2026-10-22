"""Group related FAILs into one likely root cause, for known patterns only.

Each check reports one property, which is right for triage but can leave a
reader with five FAILs that all say the same thing. A pattern here recognises
a familiar failure from the findings' details (not their wording), names it in
one sentence and says what to do first. Patterns are tried most specific
first and the first match wins. When nothing matches, there is no likely
cause and the report shows nothing extra.

The timing patterns (a short token lifetime, clock skew, an old capture) only
count when they account for every FAIL: an expired timestamp says nothing
about a broken signature found alongside it, so naming it as the cause would
mislead.

A short-lived token that expired inside the skew allowance is only a WARN, but
it has still expired and a stricter receiver rejects it, so that WARN counts
here as well. It changes only this section, never the verdict.
"""

from dataclasses import dataclass, field

from token_inspector import runbooks
from token_inspector.common import SKEW_SUSPECT_SECONDS
from token_inspector.findings import Status
from token_inspector.timefmt import duration

SIGNATURE_CHECKS = ("saml.signature.response", "saml.signature.assertion", "saml.signature.coverage")
EXPIRY_CHECKS = ("saml.time.not_on_or_after", "jwt.time.exp")
NOT_BEFORE_CHECKS = ("saml.time.not_before", "jwt.time.nbf", "jwt.time.iat")


@dataclass
class Cause:
    pattern: str  # stable id, e.g. "idp-key-rotation"
    label: str  # a few words, for one-line summaries
    summary: str  # the cause in one sentence
    first_step: str  # the first thing to do
    runbook: str = None
    explains: list = field(default_factory=list)  # check_ids of the FAILs this accounts for


def likely_cause(report):
    """The Cause behind the report's FAILs, or None when no known pattern fits."""
    fails = {f.check_id: f for f in report.findings
             if f.status == Status.FAIL or (f.status == Status.WARN and f.details.get("short_lifetime"))}
    if not fails:
        return None
    for pattern in PATTERNS:
        cause = pattern(fails, report)
        if cause and (pattern not in TIMING_PATTERNS or set(cause.explains) == fails.keys()):
            cause.explains = [f.check_id for f in report.findings if f.check_id in cause.explains]
            return cause
    return None


def _xsw(fails, report):
    coverage = fails.get("saml.signature.coverage")
    if not coverage or not ({"signed_ids", "duplicate_ids"} & coverage.details.keys()):
        return None
    return Cause(
        "signature-wrapping",
        "signature wrapping (XSW)",
        "The message has been altered so that a valid signature covers one element while the SP would read a "
        "different, unsigned assertion: an XML Signature Wrapping (XSW) attack.",
        "Treat it as a forgery attempt and escalate it as a security incident; do not change any trust "
        "settings to make it pass.",
        explains=[c for c in SIGNATURE_CHECKS if c in fails],
    )


def _tampered(fails, report):
    tampered = [c for c in (*SIGNATURE_CHECKS, "jwt.signature") if c in fails and fails[c].details.get("tampered")]
    if not tampered:
        return None
    coverage = ["saml.signature.coverage"] if "saml.signature.coverage" in fails else []
    return Cause(
        "tampered-signature",
        "changed after signing",
        "The content no longer matches its signature, so the message was changed after it was signed: edited, "
        "rewritten on the way, or damaged when it was copied.",
        "Check again with the original value (the base64 SAMLResponse or the whole token, not a reformatted or "
        "shortened copy). If that still fails, treat it as a forgery and escalate it as a security incident.",
        explains=[*tampered, *coverage],
    )


def _key_rotation(fails, report):
    trusted = fails.get("saml.cert.trusted_validity")
    if not trusted or not trusted.details.get("signer_differs") or "saml.cert.validity" in fails:
        return None
    return Cause(
        "idp-key-rotation",
        "key rotation, trusted cert expired",
        "The certificate the SP trusts has expired and the IdP has moved on to a new signing key, so the SP no "
        "longer trusts the key that signs its logins.",
        "Give the SP the IdP's current signing certificate, or have it refresh the IdP metadata.",
        runbooks.EXPIRED_SIGNING_CERT,
        [c for c in (*SIGNATURE_CHECKS, "saml.cert.trusted_validity", "saml.cert.metadata_match") if c in fails],
    )


def _signing_cert_expired(fails, report):
    signing = fails.get("saml.cert.validity")
    if not signing or signing.details.get("not_after") is None or report.now < signing.details["not_after"]:
        return None
    return Cause(
        "signing-cert-expired",
        "signing certificate expired",
        "The IdP is still signing with a certificate that has expired, so any SP that checks certificate dates "
        "rejects every login.",
        "Activate a current signing certificate in the IdP, then give it to the SP or have the SP refresh the "
        "IdP metadata.",
        runbooks.EXPIRED_SIGNING_CERT,
        [c for c in ("saml.cert.validity", "saml.cert.trusted_validity") if c in fails],
    )


def _kid_not_in_jwks(fails, report):
    if "jwt.kid" not in fails:
        return None
    return Cause(
        "kid-not-in-jwks",
        "signing key not in JWKS",
        "The token is signed with a key that is not in the JWKS the relying party has, most likely because the "
        "IdP has rotated its keys and the cached JWKS is out of date.",
        "Download the IdP's current JWKS from its jwks_uri, then refresh or restart the relying party's key "
        "cache.",
        explains=[c for c in ("jwt.kid", "jwt.signature") if c in fails],
    )


def _other_client(fails, report):
    explains = [c for c in ("jwt.audience", "oidc.azp") if c in fails]
    if not explains:
        return None
    return Cause(
        "issued-to-another-client",
        "issued to another client",
        "The token was issued to a different client or API than the one checking it, so its aud or azp does not "
        "name this relying party.",
        "Check that the client ID the application logs in with is the one it validates tokens against, and that "
        "the token was not taken from another application.",
        runbooks.API_BEARER_401,
        explains,
    )


def _saml_audience(fails, report):
    aud = fails.get("saml.audience")
    if not aud:
        return None
    actual = aud.details.get("actual")
    shown = ", ".join(repr(v) for v in (actual if isinstance(actual, list) else [actual]) if v is not None)
    return Cause(
        "saml-audience-mismatch",
        "issued for another SP",
        f"The assertion was issued for a different SP ({shown or 'no audience'}), not this one: the SP entity ID "
        "configured for this app at the IdP does not match the SP's own.",
        f"Compare the SP's entity ID ({aud.details.get('expected')!r}) with the Audience URI or Identifier set for "
        "this app at the IdP, and make them match exactly; a changed SP entity ID or settings copied from another "
        "environment are the usual reasons.",
        explains=["saml.audience"],
    )


def _nonce_mismatch(fails, report):
    nonce = fails.get("oidc.nonce")
    if not nonce or nonce.details.get("actual") is None:
        return None
    return Cause(
        "nonce-mismatch",
        "token from another login attempt",
        "The ID token's nonce does not match the one this login sent, so the token belongs to a different login "
        "attempt: the user started two logins, or the relying party lost the nonce it stored.",
        "Ask whether the user had two tabs open or used the back button, then check the relying party keeps its "
        "session between the login request and the callback: a blocked or SameSite cookie, or a load balancer "
        "without sticky sessions, loses it.",
        explains=["oidc.nonce"],
    )


def _gap(finding):
    """Seconds by which a time check missed (positive), or None."""
    d = finding.details
    if "seconds_remaining" in d:
        return -d["seconds_remaining"]
    return d.get("seconds_in_future")


def _short_lifetime(fails, report):
    exp = fails.get("jwt.time.exp")
    if not exp or not exp.details.get("short_lifetime"):
        return None
    return Cause(
        "short-lifetime",
        "token lifetime too short",
        f"The token was issued with a lifetime of only {duration(exp.details['lifetime'])} and expired "
        f"{duration(_gap(exp))} ago, so it runs out before the application has finished using it, which can look "
        "like clock skew.",
        "Check the token lifespan set for this client in the IdP (a value meant as minutes entered as seconds is "
        "a common slip), and that the application refreshes its token before it expires.",
        runbooks.API_BEARER_401,
        ["jwt.time.exp"],
    )


def _clock_skew(fails, report):
    gaps = {c: _gap(fails[c]) for c in (*EXPIRY_CHECKS, *NOT_BEFORE_CHECKS) if c in fails}
    explains = [c for c, gap in gaps.items() if gap is not None and gap <= SKEW_SUSPECT_SECONDS]
    if not explains:
        return None
    worst = max(gaps[c] for c in explains)
    return Cause(
        "clock-skew",
        "clock skew",
        f"The clocks on the IdP and the receiving server most likely disagree: the times are out by "
        f"{duration(worst)}, more than the {report.skew} s allowance.",
        "Compare both servers' clocks with a reliable UTC source and fix NTP; raising the skew allowance only "
        "hides the problem.",
        runbooks.CLOCK_SKEW,
        explains,
    )


def _simply_old(fails, report):
    for check_id in EXPIRY_CHECKS:
        finding = fails.get(check_id)
        late = _gap(finding) if finding else None
        if late is None or late <= SKEW_SUSPECT_SECONDS:
            continue
        noun = "response" if check_id.startswith("saml.") else "token"
        issued = finding.details.get("issued")
        if issued is not None and not report.now_given:
            first = (f"Re-run with --now {issued.strftime('%Y-%m-%dT%H:%M:%SZ')} to check it as at the time it was "
                     "issued, or get a fresh capture of a failing login.")
        else:
            first = "Get a fresh capture of a failing login."
        return Cause(
            f"old-{noun}",
            f"the {noun} is simply old",
            f"The {noun} expired {duration(late)} ago, far longer than clock skew could explain, so this is an "
            "old capture or a replay rather than a live failure.",
            first,
            runbooks.API_BEARER_401 if noun == "token" else None,
            [check_id],
        )
    return None


# Most specific first: a security problem outranks everything, and a cert or
# key problem outranks the age of the capture it was found in.
PATTERNS = [_xsw, _tampered, _key_rotation, _signing_cert_expired, _kid_not_in_jwks, _other_client, _saml_audience,
            _nonce_mismatch, _short_lifetime, _clock_skew, _simply_old]
TIMING_PATTERNS = (_short_lifetime, _clock_skew, _simply_old)
