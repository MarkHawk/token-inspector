"""Logic shared by the SAML and JWT checks: time windows and value matching.

Both protocols fail in the same human ways (clocks that disagree, a URL
that differs by a trailing slash), so the wording lives in one place.
"""

import urllib.parse
from dataclasses import dataclass, field

from token_inspector import runbooks
from token_inspector.findings import Finding, Status
from token_inspector.timefmt import duration, near_whole_hours, utc, utc_relative

# Beyond the configured skew allowance, a gap this small is still most likely
# two clocks disagreeing rather than a genuinely old or future token.
SKEW_SUSPECT_SECONDS = 15 * 60


@dataclass
class Options:
    now: object
    skew: int = 60
    expect_issuer: str = None
    expect_audience: str = None
    expect_destination: str = None
    expect_recipient: str = None
    expect_in_response_to: str = None
    expect_alg: str = None
    nonce: str = None
    client_id: str = None
    required_claims: list = field(default_factory=list)
    trusted_certs: list = field(default_factory=list)
    trust_source: str = None  # e.g. "metadata idp-metadata.xml"
    metadata_entity_id: str = None
    jwks: dict = None
    jwks_source: str = None
    now_given: bool = False
    token_type: str = None


def mismatch_hint(actual, expected):
    """Explain how two identifiers differ, in the ways that matter in tickets."""
    if actual is None or expected is None:
        return None
    if actual.lower() == expected.lower():
        return "they differ only in upper/lower case; these values are compared exactly"
    if actual.rstrip("/") == expected.rstrip("/"):
        return "they differ only by a trailing slash"
    a, e = urllib.parse.urlsplit(actual), urllib.parse.urlsplit(expected)
    if a.scheme and e.scheme and a.netloc and e.netloc:
        if a.scheme != e.scheme and (a.netloc, a.path) == (e.netloc, e.path):
            return f"one uses {a.scheme}:// and the other {e.scheme}://"
        if a.hostname == e.hostname and a.port != e.port:
            return "same host but a different port"
        if a.netloc != e.netloc and a.path == e.path:
            return "same path but a different host name"
        if a.netloc == e.netloc and a.path != e.path:
            return "same host but a different path"
    return None


def match_finding(check_id, title, actual, expected, expected_flag, what, next_step, source=None):
    """PASS/FAIL/SKIP for 'value X should equal what the other side expects'.

    actual may be a single value or a list (for example several audiences)."""
    if expected is None:
        return Finding(
            check_id,
            Status.SKIP,
            title,
            f"Not checked: pass {expected_flag} to compare {what}.",
            details={"actual": actual},
        )
    values = actual if isinstance(actual, list) else [actual]
    values = [v for v in values if v is not None]
    from_note = f" (expected value from {source})" if source else ""
    if not values:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"No {what} is present, but {expected!r} was expected{from_note}.",
            next_step,
            details={"actual": None, "expected": expected},
        )
    if expected in values:
        return Finding(check_id, Status.PASS, title, f"Matches {expected!r}{from_note}.",
                       details={"actual": actual, "expected": expected})
    shown = ", ".join(repr(v) for v in values)
    hints = [h for h in (mismatch_hint(v, expected) for v in values) if h]
    hint = f" Note: {hints[0]}." if hints else ""
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"{what[0].upper() + what[1:]} is {shown}, but {expected!r} was expected{from_note}.{hint}",
        next_step,
        details={"actual": actual, "expected": expected},
    )


def not_before_finding(check_id, title, when, attr, opts, subject="It", pass_text=None, missing_text=None,
                       future_text=None):
    """Check a 'not valid before' time (SAML NotBefore, JWT nbf or iat)."""
    if when is None:
        return Finding(check_id, Status.SKIP, title, missing_text or f"No {attr} is set (it is optional).")
    ahead = (when - opts.now).total_seconds()
    details = {"value": when, "seconds_in_future": max(ahead, 0)}
    if ahead <= 0:
        text = pass_text or f"{attr} {utc_relative(when, opts.now)} has passed."
        return Finding(check_id, Status.PASS, title, text.format(when=utc_relative(when, opts.now)), details=details)
    if ahead <= opts.skew:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"{attr} is {duration(ahead)} in the future, inside the {opts.skew} s skew allowance. "
            "The issuer's clock is slightly ahead of this one.",
            "Nothing to fix yet, but check both clocks use NTP: a slightly larger gap will start failing logins.",
            runbooks.CLOCK_SKEW,
            details,
        )
    if near_whole_hours(ahead):
        cause = (
            f"A gap of almost exactly {round(ahead / 3600)} h usually means a timezone bug: "
            "a local time written as if it were UTC."
        )
    elif ahead <= SKEW_SUSPECT_SECONDS:
        cause = "This looks like clock skew: the issuer's clock is ahead of this machine's clock."
    else:
        cause = "That is far ahead: check the issuer's clock and its timezone settings."
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"{future_text or subject + ' is not valid yet'}: {attr} is {utc(when)}, {duration(ahead)} from now. {cause}",
        "Compare the clocks on the IdP and the receiving server with a reliable UTC source and fix NTP. "
        "Raising the skew allowance only hides the problem.",
        runbooks.CLOCK_SKEW,
        details,
    )


def expiry_finding(check_id, title, when, attr, opts, issued=None, subject="It", missing_status=Status.WARN):
    """Check an expiry time (SAML NotOnOrAfter, JWT exp)."""
    if when is None:
        return Finding(
            check_id,
            missing_status,
            title,
            f"No {attr} is set, so {subject.lower()} never expires.",
            "Most receivers reject a token or assertion without an expiry. Check the IdP's lifetime settings.",
        )
    left = (when - opts.now).total_seconds()
    details = {"value": when, "seconds_remaining": left}
    if left > 0:
        return Finding(check_id, Status.PASS, title, f"Valid for another {duration(left)} ({attr} {utc(when)}).",
                       details=details)
    late = -left
    if late < opts.skew:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"Expired {duration(late)} ago, but that is inside the {opts.skew} s skew allowance.",
            "A receiver with a stricter allowance will reject it. Check both clocks use NTP.",
            runbooks.CLOCK_SKEW,
            details,
        )
    replay_hint = ""
    if issued is not None and not opts.now_given:
        replay_hint = f" To check it as at the time it was issued, add --now {issued.strftime('%Y-%m-%dT%H:%M:%SZ')}."
    if late <= SKEW_SUSPECT_SECONDS:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"Expired {duration(late)} ago ({attr} {utc(when)}). If the user had only just signed in, "
            "this looks like clock skew: the receiving server's clock is ahead of the issuer's.",
            "Compare the receiving server's clock with UTC. If the clocks agree, the user took too long or "
            "resubmitted an old page (back button, a tab left open)." + replay_hint,
            runbooks.CLOCK_SKEW,
            details,
        )
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"Expired {duration(late)} ago ({attr} {utc(when)}). This is an old one, not a clock problem.",
        "It was probably replayed from browser history or taken from an old capture. "
        "Get a fresh capture of a failing login." + replay_hint,
        details=details,
    )
