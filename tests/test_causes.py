"""The Likely cause section groups related FAILs into one root cause, for
known patterns only, and stays silent otherwise."""

import io
import json

import pytest

from conftest import NOW_ISO, ROOT
from token_inspector.cli import main

LAB = ROOT / "samples" / "lab" / "expired-signing-cert"
LAB_ISSUED = "2026-10-17T13:34:20Z"


def run(*argv):
    out = io.StringIO()
    main([*argv], stdout=out, stderr=io.StringIO())
    return out.getvalue()


def sample(samples, name, *extra, now=NOW_ISO):
    return run(str(samples.path(name)), *samples.args(name), "--now", now, *extra)


def cause(samples, name, *extra, **kw):
    return json.loads(sample(samples, name, "--json", *extra, **kw))["likely_cause"]


@pytest.mark.parametrize("name,pattern,explains", [
    ("saml-xsw.xml", "signature-wrapping", ["saml.signature.assertion", "saml.signature.coverage"]),
    ("saml-expired-cert.xml", "signing-cert-expired", ["saml.cert.validity", "saml.cert.trusted_validity"]),
    ("jwt-expired.txt", "old-token", ["jwt.time.exp"]),
    ("saml-expired-assertion.xml", "old-response", ["saml.time.not_on_or_after"]),
    ("saml-skew-expired.xml", "clock-skew", ["saml.time.not_on_or_after"]),
    ("saml-skew-future.xml", "clock-skew", ["saml.time.not_before"]),
    ("jwt-nbf-future.txt", "clock-skew", ["jwt.time.nbf"]),
    ("jwt-iat-future.txt", "clock-skew", ["jwt.time.iat"]),
    ("jwt-wrong-audience.txt", "issued-to-another-client", ["jwt.audience"]),
    ("oidc-azp-mismatch.txt", "issued-to-another-client", ["oidc.azp"]),
    ("jwt-unknown-kid.txt", "kid-not-in-jwks", ["jwt.kid", "jwt.signature"]),
    ("jwt-short-lifetime.txt", "short-lifetime", ["jwt.time.exp"]),
    ("saml-tampered.xml", "tampered-signature", ["saml.signature.assertion", "saml.signature.coverage"]),
    ("jwt-tampered.txt", "tampered-signature", ["jwt.signature"]),
])
def test_known_patterns(samples, name, pattern, explains):
    c = cause(samples, name)
    assert (c["pattern"], c["explains"], c["not_explained"]) == (pattern, explains, [])
    assert c["summary"].endswith(".") and c["first_step"].endswith(".")


@pytest.mark.parametrize("name,runbook", [
    ("saml-expired-cert.xml", "01-expired-signing-cert"),
    ("saml-skew-future.xml", "02-clock-skew"),
    ("jwt-wrong-audience.txt", "16-api-bearer-401"),
    ("oidc-azp-mismatch.txt", "16-api-bearer-401"),
    ("jwt-expired.txt", "16-api-bearer-401"),
    ("jwt-short-lifetime.txt", "16-api-bearer-401"),
    ("saml-expired-assertion.xml", None),
    ("saml-xsw.xml", None),
])
def test_runbook_link_where_one_exists(samples, name, runbook):
    c = cause(samples, name)
    assert c["runbook"] == runbook
    assert (c["runbook_url"] or "").endswith(f"{runbook}.md" if runbook else "")


@pytest.mark.parametrize("name", [
    "saml-unsigned.xml", "saml-rotated-cert.xml", "saml-wrong-audience.xml",
    "saml-status-responder.xml", "jwt-hs256.txt", "oidc-wrong-nonce.txt",
])
def test_no_pattern_means_nothing_extra(samples, name):
    assert cause(samples, name) is None
    assert "Likely cause" not in sample(samples, name)


def test_valid_has_no_cause(samples):
    assert cause(samples, "saml-valid.xml") is None


def test_an_old_capture_does_not_hide_a_real_problem(samples):
    """Hours later, a tampered response is also expired, but its age is not why it fails."""
    c = cause(samples, "saml-tampered.xml", now="2026-03-02T18:00:00Z")
    assert c["pattern"] == "tampered-signature" and c["not_explained"] == ["saml.time.not_on_or_after"]


def test_a_specific_cause_still_wins_on_an_old_capture(samples):
    c = cause(samples, "saml-xsw.xml", now="2026-03-02T18:00:00Z")
    assert c["pattern"] == "signature-wrapping" and c["not_explained"] == ["saml.time.not_on_or_after"]


def test_old_capture_suggests_now_only_when_not_given(samples):
    late = cause(samples, "saml-valid.xml", now="2026-03-02T18:00:00Z")
    assert late["pattern"] == "old-response" and "--now" not in late["first_step"]
    no_now = json.loads(run(str(samples.path("jwt-expired.txt")), *samples.args("jwt-expired.txt"), "--json"))
    no_now = no_now["likely_cause"]
    assert no_now["pattern"] == "old-token" and "Re-run with --now " in no_now["first_step"]


def test_short_lifetime_named_on_a_warn_without_changing_the_verdict(samples):
    """At the default 60 s skew, 5 s past exp is a WARN; the cause shows but the verdict and exit code do not move."""
    out = io.StringIO()
    code = main([str(samples.path("jwt-short-lifetime.txt")), *samples.args("jwt-short-lifetime.txt"), "--now", NOW_ISO],
                stdout=out, stderr=io.StringIO())
    text = out.getvalue()
    assert code == 0
    assert "WARN  Expiry (exp)" in text and "lifetime of only 10 s" in text
    section = text.split("== Likely cause ==")[1]
    assert "lifetime of only 10 s" in section and "16-api-bearer-401" in section
    assert "Not explained" not in section
    assert section.splitlines()[-1].startswith("Verdict: no failures, 1 warning")


def test_short_lifetime_beats_clock_skew_with_no_allowance(samples):
    c = cause(samples, "jwt-short-lifetime.txt", "--skew", "0")
    assert c["pattern"] == "short-lifetime" and c["runbook"] == "16-api-bearer-401"
    text = sample(samples, "jwt-short-lifetime.txt", "--skew", "0")
    assert "FAIL  Expiry (exp)" in text and "02-clock-skew" not in text


def test_short_lifetime_long_expired_is_simply_old(samples):
    assert cause(samples, "jwt-short-lifetime.txt", now="2026-03-02T15:00:00Z")["pattern"] == "old-token"


def test_normal_lifetime_recently_expired_is_still_clock_skew(samples):
    """jwt-valid.txt lives 5 min, above the threshold, so a recent expiry is still put down to the clocks."""
    assert cause(samples, "jwt-valid.txt", now="2026-03-02T12:10:00Z")["pattern"] == "clock-skew"


def test_short_lifetime_does_not_hide_a_real_problem(samples):
    """A wrong issuer fits no pattern, so the short lifetime must not be named as the cause of it."""
    assert cause(samples, "jwt-short-lifetime.txt", "--expect-issuer", "https://elsewhere.example.com") is None


def lab(*extra):
    return run(str(LAB / "saml-response.xml"), "--cert", str(LAB / "sp-pinned-cert.pem"), *extra)


def test_lab_rotation_capture():
    c = json.loads(lab("--now", LAB_ISSUED, "--json"))["likely_cause"]
    assert c["pattern"] == "idp-key-rotation"
    assert c["runbook"] == "01-expired-signing-cert"
    assert c["explains"] == ["saml.signature.response", "saml.signature.assertion", "saml.signature.coverage",
                             "saml.cert.trusted_validity", "saml.cert.metadata_match"]
    assert c["not_explained"] == []


def test_lab_rotation_capture_without_now_names_the_leftover():
    text = lab()
    section = text.split("== Likely cause ==")[1].split("Verdict:")[0]
    assert "Not explained:  Not on or after" in section


def test_section_sits_just_above_the_verdict_and_checks_are_unchanged():
    text = lab("--now", LAB_ISSUED)
    head, section = text.split("\n== Likely cause ==\n")
    assert section.splitlines()[-1].startswith("Verdict: ")
    assert head.rstrip().endswith("log to compare.")  # the last check line, as before
    assert "  First:" in section and "  Runbook:" in section and "  Explains:" in section
    assert "https://github.com/MarkHawk/identity-lab/blob/main/runbooks/01-expired-signing-cert.md" in section
    assert max(len(line) for line in section.splitlines()) <= 100


def test_redacted_report_keeps_the_cause():
    assert "== Likely cause ==" in lab("--now", LAB_ISSUED, "--redact")
