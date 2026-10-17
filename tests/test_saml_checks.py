"""One test per SAML check, each with a passing and a failing sample."""

import datetime as dt

import pytest

from conftest import NOW
from saml_helpers import check
from token_inspector.findings import Status

PASS, WARN, FAIL, SKIP = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP


def status(samples, name, check_id, **kw):
    return check(samples, name, **kw)[check_id].status


def test_every_saml_sample_meets_its_recorded_expectations(samples):
    for name in samples.names("saml-"):
        meta = samples.meta(name)
        md = next(a for a in meta["args"] if a.startswith("{dir}/idp-metadata")).split("/", 1)[1]
        results = check(samples, name, metadata=md)
        for check_id, expected in meta["expect"].items():
            assert results[check_id].status.value == expected, (name, check_id, results[check_id].summary)


# ---------------------------------------------------------------- status


def test_status(samples):
    assert status(samples, "saml-valid.xml", "saml.status") == PASS
    f = check(samples, "saml-status-responder.xml")["saml.status"]
    assert f.status == FAIL and "could not complete the login" in f.summary


# ---------------------------------------------------------------- signatures


def test_assertion_signature(samples):
    assert status(samples, "saml-valid.xml", "saml.signature.assertion") == PASS
    f = check(samples, "saml-tampered.xml")["saml.signature.assertion"]
    assert f.status == FAIL and "changed after it was signed" in f.summary


def test_response_signature(samples):
    assert status(samples, "saml-signed-response.xml", "saml.signature.response") == PASS
    assert status(samples, "saml-signed-both.xml", "saml.signature.response") == PASS
    f = check(samples, "saml-valid.xml")["saml.signature.response"]
    assert f.status == SKIP and "normal when the Assertion is signed" in f.summary


def test_signature_without_trust_is_a_warning(samples):
    f = check(samples, "saml-valid.xml", metadata=None)["saml.signature.assertion"]
    assert f.status == WARN and "--metadata" in f.next_step


def test_rotated_certificate(samples):
    r = check(samples, "saml-rotated-cert.xml")
    assert r["saml.signature.assertion"].status == FAIL
    assert "rotated" in r["saml.signature.assertion"].summary
    assert r["saml.signature.assertion"].runbook == "01-expired-signing-cert"
    assert r["saml.cert.metadata_match"].status == FAIL


def test_coverage(samples):
    assert status(samples, "saml-valid.xml", "saml.signature.coverage") == PASS
    r = check(samples, "saml-unsigned.xml")
    assert r["saml.signature.coverage"].status == FAIL and "Neither" in r["saml.signature.coverage"].summary
    assert r["saml.signature.assertion"].status == FAIL
    assert "Turn on assertion signing" in r["saml.signature.assertion"].next_step


def test_ids_are_shortened_in_sentences_but_kept_in_details(samples):
    r = check(samples, "saml-xsw.xml")
    f = r["saml.signature.coverage"]
    full = f.details["read_assertion_id"]
    assert len(full) > 9 and full not in f.summary and full[:9] + "\u2026" in f.summary
    p = check(samples, "saml-valid.xml")["saml.signature.coverage"]
    assert p.details["assertion_id"][:9] + "\u2026" in p.summary
    assert full.startswith("_")


def test_xml_signature_wrapping_is_detected(samples):
    r = check(samples, "saml-xsw.xml")
    f = r["saml.signature.coverage"]
    assert f.status == FAIL and "XML Signature Wrapping" in f.summary and "admin@example.com" in f.summary
    a = r["saml.signature.assertion"]
    assert a.status == FAIL and a.summary == "The assertion an SP would read is not signed."
    assert "Signature coverage" in a.next_step
    assert r["saml.signature.response"].status == SKIP


def test_algorithm(samples):
    assert status(samples, "saml-valid.xml", "saml.signature.algorithm") == PASS
    f = check(samples, "saml-sha1.xml")["saml.signature.algorithm"]
    assert f.status == WARN and "SHA-1" in f.summary
    assert status(samples, "saml-unsigned.xml", "saml.signature.algorithm") == SKIP


# ---------------------------------------------------------------- certificates


def test_cert_validity(samples):
    assert status(samples, "saml-valid.xml", "saml.cert.validity") == PASS
    f = check(samples, "saml-expired-cert.xml", metadata="idp-metadata-expired.xml")["saml.cert.validity"]
    assert f.status == FAIL and "expired" in f.summary and f.runbook == "01-expired-signing-cert"
    f = check(samples, "saml-future-cert.xml", metadata="idp-metadata-future.xml")["saml.cert.validity"]
    assert f.status == FAIL and "not valid until" in f.summary


def test_cert_expiring_soon_is_a_warning(samples):
    soon = NOW + dt.timedelta(days=320)  # the current cert has 335 days left at NOW
    f = check(samples, "saml-valid.xml", now=soon)["saml.cert.validity"]
    assert f.status == WARN and "expires" in f.summary


def test_cert_matches_metadata(samples):
    assert status(samples, "saml-valid.xml", "saml.cert.metadata_match") == PASS
    assert status(samples, "saml-rotated-cert.xml", "saml.cert.metadata_match") == FAIL
    assert status(samples, "saml-valid.xml", "saml.cert.metadata_match", metadata=None) == SKIP


# ---------------------------------------------------------------- timing


def test_not_on_or_after(samples):
    assert status(samples, "saml-valid.xml", "saml.time.not_on_or_after") == PASS
    f = check(samples, "saml-expired-assertion.xml")["saml.time.not_on_or_after"]
    assert f.status == FAIL and "not a clock problem" in f.summary and f.runbook is None


def test_recent_expiry_looks_like_clock_skew(samples):
    f = check(samples, "saml-skew-expired.xml")["saml.time.not_on_or_after"]
    assert f.status == FAIL and "clock skew" in f.summary and f.runbook == "02-clock-skew"


def test_not_before(samples):
    assert status(samples, "saml-valid.xml", "saml.time.not_before") == PASS
    f = check(samples, "saml-skew-future.xml")["saml.time.not_before"]
    assert f.status == FAIL and "looks like clock skew" in f.summary and f.runbook == "02-clock-skew"


def test_not_before_inside_skew_allowance_warns(samples):
    assert status(samples, "saml-skew-within.xml", "saml.time.not_before") == WARN
    assert status(samples, "saml-skew-within.xml", "saml.time.not_before", skew=10) == FAIL


def test_skew_option_widens_the_window(samples):
    assert status(samples, "saml-skew-future.xml", "saml.time.not_before", skew=300) == WARN


def test_whole_hour_gap_suggests_a_timezone_bug(samples):
    earlier = NOW - dt.timedelta(hours=1)
    f = check(samples, "saml-valid.xml", now=earlier)["saml.time.not_before"]
    assert f.status == FAIL and "timezone" in f.summary


# ---------------------------------------------------------------- values


@pytest.mark.parametrize(
    "check_id,sample,hint",
    [
        ("saml.audience", "saml-wrong-audience.xml", None),
        ("saml.destination", "saml-wrong-destination.xml", "https://"),
        ("saml.recipient", "saml-wrong-destination.xml", "https://"),
        ("saml.issuer", "saml-wrong-issuer.xml", "different path"),
        ("saml.in_response_to", "saml-wrong-in-response-to.xml", "two logins"),
    ],
)
def test_value_checks(samples, check_id, sample, hint):
    assert status(samples, "saml-valid.xml", check_id) == PASS
    f = check(samples, sample)[check_id]
    assert f.status == FAIL
    if hint:
        assert hint in f.summary + (f.next_step or "")


@pytest.mark.parametrize(
    "check_id,option",
    [
        ("saml.audience", "expect_audience"),
        ("saml.in_response_to", "expect_in_response_to"),
    ],
)
def test_value_checks_skip_without_expected_value(samples, check_id, option):
    f = check(samples, "saml-valid.xml", **{option: None})[check_id]
    assert f.status == SKIP and "Not checked" in f.summary


def test_issuer_falls_back_to_metadata_entity_id(samples):
    f = check(samples, "saml-wrong-issuer.xml", expect_issuer=None)["saml.issuer"]
    assert f.status == FAIL and "metadata entityID" in f.summary
    assert status(samples, "saml-valid.xml", "saml.issuer", expect_issuer=None, metadata=None) == SKIP


def test_destination_falls_back_to_recipient(samples):
    f = check(samples, "saml-valid.xml", expect_destination=None)["saml.destination"]
    assert f.status == PASS and "--expect-recipient" in f.summary
