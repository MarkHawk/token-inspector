"""One test per JWT/OIDC check, each with a passing and a failing sample."""

import json

import pytest

from conftest import NOW
from token_inspector.common import Options
from token_inspector.findings import Status
from token_inspector.inputs import detect
from token_inspector.jwt_checks import run_jwt_checks
from token_inspector.jwt_parse import JwtParseError, guess_type, parse_jwt
from token_inspector.keys import load_jwks

PASS, WARN, FAIL, SKIP = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP

EXPECT = dict(
    expect_issuer="https://idp.example.com/realms/example",
    expect_audience="example-rp",
    client_id="example-rp",
    nonce="n-0S6_WzA2Mj",
    expect_alg="RS256",
)


def check(samples, name, jwks=True, token_type=None, **overrides):
    token = detect(samples.read(name))[0]
    opts = Options(now=NOW, now_given=True, token_type=token_type, **{**EXPECT, **overrides})
    if jwks:
        opts.jwks, opts.jwks_source = load_jwks(samples.path("jwks.json")), "JWKS jwks.json"
    parsed = parse_jwt(token.payload, token.kind, token_type)
    return {f.check_id: f for f in run_jwt_checks(parsed, opts)}


def status(samples, name, check_id, **kw):
    return check(samples, name, **kw)[check_id].status


def test_every_jwt_sample_meets_its_recorded_expectations(samples):
    names = samples.names("jwt-") + samples.names("oidc-")
    assert len(names) >= 19
    for name in names:
        args = samples.meta(name)["args"]
        opts = {}
        flags = {"--expect-issuer": "expect_issuer", "--expect-audience": "expect_audience",
                 "--client-id": "client_id", "--nonce": "nonce", "--expect-alg": "expect_alg"}
        for flag, field in flags.items():
            opts[field] = args[args.index(flag) + 1] if flag in args else None
        results = check(samples, name, **opts)
        for check_id, expected in samples.meta(name)["expect"].items():
            assert results[check_id].status.value == expected, (name, check_id, results[check_id].summary)


# ---------------------------------------------------------------- parsing


def test_parse_and_guess_type(samples):
    t = parse_jwt(samples.read("jwt-valid.txt").decode().strip())
    assert t.header["kid"] == "k-2026-04" and t.claims["sub"] and t.token_type == "id"
    a = parse_jwt(samples.read("jwt-access-token.txt").decode().strip())
    assert a.token_type == "access" and "at+jwt" in a.type_reason
    assert guess_type({}, {"scope": "openid"})[0] == "access"
    assert parse_jwt(samples.read("jwt-access-token.txt").decode().strip(), token_type="id").token_type == "id"


def test_parse_rejects_non_json_payload():
    with pytest.raises(JwtParseError, match="not valid JSON"):
        parse_jwt("eyJhbGciOiJSUzI1NiJ9.bm90IGpzb24.c2ln")


# ---------------------------------------------------------------- algorithm, kid, signature


def test_algorithm(samples):
    assert status(samples, "jwt-valid.txt", "jwt.algorithm") == PASS
    f = check(samples, "jwt-alg-none.txt")["jwt.algorithm"]
    assert f.status == FAIL and "alg none" in f.summary
    f = check(samples, "jwt-hs256.txt")["jwt.algorithm"]
    assert f.status == FAIL and "algorithm confusion" in f.summary


def test_algorithm_expectation_inferred_from_jwks(samples):
    f = check(samples, "jwt-hs256.txt", expect_alg=None)["jwt.algorithm"]
    assert f.status == FAIL and "keys in JWKS jwks.json" in f.summary
    assert status(samples, "jwt-hs256.txt", "jwt.algorithm", expect_alg=None, jwks=False) == WARN


def test_kid(samples):
    assert status(samples, "jwt-valid.txt", "jwt.kid") == PASS
    assert status(samples, "jwt-no-kid.txt", "jwt.kid") == WARN
    f = check(samples, "jwt-unknown-kid.txt")["jwt.kid"]
    assert f.status == FAIL and "rotated" in f.summary and "k-2026-04" in f.summary
    assert status(samples, "jwt-valid.txt", "jwt.kid", jwks=False) == SKIP


def test_signature(samples):
    f = check(samples, "jwt-valid.txt")["jwt.signature"]
    assert f.status == PASS and "k-2026-04" in f.summary
    f = check(samples, "jwt-tampered.txt")["jwt.signature"]
    assert f.status == FAIL and "changed after signing" in f.summary
    assert status(samples, "jwt-unknown-kid.txt", "jwt.signature") == FAIL
    assert status(samples, "jwt-no-kid.txt", "jwt.signature") == PASS  # found by trying each RSA key
    assert status(samples, "jwt-valid.txt", "jwt.signature", jwks=False) == SKIP
    assert status(samples, "jwt-hs256.txt", "jwt.signature") == SKIP


# ---------------------------------------------------------------- time


def test_exp(samples):
    assert status(samples, "jwt-valid.txt", "jwt.time.exp") == PASS
    f = check(samples, "jwt-expired.txt")["jwt.time.exp"]
    assert f.status == FAIL and "3 h ago" in f.summary and "not a clock problem" in f.summary


def test_nbf(samples):
    assert status(samples, "jwt-valid.txt", "jwt.time.nbf") == SKIP  # optional, absent
    f = check(samples, "jwt-nbf-future.txt")["jwt.time.nbf"]
    assert f.status == FAIL and "clock skew" in f.summary and f.runbook == "02-clock-skew"


def test_iat(samples):
    assert status(samples, "jwt-valid.txt", "jwt.time.iat") == PASS
    f = check(samples, "jwt-iat-future.txt")["jwt.time.iat"]
    assert f.status == FAIL and f.summary.startswith("The token says it was issued in the future")


def test_skew_option_applies_to_jwt(samples):
    token = detect(samples.read("jwt-nbf-future.txt"))[0]
    opts = Options(now=NOW, skew=300, **EXPECT)
    findings = {f.check_id: f for f in run_jwt_checks(parse_jwt(token.payload), opts)}
    assert findings["jwt.time.nbf"].status == WARN


# ---------------------------------------------------------------- claims


def test_issuer(samples):
    assert status(samples, "jwt-valid.txt", "jwt.issuer") == PASS
    f = check(samples, "jwt-wrong-issuer.txt")["jwt.issuer"]
    assert f.status == FAIL and "different port" in f.summary


def test_audience(samples):
    assert status(samples, "jwt-valid.txt", "jwt.audience") == PASS
    f = check(samples, "jwt-wrong-audience.txt")["jwt.audience"]
    assert f.status == FAIL and "'other-app'" in f.summary
    assert status(samples, "oidc-multi-aud-no-azp.txt", "jwt.audience") == PASS  # list containing the client


def test_audience_falls_back_to_client_id(samples):
    f = check(samples, "jwt-wrong-audience.txt", expect_audience=None)["jwt.audience"]
    assert f.status == FAIL and "--client-id" in f.summary


def test_nonce(samples):
    assert status(samples, "jwt-valid.txt", "oidc.nonce") == PASS
    assert status(samples, "oidc-missing-nonce.txt", "oidc.nonce") == FAIL
    f = check(samples, "oidc-wrong-nonce.txt")["oidc.nonce"]
    assert f.status == FAIL and "different login attempt" in f.summary
    assert status(samples, "jwt-valid.txt", "oidc.nonce", nonce=None) == SKIP
    assert status(samples, "jwt-access-token.txt", "oidc.nonce") == SKIP


def test_azp(samples):
    assert status(samples, "jwt-valid.txt", "oidc.azp") == PASS
    assert status(samples, "oidc-multi-aud-no-azp.txt", "oidc.azp") == WARN
    f = check(samples, "oidc-azp-mismatch.txt")["oidc.azp"]
    assert f.status == FAIL and "another client" in f.summary


def test_required_claims(samples):
    assert status(samples, "jwt-valid.txt", "oidc.required_claims") == PASS
    f = check(samples, "oidc-missing-claims.txt")["oidc.required_claims"]
    assert f.status == FAIL and f.summary == "Missing sub, which an OIDC ID token must contain."
    f = check(samples, "jwt-valid.txt", required_claims=["groups"])["oidc.required_claims"]
    assert f.status == FAIL and "groups, which you asked for with --require-claim" in f.summary
    assert status(samples, "jwt-access-token.txt", "oidc.required_claims") == PASS  # RFC 9068 set


def test_encrypted_token(samples):
    results = check(samples, "jwt-encrypted.txt")
    assert list(results) == ["jwt.encrypted"]
    assert results["jwt.encrypted"].status == WARN and "RSA-OAEP-256" in results["jwt.encrypted"].summary


def test_time_claim_with_wrong_type(samples):
    token = parse_jwt(samples.read("jwt-valid.txt").decode().strip())
    token.claims["exp"] = "2026-03-02"
    findings = {f.check_id: f for f in run_jwt_checks(token, Options(now=NOW))}
    assert findings["jwt.time.format"].status == FAIL
    assert findings["jwt.time.exp"].status == FAIL  # treated as missing on an ID token


def test_jwks_is_never_fetched(samples, monkeypatch):
    """Even a token whose header points at a remote key set stays offline."""
    import base64

    token = samples.read("jwt-valid.txt").decode().strip()
    head = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    head["jku"] = "https://attacker.example.com/jwks.json"
    forged = base64.urlsafe_b64encode(json.dumps(head).encode()).rstrip(b"=").decode()
    parsed = parse_jwt(".".join([forged] + token.split(".")[1:]))
    findings = {f.check_id: f for f in run_jwt_checks(parsed, Options(now=NOW, **EXPECT))}
    assert findings["jwt.signature"].status == SKIP  # no --jwks: nothing fetched, nothing verified
