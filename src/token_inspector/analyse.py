"""Turn a detected token plus options into a Report."""

from token_inspector.findings import Report
from token_inspector.jwt_checks import describe_jwt, run_jwt_checks
from token_inspector.jwt_parse import parse_jwt
from token_inspector.saml_checks import describe_saml, run_saml_checks
from token_inspector.saml_parse import parse_saml
from token_inspector.saml_verify import verify_signatures


def analyse(token, opts):
    report = Report(
        kind=token.kind,
        encoding=token.encoding,
        container=token.container,
        location=token.location,
        now=opts.now,
        skew=opts.skew,
        label="SAML Response" if token.kind == "saml" else "Encrypted JWT (JWE)",
    )
    if token.kind == "saml":
        msg = parse_saml(token.payload)
        sigs = verify_signatures(msg, opts.trusted_certs)
        report.sections = describe_saml(msg, sigs)
        report.findings = run_saml_checks(msg, sigs, opts)
        return report
    token_jwt = parse_jwt(token.payload, token.kind, opts.token_type)
    report.sections = describe_jwt(token_jwt)
    report.findings = run_jwt_checks(token_jwt, opts)
    if token_jwt.token_type:
        report.label = "ID token (JWT)" if token_jwt.token_type == "id" else "access token (JWT)"
    return report
