"""Turn a detected token plus options into a Report."""

from token_inspector.findings import Report
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
    )
    if token.kind == "saml":
        msg = parse_saml(token.payload)
        sigs = verify_signatures(msg, opts.trusted_certs)
        report.sections = describe_saml(msg, sigs)
        report.findings = run_saml_checks(msg, sigs, opts)
        return report
    raise NotImplementedError("JWT checks are not implemented yet")
