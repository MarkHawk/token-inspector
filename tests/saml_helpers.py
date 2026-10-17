from conftest import NOW
from token_inspector.common import Options
from token_inspector.inputs import detect
from token_inspector.keys import load_metadata
from token_inspector.saml_checks import run_saml_checks
from token_inspector.saml_parse import parse_saml
from token_inspector.saml_verify import verify_signatures

EXPECT = dict(
    expect_issuer="https://idp.example.com/realms/example",
    expect_audience="https://sp.example.com/saml/metadata",
    expect_destination="https://sp.example.com/saml/acs",
    expect_recipient="https://sp.example.com/saml/acs",
    expect_in_response_to="_req-4f1c2a9e",
)


def check(samples, name, metadata="idp-metadata.xml", now=NOW, **overrides):
    """Run every SAML check on a sample and return {check_id: Finding}."""
    msg = parse_saml(detect(samples.read(name))[0].payload)
    opts = Options(now=now, now_given=True, **{**EXPECT, **overrides})
    if metadata:
        md = load_metadata(samples.path(metadata))
        opts.trusted_certs, opts.trust_source, opts.metadata_entity_id = md.signing_certs, f"metadata {metadata}", md.entity_id
    findings = run_saml_checks(msg, verify_signatures(msg, opts.trusted_certs), opts)
    return {f.check_id: f for f in findings}
