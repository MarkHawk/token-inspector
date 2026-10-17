"""Command-line entry point."""

import argparse
import datetime as dt
import os
import sys

from token_inspector import __version__
from token_inspector.analyse import analyse
from token_inspector.common import Options
from token_inspector.inputs import InputError, detect, read_input
from token_inspector.keys import KeyFileError, load_certs, load_jwks, load_metadata
from token_inspector.render import render_text, use_colour
from token_inspector.saml_parse import SamlParseError
from token_inspector.xmlsafe import XMLRejected

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def build_parser():
    p = argparse.ArgumentParser(
        prog="token-inspector",
        description="Decode a SAML response or a JWT and explain what is wrong with it. Fully offline.",
        epilog="Exit status: 0 no failed checks, 1 at least one FAIL, 2 the input or a key file could not be used.",
    )
    p.add_argument("file", nargs="?", help="file to read; '-' or omit for stdin")
    p.add_argument("--token", help="the token or SAMLResponse value itself, instead of a file")
    p.add_argument("--pick", type=int, default=1, metavar="N", help="which token to inspect when the input holds several")

    trust = p.add_argument_group("trust material (local files only)")
    trust.add_argument("--cert", action="append", default=[], metavar="FILE", help="IdP signing certificate (PEM or DER); repeatable")
    trust.add_argument("--metadata", metavar="FILE", help="IdP SAML metadata XML")
    trust.add_argument("--jwks", metavar="FILE", help="JWKS JSON file")

    exp = p.add_argument_group("expected values")
    exp.add_argument("--expect-issuer", metavar="VALUE")
    exp.add_argument("--expect-audience", metavar="VALUE", help="SP entity ID (SAML) or client ID / API audience (JWT)")
    exp.add_argument("--expect-destination", metavar="URL", help="SP ACS URL (SAML Response Destination)")
    exp.add_argument("--expect-recipient", metavar="URL", help="SP ACS URL (SubjectConfirmationData Recipient)")
    exp.add_argument("--expect-in-response-to", metavar="ID", help="the SP's AuthnRequest ID")
    exp.add_argument("--expect-alg", metavar="ALG", help="expected JWT algorithm, for example RS256")
    exp.add_argument("--nonce", help="nonce sent in the OIDC authentication request")
    exp.add_argument("--client-id", help="OIDC client ID (for azp)")
    exp.add_argument("--require-claim", action="append", default=[], metavar="NAME", help="claim that must be present; repeatable")

    t = p.add_argument_group("time")
    t.add_argument("--skew", type=int, default=60, metavar="SECONDS", help="clock skew allowance (default 60)")
    t.add_argument("--now", metavar="ISO8601", help="evaluate as at this UTC time, for example the time of the ticket")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def parse_now(value):
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InputError(f"--now {value!r} is not an ISO 8601 time such as 2026-03-02T12:00:00Z") from None
    return (t if t.tzinfo else t.replace(tzinfo=dt.UTC)).astimezone(dt.UTC)


def build_options(args):
    opts = Options(
        now=parse_now(args.now) if args.now else dt.datetime.now(dt.UTC).replace(microsecond=0),
        now_given=bool(args.now),
        skew=args.skew,
        expect_issuer=args.expect_issuer,
        expect_audience=args.expect_audience,
        expect_destination=args.expect_destination,
        expect_recipient=args.expect_recipient,
        expect_in_response_to=args.expect_in_response_to,
        expect_alg=args.expect_alg,
        nonce=args.nonce,
        client_id=args.client_id,
        required_claims=args.require_claim,
    )
    sources = []
    if args.metadata:
        md = load_metadata(args.metadata)
        opts.trusted_certs += md.signing_certs
        opts.metadata_entity_id = md.entity_id
        sources.append(f"metadata {os.path.basename(args.metadata)}")
    for path in args.cert:
        opts.trusted_certs += load_certs(path)
        sources.append(f"certificate {os.path.basename(path)}")
    opts.trust_source = " and ".join(sources) or None
    if args.jwks:
        opts.jwks = load_jwks(args.jwks)
        opts.jwks_source = f"JWKS {os.path.basename(args.jwks)}"
    return opts


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        opts = build_options(args)
        tokens = detect(read_input(args.file, args.token, stdin))
        if not 1 <= args.pick <= len(tokens):
            raise InputError(f"--pick {args.pick}: the input holds {len(tokens)} token(s)")
        token = tokens[args.pick - 1]
        report = analyse(token, opts)
        report.other_tokens = len(tokens) - 1
    except (InputError, KeyFileError, SamlParseError, XMLRejected, NotImplementedError) as exc:
        print(f"token-inspector: {exc}", file=stderr)
        return EXIT_ERROR
    stdout.write(render_text(report, colour=use_colour(stdout)))
    return report.exit_code
