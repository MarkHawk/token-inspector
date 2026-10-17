"""Split a compact JWT or JWE into its parts without trusting any of them."""

import base64
import binascii
import json
from dataclasses import dataclass, field


class JwtParseError(ValueError):
    """The token's parts are not valid base64url JSON."""


@dataclass
class Jwt:
    raw: str
    header: dict
    claims: dict = field(default_factory=dict)
    signing_input: bytes = b""
    signature: bytes = b""
    encrypted: bool = False
    token_type: str = None  # "id" or "access"
    type_reason: str = None


def b64url_decode(segment):
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        raise JwtParseError("a token segment is not valid base64url") from None


def _json_part(segment, what):
    try:
        value = json.loads(b64url_decode(segment))
    except (ValueError, UnicodeDecodeError):
        raise JwtParseError(f"the JWT {what} is not valid JSON; the token may be truncated or not a JWT") from None
    if not isinstance(value, dict):
        raise JwtParseError(f"the JWT {what} is JSON but not an object")
    return value


def parse_jwt(compact, kind="jwt", token_type=None):
    parts = compact.split(".")
    header = _json_part(parts[0], "header")
    if kind == "jwe":
        return Jwt(raw=compact, header=header, encrypted=True)
    if len(parts) != 3:
        raise JwtParseError("a signed JWT has three dot-separated parts")
    token = Jwt(
        raw=compact,
        header=header,
        claims=_json_part(parts[1], "payload"),
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=b64url_decode(parts[2]),
    )
    if token_type:
        token.token_type, token.type_reason = token_type, "set with --token-type"
    else:
        token.token_type, token.type_reason = guess_type(token.header, token.claims)
    return token


def guess_type(header, claims):
    """ID token or access token, with the reason, for the report."""
    typ = str(header.get("typ", "")).lower()
    if typ in ("at+jwt", "application/at+jwt"):
        return "access", f"header typ is {header['typ']}"
    if claims.get("typ") == "ID":
        return "id", "claim typ is ID"
    if claims.get("typ") == "Bearer":
        return "access", "claim typ is Bearer"
    if "nonce" in claims or "at_hash" in claims:
        return "id", "has a " + ("nonce" if "nonce" in claims else "at_hash") + " claim"
    if "scope" in claims or "scp" in claims:
        return "access", "has a scope claim"
    return "id", "no access-token markers (use --token-type access if this is an access token)"
