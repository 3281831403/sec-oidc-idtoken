"""OpenID Connect ID token claim validation.

The module intentionally performs claim validation only.  Signature
verification belongs to the caller, which already has the issuer metadata
and signing keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any


def parse_token(text: str) -> dict[str, Any]:
    """Parse a compact JWT into its header, claims, and signature segment."""

    if not isinstance(text, str):
        raise TypeError("token must be text")
    segments = text.split(".")
    if len(segments) != 3:
        raise ValueError("token must contain three segments")

    encoded_header, encoded_claims, signature = segments
    if not encoded_header or not encoded_claims:
        raise ValueError("token header and claims must be present")

    try:
        header_bytes = base64.urlsafe_b64decode(
            encoded_header + "=" * (-len(encoded_header) % 4)
        )
        claims_bytes = base64.urlsafe_b64decode(
            encoded_claims + "=" * (-len(encoded_claims) % 4)
        )
        header = json.loads(header_bytes.decode("utf-8"))
        claims = json.loads(claims_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("token contains invalid base64url or JSON") from exc

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("token header and claims must be JSON objects")

    return {"header": header, "claims": claims, "signature": signature}


def check_nonce(claims: dict[str, Any], expected: str) -> bool:
    """Check that the token is bound to the authorization request nonce."""

    if not isinstance(claims, dict) or not isinstance(expected, str):
        return False
    if not expected:
        return False
    value = claims.get("nonce")
    if not isinstance(value, str):
        return False
    return hmac.compare_digest(value, expected)


def check_audience(claims: dict[str, Any], client_id: str) -> bool:
    """Check that the registered client is one of the token audiences."""

    if not isinstance(claims, dict) or not isinstance(client_id, str):
        return False
    if not client_id:
        return False
    audience = claims.get("aud")
    if isinstance(audience, str):
        return hmac.compare_digest(audience, client_id)
    if isinstance(audience, list):
        if not audience:
            return False
        return any(
            isinstance(entry, str) and hmac.compare_digest(entry, client_id)
            for entry in audience
        )
    return False


def check_issuer(claims: dict[str, Any], issuer: str) -> bool:
    """Check that the token was issued by the configured issuer."""

    if not isinstance(claims, dict) or not isinstance(issuer, str):
        return False
    if not issuer:
        return False
    value = claims.get("iss")
    if not isinstance(value, str):
        return False
    return hmac.compare_digest(value, issuer)


def _hash_name_for_alg(alg: Any) -> str | None:
    """Map a JWS algorithm to the hash used for the access token digest."""

    if not isinstance(alg, str):
        return None
    suffix = alg[-3:] if len(alg) >= 3 else ""
    return {
        "256": "sha256",
        "384": "sha384",
        "512": "sha512",
    }.get(suffix)


def check_at_hash(
    claims: dict[str, Any], access_token: str, alg: str
) -> bool:
    """Check the access token hash embedded in the ID token."""

    if not isinstance(claims, dict) or not isinstance(access_token, str):
        return False
    value = claims.get("at_hash")
    if not isinstance(value, str):
        return False

    hash_name = _hash_name_for_alg(alg)
    if hash_name is None:
        return False
    try:
        digest = hashlib.new(hash_name, access_token.encode("utf-8")).digest()
    except (ValueError, TypeError):
        return False
    expected = base64.urlsafe_b64encode(digest[: len(digest) // 2])
    return hmac.compare_digest(value, expected.rstrip(b"=").decode("ascii"))


def check_times(claims: dict[str, Any], now: float, skew: float) -> bool:
    """Check the issued-at and expiration times with a single skew."""

    if not isinstance(claims, dict):
        return False
    try:
        expiration = float(claims["exp"])
        issued_at = float(claims["iat"])
        current = float(now)
        allowance = float(skew)
    except (KeyError, TypeError, ValueError):
        return False
    if allowance < 0:
        return False
    # Reject tokens at or past their expiration boundary.
    if expiration <= current - allowance:
        return False
    # Reject tokens issued in the future beyond the allowed skew.
    if issued_at > current + allowance:
        return False
    return True


def check_azp(claims: dict[str, Any], client_id: str) -> bool:
    """Check the authorized party when more than one audience is present."""

    if not isinstance(claims, dict) or not isinstance(client_id, str):
        return False
    if not client_id:
        return False
    audience = claims.get("aud")
    multi = isinstance(audience, list) and len(audience) > 1
    value = claims.get("azp")
    if multi:
        # Multiple audiences: the authorized party must be declared and
        # must be this client.
        return isinstance(value, str) and hmac.compare_digest(value, client_id)
    if value is None:
        return True
    return isinstance(value, str) and hmac.compare_digest(value, client_id)


def idtoken_batch(
    tokens: list[Any], policy: dict[str, Any], now: float
) -> dict[str, Any]:
    """Validate each token independently and return only per-token outcomes."""

    outcomes: list[bool] = []
    accepted: list[int] = []
    rejected: list[int] = []

    for index, item in enumerate(tokens):
        if isinstance(item, dict):
            text = item.get("token")
            nonce = item.get("nonce", policy.get("nonce"))
            access_token = item.get("access_token", policy.get("access_token"))
        else:
            text = item
            nonce = policy.get("nonce")
            access_token = policy.get("access_token")

        valid = False
        try:
            parsed = parse_token(text)
            claims = parsed["claims"]
            alg = parsed["header"].get("alg")
            valid = bool(
                isinstance(nonce, str)
                and isinstance(access_token, str)
                and check_nonce(claims, nonce)
                and check_audience(claims, policy.get("client_id"))
                and check_issuer(claims, policy.get("issuer"))
                and check_at_hash(claims, access_token, alg)
                and check_times(claims, now, policy.get("skew", 0))
                and check_azp(claims, policy.get("client_id"))
            )
        except (TypeError, ValueError):
            valid = False

        outcomes.append(valid)
        if valid:
            accepted.append(index)
        else:
            rejected.append(index)

    return {
        "total": len(outcomes),
        "valid": outcomes,
        "accepted": accepted,
        "rejected": rejected,
    }
