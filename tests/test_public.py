"""Public tests for the OpenID Connect ID token validator."""

import base64
import hashlib
import json

import pytest

from idtoken import (
    check_at_hash,
    check_audience,
    check_nonce,
    check_times,
    idtoken_batch,
    parse_token,
)

ISSUER = "https://login.example.test"
CLIENT_ID = "web-client"
ACCESS_TOKEN = "opaque-access-token-001"
NOW = 1_800_000_000


def _encode(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _at_hash(access_token, algorithm="sha256"):
    digest = hashlib.new(algorithm, access_token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).decode("ascii").rstrip("=")


def _token(claims, alg="RS256"):
    header = {"alg": alg, "typ": "JWT"}
    return f"{_encode(header)}.{_encode(claims)}.signature"


def _claims(**overrides):
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "alice",
        "iat": NOW - 30,
        "exp": NOW + 600,
        "nonce": "nonce-A1",
        "at_hash": _at_hash(ACCESS_TOKEN),
    }
    claims.update(overrides)
    return claims


def _policy(**overrides):
    policy = {
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "nonce": "nonce-A1",
        "access_token": ACCESS_TOKEN,
        "skew": 0,
    }
    policy.update(overrides)
    return policy


def test_parse_token_exposes_header_and_claims():
    claims = _claims(at_hash=_at_hash(ACCESS_TOKEN, "sha512"))
    token = _token(claims, alg="RS512")

    with pytest.raises(ValueError):
        parse_token("only.two")

    parsed = parse_token(token)
    assert parsed["header"]["alg"] == "RS512"
    assert parsed["signature"] == "signature"
    assert parsed["claims"]["sub"] == "alice"
    assert parsed["claims"]["nonce"] == "nonce-A1"
    assert check_at_hash(parsed["claims"], ACCESS_TOKEN, parsed["header"]["alg"]) is True


def test_nonce_requires_exact_request_value():
    claims = _claims()

    assert check_nonce(claims, "nonce-A1") is True
    assert check_nonce(claims, "nonce-A") is False


def test_audience_accepts_registered_client_in_all_entries():
    claims = _claims(aud=["partner-client", CLIENT_ID])

    assert check_audience(claims, CLIENT_ID) is True


def test_expiration_boundary_is_rejected():
    claims = _claims(iat=NOW - 60, exp=NOW)

    assert check_times(claims, NOW, 0) is False


def test_batch_keeps_tokens_independent():
    tokens = [
        {
            "token": _token(_claims(nonce="foreign-request-nonce")),
            "nonce": "nonce-A1",
            "access_token": ACCESS_TOKEN,
        },
        {
            "token": _token(_claims()),
            "nonce": "nonce-A1",
            "access_token": ACCESS_TOKEN,
        },
    ]

    result = idtoken_batch(tokens, _policy(), NOW)

    assert result["valid"] == [False, True]
    assert result["accepted"] == [1]
    assert result["rejected"] == [0]