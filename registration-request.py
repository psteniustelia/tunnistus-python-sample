from jwcrypto import jwk
from lib.oidc_common import DEFAULT_REDIRECT_URI
from os.path import exists
import argparse
import json

# python registration-request.py --new

DEFAULT_CLIENT_JWKS = "client.jwks"

parser = argparse.ArgumentParser(description="OpenID Connect client registration")
parser.add_argument(
    "-j",
    "--client-jwks",
    default=DEFAULT_CLIENT_JWKS,
    help=f"OpenID Relying Party jwks, default {DEFAULT_CLIENT_JWKS}",
)
parser.add_argument("--new", help="Always generate new jwks", action="store_true")
args = parser.parse_args()

# read or create client.jwks

jwks = None
if exists(args.client_jwks) and not args.new:
    with open(args.client_jwks, "r", encoding="utf-8-sig") as fp:
        jwks = jwk.JWKSet.from_json(fp.read())
else:
    sig = jwk.JWK(generate="RSA", use="sig")
    sig.update(kid=sig.thumbprint())
    enc = jwk.JWK(generate="RSA", use="enc")
    enc.update(kid=enc.thumbprint())
    jwks = jwk.JWKSet()
    jwks.add(sig)
    jwks.add(enc)
    with open(args.client_jwks, "w", encoding="utf-8") as fp:
        t = jwks.export(private_keys=True, as_dict=True)
        json.dump(t, fp=fp, ensure_ascii=False, indent=2)

request = {
    "require_signed_request_object": True,
    "request_object_signing_alg": "RS256",
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "RS256",
    "id_token_signed_response_alg": "RS256",
    "id_token_encrypted_response_alg": "RSA-OAEP",
    "userinfo_signed_response_alg": "RS256",
    "userinfo_encrypted_response_alg": "RSA-OAEP",
    "redirect_uris": [DEFAULT_REDIRECT_URI],
    "grant_types": ["authorization_code"],
    "scope": "openid",
    "jwks": jwks.export(private_keys=False, as_dict=True),
}

print(json.dumps(request, ensure_ascii=False, indent=2))
