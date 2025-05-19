from lib.oidc_common import decode_self_signed_entity_statement
import argparse
import hashlib
import json
import requests

## tunnistus-te.telia.fi
# python update-entity-statement.py -u https://tunnistus-te.telia.fi/.well-known/openid-federation --fingerprint 5a63af389f778fd8e94572b8b84880caea22dc23da388d46fc3379ec481b39ad
# python update-entity-statement.py -u https://tunnistus-te.telia.fi/.well-known/openid-federation --previous openid-federation.jwt
# python update-entity-statement.py -u https://tunnistus-te.telia.fi/.well-known/openid-federation --insecure

## tunnistus-pp.telia.fi
# python update-entity-statement.py -u https://tunnistus-pp.telia.fi/.well-known/openid-federation --fingerprint 2bb459b631d4c157f91ef7858d7f5baec6961d1d59df1b61eff7ae6905061cda

## tunnistus.telia.fi
# python update-entity-statement.py -u https://tunnistus.telia.fi/.well-known/openid-federation --fingerprint 1e8ba3d6cd534a8199ef0596ce94fece75c58d40d990c7e8ea792b99affc762c

DEFAULT_ENTITY_STATEMENT = "openid-federation.jwt"

parser = argparse.ArgumentParser(description="OpenID Federation entity statement")
parser.add_argument(
    "-f",
    "--file",
    default=DEFAULT_ENTITY_STATEMENT,
    help=f"OpenID Federation entity statement file, default {DEFAULT_ENTITY_STATEMENT}",
)
parser.add_argument(
    "-u",
    "--url",
    required=True,
    help=f"OpenID Federation entity statement endpoint",
)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--fingerprint",
    help=f"OpenID Federation entity statement fingerprint. User to verify entity statement",
)
group.add_argument(
    "--previous",
    help=f"Previous entity statement file. Used to verify entity statement",
)
group.add_argument(
    "--insecure",
    action="store_true",
    help=f"Does not validate entity statement",
)
args = parser.parse_args()

assert args.file is not None
assert args.url is not None


r = requests.get(args.url)
r.raise_for_status()
(token, token_jwks) = decode_self_signed_entity_statement(r.text)

if args.fingerprint is not None:
    hash = hashlib.sha256(r.content)
    assert args.fingerprint == hash.hexdigest()
elif args.previous is not None:
    with open(args.previous, "r", encoding="utf-8-sig") as fp:
        (prev, prev_jwks) = decode_self_signed_entity_statement(
            fp.read(), check_claims=False
        )
    token.validate(prev_jwks)
elif args.insecure:
    claims = json.loads(token.claims)
    print(f"the entity statement issued by {claims.get("iss")} was not validated")
    print(f"fingerprint {hashlib.sha256(r.content).hexdigest()}")
else:
    raise Exception()

with open(args.file, "w", encoding="utf-8") as fp:
    fp.write(r.text)
