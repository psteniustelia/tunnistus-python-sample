from collections.abc import Iterable
from datetime import datetime, timedelta
from jwcrypto import jwk, jwt, jwe
from urllib.parse import urlencode, parse_qs
from urllib3.util import Url, parse_url
import html
import json
import logging
import requests
import uuid

DEFAULT_REDIRECT_URI = "http://localhost/redirect"

HTML = """
<!DOCTYPE html>
<html>
<head><title>OIDC</title></head>
<body onload="window.history.replaceState(null, null, '/')">
{0}
</body>
</html>
"""


def find_jwk_by_use(jwks: jwk.JWKSet, use: str) -> jwk.JWK:
    if jwks is None:
        return None
    jwk = None
    for k in jwks:
        t = k.export(private_key=False, as_dict=True)
        if "use" in t and t["use"] == use:
            return k
        if not "use" in t:
            jwk = k
    return jwk


def to_html_list(input: dict) -> str:
    r = "<dl>"
    for k, v in input.items():
        r += f"<dt><b>{html.escape(k)}</b></dt>"
        if not isinstance(v, str) and isinstance(v, Iterable):
            for i in v:
                r += f"<dd><i>{html.escape(str(i))}</i></dd>"
        else:
            r += f"<dd><i>{html.escape(str(v))}</i></dd>"
    r += "</dl>"
    return r


global_state = dict()


class ClientState:
    state: str
    nonce: str

    def __init__(self):
        self.state = str(uuid.uuid4())
        self.nonce = str(uuid.uuid4())
        global_state[self.state] = self


def get_client_state(state: str | None) -> ClientState | None:
    if state is None:
        return None
    if state not in global_state:
        return None
    state = global_state.pop(state)
    if state is None:
        return None
    return state


def decode_self_signed_entity_statement(
    input: str, check_claims: bool = False
) -> tuple[jwt.JWT, jwk.JWKSet]:
    if check_claims:
        token = jwt.JWT(check_claims={"exp": None})
    else:
        token = jwt.JWT()
    token.deserialize(input)
    claims = json.loads(token.token.objects.get("payload"))
    assert claims.get("iss") is not None
    assert claims.get("iss") == claims.get("sub")
    jwks = jwk.JWKSet.from_json(json.dumps(claims.get("jwks")))
    token.validate(jwks)
    return (token, jwks)


class OpenIDConfiguration:
    entity_statement: jwt.JWT = None
    _entity_claims: dict = None
    entity_jwks: jwk.JWKSet = None

    def __init__(self, openid_federation: str):
        logging.debug(f"read {openid_federation}")
        with open(openid_federation, "r", encoding="utf-8-sig") as fp:
            token = fp.read()
            (self.entity_statement, self.entity_jwks) = (
                decode_self_signed_entity_statement(token, check_claims=False)
            )

    @property
    def entity_claims(self) -> dict:
        if self._entity_claims is None:
            self._entity_claims = json.loads(self.entity_statement.claims)
        return self._entity_claims

    @property
    def entity_issuer(self) -> str:
        assert "iss" in self.entity_claims
        return self.entity_claims["iss"]

    @property
    def provider(self) -> dict:
        assert "metadata" in self.entity_claims
        assert "openid_provider" in self.entity_claims["metadata"]
        return self.entity_claims["metadata"]["openid_provider"]

    @property
    def issuer(self):
        assert "issuer" in self.provider
        return self.provider["issuer"]

    @property
    def authorization_endpoint(self):
        assert "authorization_endpoint" in self.provider
        return self.provider["authorization_endpoint"]

    @property
    def token_endpoint(self):
        assert "token_endpoint" in self.provider
        return self.provider["token_endpoint"]

    @property
    def signed_jwks_uri(self):
        assert "signed_jwks_uri" in self.provider
        return self.provider["signed_jwks_uri"]

    def get_jwks(self) -> jwk.JWKSet:
        logging.debug(f"GET {self.signed_jwks_uri}")
        r = requests.get(self.signed_jwks_uri)
        r.raise_for_status()
        token = jwt.JWT(
            check_claims={
                "iss": self.entity_issuer,
                "sub": self.entity_issuer,
            }
        )
        token.deserialize(r.text)
        token.validate(self.entity_jwks)
        return jwk.JWKSet.from_json(token.claims)


class ClientConfiguration:
    client: dict
    client_jwks: jwk.JWKSet
    _redirect_uri: str

    def __init__(self, client_configuration: str, client_jwks: str):
        logging.debug(f"read {client_configuration}")
        with open(client_configuration, "r", encoding="utf-8-sig") as fp:
            self.client = json.load(fp)
        logging.debug(f"read {client_jwks}")
        with open(client_jwks, "r", encoding="utf-8-sig") as fp:
            self.client_jwks = jwk.JWKSet.from_json(fp.read())
        if "redirect_uris" not in self.client:
            self._redirect_uri = DEFAULT_REDIRECT_URI
        else:
            self._redirect_uri = self.client["redirect_uris"][0]

    @property
    def client_id(self) -> str:
        assert "client_id" in self.client
        return self.client["client_id"]

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    @property
    def port(self) -> int:
        u = parse_url(self.redirect_uri)
        return 80 if u.port is None else u.port

    @port.setter
    def port(self, value: int | None):
        self._port = 80 if value is None else value
        u = parse_url(self.redirect_uri)
        u = Url(
            scheme=u.scheme, host=u.host, port=self._port, path=u.path, query=u.query
        )
        self._redirect_uri = u.url

    @property
    def scope(self) -> str:
        return "openid"

    def sign_request_object(self, provider: OpenIDConfiguration, params: dict):
        jwk = find_jwk_by_use(self.client_jwks, "sig")
        alg = "RS256"
        token = jwt.JWT(
            header={"alg": alg, "typ": "JWT", "kid": jwk.kid},
            claims=params,
        )
        token.make_signed_token(jwk)
        return token

    def sign_client_assertion(self, provider: OpenIDConfiguration, claims: dict):
        jwk = find_jwk_by_use(self.client_jwks, "sig")
        alg = "RS256"
        token = jwt.JWT(
            header={"alg": alg, "typ": "JWT", "kid": jwk.kid},
            claims=claims,
        )
        token.make_signed_token(jwk)
        return token


class RelyingParty:
    provider: OpenIDConfiguration
    client: ClientConfiguration

    def __init__(self, provider: OpenIDConfiguration, client: ClientConfiguration):
        self.provider = provider
        self.client = client

    def is_redirect_uri(self, url: Url) -> bool:
        t = parse_url(self.client.redirect_uri)
        return url.path == t.path

    def new_authorization_request(self, url: Url) -> str:
        state = ClientState()
        authorization_request = {
            "iss": self.client.client_id,
            "aud": self.provider.issuer,
            "response_type": "code",
            "client_id": self.client.client_id,
            "scope": self.client.scope,
            "redirect_uri": self.client.redirect_uri,
            "state": state.state,
            "nonce": state.nonce,
        }
        logging.debug(json.dumps(authorization_request, ensure_ascii=False, indent=2))
        token = self.client.sign_request_object(self.provider, authorization_request)
        authorization_request = {"request": token.serialize()}
        t = f"{self.provider.authorization_endpoint}?{urlencode(authorization_request)}"
        logging.debug(f"GET {t}")
        return t

    def handle_authorization_response(self, url: Url) -> str:
        authorization_response = parse_qs(url.query)
        state = None
        if "state" in authorization_response:
            state = get_client_state(authorization_response["state"][0])
        if state is None:
            return HTML.format("<h1>Error</h1>")
        if "code" in authorization_response:
            return self.invoke_token_request(authorization_response["code"][0], state)
        else:
            t = "<h1>Authorization Response -- error</h1>"
            t += to_html_list(authorization_response)
            return HTML.format(t)

    def invoke_token_request(self, code: str, state: ClientState) -> str:
        client_assertion = {
            "iss": self.client.client_id,
            "sub": self.client.client_id,
            "aud": self.provider.token_endpoint,
            "exp": int((datetime.now() + timedelta(minutes=10)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        logging.debug(json.dumps(client_assertion, ensure_ascii=False, indent=2))
        token = self.client.sign_client_assertion(self.provider, client_assertion)
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.client.redirect_uri,
            "client_id": self.client.client_id,
            "client_assertion": token.serialize(),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }
        logging.debug(json.dumps(token_request, ensure_ascii=False, indent=2))
        logging.debug(f"POST {self.provider.token_endpoint}")
        logging.debug(urlencode(token_request))
        response = requests.post(self.provider.token_endpoint, data=token_request)
        if response.status_code == 200:
            token_response = response.json()
            logging.debug(json.dumps(token_response, ensure_ascii=False, indent=2))
            if "id_token" in token_response:
                claims = self.decode_id_token(token_response["id_token"], state)
                t = "<h1>ID Token</h1>"
                t += to_html_list(claims)
                return HTML.format(t)
            else:
                t = "<h1>Token Response</h1>"
                t += to_html_list(token_response)
                return HTML.format(t)
        else:
            t = "<h1>Token Response -- error</h1>"
            t += f"<p>{html.escape(response.text)}</p>"
            return HTML.format(t)

    def decode_id_token(self, id_token: str, state: ClientState) -> dict:
        plaintext: str = None
        try:
            token = jwe.JWE.from_jose_token(id_token)
            token.decrypt(self.client.client_jwks)
            plaintext = token.plaintext.decode("utf-8")
        except:
            plaintext = id_token
        token = jwt.JWT(
            check_claims={
                "iss": self.provider.issuer,
                "aud": self.client.client_id,
                "nonce": state.nonce,
                "exp": None,
            }
        )
        token.deserialize(plaintext, key=self.provider.get_jwks())
        return json.loads(token.claims)
