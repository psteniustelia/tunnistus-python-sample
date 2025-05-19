from lib.input import start_input_thread
from lib.LoopbackServer import LoopbackServer
from lib.oidc_common import ClientConfiguration, OpenIDConfiguration, RelyingParty
import argparse
import logging
import webbrowser

DEFAULT_ENTITY_STATEMENT = "openid-federation.jwt"
DEFAULT_CLIENT = "client.json"
DEFAULT_CLIENT_JWKS = "client.jwks"
DEFAULT_PORT = 8080

parser = argparse.ArgumentParser(description="OpenID Connect client")
parser.add_argument(
    "-e",
    "--entity-statement",
    default=DEFAULT_ENTITY_STATEMENT,
    help=f"OpenID Federation entity statement file, default {DEFAULT_ENTITY_STATEMENT}",
)
parser.add_argument(
    "-c",
    "--client",
    default=DEFAULT_CLIENT,
    help=f"Client configuration file, default {DEFAULT_CLIENT}",
)
parser.add_argument(
    "-j",
    "--client-jwks",
    default=DEFAULT_CLIENT_JWKS,
    help=f"Client private keys, default {DEFAULT_CLIENT_JWKS}",
)
parser.add_argument(
    "-p",
    "--port",
    default=DEFAULT_PORT,
    help=f"HTTP port, default {DEFAULT_PORT}",
)
parser.add_argument("--verbose", action="store_true")

args = parser.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

provider = OpenIDConfiguration(args.entity_statement)
client = ClientConfiguration(args.client, args.client_jwks)
client.port = int(args.port)
rp = RelyingParty(provider, client)

with LoopbackServer(rp, client.port) as httpd:
    print(httpd.base_uri)
    webbrowser.open(httpd.base_uri)
    start_input_thread("Press enter to stop\r\n", httpd.done)
    httpd.wait()
