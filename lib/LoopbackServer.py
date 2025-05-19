from lib.oidc_common import RelyingParty
from threading import Thread, Event
from urllib.parse import urljoin
from urllib3.util import parse_url
import http.server
import logging


class LoopbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        server: LoopbackServer = self.server
        url = parse_url(urljoin(server.base_uri, self.path))
        logging.debug(f"GET {self.path}")

        if server.rp is None:
            self.send_error(503)
            self.end_headers()
            return

        if url.path == "/favicon.ico":
            self.send_error(404)
            self.end_headers()
            return

        # handles authorization response
        if server.rp.is_redirect_uri(url):
            response = server.rp.handle_authorization_response(url)
            body = response.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
            return

        # any other request generates 302 redirect with authorization request
        request = server.rp.new_authorization_request(url)
        if request is not None:
            self.send_response(302)
            self.send_header("Location", request)
            self.end_headers()
        else:
            self.send_error(404)
            self.end_headers()


class LoopbackServer(http.server.ThreadingHTTPServer):
    rp: RelyingParty = None

    def __init__(self, rp: RelyingParty | None = None, port: int | None = None):
        super().__init__(("localhost", port or 0), LoopbackHandler)
        self.done = Event()
        self.rp = rp
        self.__port = self.socket.getsockname()[1]

    @property
    def active(self):
        return not self.done.is_set()

    @property
    def port(self):
        return self.__port

    @property
    def base_uri(self):
        if self.port == 80:
            return "http://localhost"
        else:
            return f"http://localhost:{self.port}"

    def server_thread(self):
        while self.active:
            self.timeout = 0.5
            try:
                self.handle_request()
            except:
                pass

    def wait(self):
        t = Thread(
            name="LoopbackServer", target=lambda: self.server_thread(), daemon=True
        )
        t.start()
        try:
            self.done.wait()
        except KeyboardInterrupt:
            self.done.set()
