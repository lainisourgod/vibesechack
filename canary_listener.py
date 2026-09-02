import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else "canary_hits.log"


class H(BaseHTTPRequestHandler):
    def _log(self, s):
        with open(LOG_PATH, "a") as f:
            f.write(s + "\n")

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        self._log("POST " + self.rfile.read(n).decode("utf-8", "replace"))
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self._log("GET " + self.path)  # token may arrive in the query string
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


class Server(HTTPServer):
    allow_reuse_address = True


Server(("127.0.0.1", 8899), H).serve_forever()
