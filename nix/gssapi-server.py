"""Test-only HTTP acceptor backed by MIT GSSAPI, independent of rskrb5."""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer

import gssapi


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Negotiate "):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate")
            self.end_headers()
            return
        try:
            context = gssapi.SecurityContext(usage="accept")
            token = context.step(base64.b64decode(authorization[10:], validate=True))
            if not context.complete:
                raise ValueError("incomplete security context")
            body = f"authenticated: {context.initiator_name}\n".encode()
            self.send_response(200)
            if token:
                self.send_header("WWW-Authenticate", "Negotiate " + base64.b64encode(token).decode())
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as error:
            self.log_error("authentication failed: %s", error)
            self.send_response(403)
            self.end_headers()


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
