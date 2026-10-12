"""Minimal JSON health endpoint for CI/CD security-gate demonstration."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404);return
        body=json.dumps({'status':'ok'}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

if __name__=='__main__': HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
