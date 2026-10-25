#!/usr/bin/env python3
"""
Minimal SPA test fixture for the spider. Serves one HTML page whose JavaScript
fires fetch() calls to API endpoints, the way a real single-page app does.
A link-crawler (katana) would see only the one page; the spider should drive
the JS and capture the API calls.

Run: python3 spa_fixture_server.py  (listens on 127.0.0.1:8130)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

PAGE = """<!doctype html><html><head><title>SPA</title></head><body>
<h1>Fake SPA</h1>
<a href="#/profile">Profile</a> <a href="#/orders">Orders</a>
<button id="b1" onclick="loadBasket()">Load basket</button>
<button id="b2" onclick="loadOrder()">Load order</button>
<button id="b3" onclick="updateProfile()">Save profile</button>
<div id="out"></div>
<script>
// these endpoints only ever get hit by running JS, never as links
async function loadBasket(){ await fetch('/rest/basket/6'); }
async function loadOrder(){ await fetch('/api/orders/42'); }
async function createNote(){ await fetch('/api/notes', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'}); }
async function updateProfile(){ await fetch('/api/notes/7', {method:'PUT', headers:{'Content-Type':'application/json'}, body:'{}'}); }
async function readNote(){ await fetch('/api/notes/100'); }
// fire some on load so even a passive visit captures them. notes gets full
// CRUD (create+read+update) so the resources scaffold has something to build.
window.addEventListener('load', async ()=>{ fetch('/rest/user/whoami'); await createNote(); readNote(); });
// hash routing triggers more
window.addEventListener('hashchange', ()=>{
  if(location.hash==='#/profile') fetch('/api/profile/9');
  if(location.hash==='#/orders') fetch('/api/orders/42');
});
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        # every API path just returns a small object with an id
        self._json({"id": 1, "owner": "a", "data": "x"})

    def do_POST(self):
        self._json({"id": 100, "owner": "a"}, 201)

    def do_PUT(self):
        self._json({"id": 7, "owner": "a", "updated": True})


if __name__ == "__main__":
    print("SPA fixture on http://127.0.0.1:8130")
    HTTPServer(("127.0.0.1", 8130), H).serve_forever()
