#!/usr/bin/env python3
"""
Mock target for testing IGOR. Models OWASP Juice Shop style access-control bugs,
now with create/update so the write-side engine has something to test.

Accounts (cookie token=alice / token=bob).

Resources:
  /api/baskets   VULNERABLE: no owner check on GET or PUT.
                 -> read IDOR and write IDOR.
  /api/notes     SAFE: owner check on GET and PUT (403 cross-account).
  /api/BasketItems/{id}  legacy read-only IDOR (kept for the read-engine test).
  /api/Whoami            safe, no object ref.
  /api/public/status     public.

Run: python3 mock_vuln_server.py   (listens on 127.0.0.1:8099)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re

TOKEN_TO_USER = {"alice": "alice", "bob": "bob"}

# legacy fixed baskets for the read-engine test
BASKET_ITEMS = {
    "1": {"basketId": 1, "owner": "alice", "items": ["apple juice", "SECRET alice ****1111"]},
    "2": {"basketId": 2, "owner": "bob", "items": ["banana juice", "SECRET bob ****2222"]},
}

# dynamic stores for the write-engine test
BASKETS = {}
NOTES = {}
_next_id = {"baskets": 100, "notes": 100}


def new_id(kind):
    _next_id[kind] += 1
    return _next_id[kind]


def token_of(headers):
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("token="):
            return part[len("token="):]
    return None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def _user(self):
        return TOKEN_TO_USER.get(token_of(self.headers))

    # --- GET ---------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]
        user = self._user()

        if path == "/api/public/status":
            return self._send(200, {"status": "ok", "version": "1.0"})

        if path == "/api/Whoami":
            if not user:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"user": user})

        m = re.fullmatch(r"/api/BasketItems/(\d+)", path)
        if m:
            if not user:
                return self._send(401, {"error": "unauthorized"})
            b = BASKET_ITEMS.get(m.group(1))
            return self._send(200, b) if b else self._send(404, {"error": "not found"})

        m = re.fullmatch(r"/api/baskets/(\d+)", path)
        if m:
            if not user:
                return self._send(401, {"error": "unauthorized"})
            b = BASKETS.get(m.group(1))
            # BUG: no check that b["owner"] == user
            return self._send(200, b) if b else self._send(404, {"error": "not found"})

        m = re.fullmatch(r"/api/notes/(\d+)", path)
        if m:
            if not user:
                return self._send(401, {"error": "unauthorized"})
            n = NOTES.get(m.group(1))
            if not n:
                return self._send(404, {"error": "not found"})
            if n["owner"] != user:                       # SAFE: owner check
                return self._send(403, {"error": "forbidden"})
            return self._send(200, n)

        return self._send(404, {"error": "no such route"})

    # --- POST (create) -----------------------------------------------------
    def do_POST(self):
        path = self.path.split("?")[0]
        user = self._user()
        if not user:
            return self._send(401, {"error": "unauthorized"})
        body = self._read_body()

        if path == "/api/baskets":
            bid = new_id("baskets")
            obj = {"id": bid, "owner": user, "qty": body.get("qty", 1)}
            BASKETS[str(bid)] = obj
            return self._send(201, obj)

        if path == "/api/notes":
            nid = new_id("notes")
            obj = {"id": nid, "owner": user, "text": body.get("text", "")}
            NOTES[str(nid)] = obj
            return self._send(201, obj)

        return self._send(404, {"error": "no such route"})

    # --- PUT (update) ------------------------------------------------------
    def do_PUT(self):
        path = self.path.split("?")[0]
        user = self._user()
        if not user:
            return self._send(401, {"error": "unauthorized"})
        body = self._read_body()

        m = re.fullmatch(r"/api/baskets/(\d+)", path)
        if m:
            b = BASKETS.get(m.group(1))
            if not b:
                return self._send(404, {"error": "not found"})
            # BUG: no owner check. Anyone can update anyone's basket.
            if "qty" in body:
                b["qty"] = body["qty"]
            return self._send(200, b)

        m = re.fullmatch(r"/api/notes/(\d+)", path)
        if m:
            n = NOTES.get(m.group(1))
            if not n:
                return self._send(404, {"error": "not found"})
            if n["owner"] != user:                       # SAFE: owner check
                return self._send(403, {"error": "forbidden"})
            if "text" in body:
                n["text"] = body["text"]
            return self._send(200, n)

        return self._send(404, {"error": "no such route"})

    # --- DELETE (owner-checked, for teardown) ------------------------------
    def do_DELETE(self):
        path = self.path.split("?")[0]
        user = self._user()
        if not user:
            return self._send(401, {"error": "unauthorized"})
        for store, prefix in ((BASKETS, "/api/baskets/"), (NOTES, "/api/notes/")):
            m = re.fullmatch(re.escape(prefix) + r"(\d+)", path)
            if m:
                obj = store.get(m.group(1))
                if not obj:
                    return self._send(404, {"error": "not found"})
                if obj["owner"] != user:
                    return self._send(403, {"error": "forbidden"})
                del store[m.group(1)]
                return self._send(204, {})
        return self._send(404, {"error": "no such route"})


if __name__ == "__main__":
    print("mock target on http://127.0.0.1:8099")
    HTTPServer(("127.0.0.1", 8099), H).serve_forever()
