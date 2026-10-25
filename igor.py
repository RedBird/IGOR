#!/usr/bin/env python3
"""
IGOR - the assistant that helps you hunt IDORs.

Read-side engine (v0.1). Point it at captured requests, give it two account
sessions, and it replays each request as account A (baseline), as account B,
and unauthenticated, then compares the responses to flag likely IDORs.

Zero dependencies. Python 3.8+ stdlib only, so it runs clean on a Kali
cyberdeck with no pip step.

Authorized testing only. You are responsible for staying in scope.
"""

import argparse
import base64
import binascii
import csv
import difflib
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit, parse_qsl
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Small helpers: color output, only when we're talking to a real terminal.
# ---------------------------------------------------------------------------

class C:
    RED = "\033[31m"
    YEL = "\033[33m"
    GRN = "\033[32m"
    DIM = "\033[2m"
    BLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def off():
        for k in ("RED", "YEL", "GRN", "DIM", "BLD", "END"):
            setattr(C, k, "")


if not sys.stdout.isatty():
    C.off()


# Headers that carry identity. We strip these off a captured request and then
# apply the chosen session's own auth, so the test is deterministic no matter
# which account happened to capture the traffic.
DEFAULT_AUTH_HEADERS = ["cookie", "authorization", "x-api-key", "x-auth-token"]

# PwnFox tags each container's traffic with this. It is only meaningful inside
# Burp, so we group on it but never send it at the target.
PWNFOX_HEADER = "x-pwnfox-color"


# ---------------------------------------------------------------------------
# Request model + raw HTTP parsing (Burp "copy to file" format).
# ---------------------------------------------------------------------------

@dataclass
class Req:
    method: str
    url: str
    headers: dict
    body: bytes = b""
    source: str = ""           # where this request came from (filename etc.)
    pwnfox_color: str = ""      # if captured via PwnFox containers


def _scheme_for(host: str) -> str:
    # Local targets (Juice Shop runs on localhost:3000) are almost always
    # plain http. Everything else defaults to https. Override per request in
    # a targets.json if you need to.
    h = host.lower()
    if h.startswith("localhost") or h.startswith("127.") or ":3000" in h:
        return "http"
    return "https"


def parse_raw_http(text: str, source: str = "") -> Req:
    """Parse a raw HTTP request as saved from Burp."""
    # Split headers from body on the first blank line.
    if "\r\n\r\n" in text:
        head, _, body = text.partition("\r\n\r\n")
    else:
        head, _, body = text.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"bad request line: {request_line!r}")
    method, path = parts[0], parts[1]

    headers = {}
    pwnfox = ""
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        headers[name] = value
        if name.lower() == PWNFOX_HEADER:
            pwnfox = value.lower()

    host = headers.get("Host") or headers.get("host") or ""
    if path.lower().startswith("http"):
        url = path
    else:
        url = f"{_scheme_for(host)}://{host}{path}"

    return Req(
        method=method.upper(),
        url=url,
        headers=headers,
        body=body.encode() if isinstance(body, str) else body,
        source=source,
        pwnfox_color=pwnfox,
    )


def load_targets(paths):
    """Load requests from raw .txt/.req files or a targets.json list."""
    reqs = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix.lower() in (".txt", ".req", ".http"):
                    reqs.append(parse_raw_http(child.read_text(errors="replace"),
                                               source=child.name))
        elif p.suffix.lower() == ".json":
            data = json.loads(p.read_text())
            for item in data:
                reqs.append(Req(
                    method=item.get("method", "GET").upper(),
                    url=item["url"],
                    headers=item.get("headers", {}),
                    body=(item.get("body", "") or "").encode(),
                    source=str(p.name),
                ))
        else:
            reqs.append(parse_raw_http(p.read_text(errors="replace"),
                                       source=p.name))
    return reqs


# ---------------------------------------------------------------------------
# ID extraction + decoding (the CyberChef-lite step, inline into the report).
# ---------------------------------------------------------------------------

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
NUMERIC_RE = re.compile(r"(?<![0-9a-zA-Z_])[0-9]{1,}(?![0-9a-zA-Z_])")
TOKENISH_RE = re.compile(r"[A-Za-z0-9_\-=]{8,}")


def classify_uuid(u: str) -> str:
    """UUIDs aren't decoded, they're classified. The version tells you whether
    IDs are guessable, which is the whole game for enumeration."""
    try:
        version = int(u[14], 16)
    except (ValueError, IndexError):
        return "uuid?"
    if version == 4:
        return "uuidv4 (random, not enumerable)"
    if version in (1, 7):
        return f"uuidv{version} (time-based, IDs are roughly sequential: enumerable)"
    return f"uuidv{version}"


def try_decode(value: str):
    """Attempt the common encodings. Returns a short human string or None."""
    # JWT: three base64url parts. The real user id often hides in a claim.
    if value.count(".") == 2 and all(value.split(".")):
        try:
            h, pl, _ = value.split(".")
            payload = base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4))
            obj = json.loads(payload)
            keys = ", ".join(list(obj.keys())[:6])
            return f"JWT payload keys: {keys}"
        except Exception:
            pass

    # base64 / base64url, only if it decodes to mostly-printable bytes.
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = dec(value + "=" * (-len(value) % 4))
            if raw and _printable_ratio(raw) > 0.85 and len(raw) >= 2:
                return f"base64 -> {raw.decode(errors='replace')[:60]}"
        except (binascii.Error, ValueError):
            pass

    # hex
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0 and len(value) >= 4:
        try:
            raw = bytes.fromhex(value)
            if _printable_ratio(raw) > 0.85:
                return f"hex -> {raw.decode(errors='replace')[:60]}"
        except ValueError:
            pass
    return None


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(raw)


def _candidate_values(url: str, body: bytes = b""):
    """Pull only the parts of a request that can carry an object reference:
    path segments and query values. Never the host or port. Plus any
    id-looking values in the body. This is what keeps the IDs column signal
    instead of noise."""
    from urllib.parse import urlsplit, parse_qsl
    parts = urlsplit(url)
    values = []
    for seg in parts.path.split("/"):
        seg = seg.strip()
        if seg:
            values.append(seg)
    for _, v in parse_qsl(parts.query):
        if v:
            values.append(v)
    if body:
        text = body[:4000].decode(errors="replace")
        # grab "...":"value" and "...":123 pairs from JSON-ish bodies
        for m in re.findall(r'"\s*:\s*"?([A-Za-z0-9_\-=.]{1,})"?', text):
            values.append(m)
    return values


def analyze_ids(url: str, body: bytes = b""):
    """Annotate candidate IDs. Returns (list_of_(value,note), has_object_ref).
    has_object_ref is the gate: no tamperable identifier means it is not an
    IDOR candidate, whatever the response looks like."""
    found = []
    seen = set()
    has_ref = False
    for val in _candidate_values(url, body):
        if val in seen:
            continue
        if UUID_RE.fullmatch(val):
            found.append((val, classify_uuid(val)))
            seen.add(val)
            has_ref = True
        elif val.isdigit() and 1 <= len(val) <= 12:
            found.append((val, "numeric (enumerable)"))
            seen.add(val)
            has_ref = True
        else:
            decoded = try_decode(val)
            if decoded:
                found.append((val, decoded))
                seen.add(val)
                has_ref = True  # an encoded id is still an object reference
    return found, has_ref


def cyberchef_link(value: str, base="https://gchq.github.io/CyberChef/") -> str:
    """For encodings we can't crack, hand off to CyberChef's Magic auto-detect.
    Input rides in the URL fragment, which the browser does not send to the
    server. Point `base` at a local instance for real engagement data."""
    recipe = base64.b64encode(b'[{"op":"Magic","args":[3,false,false,""]}]').decode()
    data = base64.b64encode(value.encode()).decode()
    return f"{base}#recipe={recipe}&input={data}"


# ---------------------------------------------------------------------------
# HTTP send + the swap test.
# ---------------------------------------------------------------------------

@dataclass
class Resp:
    status: int
    body: bytes
    length: int
    error: str = ""
    headers: dict = field(default_factory=dict)


def send(req: Req, session_headers: dict, strip_auth: list, timeout=15) -> Resp:
    """Send a request, replacing its identity headers with the session's."""
    headers = {}
    strip = set(h.lower() for h in strip_auth) | {PWNFOX_HEADER, "content-length"}
    # Global headers go on EVERY request, including the unauthenticated
    # baseline. This is how a mandatory program header such as a bug-bounty
    # identifier (X-Bug-Bounty) rides on all traffic. Set first so a session
    # can still override a value, but a program header normally just stays.
    for name, value in (GLOBAL_HEADERS or {}).items():
        headers[name] = value
    for name, value in req.headers.items():
        if name.lower() in strip:
            continue
        headers[name] = value
    for name, value in (session_headers or {}).items():
        headers[name] = value  # session auth wins

    data = req.body if req.method in ("POST", "PUT", "PATCH") else None
    r = urllib.request.Request(req.url, data=data, headers=headers, method=req.method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            return Resp(resp.status, body, len(body), headers=dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return Resp(e.code, body, len(body), headers=dict(getattr(e, "headers", {}) or {}))
    except Exception as e:
        return Resp(0, b"", 0, error=str(e))


def similarity(a: bytes, b: bytes) -> float:
    # Truncate so huge responses don't make the diff crawl.
    ta = a[:20000].decode(errors="replace")
    tb = b[:20000].decode(errors="replace")
    if not ta and not tb:
        return 1.0
    return difflib.SequenceMatcher(None, ta, tb).ratio()


ERROR_HINT = re.compile(rb"(not authori|forbidden|denied|unauthor|no access|"
                        rb"invalid token|please log|error)", re.I)


def verdict_for(baseline: Resp, attack: Resp, label: str):
    """Score one swap. Returns (verdict, note). Conservative on purpose:
    the tool shrinks your manual list, it does not declare the bug."""
    if baseline.status == 0:
        return "NO_BASELINE", f"baseline request failed: {baseline.error}"
    if not (200 <= baseline.status < 300):
        return "NO_BASELINE", f"baseline not 2xx (got {baseline.status}), no control"
    if attack.status == 0:
        return "ERR", f"{label} request failed: {attack.error}"

    sim = similarity(baseline.body, attack.body)

    if attack.status in (401, 403):
        return "PASS", f"{label} blocked ({attack.status})"
    if 200 <= attack.status < 300:
        # A 2xx that looks like A's data is the hit, unless it's clearly an
        # error page that happens to match.
        if sim >= 0.95:
            if ERROR_HINT.search(attack.body) and attack.length < 600:
                return "LOW", f"{label} 2xx but body looks like a shared error page"
            return "HIGH", f"{label} 2xx, body {sim:.0%} match to A's data"
        if sim >= 0.60:
            return "MED", f"{label} 2xx, partial match {sim:.0%}, eyeball it"
        return "LOW", f"{label} 2xx but different body ({sim:.0%}), likely own/empty data"
    return "INFO", f"{label} returned {attack.status}"


RANK = {"HIGH": 0, "MED": 1, "PUBLIC": 1, "LOW": 2, "PASS": 3,
        "INFO": 4, "ERR": 5, "NO_BASELINE": 6, "SKIP": 7}


# ---------------------------------------------------------------------------
# PoC generation. On a confirmed finding, write a paste-ready repro. Real
# cookies are replaced with $A_COOKIE / $B_COOKIE so the file never carries a
# live session token.
# ---------------------------------------------------------------------------

def _curl(method, url, cookie_var=None, body=b"", content_type=None):
    parts = ["curl -s -i"]
    if method != "GET":
        parts.append(f"-X {method}")
    if cookie_var:
        parts.append(f"-H \"Cookie: ${cookie_var}\"")
    if content_type:
        parts.append(f"-H \"Content-Type: {content_type}\"")
    if body:
        text = body.decode(errors="replace") if isinstance(body, bytes) else str(body)
        parts.append(f"--data '{text}'")
    parts.append(f"\"{url}\"")
    return " ".join(parts)


def _snippet(b: bytes, n=400):
    return (b or b"")[:n].decode(errors="replace")


def _slug(url):
    s = re.sub(r"^https?://", "", url)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")
    return s[:80]


def write_run_poc(outdir, req, verdict, base, atk, un, attacker_label):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    path = Path(outdir) / f"{verdict}_{req.method}_{_slug(req.url)}.md"
    if verdict == "PUBLIC":
        steps = (
            "## Repro\n\n"
            "1. As the owner, confirm the object is yours (baseline):\n\n"
            f"```bash\n{_curl(req.method, req.url, 'A_COOKIE')}\n```\n\n"
            "2. Request the same object with NO authentication:\n\n"
            f"```bash\n{_curl(req.method, req.url)}\n```\n\n"
            f"The unauthenticated request returns {un.status} with the same "
            "private data. No session required.\n"
        )
        evidence = _snippet(un.body)
    else:
        steps = (
            "## Repro\n\n"
            "1. As account A (owner), establish the baseline:\n\n"
            f"```bash\n{_curl(req.method, req.url, 'A_COOKIE')}\n```\n\n"
            "2. Send the same request as account B, changing only the session:\n\n"
            f"```bash\n{_curl(req.method, req.url, 'B_COOKIE')}\n```\n\n"
            f"Account B receives HTTP {atk.status} containing account A's data, "
            "which B has no authorization to see.\n"
        )
        evidence = _snippet(atk.body)

    content = (
        f"# IDOR: {req.method} {req.url}\n\n"
        f"**Severity signal:** {verdict}\n\n"
        f"**Endpoint:** `{req.method} {req.url}`\n\n"
        "Set your two session cookies first:\n\n"
        "```bash\nexport A_COOKIE=\"...account A cookie...\"\n"
        "export B_COOKIE=\"...account B cookie...\"\n```\n\n"
        f"{steps}\n"
        f"## Evidence (response body, truncated)\n\n```\n{evidence}\n```\n\n"
        "## Impact\n\n"
        "A user can access another user's private object by referencing its id. "
        "Confirm the data is genuinely private and describe the real-world impact "
        "for the report.\n\n"
        "_Generated by IGOR. Confirm by hand before submitting._\n"
    )
    path.write_text(content)
    return path


def write_write_poc(outdir, res_spec, aid, row, attacker_label):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    name = res_spec["name"]
    path = Path(outdir) / f"WRITE_{name}.md"
    up = res_spec["update"]
    read_url = res_spec["read"]["url"].replace("{id}", str(aid))
    up_url = up["url"].replace("{id}", str(aid))
    mf, atkv = up["marker_field"], up["attack_value"]
    body = dict(up.get("body", {})); body[mf] = atkv
    body_bytes = json.dumps(body).encode()
    content = (
        f"# Write IDOR: {name}\n\n"
        f"**Severity signal:** WRITE {row['write_verdict']}\n\n"
        "Set your two session cookies first:\n\n"
        "```bash\nexport A_COOKIE=\"...account A cookie...\"\n"
        "export B_COOKIE=\"...account B cookie...\"\n```\n\n"
        "## Repro\n\n"
        f"1. As account A, create an object you own (id `{aid}` here):\n\n"
        f"```bash\n{_curl(res_spec['create']['method'], res_spec['create']['url'], 'A_COOKIE', json.dumps(res_spec['create'].get('body',{})).encode(), 'application/json')}\n```\n\n"
        f"2. As account B, modify A's object:\n\n"
        f"```bash\n{_curl(up['method'], up_url, 'B_COOKIE', body_bytes, 'application/json')}\n```\n\n"
        f"3. As account A, re-read the object and observe B's change landed:\n\n"
        f"```bash\n{_curl('GET', read_url, 'A_COOKIE')}\n```\n\n"
        f"Field `{mf}` is now `{atkv}`, written by account B. "
        f"{row['write_detail']}\n\n"
        "## Impact\n\n"
        "A user can modify another user's data by referencing its id. Describe "
        "the concrete impact (tampering, takeover, fraud) for the report.\n\n"
        "_Generated by IGOR. Confirm by hand before submitting._\n"
    )
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# Config + scope.
# ---------------------------------------------------------------------------

# Headers applied to EVERY request IGOR sends, in every mode. Populated from
# config.global_headers at load time. This is where a program's mandatory
# header (e.g. X-Bug-Bounty) lives so no request, not even the unauth
# baseline, can slip out without it.
GLOBAL_HEADERS = {}


def load_config(path):
    cfg = json.loads(Path(path).read_text())
    cfg.setdefault("sessions", {})
    cfg.setdefault("scope", [])
    cfg.setdefault("delay", 0.3)
    cfg.setdefault("auth_headers", DEFAULT_AUTH_HEADERS)
    cfg.setdefault("roles", {"owner": "A", "attacker": "B"})
    cfg.setdefault("global_headers", {})
    GLOBAL_HEADERS.clear()
    GLOBAL_HEADERS.update(cfg["global_headers"])
    return cfg


def in_scope(url: str, scope: list) -> bool:
    if not scope:
        return False  # empty scope = nothing allowed, on purpose
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    for s in scope:
        s = s.lower().lstrip(".")
        if host == s or host.endswith("." + s):
            return True
    return False


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------

# Transport/framework noise that is never an IDOR target: websocket handshakes,
# heartbeats, static i18n bundles. These slipped through before (socket.io's
# t=/sid= params looked like ids) and created false MEDs. Filtered everywhere.
NOISE_URL_RE = re.compile(r"/socket\.io/|/sockjs/|/__webpack|/assets/i18n/", re.I)
# Junk ids a crawler captures when the app had no real object loaded.
JUNK_ID_RE = re.compile(r"/(NaN|undefined|null)(/|$|\?)", re.I)


def is_noise(url: str) -> bool:
    return bool(NOISE_URL_RE.search(url) or JUNK_ID_RE.search(url))


def run(cfg, reqs, include_writes=False, out_csv="igor_report.csv", poc_dir="poc"):
    sessions = cfg["sessions"]
    owner = cfg["roles"]["owner"]
    attacker = cfg["roles"]["attacker"]
    strip = cfg["auth_headers"]
    delay = cfg["delay"]
    scope = cfg["scope"]

    if owner not in sessions or attacker not in sessions:
        sys.exit(f"[!] config.roles point at sessions {owner!r}/{attacker!r} "
                 f"but sessions defines {list(sessions)}")

    rows = []
    baseline_fail = 0   # for stale-session detection
    baseline_total = 0
    atk_fail = 0        # for dead-attacker-token detection
    atk_total = 0
    pocs = []
    for req in reqs:
        ids, has_ref = analyze_ids(req.url, req.body)
        id_str = " | ".join(f"{v}={note}" for v, note in ids)

        if is_noise(req.url):
            rows.append(dict(verdict="SKIP", method=req.method, url=req.url,
                             detail="transport/framework noise or junk id, not tested",
                             ids=id_str, source=req.source))
            print(f"{C.DIM}[skip] noise: {req.url}{C.END}")
            continue

        if not in_scope(req.url, scope):
            rows.append(dict(verdict="SKIP", method=req.method, url=req.url,
                             detail="OUT OF SCOPE, not sent", ids=id_str,
                             source=req.source))
            print(f"{C.DIM}[skip] out of scope: {req.url}{C.END}")
            continue

        # Read engine: only GET/HEAD auto-fire. Writes are the fixture path,
        # not blind replay, so here they are dry-run unless forced.
        if req.method not in ("GET", "HEAD") and not include_writes:
            rows.append(dict(verdict="SKIP", method=req.method, url=req.url,
                             detail="write method, dry-run (fixture testing not in read engine)",
                             ids=id_str, source=req.source))
            print(f"{C.YEL}[dry] {req.method} {req.url} (not sent){C.END}")
            continue

        base = send(req, sessions[owner].get("headers", {}), strip)
        time.sleep(delay)
        atk = send(req, sessions[attacker].get("headers", {}), strip)
        time.sleep(delay)
        un = send(req, {}, strip)  # unauthenticated
        time.sleep(delay)

        baseline_total += 1
        if base.status in (401, 403):
            baseline_fail += 1
        # Track the attacker side too: an all-401 attacker means a dead token,
        # which turns every real IDOR into a false PASS. We only count cases
        # where the owner baseline worked, so a 401 is attributable to B's
        # session rather than the endpoint itself.
        if 200 <= base.status < 300:
            atk_total += 1
            if atk.status in (401, 403):
                atk_fail += 1

        v_atk, note_atk = verdict_for(base, atk, f"B({attacker})")
        v_un, note_un = verdict_for(base, un, "unauth")

        # Unauth access to private data is its own finding: often worse than an
        # IDOR, and it also tells you the data might just be public.
        if v_un == "HIGH":
            verdict, detail = "PUBLIC", f"reachable with NO auth. {note_un}"
        else:
            verdict, detail = v_atk, note_atk

        # The gate: an IDOR needs a tamperable object reference. No id in the
        # path, query or body means a high body-match is just two similar
        # records, not a leak. Cap it at INFO so it does not create noise.
        if verdict in ("HIGH", "MED") and not has_ref:
            verdict = "INFO"
            detail = f"no object reference to tamper, not an IDOR candidate ({detail})"

        rows.append(dict(verdict=verdict, method=req.method, url=req.url,
                         detail=detail, ids=id_str, source=req.source,
                         base_status=base.status, atk_status=atk.status,
                         unauth_status=un.status))

        if poc_dir and verdict in ("HIGH", "PUBLIC"):
            p = write_run_poc(poc_dir, req, verdict, base, atk, un, attacker)
            pocs.append(p)

        color = {"HIGH": C.RED, "PUBLIC": C.RED, "MED": C.YEL}.get(verdict, C.DIM)
        print(f"{color}[{verdict:4}]{C.END} {req.method} {req.url}  {C.DIM}{detail}{C.END}")

    # Stale-session guard: if the owner baseline was rejected across the board,
    # the cookie is almost certainly dead and every verdict is untrustworthy.
    if baseline_total >= 3 and baseline_fail == baseline_total:
        print(f"\n{C.RED}{C.BLD}[!] every account-A baseline came back "
              f"401/403.{C.END} Your owner cookie is probably expired. Re-grab "
              f"it and rerun; do not trust these results.")

    # Dead-attacker-token guard: owner worked but attacker was rejected on
    # everything. Every PASS here is a false pass, there could be IDORs that
    # look safe only because B has no valid session. This is the silent
    # false-negative that all-green runs hide.
    if atk_total >= 3 and atk_fail == atk_total:
        print(f"\n{C.RED}{C.BLD}[!] account-B was rejected (401/403) on every "
              f"endpoint the owner could reach.{C.END} Your ATTACKER token is "
              f"almost certainly dead or still a placeholder. Every PASS above "
              f"is meaningless, a real IDOR would look identical. Put a valid "
              f"account-B token in the config and rerun.")

    rows.sort(key=lambda r: RANK.get(r["verdict"], 9))
    write_csv(rows, out_csv)

    hi = sum(1 for r in rows if r["verdict"] in ("HIGH", "PUBLIC"))
    md = sum(1 for r in rows if r["verdict"] == "MED")
    print(f"\n{C.BLD}Done.{C.END} {len(rows)} endpoints. "
          f"{C.RED}{hi} likely{C.END}, {C.YEL}{md} worth a look{C.END}. "
          f"Report: {out_csv}")
    if pocs:
        print(f"{C.GRN}{len(pocs)} PoC(s) written to {poc_dir}/{C.END}")
    return rows


def write_csv(rows, path):
    cols = ["verdict", "method", "url", "detail", "ids", "base_status",
            "atk_status", "unauth_status", "source"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


# ---------------------------------------------------------------------------
# Write-side testing via fixtures.
#
# The rule: never touch an object we did not create. We create throwaway
# objects as each account, then test whether the other account can read or
# change THOSE. A registry of every id we minted this session gates every
# mutating request, so the engine is structurally unable to hit real data.
# ---------------------------------------------------------------------------

class FixtureRegistry:
    def __init__(self):
        self._ids = set()          # (resource, id) pairs we created

    def mint(self, resource, oid):
        self._ids.add((resource, str(oid)))

    def owns(self, resource, oid):
        return (resource, str(oid)) in self._ids

    def guard(self, resource, oid):
        """Raise rather than send a mutating request at an id we did not
        create. This is the seatbelt for the whole write engine."""
        if not self.owns(resource, oid):
            raise RuntimeError(
                f"REFUSING to send a write at {resource}/{oid}: not a fixture "
                f"this session created. This guard protects real data.")


def _dotted_get(obj, path):
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def extract_id(resp: "Resp", id_from: str):
    """Pull the new object's id out of a create response.
    id_from is 'header:Location', 'body:id', or 'body:data.id' (dotted)."""
    if id_from.startswith("header:"):
        name = id_from[len("header:"):]
        val = None
        for k, v in (resp.headers or {}).items():
            if k.lower() == name.lower():
                val = v
                break
        if not val:
            return None
        # a Location is usually a URL or path; take the last non-empty segment
        seg = [s for s in val.split("?")[0].rstrip("/").split("/") if s]
        return seg[-1] if seg else None
    if id_from.startswith("body:"):
        try:
            obj = json.loads(resp.body or b"{}")
        except Exception:
            return None
        val = _dotted_get(obj, id_from[len("body:"):])
        return str(val) if val is not None else None
    return None


def build_req(template: dict, subs: dict) -> Req:
    """Turn a resource-spec step into a Req, substituting {id} etc."""
    url = template["url"]
    for k, v in subs.items():
        url = url.replace("{" + k + "}", str(v))
    body = template.get("body")
    headers = dict(template.get("headers", {}))
    if isinstance(body, (dict, list)):
        raw = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        raw = body.encode()
    else:
        raw = b""
    return Req(method=template["method"].upper(), url=url, headers=headers, body=raw)


def _read_field(resp: "Resp", field: str):
    try:
        obj = json.loads(resp.body or b"{}")
    except Exception:
        return None
    return _dotted_get(obj, field)


def run_write_tests(cfg, resources, out_csv="igor_write_report.csv", poc_dir="poc"):
    sessions = cfg["sessions"]
    owner = cfg["roles"]["owner"]
    attacker = cfg["roles"]["attacker"]
    strip = cfg["auth_headers"]
    delay = cfg["delay"]
    scope = cfg["scope"]

    a_hdr = sessions[owner].get("headers", {})
    b_hdr = sessions[attacker].get("headers", {})
    reg = FixtureRegistry()
    rows = []
    created = []   # (res_spec, aid) for teardown
    pocs = []

    def fire(template, subs, who):
        r = build_req(template, subs)
        if not in_scope(r.url, scope):
            raise RuntimeError(f"out of scope: {r.url}")
        res = send(r, a_hdr if who == "A" else b_hdr, strip)
        time.sleep(delay)
        return res

    for res_spec in resources:
        name = res_spec["name"]
        row = dict(resource=name, read_verdict="-", write_verdict="-",
                   read_detail="", write_detail="")

        # 1. CREATE a fixture as A
        try:
            c = fire(res_spec["create"], {}, "A")
        except RuntimeError as e:
            row.update(write_verdict="SKIP", write_detail=str(e))
            rows.append(row); _print_write(row); continue
        if not (200 <= c.status < 300):
            row.update(write_verdict="SKIP",
                       write_detail=f"create as A failed ({c.status}), cannot test")
            rows.append(row); _print_write(row); continue
        aid = extract_id(c, res_spec.get("id_from", "body:id"))
        if not aid:
            row.update(write_verdict="SKIP",
                       write_detail="could not extract new id from create response")
            rows.append(row); _print_write(row); continue
        reg.mint(name, aid)
        row["fixture_id"] = aid
        created.append((res_spec, aid))

        # 2. READ test: can B read A's fresh object?
        if "read" in res_spec:
            base = fire(res_spec["read"], {"id": aid}, "A")
            atk = fire(res_spec["read"], {"id": aid}, "B")
            v, note = verdict_for(base, atk, f"B({attacker})")
            row["read_verdict"] = v
            row["read_detail"] = note

        # 3. WRITE test with a positive control, then the attack.
        if "update" in res_spec:
            up = res_spec["update"]
            mf = up["marker_field"]
            ctrl, atkv = up["control_value"], up["attack_value"]

            # 3a. control: A updates its own object. Proves the field is
            # actually writable, so a "no change" in 3c means protected, not
            # inert. Without this the oracle lies.
            up_ctrl = dict(up); up_ctrl["body"] = dict(up.get("body", {}))
            up_ctrl["body"][mf] = ctrl
            reg.guard(name, aid)
            fire(up_ctrl, {"id": aid}, "A")
            check = fire(res_spec["read"], {"id": aid}, "A")
            if _read_field(check, mf) != ctrl:
                row.update(write_verdict="SKIP",
                           write_detail=f"{mf} not writable even by owner, cannot test write IDOR")
                rows.append(row); _print_write(row); continue

            # 3b. attack: B updates A's object with a different marker.
            up_atk = dict(up); up_atk["body"] = dict(up.get("body", {}))
            up_atk["body"][mf] = atkv
            reg.guard(name, aid)       # seatbelt: only ever our fixture
            b_res = fire(up_atk, {"id": aid}, "B")

            # 3c. oracle: A re-reads. Did B's marker land?
            after = fire(res_spec["read"], {"id": aid}, "A")
            landed = _read_field(after, mf)
            if landed == atkv:
                row.update(write_verdict="HIGH",
                           write_detail=f"B changed A's {mf} to {atkv!r}, confirmed by owner re-read")
            elif b_res.status in (401, 403):
                row.update(write_verdict="PASS",
                           write_detail=f"B blocked on write ({b_res.status})")
            else:
                row.update(write_verdict="LOW",
                           write_detail=f"B got {b_res.status} but A's {mf} unchanged, no real write")

        if poc_dir and row.get("write_verdict") == "HIGH":
            pocs.append(write_write_poc(poc_dir, res_spec, aid, row, attacker))
        rows.append(row); _print_write(row)

    # Teardown: A deletes its own fixtures so we don't litter the target.
    # Only own fixtures, only via the registry guard, owner session only.
    deleted, left = 0, []
    for res_spec, aid in created:
        dtpl = res_spec.get("delete")
        if not dtpl:
            left.append((res_spec["name"], aid))
            continue
        try:
            reg.guard(res_spec["name"], aid)   # cannot delete a non-fixture
            r = build_req(dtpl, {"id": aid})
            send(r, a_hdr, strip)
            time.sleep(delay)
            deleted += 1
        except Exception as e:
            left.append((res_spec["name"], aid))
    if deleted:
        print(f"{C.DIM}teardown: deleted {deleted} fixture(s){C.END}")
    if left:
        pretty = ", ".join(f"{n}/{i}" for n, i in left)
        print(f"{C.YEL}[!] left {len(left)} fixture(s) on target "
              f"(no delete template): {pretty}. Remove them by hand.{C.END}")

    rows.sort(key=lambda r: min(RANK.get(r["read_verdict"], 9),
                                RANK.get(r["write_verdict"], 9)))
    _write_write_csv(rows, out_csv)
    hi = sum(1 for r in rows if "HIGH" in (r["read_verdict"], r["write_verdict"]))
    print(f"\n{C.BLD}Write tests done.{C.END} {len(rows)} resources. "
          f"{C.RED}{hi} with a confirmed IDOR{C.END}. Report: {out_csv}")
    if pocs:
        print(f"{C.GRN}{len(pocs)} PoC(s) written to {poc_dir}/{C.END}")
    return rows


def _print_write(row):
    for kind, dkey, tag in (("read_verdict", "read_detail", "READ "),
                            ("write_verdict", "write_detail", "WRITE")):
        v = row.get(kind, "-")
        if v in ("-", "SKIP"):
            continue
        color = {"HIGH": C.RED}.get(v, C.DIM)
        print(f"{color}[{tag} {v:4}]{C.END} {row['resource']}  {C.DIM}{row.get(dkey,'')}{C.END}")
    if row.get("write_verdict") == "SKIP" and row.get("read_verdict") in ("-", "SKIP"):
        print(f"{C.YEL}[skip]{C.END} {row['resource']}  {C.DIM}{row.get('write_detail','')}{C.END}")


def _write_write_csv(rows, path):
    cols = ["resource", "read_verdict", "read_detail", "write_verdict",
            "write_detail", "fixture_id"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def cmd_writetest(args):
    cfg = load_config(args.config)
    if not cfg["scope"]:
        sys.exit("[!] scope is empty. Add target hosts to config.scope.")
    resources = json.loads(Path(args.resources).read_text())
    print(f"{C.YEL}[!] write testing creates throwaway objects on the target. "
          f"Keep it to targets where that is in scope.{C.END}")
    run_write_tests(cfg, resources, out_csv=args.out,
                    poc_dir=None if args.no_poc else args.poc_dir)


# ---------------------------------------------------------------------------
# Discovery via katana (optional). Turns a seed URL into a target list.
# ---------------------------------------------------------------------------

# State-changing GETs that an authenticated crawl must not follow, or katana
# logs itself out partway through and the rest of the crawl is unauthenticated
# junk. This is the single most common way an auth crawl silently fails.
DANGER_PATH_RE = re.compile(
    r"(logout|log-off|logoff|signout|sign-out|/delete|/destroy|/remove|"
    r"/revoke|/deactivate)", re.I)


def _headers_to_katana(headers: dict):
    """Turn a session's headers dict into repeated -H args for katana."""
    args = []
    for name, value in (headers or {}).items():
        args += ["-H", f"{name}: {value}"]
    return args


def template_key(url: str) -> str:
    """Collapse concrete IDs to {id} so /users/1 and /users/2 map to the same
    endpoint. You only need one representative per endpoint to test the class.
    This is what stops a crawl of 4000 URLs becoming 4000 swap tests."""
    parts = urlsplit(url)
    segs = []
    for seg in parts.path.split("/"):
        if UUID_RE.fullmatch(seg) or (seg.isdigit() and len(seg) >= 1):
            segs.append("{id}")
        else:
            segs.append(seg)
    qkeys = sorted(k for k, _ in parse_qsl(parts.query))
    return f"{parts.netloc}{'/'.join(segs)}?{'&'.join(qkeys)}"


def filter_crawl(urls, scope, keep_no_id=False):
    """From raw crawled URLs, keep in-scope, drop dangerous paths, dedupe by
    endpoint template, and prefer the ones carrying an object reference.
    Returns (targets, stats)."""
    seen_templates = {}
    out = []
    stats = dict(raw=0, out_of_scope=0, dangerous=0, noise=0, no_id=0, kept=0)
    for url in urls:
        url = url.strip()
        if not url or not url.lower().startswith("http"):
            continue
        stats["raw"] += 1
        if not in_scope(url, scope):
            stats["out_of_scope"] += 1
            continue
        if is_noise(url):
            stats["noise"] += 1
            continue
        if DANGER_PATH_RE.search(url):
            stats["dangerous"] += 1
            continue
        key = template_key(url)
        if key in seen_templates:
            continue
        _, has_ref = analyze_ids(url)
        if not has_ref and not keep_no_id:
            stats["no_id"] += 1
            continue
        seen_templates[key] = True
        out.append({"method": "GET", "url": url, "headers": {}})
        stats["kept"] += 1
    return out, stats


def cmd_crawl(args):
    cfg = load_config(args.config)
    if not cfg["scope"]:
        sys.exit("[!] scope is empty. Add target hosts to config.scope before crawling.")
    if not shutil.which("katana"):
        sys.exit("[!] katana not found on PATH. Install it:\n"
                 "    go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
                 "    (or: brew install katana)")

    session = args.session or cfg["roles"]["owner"]
    headers = cfg["sessions"].get(session, {}).get("headers", {})
    if not headers:
        print(f"{C.YEL}[!] session {session!r} has no headers, crawling "
              f"UNauthenticated. You will miss the logged-in surface.{C.END}")

    scope_hosts = [re.sub(r"^https?://", "", s).split("/")[0] for s in cfg["scope"]]

    cmd = ["katana", "-u", args.url, "-jc", "-silent", "-d", str(args.depth)]
    for h in scope_hosts:
        cmd += ["-cs", h]              # stay on the in-scope hosts
    cmd += ["-cos", DANGER_PATH_RE.pattern]  # never crawl logout/delete links
    cmd += _headers_to_katana(headers)
    cmd += _headers_to_katana(GLOBAL_HEADERS)  # mandatory program headers on the crawl too
    if args.extra:
        cmd += args.extra.split()

    print(f"{C.DIM}running: katana -u {args.url} -jc -d {args.depth} "
          f"(as session {session}){C.END}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as e:
        print(f"{C.YEL}[!] katana hit the {args.timeout}s timeout, using what it found.{C.END}")
        proc = e
    urls = (proc.stdout or "").splitlines()

    targets, stats = filter_crawl(urls, cfg["scope"], keep_no_id=args.keep_no_id)
    Path(args.out).write_text(json.dumps(targets, indent=2))

    print(f"\n{C.BLD}Crawl done.{C.END}")
    print(f"  {stats['raw']} urls crawled")
    print(f"  {C.DIM}-{stats['out_of_scope']} out of scope, "
          f"-{stats['dangerous']} dangerous paths, -{stats['noise']} noise, "
          f"-{stats['no_id']} with no id to tamper{C.END}")
    print(f"  {C.GRN}{stats['kept']} distinct endpoints worth testing{C.END} -> {args.out}")
    print(f"\nNext: python3 igor.py run -c {args.config} -t {args.out}")


# ---------------------------------------------------------------------------
# Import a Burp export (proxy history / sitemap XML). If the traffic was
# captured through PwnFox, requests carry X-PwnFox-Color, so we split sessions
# by color automatically: no hand-copying cookies.
# ---------------------------------------------------------------------------

def parse_burp_xml(path):
    """Return a list of Req from a Burp XML export."""
    import xml.etree.ElementTree as ET
    root = ET.parse(path).getroot()
    reqs = []
    for item in root.findall("item"):
        rel = item.find("request")
        if rel is None or not (rel.text or "").strip():
            continue
        raw = rel.text.strip()
        if (rel.get("base64") or "").lower() == "true":
            try:
                raw = base64.b64decode(raw).decode(errors="replace")
            except Exception:
                continue
        try:
            req = parse_raw_http(raw, source="burp")
        except Exception:
            continue
        # Burp stores the absolute url and protocol separately; prefer them so
        # https is correct instead of guessed.
        u = item.find("url")
        if u is not None and (u.text or "").startswith("http"):
            req.url = u.text.strip()
        reqs.append(req)
    return reqs


def _auth_headers_of(req, auth_names):
    out = {}
    for name, value in req.headers.items():
        if name.lower() in auth_names:
            out[name] = value
    return out


def cmd_import(args):
    auth_names = set(h.lower() for h in DEFAULT_AUTH_HEADERS)
    reqs = parse_burp_xml(args.input)
    if not reqs:
        sys.exit("[!] no requests parsed from that export.")

    # group by pwnfox color
    by_color = {}
    hosts = set()
    for r in reqs:
        by_color.setdefault(r.pwnfox_color or "nocolor", []).append(r)
        hosts.add(re.sub(r"^https?://", "", r.url).split("/")[0].split(":")[0])

    # per color, the auth headers are whatever that color's traffic carried.
    # take the most common cookie so one stray request doesn't poison it.
    from collections import Counter
    sessions = {}
    for color, rs in by_color.items():
        if color == "nocolor":
            continue
        cookies = Counter()
        hdrs = {}
        for r in rs:
            a = _auth_headers_of(r, auth_names)
            if "Cookie" in a:
                cookies[a["Cookie"]] += 1
            for k, v in a.items():
                if k.lower() != "cookie":
                    hdrs[k] = v
        if cookies:
            hdrs["Cookie"] = cookies.most_common(1)[0][0]
        sessions[color] = {"headers": hdrs}

    print(f"{C.BLD}Parsed {len(reqs)} requests.{C.END}")
    for color, rs in by_color.items():
        print(f"  {color}: {len(rs)} requests")

    if not sessions:
        print(f"{C.YEL}[!] no X-PwnFox-Color headers found. This export was not "
              f"captured through PwnFox, so sessions can't be split automatically. "
              f"Targets were still written; set sessions in the config by hand.{C.END}")

    # dedupe targets by endpoint template
    seen, targets = set(), []
    for r in reqs:
        key = (r.method, template_key(r.url))
        if key in seen:
            continue
        seen.add(key)
        targets.append({"method": r.method, "url": r.url,
                        "body": r.body.decode(errors="replace") if r.body else ""})
    Path(args.targets_out).write_text(json.dumps(targets, indent=2))

    # map colors to roles if the user named them
    roles = {"owner": "A", "attacker": "B"}
    color_list = [c for c in sessions]
    if args.owner_color and args.attacker_color:
        roles = {"owner": args.owner_color, "attacker": args.attacker_color}
    elif len(color_list) >= 2:
        roles = {"owner": color_list[0], "attacker": color_list[1]}
        print(f"{C.YEL}[!] guessed roles owner={color_list[0]} "
              f"attacker={color_list[1]}. Set --owner-color/--attacker-color "
              f"to control this.{C.END}")

    config = {
        "scope": sorted(hosts),
        "delay": 0.3,
        "roles": roles,
        "auth_headers": DEFAULT_AUTH_HEADERS,
        "sessions": sessions or {"A": {"headers": {}}, "B": {"headers": {}}},
    }
    Path(args.config_out).write_text(json.dumps(config, indent=2))

    print(f"\n{C.GRN}Wrote {args.config_out}{C.END} (scope + sessions) and "
          f"{C.GRN}{args.targets_out}{C.END} ({len(targets)} endpoints).")
    print(f"{C.YEL}Check the scope list before running.{C.END}")
    print(f"\nNext: python3 igor.py run -c {args.config_out} -t {args.targets_out}")


# ---------------------------------------------------------------------------
# Enumeration: walk neighbor IDs as the attacker to harvest others' objects.
# Read-only (GET), scope-gated, throttled, hard-capped.
# ---------------------------------------------------------------------------

ENUM_HARD_CAP = 500


def find_pivot(url: str):
    """Replace the last numeric path segment with {id} and return
    (template, base_int). This is the id we pivot the range around."""
    parts = urlsplit(url)
    segs = parts.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            base = int(segs[i])
            segs[i] = "{id}"
            tmpl = parts._replace(path="/".join(segs)).geturl()
            return tmpl, base
    return None, None


def cmd_enum(args):
    cfg = load_config(args.config)
    scope = cfg["scope"]
    strip = cfg["auth_headers"]
    delay = cfg["delay"]
    session = args.session or cfg["roles"]["attacker"]
    hdr = cfg["sessions"].get(session, {}).get("headers", {})

    if "{id}" in args.url:
        tmpl, base = args.url, (args.start if args.start is not None else 1)
    else:
        tmpl, base = find_pivot(args.url)
        if tmpl is None:
            sys.exit("[!] no numeric id in the URL to pivot on. Pass a URL with "
                     "a number, or a template with {id} plus --start.")

    if args.start is not None and args.end is not None:
        lo, hi = args.start, args.end
    else:
        lo, hi = base - args.range, base + args.range
    lo = max(lo, 0)
    ids = list(range(lo, hi + 1))
    if len(ids) > ENUM_HARD_CAP:
        sys.exit(f"[!] range is {len(ids)} ids, over the {ENUM_HARD_CAP} cap. "
                 f"Narrow it. Enumeration should be targeted, not a DoS.")

    sample = tmpl.replace("{id}", str(base))
    if not in_scope(sample, scope):
        sys.exit(f"[!] out of scope: {sample}")

    print(f"{C.DIM}enumerating {tmpl} over {lo}..{hi} as session {session}{C.END}")
    rows, bodies = [], {}
    for i in ids:
        url = tmpl.replace("{id}", str(i))
        r = send(Req("GET", url, {}), hdr, strip)
        time.sleep(delay)
        hit = 200 <= r.status < 300 and r.length > 0
        rows.append(dict(id=i, status=r.status, length=r.length, accessible=hit))
        if hit:
            bodies[i] = r.body
            print(f"{C.RED}[{r.status}]{C.END} {url}  {C.DIM}{r.length} bytes{C.END}")
        else:
            print(f"{C.DIM}[{r.status}] {url}{C.END}")

    # Distinct-record check: if the accessible bodies differ from each other,
    # you are pulling different objects, which is the real harvest signal
    # rather than the same shared page echoed back.
    distinct = len({b[:500] for b in bodies.values()})
    accessible = [r for r in rows if r["accessible"]]

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "status", "length", "accessible"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"\n{C.BLD}Enumeration done.{C.END} {len(ids)} ids tried, "
          f"{C.RED}{len(accessible)} accessible as {session}{C.END}, "
          f"{distinct} distinct record(s). Report: {args.out}")
    if len(accessible) > 1 and distinct > 1:
        print(f"{C.RED}Multiple distinct objects reachable by walking the id. "
              f"Confirm they belong to other users, that is your IDOR.{C.END}")


# ---------------------------------------------------------------------------
# SPA spider. Katana can't crawl a single-page app because it never runs the
# app's JavaScript. This drives a real headless browser, logs in, walks the
# app, and records every XHR/fetch the SPA fires. That is the only honest way
# to discover an SPA's API surface. Playwright is an optional dependency; the
# rest of IGOR stays zero-dep.
# ---------------------------------------------------------------------------

STATIC_EXT = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|avif)(\?|$)", re.I)


def _looks_api(url, resource_type):
    """Keep real API calls, drop static assets and transport noise. XHR/fetch
    is the strong signal; extension and noise checks are backstops."""
    if resource_type in ("xhr", "fetch"):
        return not STATIC_EXT.search(url) and not is_noise(url)
    return False


def _dig_token(obj):
    """Find a login token anywhere in a JSON login response. Handles the
    common shapes: {token}, {data:{token}}, {authentication:{token}},
    {data:{authentication:{token}}}, and {access_token}/{accessToken}."""
    if not isinstance(obj, (dict, list)):
        return None
    keys = ("token", "access_token", "accessToken", "jwt", "id_token", "idToken")
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k in keys:
                v = cur.get(k)
                if isinstance(v, str) and len(v) > 20:
                    return v.replace("Bearer ", "").strip()
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def cmd_spider(args):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        sys.exit("[!] playwright not installed. This is the one optional dep.\n"
                 "    pip install playwright --break-system-packages\n"
                 "    playwright install chromium")

    cfg = load_config(args.config)
    scope = cfg["scope"]
    if not scope:
        sys.exit("[!] scope is empty. Add target hosts to config.scope before spidering.")
    session = args.session or cfg["roles"]["owner"]
    sess_headers = cfg["sessions"].get(session, {}).get("headers", {})
    extra_headers = {**GLOBAL_HEADERS, **sess_headers}

    # token to seed into localStorage for SPAs that read auth from there
    token_val = args.token_value
    if not token_val:
        for k, v in sess_headers.items():
            if k.lower() == "authorization":
                token_val = v.replace("Bearer ", "").strip()
    captured = {}   # (method, template) -> {method,url,body}

    def on_request(req):
        try:
            url = req.url
            if not in_scope(url, scope):
                return
            if not _looks_api(url, req.resource_type):
                return
            key = (req.method, template_key(url))
            if key in captured:
                return
            body = req.post_data or ""
            captured[key] = {"method": req.method, "url": url, "body": body}
        except Exception:
            pass

    origin = re.sub(r"^(https?://[^/]+).*", r"\1", args.url)
    print(f"{C.DIM}spidering {args.url} as session {session} "
          f"(headless, {args.timeout}s budget){C.END}")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headful)
        ctx = browser.new_context(extra_http_headers=extra_headers or {})

        # Login step: POST credentials in-browser and take the token from the
        # response. This establishes a session the app actually recognizes,
        # instead of hoping a pre-grabbed token is enough. The token is then
        # set BOTH in localStorage and as a cookie, because apps read auth from
        # one or the other and a cookie is what most servers check.
        if args.login_url and args.login_email:
            body = {args.login_field_email: args.login_email,
                    args.login_field_password: args.login_password or ""}
            try:
                r = ctx.request.post(
                    args.login_url,
                    data=json.dumps(body),
                    headers={"Content-Type": "application/json", **GLOBAL_HEADERS})
                obj = r.json()
                tok = _dig_token(obj)
                if tok:
                    token_val = tok
                    print(f"{C.GRN}logged in via {args.login_url} "
                          f"(HTTP {r.status}), token acquired{C.END}")
                else:
                    print(f"{C.YEL}[!] login returned HTTP {r.status} but no token "
                          f"found in the response. Check --token-json-path.{C.END}")
            except Exception as e:
                print(f"{C.YEL}[!] login request failed: {e}{C.END}")

        if token_val:
            # cookie (most servers read this) + localStorage (SPA client reads
            # this). Belt and suspenders so the app is actually authenticated.
            try:
                ctx.add_cookies([{"name": args.token_key, "value": token_val,
                                  "url": origin}])
            except Exception:
                pass
            ctx.add_init_script(
                f"try{{localStorage.setItem({json.dumps(args.token_key)}, {json.dumps(token_val)});}}catch(e){{}}")
        page = ctx.new_page()
        page.on("request", on_request)

        deadline = time.time() + args.timeout
        visited = set()

        def settle():
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

        try:
            page.goto(args.url, timeout=20000)
            settle()
            # Give the authenticated app time to bootstrap from the seeded
            # token (resolve the logged-in user, basket id, etc.) THEN reload
            # once, so the second pass fires calls with real object ids instead
            # of NaN/undefined. This is what makes the flow reach the real bugs.
            if token_val:
                page.wait_for_timeout(1500)
                try:
                    page.goto(args.url, timeout=20000)
                    settle()
                except Exception:
                    pass
                # sanity: confirm the session actually took
                try:
                    # Soft auth probe. Only warn on a clear anonymous result
                    # from a real whoami-shaped response; stay quiet if the app
                    # has no such endpoint (returns 'na'), so non-Juice-Shop
                    # targets don't get a false warning.
                    who = page.evaluate(
                        "async()=>{try{const r=await fetch('/rest/user/whoami');"
                        "if(!r.ok) return 'na';"
                        "const j=await r.json();"
                        "if(!j||!('user' in j)) return 'na';"
                        "const u=j.user;"
                        "return (u&&(u.id||u.email))?'ok':'anon';}"
                        "catch(e){return 'na';}}")
                    if who == "anon":
                        print(f"{C.YEL}[!] the seeded token did not log the app in "
                              f"(whoami is anonymous). Check the token/login and "
                              f"--token-key; authenticated endpoints may be missed.{C.END}")
                    elif who == "ok":
                        print(f"{C.GRN}authenticated session confirmed (whoami).{C.END}")
                except Exception:
                    pass
        except Exception as e:
            print(f"{C.YEL}[!] initial load issue: {e}{C.END}")

        # gather in-app routes (hrefs incl. hash routes) and queue same-origin
        def collect_links():
            try:
                return page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)") or []
            except Exception:
                return []

        queue = [u for u in collect_links() if u.startswith(origin)]
        pages_done = 0

        # click non-navigating controls on the current view to trigger XHR
        def click_controls():
            nonlocal_clicks = 0
            try:
                handles = page.query_selector_all(
                    "button, [role=button], [type=submit]")
            except Exception:
                handles = []
            for h in handles[:args.max_clicks]:
                if time.time() > deadline:
                    break
                try:
                    h.click(timeout=1500, no_wait_after=True)
                    nonlocal_clicks += 1
                    page.wait_for_timeout(250)
                except Exception:
                    continue
            return nonlocal_clicks

        click_controls()
        while queue and pages_done < args.max_pages and time.time() < deadline:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                page.goto(url, timeout=15000)
                settle()
                click_controls()
                pages_done += 1
                for u in collect_links():
                    if u.startswith(origin) and u not in visited:
                        queue.append(u)
            except Exception:
                continue

        browser.close()

    targets = sorted(captured.values(), key=lambda r: (r["method"], r["url"]))
    Path(args.out).write_text(json.dumps(targets, indent=2))

    # scaffold resources.json for write-testing by grouping CRUD on each path
    resources = scaffold_resources(captured)
    if resources and args.resources_out:
        Path(args.resources_out).write_text(json.dumps(resources, indent=2))

    print(f"\n{C.BLD}Spider done.{C.END} "
          f"{C.GRN}{len(targets)} distinct API endpoints captured{C.END} -> {args.out}")
    if resources:
        print(f"{C.GRN}{len(resources)} resource(s) with CRUD scaffolded{C.END} "
              f"-> {args.resources_out}  (fill marker_field/values before writetest)")
    print(f"\nNext: python3 igor.py run -c {args.config} -t {args.out}")


def scaffold_resources(captured):
    """From captured requests, group create/read/update by collection path so
    writetest has a starting resources.json instead of being hand-authored."""
    from urllib.parse import urlsplit
    # map collection path -> {create, read, update}
    groups = {}
    for (method, tmpl), rec in captured.items():
        parts = urlsplit(rec["url"])
        segs = [s for s in parts.path.split("/") if s]
        if not segs:
            continue
        has_id = "{id}" in tmpl
        collection = "/".join(parts.path.rstrip("/").split("/")[:-1]) if has_id else parts.path.rstrip("/")
        name = (collection.strip("/").split("/")[-1] or "resource")
        g = groups.setdefault(name, {"collection": collection})
        base = f"{parts.scheme}://{parts.netloc}"
        if method == "POST" and not has_id:
            g["create"] = {"method": "POST", "url": rec["url"], "body": {}}
        elif method == "GET" and has_id:
            g["read"] = {"method": "GET", "url": base + re.sub(r"/\d+", "/{id}", parts.path)}
        elif method in ("PUT", "PATCH") and has_id:
            g["update"] = {"method": method, "url": base + re.sub(r"/\d+", "/{id}", parts.path),
                           "body": {}, "marker_field": "FILL_ME",
                           "control_value": "igor_ctl", "attack_value": "igor_pwned"}
    out = []
    for name, g in groups.items():
        if "create" in g and "read" in g:   # need at least create+read to test
            entry = {"name": name, "create": g["create"], "id_from": "body:id",
                     "read": g["read"]}
            if "update" in g:
                entry["update"] = g["update"]
            out.append(entry)
    return out


def cmd_decode(args):
    """Standalone decoder, for when you just want to crack one ID."""
    for value in args.values:
        print(f"{C.BLD}{value}{C.END}")
        if UUID_RE.fullmatch(value):
            print(f"  {classify_uuid(value)}")
        dec = try_decode(value)
        if dec:
            print(f"  {dec}")
        elif not UUID_RE.fullmatch(value):
            print(f"  no native decode. CyberChef Magic:")
            print(f"  {C.DIM}{cyberchef_link(value)}{C.END}")


def main():
    ap = argparse.ArgumentParser(
        description="IGOR - IDOR hunting assistant. "
                    "import | crawl | run | writetest | enum | decode")
    sub = ap.add_subparsers(dest="cmd")

    rp = sub.add_parser("run", help="replay + swap test captured requests")
    rp.add_argument("-c", "--config", required=True)
    rp.add_argument("-t", "--targets", nargs="+", required=True,
                    help="raw request files/dirs or a targets.json")
    rp.add_argument("-o", "--out", default="igor_report.csv")
    rp.add_argument("--poc-dir", default="poc", help="where to write PoC files")
    rp.add_argument("--no-poc", action="store_true", help="don't write PoC files")
    rp.add_argument("--include-writes", action="store_true",
                    help="DANGER: actually send POST/PUT/PATCH/DELETE. "
                         "The read engine has no fixture safety yet, so this "
                         "blind-fires writes. Leave off unless you know why.")

    cp = sub.add_parser("crawl", help="discover endpoints with katana into a target list")
    cp.add_argument("-c", "--config", required=True)
    cp.add_argument("-u", "--url", required=True, help="seed URL to crawl")
    cp.add_argument("-o", "--out", default="targets.json")
    cp.add_argument("--session", help="which config session to crawl as (default: the owner role)")
    cp.add_argument("-d", "--depth", type=int, default=3)
    cp.add_argument("--timeout", type=int, default=180, help="katana time budget, seconds")
    cp.add_argument("--keep-no-id", action="store_true",
                    help="keep endpoints with no detectable id (noisier, catches header/body refs)")
    cp.add_argument("--extra", help="extra flags passed straight to katana, quoted")

    wp = sub.add_parser("writetest", help="fixture-based CRUD IDOR testing")
    wp.add_argument("-c", "--config", required=True)
    wp.add_argument("-r", "--resources", required=True, help="resources.json spec")
    wp.add_argument("-o", "--out", default="igor_write_report.csv")
    wp.add_argument("--poc-dir", default="poc", help="where to write PoC files")
    wp.add_argument("--no-poc", action="store_true", help="don't write PoC files")

    ip = sub.add_parser("import", help="import a Burp/PwnFox export into a config + targets")
    ip.add_argument("-i", "--input", required=True, help="Burp XML export (proxy history or sitemap)")
    ip.add_argument("--config-out", default="igor.config.json")
    ip.add_argument("--targets-out", default="targets.json")
    ip.add_argument("--owner-color", help="PwnFox color of the owner/victim account")
    ip.add_argument("--attacker-color", help="PwnFox color of the attacker account")

    ep = sub.add_parser("enum", help="walk neighbor ids as the attacker to harvest objects")
    ep.add_argument("-c", "--config", required=True)
    ep.add_argument("-u", "--url", required=True, help="URL with a numeric id, or a template with {id}")
    ep.add_argument("--session", help="which session to enumerate as (default: attacker role)")
    ep.add_argument("--range", type=int, default=10, help="ids to try on each side of the pivot")
    ep.add_argument("--start", type=int, help="explicit range start (with --end)")
    ep.add_argument("--end", type=int, help="explicit range end (with --start)")
    ep.add_argument("-o", "--out", default="igor_enum.csv")

    sp = sub.add_parser("spider", help="SPA crawler: drive a headless browser, capture XHR into targets")
    sp.add_argument("-c", "--config", required=True)
    sp.add_argument("-u", "--url", required=True, help="seed URL to spider")
    sp.add_argument("-o", "--out", default="targets.json")
    sp.add_argument("--resources-out", default="resources.scaffold.json",
                    help="write a writetest resources.json skeleton from captured CRUD")
    sp.add_argument("--session", help="which config session to drive as (default: owner)")
    sp.add_argument("--token-key", default="token",
                    help="localStorage/cookie key the app reads its auth token from (default: token)")
    sp.add_argument("--token-value", help="explicit token to seed; defaults to the session's Bearer token")
    sp.add_argument("--login-url", help="login endpoint to POST credentials to (establishes a real session)")
    sp.add_argument("--login-email", help="email/username for the login step")
    sp.add_argument("--login-password", help="password for the login step")
    sp.add_argument("--login-field-email", default="email", help="JSON field name for the email (default: email)")
    sp.add_argument("--login-field-password", default="password", help="JSON field name for the password (default: password)")
    sp.add_argument("--timeout", type=int, default=120, help="total crawl budget, seconds")
    sp.add_argument("--max-pages", type=int, default=25, help="max in-app routes to visit")
    sp.add_argument("--max-clicks", type=int, default=15, help="controls to click per view")
    sp.add_argument("--headful", action="store_true", help="show the browser (debug)")

    dp = sub.add_parser("decode", help="decode/classify IDs")
    dp.add_argument("values", nargs="+")

    args = ap.parse_args()
    if args.cmd == "spider":
        cmd_spider(args)
    elif args.cmd == "crawl":
        cmd_crawl(args)
    elif args.cmd == "import":
        cmd_import(args)
    elif args.cmd == "enum":
        cmd_enum(args)
    elif args.cmd == "writetest":
        cmd_writetest(args)
    elif args.cmd == "run":
        cfg = load_config(args.config)
        reqs = load_targets(args.targets)
        if not cfg["scope"]:
            print(f"{C.YEL}[!] scope is empty, so everything will be skipped. "
                  f"Add target hosts to config.scope.{C.END}")
        run(cfg, reqs, include_writes=args.include_writes, out_csv=args.out,
            poc_dir=None if args.no_poc else args.poc_dir)
    elif args.cmd == "decode":
        cmd_decode(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
