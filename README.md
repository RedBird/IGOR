# IGOR

A helper for hunting IDORs. Named after Frankenstein's Igor, because it does
the grunt work, not the thinking.

I built this because the boring part of IDOR testing is the same every time:
capture a request, replay it as a second account, replay it with no auth,
compare the three. Do that by hand across a few hundred endpoints and you
lose a whole evening to copy-paste. IGOR does the replay-and-compare loop so
I can spend my time deciding which leads are real.

That is the honest scope of it. IGOR does not find bugs for you. It shrinks a
big endpoint list down to the handful worth looking at by hand, and it decodes
the IDs inline so I am not flipping to a CyberChef tab for every one. Every
HIGH it prints is a lead, not a confirmed bug. You still have to judge whether
the leaked object actually matters.

## Where it fits

I do not run IGOR on its own. It is the last stage of a pipeline, and each
tool in front of it has a job IGOR does not try to duplicate:

```
scanner (katana / rad)  -> crawl the surface, find endpoints
burp                    -> capture real requests with bodies and auth
autorize                -> live swap-test as I browse, flags leads red/green
   |
   v
IGOR                    -> re-confirm the flagged ones deterministically,
                           write-test them safely, and generate a PoC
```

Autorize already does passive read-swap triage while you browse, and it does
it well, so IGOR is not trying to replace it. IGOR earns its place on the parts
Autorize does not cover: deterministic re-confirmation from a saved request
set, safe write-side testing, paste-ready PoCs, and running headless in a
script.

One thing I learned the hard way: a link crawler like katana cannot crawl a
single-page app. It does not run the app's JavaScript, so the real API calls
never show up. On an SPA the endpoints come from being logged in and actually
using the app through Burp, or from IGOR's own `spider`, not from pointing
katana at the homepage. If you crawl a logged-out marketing site you get
marketing pages, nothing to test.

## Commands

| Command     | What it does |
|-------------|--------------|
| `import`    | turn a Burp/PwnFox export into a config + target list, sessions split by color |
| `crawl`     | run katana and write a target list |
| `spider`    | drive a headless browser to discover an SPA's real endpoints |
| `run`       | read-side swap test, ranks leads, writes PoCs |
| `writetest` | fixture-based create/update IDOR testing, with teardown |
| `enum`      | walk neighbor ids as the attacker |
| `decode`    | decode or classify a single id |

## Zero dependencies

Pure Python 3.8+ stdlib. No pip step, nothing to break. Clone it and run it on
a stock Kali box or a cyberdeck with no network. The one exception is `spider`,
which needs Playwright. If Playwright is not installed, every other command
still works and only `spider` is unavailable.

## Mandatory program headers

Some programs make you send a header on every request or they treat your
traffic as a real attack and IP-ban you. Bugcrowd's `X-Bug-Bounty` is the one
I run into. Put it in `global_headers` and IGOR sends it on every request in
every mode, including the unauthenticated baseline and the crawl:

```json
"global_headers": { "X-Bug-Bounty": "Bugcrowd-yourname" }
```

This is not optional on programs that require it. I got the warning the hard
way, so it rides on everything now.

## Authorized use only

IGOR sends live requests at whatever you point it at. Only test what you own
or have written permission to test. The `scope` allowlist is the guardrail: any
host not in your config is skipped, never sent, so a fat-fingered URL does not
turn into an out-of-scope incident. Empty scope means nothing fires.

## How the swap test works

For each captured request, IGOR:

1. Sends it as account **A**, the owner. This is the control. A owns the object
   in the URL, so a 2xx with A's data is expected.
2. Sends the same request as account **B**, swapping only the auth headers.
3. Sends it with no auth at all.
4. Compares B and unauth against A's baseline.

| Verdict  | Meaning |
|----------|---------|
| `HIGH`   | B got a 2xx that closely matches A's data. Likely IDOR. |
| `PUBLIC` | Reachable with no auth. Could be worse than an IDOR, or just public. Judge the sensitivity. |
| `MED`    | B got a partial match. Look at it. |
| `LOW`    | B got a 2xx but different data, probably its own or empty. |
| `PASS`   | B was blocked (401/403). Access control is working. |
| `INFO`   | No object reference to tamper, so not a candidate. |
| `SKIP`   | Out of scope, or a write method in dry-run. Not sent. |

The rule that keeps it honest: a request with no tamperable id in its path,
query, or body cannot rank as a finding, no matter how similar the responses
look. Two users' records look alike. That is not a leak.

## Example output

`run` writes one row per endpoint to `report.csv`:

```
verdict | method | url                                   | base | atk | unauth
--------|--------|---------------------------------------|------|-----|-------
HIGH    | GET    | /rest/basket/7                        | 200  | 200 | 401
PUBLIC  | GET    | /rest/admin/application-configuration | 200  | 200 | 200
PASS    | GET    | /api/Users/26                         | 200  | 403 | 401
INFO    | GET    | /rest/products/search                 | 200  | -   | -
```

Reading the HIGH: account A owns basket 7. Account B, swapping only its auth,
got a 200 with A's basket contents. Unauthenticated got a 401, so the object
is not public. B reaching it is broken object-level authorization. IGOR flags
it HIGH. I still confirm the leaked data actually matters before reporting it.

## Usage

```bash
# 1. make a config
cp examples/igor.config.example.json igor.config.json
# edit: add target hosts to scope, paste both accounts' auth

# 2. capture requests as account A, or build a target list another way

# 3. run
python3 igor.py run -c igor.config.json -t requests/ -o report.csv
```

Decode an id on its own:

```bash
python3 igor.py decode f47ac10b-58cc-4372-a567-0e02b2c3d479 dXNlcl9pZDo0Mg==
```

UUIDs get classified, not decoded. A v4 is random so enumeration is dead. A v1
or v7 is time-based, so ids are roughly sequential and worth walking. Anything
IGOR cannot crack gets a CyberChef Magic link with the value preloaded.

## Input formats

- Raw HTTP request files saved from Burp (`.txt`, `.req`, `.http`), or a folder
  of them.
- A `targets.json`: a list of `{ "method", "url", "headers", "body" }`.

Local hosts (localhost, 127.x, :3000) default to http so Juice Shop works out
of the box. Everything else defaults to https.

## Import from Burp / PwnFox

If I captured traffic through Burp with PwnFox containers, I let IGOR build the
config and target list instead of hand-copying cookies. It splits sessions by
the `X-PwnFox-Color` header:

```bash
python3 igor.py import -i burp_export.xml --owner-color red --attacker-color blue
python3 igor.py run    -c igor.config.json -t targets.json
```

It writes `igor.config.json` (scope prefilled from the hosts it saw, one
session per color) and `targets.json` (deduped by endpoint). Check the scope
list before you run.

## Discovery on SPAs (spider)

Katana cannot see an SPA's API because it does not run the app's JavaScript.
`spider` drives a real headless browser, logs in, walks the app, and captures
every XHR and fetch it fires. That is the only honest way to find an SPA's
surface.

```bash
pip install playwright --break-system-packages && playwright install chromium   # one-time
python3 igor.py spider -c igor.config.json -u https://target/
python3 igor.py run    -c igor.config.json -t targets.json
```

For the browser to reach authenticated endpoints it needs a real session, not
just a token sitting in storage. Give it a login step and it posts your
credentials, takes the token from the response, and sets it as both a cookie
and localStorage, because apps read one or the other and the cookie is what
most servers actually check:

```bash
python3 igor.py spider -c igor.config.json -u http://localhost:3000/ \
  --login-url http://localhost:3000/rest/user/login \
  --login-email you@example.com --login-password yourpass
```

It prints `authenticated session confirmed` when the app is really logged in,
and warns if it is not, so I do not quietly crawl only the public surface. It
carries `global_headers` on every request, visits in-app and hash routes,
clicks non-navigating controls to trigger more calls, and writes `targets.json`.
It also drops a `resources.scaffold.json` for `writetest`, built from the
create/read/update calls it saw, so I am not hand-authoring the write tests from
scratch.

## Discovery with katana

If `katana` is on your PATH, IGOR can run it for you. Running it through IGOR
instead of standalone matters for one reason: IGOR carries your owner session
auth and your `global_headers` into the crawl, so the mandatory program header
is on every crawl request too.

```bash
python3 igor.py crawl -c igor.config.json -u https://api.example.com -o targets.json
python3 igor.py run   -c igor.config.json -t targets.json
```

The crawl stays on in-scope hosts, refuses to follow logout and delete links,
and collapses `/users/1`, `/users/2`, `/users/3` into one `/users/{id}` so I
test each endpoint once instead of a thousand times. Endpoints with no
tamperable id are dropped unless you pass `--keep-no-id`. On an SPA, expect this
to find less than you hope. That is the crawler's limit, not a bug.

## Write-side testing (fixtures)

`run` covers read IDORs. `writetest` covers create and update, safely. It never
touches a real object. It creates its own throwaway objects as each account and
tests whether the other account can read or change those.

```bash
python3 igor.py writetest -c igor.config.json -r resources.json
```

You describe each resource's CRUD requests in `resources.json` (see
`tests/resources.json` for a working example):

```json
{
  "name": "baskets",
  "create": { "method": "POST", "url": ".../api/baskets", "body": { "qty": 1 } },
  "id_from": "body:id",
  "read":   { "method": "GET",  "url": ".../api/baskets/{id}" },
  "update": { "method": "PUT",  "url": ".../api/baskets/{id}",
              "body": { "qty": 1 },
              "marker_field": "qty", "control_value": 111, "attack_value": 999 }
}
```

How it decides a write IDOR is real, in order:

1. Create a fixture as A, capture its id.
2. Control: A updates its own object to `control_value`, re-read confirms the
   field is actually writable. If it is not, the resource is skipped, not
   falsely passed.
3. Attack: B updates A's object to `attack_value`.
4. Oracle: A re-reads. If A's own view now shows `attack_value`, that is a
   confirmed write IDOR, not a 200 that did nothing.

Two safety rules. Every mutating request is gated by a registry of ids this
session created, so the engine cannot write to an object it did not make.
DELETE is deliberately not implemented. It is the destructive method and I do
not need it to prove the class.

## Why this is not "test every endpoint on auto"

I wanted this to auto-fire CRUD at everything when I started. It is a bad idea.
Auto-firing DELETE and PUT at a live site wipes real data, fires real emails,
and gets you banned. The fixture approach creates its own throwaway objects and
only tests cross-account access against those. Same coverage, no blast radius.
Until write methods go through fixtures they stay dry-run: IGOR shows what it
would send and does not send it. `--include-writes` overrides that, and the
name is the warning.

## Roadmap

- [x] `crawl`: katana front-end, authenticated discovery into targets
- [x] `spider`: headless browser discovery for SPAs
- [x] `writetest`: fixture-based create and update, oracle-confirmed
- [x] `import`: auto-split PwnFox/Burp sessions by `X-PwnFox-Color`
- [x] PoC generator: paste-ready repro on every HIGH, cookies redacted
- [x] `enum`: walk neighbor ids to harvest other users' objects
- [ ] OpenAPI/Swagger import: auto-build valid create bodies for writetest
- [ ] DELETE testing in writetest, fixtures only
- [ ] HPP mode: duplicate-parameter tests (`id=A&id=B`)

## License

MIT. See LICENSE.
