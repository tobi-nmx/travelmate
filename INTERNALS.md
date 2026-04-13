# magic.login — Internals

Technical reference for `magic.login`. Useful if you want to understand how the
script works, write a custom portal handler, or diagnose an unusual portal flow.

For a step-by-step guide on capturing a debug log and generating a handler with
AI assistance, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Architecture overview

```
magic.login
│
├── Fast online pre-check (curl, interface-bound)
│     └── exits immediately if already online (~1s)
│
├── detect_portal()
│     └── probes generate_204 / success.txt without following redirects
│           → returns (portal_url, html) or (None, None)
│
├── dispatch(portal_url, html)
│     ├── loads all *.yaml and *.py files from magic.d/, sorted by priority
│     ├── tries each handler in order (can_handle / match patterns)
│     ├── runs the first matching handler
│     └── falls back to handle_generic() if nothing matches
│
├── _run_yaml_handler()    — executes a YAML handler step by step
├── handle_generic()       — generic HTML form fallback (recursive, up to 3 steps)
└── _connectivity_ok()     — verifies actual internet access after login
```

---

## Fast online pre-check

Runs before any heavy Python imports to keep the "already online" path fast
(~1s on slow MIPS hardware). Uses `curl` rather than `urllib` so it can bind
to the Travelmate uplink interface via `--interface`, ensuring the check goes
over the WiFi uplink even when LTE/mwan is also active.

Two probes are tried in order:

1. `generate_204` — expects HTTP 204 with strictly empty body
2. `detectportal.firefox.com/success.txt` — expects the string `success`

Any redirect, unexpected status code, or non-empty body on `generate_204` is
treated as a portal intercept. The full login flow is only started if the fast
check fails or if `--force` / `--debug` are passed.

---

## Interface binding

On OpenWrt, `SO_BINDTODEVICE` is used to bind all HTTP sockets to the active
Travelmate uplink interface (e.g. `phy1-sta0`). This ensures portal probes and
login requests go over the WiFi uplink even when a higher-priority default route
exists (e.g. LTE via mwan3).

The uplink interface is detected once at startup from `/tmp/trm_runtime.json`
(fields tried: `sta_iface`, `travelmate_iface`, `iface`). If the JSON is not
available, `ip route` is scanned for a `sta*` or `wwan*` interface as fallback.

Use `--no-bind` to skip interface binding when running outside OpenWrt
(e.g. on a laptop or Android/Termux for portal debugging).

---

## Dispatcher and handler loading

`_load_handlers()` scans `magic.d/` for `*.yaml` and `*.py` files, loads them,
and returns a list sorted by `priority` (lower = checked first, default 50).

For each handler, `dispatch()` checks whether it matches the current portal:

- **Python plugins** — `can_handle(portal_url, html)` is called; the plugin
  decides based on URL or HTML content
- **YAML handlers** — each `match` pattern is checked against the portal URL
  and the initial HTML (substring match, case-insensitive)

The first matching handler is used. If no handler matches, `handle_generic()`
is called as the final fallback.

---

## Generic handler

`handle_generic()` is the built-in fallback for portals not covered by any
handler in `magic.d/`. It:

1. Parses all `<form>` elements in the HTML
2. Scores each form to find the most likely login form (prefers POST, fields
   named `user`, `pass`, `ticket`, checkboxes, etc.)
3. Fills in credentials from CLI args or the credentials file
4. Submits the form and checks the response for success keywords
5. Follows up to 3 sequential form steps recursively
6. Falls back to `_connectivity_ok()` if keyword detection is inconclusive

The generic handler is sufficient for most simple portals. A YAML handler is
only needed when the generic handler mis-detects success/failure, or when steps
must be conditionally skipped.

---

## YAML handler reference

### File structure

```yaml
# Portal name captive portal handler
# ──────────────────────────────────────
# Brief description of the portal and its login flow.
# Number of login steps: <N>
# SSID: <if known>
# Portal URL: <detected URL>

name: My Portal
priority: 30          # lower = checked before other handlers (default: 50)

match:
  - myportal.example.com   # matched against portal URL and initial HTML

retry_delays: [1, 2, 3, 5, 5]   # seconds to wait between connectivity checks

steps:
  - label: login
    action: from_form
    fields: from_form
```

### Step options

| Option | Values | Description |
|--------|--------|-------------|
| `label` | string | Name shown in log output and debug filenames |
| `action` | `from_form` / URL | Where to POST; `from_form` reads it from the HTML form |
| `fields` | `from_form` / dict | Form data; `from_form` fills from HTML, dict overrides entirely |
| `method` | `POST` / `GET` | HTTP method (default: `POST`) |
| `check_boxes` | `true` | Tick all checkboxes before submitting (T&C acceptance) |
| `clear_fields` | list | Set these field values to empty string before submitting |
| `inject_fields` | dict | Add or override specific fields in the POST data |
| `only_if` | string | Skip step unless this string appears in the last response body |
| `only_if_action` | string | Skip step unless the form action URL contains this string |

### Multi-step example

```yaml
name: Example multi-step portal
match: [example-portal.com]
retry_delays: [1, 2, 3, 5, 5]

steps:
  - label:        initial_post
    action:       from_form
    fields:       from_form
    # link-orig is present in the form but must be sent empty
    clear_fields: [link-orig]

  - label:    token_auth
    action:   from_form
    fields:   from_form
    # only runs if the server returned a form containing a session token
    only_if:  SESSION_TOKEN

  - label:       accept_tos
    action:      from_form
    fields:      from_form
    check_boxes: true
    only_if:     agb

  - label:          router_login
    action:         from_form
    fields:         from_form
    # only runs when the form action points back to the access point
    only_if_action: hotspot
```

### When to use each option

**`only_if`** — use when a step should only run if the previous response
contained a specific token or field name (e.g. `FREEKEYWIFI`, `SESSION_TOKEN`).
Without this guard, the handler would attempt the step on every portal that
matches the `match` patterns, not just the one that returns that token.

**`only_if_action`** — use when the final login POST goes to a different host
than the portal pages (e.g. directly to the hotspot router). This prevents the
step from firing prematurely on an intermediate page.

**`clear_fields`** — use for fields like `link-orig`, `dst`, or `redirect` that
are present in the form HTML but must be sent empty. Browsers send them empty;
some portals break if the original value is echoed back.

**`check_boxes`** — use for T&C / AGB acceptance steps. The generic handler
ticks checkboxes too, but does not do so reliably across multi-step flows.

---

## Python plugin API

For portals requiring custom logic (REST APIs, JSONP responses, dynamic URL
construction), create a `.py` file in `magic.d/`:

```python
# magic.d/myplugin.py

PRIORITY = 20   # optional, default 50

def can_handle(portal_url, html):
    return 'myportal.example.com' in portal_url.lower()

def handle(portal_url, html, ticket=None, username=None, password=None):
    log              = _ctx['log']
    http_get         = _ctx['http_get']
    http_post        = _ctx['http_post']
    _make_opener     = _ctx['_make_opener']
    _connectivity_ok = _ctx['_connectivity_ok']

    log('[MyPortal] Starting login')
    opener, _ = _make_opener()
    # ... custom logic ...
    return _connectivity_ok(opener)
```

Core helpers are injected via the `_ctx` dict at load time:

| Key | Description |
|-----|-------------|
| `log(msg)` | Print to stdout and to the debug log if `--debug` is active |
| `dbg(msg)` | Debug-only log output (suppressed unless `--debug`) |
| `http_get(url, opener, _dbg_label)` | Perform a GET request; returns `(body, final_url, resp)` |
| `http_post(url, data, opener, ...)` | Perform a POST request; returns `(body, final_url, resp)` |
| `_make_opener(jar, follow_redirects)` | Create a cookie-aware HTTP opener, interface-bound if applicable |
| `_connectivity_ok(opener, status_url)` | Verify internet access via probe URLs; returns `True` if online |
| `origin_of(url)` | Extract `scheme://host` from a URL |
| `json` | `json` standard library module |
| `time` | `time` standard library module |
| `urllib_parse` | `urllib.parse` module |
| `urllib_error` | `urllib.error` module |

See `magic.d/bahn.py` for a real-world example covering two portal backends
(Ombord MAC-based and CNA REST API) with automatic backend detection.

---

## Known portal quirks

**Success detection — form presence and state tracking** — the generic
handler does not detect success from response keywords. Instead it asks: *should
we follow the next form, or are we done?* This decision is made by
`_should_follow_form()` using three inputs:

1. **Form score** from `best_form()` — login-relevant fields (password, user,
   ticket, checkbox, non-logout submit button) score positively; logout forms
   score -3 and are never followed.
2. **Submitted state** — tracks whether credentials and/or a checkbox have
   already been submitted in previous steps. Once both have been submitted,
   no further form is expected and `_connectivity_ok()` is called directly.

In `--debug` mode `_should_follow_form()` always returns `True` (with a log
warning) so that the complete portal flow is captured for YAML development —
even steps that would be skipped in normal operation.

`FAILURE_WORDS` are still checked after every form submission and trigger an
immediate abort if a clear failure message is detected (wrong password, session
expired, access denied). These are available in English, German, French, Italian,
Spanish, and Dutch. They are deliberately conservative — only phrases that
unambiguously signal failure, never single words that could appear in other
contexts.

**`link-orig` / `dst` / `redirect` fields** — many portal frameworks include a
redirect-back field in the login form. Some portals break if this value is
echoed; use `clear_fields` to send it empty.

**Connectivity check timing** — after the final login POST, the hotspot router
may still intercept HTTP probes for a few seconds while it processes the MAC
authorization. `retry_delays` controls how long to keep retrying. For portals
with a status page (e.g. `hotspot.example.com/status`), the script also checks
that page if all probe URLs are still redirected.

**Session expiry** — some portals (e.g. free-key.eu) expire sessions after a
few hours. Travelmate may not detect this because its connectivity check accepts
any HTTP 200 or 204 response as "online" — it does not verify that the response
body is empty or that no redirect occurred at the HTTP level. A hotspot that
returns a well-formed 204 after session expiry (instead of redirecting to the
login page again) will therefore fool Travelmate indefinitely.

Switching `trm_captiveurl` to HTTPS would in theory prevent this (a hotspot
cannot fake a TLS-verified 204 from Google), but it would also break initial
portal detection — the hotspot can only intercept and redirect plain HTTP
requests, so HTTPS would never trigger the captive portal flow.

The recommended workaround is a cron job that runs `magic.login` every 5
minutes. When the session has expired and the portal redirects again,
`magic.login` will detect the login page and re-authenticate. The fast
pre-check (`generate_204` with strict empty-body requirement) keeps the
overhead to ~1s in the normal "already online" case.

**`_detect_uplink_iface()` compatibility** — the field name for the uplink
interface in `/tmp/trm_runtime.json` varies across Travelmate versions. The
script tries `sta_iface`, `travelmate_iface`, and `iface` in order, then falls
back to scanning `ip route` for a `sta*` or `wwan*` interface.
