# magic.login

**Universal captive portal auto-login for OpenWrt / Travelmate**

`magic.login` automatically handles captive portal login when your OpenWrt router connects to a new WiFi network via [Travelmate](https://github.com/openwrt/packages/tree/master/net/travelmate). It supports free/checkbox portals, username+password portals, and ticket/voucher portals — with portal-specific behaviour driven by YAML configuration files or Python plugins.

---

## Features

- **YAML-driven handlers** — add support for a new portal by dropping a `.yaml` file into `magic.d/`, no Python required
- **Python plugin handlers** — for portals requiring custom logic (e.g. REST APIs, JSONP), drop a `.py` file into `magic.d/`
- **Generic HTML form fallback** — works out of the box for most simple portals (hotels, airports, cafés) without any configuration
- **Multi-step portal flows** — handles portals that require several sequential form submissions (T&C acceptance, token exchange, router login)
- **Automatic credential lookup** — matches the current SSID against `/etc/captive-credentials.conf` for portals requiring username/password or a ticket
- **Interface-bound checks** — all HTTP requests are bound to the Travelmate uplink interface, so LTE/mwan fallback routes are ignored
- **Fast online pre-check** — exits in ~1s if already online (before loading heavy modules), suitable for cron-based session renewal
- **Reliable connectivity detection** — verifies that probe responses are genuine (not portal intercepts) and optionally checks a portal status page
- **`--debug` mode** — writes a timestamped session log and full HTML dumps of every step to `/tmp/captive-debug/`

---

## Included handlers

| File | Portal | Notes |
|------|--------|-------|
| `magic.d/bahn.py` | Deutsche Bahn WIFIonICE + stations | Ombord (MAC-based) and CNA (REST API) |
| `magic.d/freekey.yaml` | free-key.eu | German public WiFi, 4-step flow |
| *(built-in)* | Generic HTML form | Fallback for all other portals |

Only portals that have been tested are included. For a full list of known portals
and their test status, see [TESTED_PORTALS.md](TESTED_PORTALS.md).

---

## Requirements

- OpenWrt with Python 3
- [Travelmate](https://github.com/openwrt/packages/tree/master/net/travelmate)
- `python3-yaml` for YAML handler support

```sh
opkg update
opkg install python3 python3-yaml
```

---

## Installation

```sh
# Copy files to router
scp magic.login root@192.168.1.1:/etc/travelmate/
scp -r magic.d   root@192.168.1.1:/etc/travelmate/

# Make executable
ssh root@192.168.1.1 chmod +x /etc/travelmate/magic.login
```

Configure Travelmate to use the script:

```sh
uci set travelmate.global.trm_captivescript='/etc/travelmate/magic.login'
uci set travelmate.global.trm_captiveurl='http://connectivitycheck.gstatic.com/generate_204'
uci set travelmate.global.trm_captive='1'
uci commit travelmate
service travelmate restart
```

### Optional: cron-based session renewal

Some portals (e.g. free-key.eu) expire sessions after a few hours without Travelmate noticing. Running `magic.login` via cron re-authenticates automatically. The script exits in ~1s if already online, so the overhead is minimal.

```sh
# Re-login every 5 minutes if session has expired
echo "*/5 * * * * /etc/travelmate/magic.login" >> /etc/crontabs/root
/etc/init.d/cron restart
```

Use `--force` to bypass the fast online check and always run the full login flow.

---

## Credentials file

For portals that require a username/password or ticket, create `/etc/captive-credentials.conf`:

```
# SSID pattern (fnmatch wildcards)   type       credential(s)
Telekom_FON_*                        userpass   your@t-online.de   yourpassword
VodafoneWifi*                        userpass   myuser             mypassword
CoffeeShop_WLAN                      ticket     ABCD-1234
*                                    free
```

The script reads the active SSID from Travelmate's runtime JSON and matches it against this file automatically. Free/checkbox portals need no entry.

---

## Writing a custom handler

### YAML handler (simple portals)

Create a file in `magic.d/` — for example `magic.d/myportal.yaml`:

```yaml
name: My Hotel Portal
priority: 20          # lower = checked first (default: 50)

# Portal is matched when any of these strings appear in the portal URL or HTML
match:
  - myhotel-wifi.com
  - myhotelportal

retry_delays: [1, 2, 3, 5, 5]   # seconds between connectivity checks

steps:
  - label:       login
    action:      from_form      # use action URL from the HTML form
    fields:      from_form      # fill all fields from the HTML form
    check_boxes: true           # tick any checkboxes (T&C acceptance)
```

#### Step options

| Option | Values | Description |
|--------|--------|-------------|
| `label` | string | Name shown in log output and debug filenames |
| `action` | `from_form` / URL | Where to POST; `from_form` reads it from the HTML |
| `fields` | `from_form` / dict | Form data; `from_form` fills from HTML, dict overrides |
| `method` | `POST` / `GET` | HTTP method (default: `POST`) |
| `check_boxes` | `true` | Tick all checkboxes before submitting |
| `clear_fields` | list | Set these field values to empty string |
| `inject_fields` | dict | Add or override specific fields |
| `only_if` | string | Skip step unless this string appears in the last response |
| `only_if_action` | string | Skip step unless form action URL contains this string |

#### Multi-step example (free-key.eu style)

```yaml
name: Example multi-step portal
match: [example-portal.com]
retry_delays: [1, 2, 3, 5, 5]

steps:
  - label:        initial_post
    action:       from_form
    fields:       from_form
    clear_fields: [link-orig]

  - label:    token_auth
    action:   from_form
    fields:   from_form
    only_if:  SESSION_TOKEN    # only runs if server returned a token form

  - label:       accept_tos
    action:      from_form
    fields:      from_form
    check_boxes: true
    only_if:     agb

  - label:          router_login
    action:         from_form
    fields:         from_form
    only_if_action: hotspot    # only runs when form posts back to the AP
```

### Python plugin (complex portals)

For portals that require custom logic (REST APIs, JSONP, dynamic URL construction),
create a `.py` file in `magic.d/`:

```python
# magic.d/myplugin.py

PRIORITY = 20   # optional, default 50

def can_handle(portal_url, html):
    return 'myportal.example.com' in portal_url.lower()

def handle(portal_url, html, ticket=None, username=None, password=None):
    log      = _ctx['log']
    http_get = _ctx['http_get']
    http_post = _ctx['http_post']
    _make_opener = _ctx['_make_opener']
    _connectivity_ok = _ctx['_connectivity_ok']

    log('[MyPortal] Starting login')
    opener, _ = _make_opener()
    # ... custom logic ...
    return _connectivity_ok(opener)
```

Core helpers available via `_ctx`:

| Key | Description |
|-----|-------------|
| `log` | Print to stdout (and debug log if active) |
| `dbg` | Debug-only log output |
| `http_get(url, opener, _dbg_label)` | GET request |
| `http_post(url, data, opener, ...)` | POST request |
| `_make_opener(jar, follow_redirects)` | Create a cookie-aware HTTP opener bound to the uplink interface |
| `_connectivity_ok(opener, status_url)` | Verify internet access via probe URLs |
| `origin_of(url)` | Extract `scheme://host` from a URL |
| `json` | `json` module |
| `time` | `time` module |
| `urllib_parse` | `urllib.parse` module |
| `urllib_error` | `urllib.error` module |

---

## Debugging

Run with `--debug` to get a full session log and HTML dumps:

```sh
/etc/travelmate/magic.login --debug
```

Output is written to `/tmp/captive-debug/`:
- `session.log` — timestamped log of all requests, responses, cookies and headers
- `step_01_*.html`, `step_02_*.html`, … — raw HTML of every page with parsed form fields in the header comments

Additional flags:
- `--force` — skip the fast online pre-check and always run the full login flow

---

## Repository structure

```
magic.login          # main script (Python 3, requires python3-yaml)
magic.d/
  bahn.py            # Deutsche Bahn (ICE + stations) — Python plugin
  freekey.yaml       # free-key.eu
README.md
CONTRIBUTING.md
TESTED_PORTALS.md
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for a step-by-step guide on how to capture
a debug log, generate a YAML handler with AI assistance, and submit it — either
as a GitHub Issue or a pull request.

---

## License

MIT
