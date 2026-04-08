# magic.login

**Universal captive portal auto-login for OpenWrt / Travelmate**

`magic.login` automatically handles captive portal login when your OpenWrt router connects to a new WiFi network via [Travelmate](https://github.com/openwrt/packages/tree/master/net/travelmate). It supports free/checkbox portals, username+password portals, and ticket/voucher portals — with portal-specific behaviour driven by simple YAML configuration files.

---

## Features

- **YAML-driven handlers** — add support for a new portal by dropping a `.yaml` file into `magic.d/`, no Python required
- **Generic HTML form fallback** — works out of the box for most simple portals (hotels, airports, cafés) without any configuration
- **Multi-step portal flows** — handles portals that require several sequential form submissions (T&C acceptance, token exchange, router login)
- **Automatic credential lookup** — matches the current SSID against `/etc/captive-credentials.conf` for portals requiring username/password or a ticket
- **Reliable connectivity detection** — probes multiple well-known URLs and optionally checks a portal status page to avoid false positives
- **`--debug` mode** — writes a timestamped session log and full HTML dumps of every step to `/tmp/captive-debug/` for easy troubleshooting

---

## Included handlers

| File | Portal | Notes |
|------|--------|-------|
| `magic.d/freekey.yaml` | free-key.eu | German public WiFi, multi-step flow |
| `magic.d/hotsplots.yaml` | Hotsplots | Venues, restaurants, hotels |
| `magic.d/bayernwlan.yaml` | BayernWLAN (@BayernWLAN) | Free, T&C only, Vodafone-betrieben |
| `magic.d/telekom.yaml` | Telekom Hotspot | Requires credentials |
| `magic.d/vodafone.yaml` | Vodafone Hotspot | Requires credentials |
| *(built-in)* | Deutsche Bahn ICE (Ombord) | MAC-based, no form |
| *(built-in)* | Deutsche Bahn CNA (stations) | REST API |
| *(built-in)* | Generic HTML form | Fallback for all others |

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

Create a file in `magic.d/` — for example `magic.d/myportal.yaml`:

```yaml
name: My Hotel Portal
priority: 20          # lower = checked first (default: 50)

# Portal is used when any of these strings appear in the portal URL or HTML
match:
  - myhotel-wifi.com
  - myhotelportal

retry_delays: [1, 2, 3, 5, 5]   # seconds between connectivity checks

steps:
  - label:       login
    action:      from_form      # use action URL from the HTML form
    fields:      from_form      # use all fields from the HTML form
    check_boxes: true           # tick any checkboxes (T&C acceptance)
```

### Step options

| Option | Values | Description |
|--------|--------|-------------|
| `label` | string | Name shown in log output and debug filenames |
| `action` | `from_form` / URL | Where to POST; `from_form` reads it from the HTML |
| `fields` | `from_form` / dict | Form data; `from_form` fills from HTML, dict overrides |
| `method` | `POST` / `GET` | HTTP method (default: `POST`) |
| `check_boxes` | `true` | Tick all checkboxes before submitting |
| `clear_fields` | list | Set these field values to empty string |
| `inject_fields` | dict | Add or override specific fields |
| `only_if` | string | Skip step unless this string is in the last response |
| `only_if_action` | string | Skip step unless form action URL contains this |

### Multi-step example (free-key.eu style)

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

---

## Debugging

Run with `--debug` to get a full session log and HTML dumps:

```sh
/etc/travelmate/magic.login --debug
```

Output is written to `/tmp/captive-debug/`:
- `session.log` — timestamped log of all requests, responses, cookies and headers
- `step_01_*.html`, `step_02_*.html`, … — raw HTML of every page with parsed form fields in the header comments

---

## Repository structure

```
magic.login          # main script (Python 3, no dependencies except python3-yaml)
magic.d/
  freekey.yaml       # free-key.eu
  hotsplots.yaml     # Hotsplots / BayernWLAN
  telekom.yaml       # Telekom Hotspot
  vodafone.yaml      # Vodafone Hotspot
README.md
```

---

## Contributing

Pull requests for new portal handlers are welcome — a YAML file is usually all that's needed. If a portal requires logic that can't be expressed in YAML (like the Deutsche Bahn REST API), a Python handler can be added to the dispatcher in `magic.login`.

When submitting a handler please include:
- The portal name and URL
- Which SSIDs / regions it applies to
- Whether credentials are required
- A brief description of the login flow

---

## License

MIT
