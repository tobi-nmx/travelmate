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

---

## Credentials

For portals that require a username/password or ticket, there are two ways to
provide credentials.

### 1. Per-station in Travelmate (recommended)

In LuCI, set `magic.login` as the **Auto Login Script** for a wireless station
and enter the credentials as **Script Arguments**. In `/etc/config/travelmate`
this looks like:

```
config station 'mystation'
    option script      '/etc/travelmate/magic.login'
    option script_args 'myuser mypassword'   # or just 'myticket' for ticket portals
```

Travelmate passes the arguments directly to the script when it connects to that
station. Free/checkbox portals need no arguments.

### 2. Credentials file

For setups with many SSIDs, or when you prefer to manage all credentials in one
place, create `/etc/captive-credentials.conf`:

```
# SSID pattern (fnmatch wildcards)   type       credential(s)
Telekom_FON_*                        userpass   your@t-online.de   yourpassword
VodafoneWifi*                        userpass   myuser             mypassword
CoffeeShop_WLAN                      ticket     ABCD-1234
*                                    free
```

The script reads the active SSID from Travelmate's runtime JSON and matches it
against this file automatically. Per-station script arguments take priority over
the credentials file if both are set.

---

## Debugging & Contributing

Run with `--debug` to get a full session log and HTML dumps:

```sh
/etc/travelmate/magic.login --debug --force
```

Output is written to `/tmp/captive-debug/`:
- `session.log` — timestamped log of all requests, responses, cookies and headers
- `step_01_*.html`, `step_02_*.html`, … — raw HTML of every page with parsed form fields in the header comments

Additional flags:
- `--force` — skip the fast online pre-check and always run the full login flow
- `--no-bind` — skip interface binding, required when running outside OpenWrt (e.g. on a laptop or Android/Termux for portal debugging)

A debug log is also the starting point for contributing support for a new portal.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the full step-by-step guide.

---

## Going deeper

[INTERNALS.md](INTERNALS.md) covers the technical details of `magic.login` — useful if you want to understand how the script works, write a custom handler, or diagnose an unusual portal:

- Architecture overview (dispatcher, plugin loading, generic handler, fast check)
- YAML handler reference with all step options
- Python plugin API
- Known portal quirks and gotchas

---

## Repository structure

```
magic.login          # main script (Python 3, requires python3-yaml)
magic.d/
  bahn.py            # Deutsche Bahn (ICE + stations) — Python plugin
  freekey.yaml       # free-key.eu
README.md
CONTRIBUTING.md      # how to add support for a new portal
INTERNALS.md         # architecture, YAML reference, Python plugin API
TESTED_PORTALS.md
```

---

## License

MIT
