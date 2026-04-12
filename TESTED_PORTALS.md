# Tested portals

This page lists portals that have been verified to work with `magic.login`,
either through a dedicated handler in `magic.d/` or the built-in generic handler.

If you have tested a portal not listed here — or found that a listed portal no
longer works — please [open an issue](../../issues/new).

---

## Portal overview

| Portal | SSID | Handler | Region | Status | Notes |
|--------|------|---------|--------|--------|-------|
| free-key.eu | free-key * | `magic.d/freekey.yaml` | DE (towns, campsites) | ✅ tested | 4-step flow with session token and T&C |
| Deutsche Bahn WIFIonICE | WIFIonICE | `magic.d/bahn.py` | DE/EU (ICE, IC trains) | ✅ tested | Ombord MAC-based auth |
| Deutsche Bahn stations | WIFI@DB | `magic.d/bahn.py` | DE (stations) | ✅ tested | CNA REST API |
| BayernWLAN | @BayernWLAN | generic | DE (Bavaria) | ✅ tested | Simple captive portal with single T&C accept, no registration |
| M-WLAN (Munich) | M-WLAN Free WiFi | generic | DE (Munich) | ❓ untested | Simple AGB portal with browser redirect; time-limited session, no registration |
| Telekom Hotspot | Telekom_FON_* | generic | DE | ❓ untested | Redirect-based captive portal with login form (Hotspot pass / t-online.de credentials or ticket) |
| Vodafone Hotspot | VodafoneWifi* | generic | DE | ❓ untested | Captive portal with T&C splash, short free session, optional extension via Hotspot flat or ticket |
| Hotsplots | varies | generic | DE | ❓ untested | Splash page with T&C checkbox, often plus voucher/ticket field depending on location |
| McDonald's / The Cloud | McDonaldsWifi | generic | EU | ❓ untested | Provider-managed splash page with T&C accept; sometimes minimal form (e.g. name/email) |
| Autobahn / Tank & Rast | varies | generic | DE | ❓ untested | Typically simple redirect-based captive portals; implementations vary by operator and location |
| Frankfurt Airport (FRA) | FRA Free WiFi | generic | DE | ❓ untested | Redirect to portal with T&C button, then time-limited session |
| Munich Airport (MUC) | MUC Free WiFi | generic | DE | ❓ untested | Browser-based portal with email and T&C accept, then unlimited free Wi-Fi |
| Starbucks | StarbucksWiFi | dedicated | EU | ❓ untested | Captive portals run by different providers; often T&C plus optional social/federated login — may need a dedicated handler |
| Lidl | LidlPlusWLAN | generic | DE | ❓ untested | T&C splash page, simple accept-and-go flow; auto-login across all stores once accepted |
| O2 / Telefónica Free WiFi | o2-wifi / O2 Wifi | generic | DE | ❓ untested | Standard captive portal, usually simple redirect + T&C |
| REWE | -REWE gratis WLAN- | generic | DE | ❓ untested | Captive portal with AGB page and "Online gehen" button; 1-hour free session, extendable on reconnect |
| REWE WiFi | REWE FREE WIFI | generic | DE | ❓ untested | Retail captive portal, typically simple accept flow |
| EDEKA WiFi | varies | generic | DE | ❓ untested | Supermarket WiFi with basic T&C portal |
| IKEA WiFi | IKEA WiFi | generic | EU | ❓ untested | Simple captive portal (accept terms) |
| McFIT / Gym WiFi | varies | generic | DE | ❓ untested | Standard captive portals in fitness studios |
| BVG Free WiFi | BVG WiFi | generic | DE | ❓ untested | Public transport Berlin, provider may vary |
| MVV Free WiFi | MVV WiFi | generic | DE | ❓ untested | Munich public transport WiFi, often aggregated providers |
| FlixBus WiFi | FlixBus WiFi | generic | EU | ❓ untested | Captive portal with session-limited connectivity |
| ÖBB / Railjet WiFi | ÖBB WiFi / Railjet WiFi | generic | AT/EU | ❓ untested | Train WiFi with portal + session-based access |

---

## Legend

### Handler
- **`magic.d/file`** — Requires a dedicated handler (complex flow, REST API, etc.)
- **generic** — Expected to work with the built-in generic handler

### Status
- ✅ **tested** — Confirmed working
- ❓ **untested** — Not yet verified; handler type is an educated guess

---

## Adding a tested portal

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In short:

1. Connect to the hotspot
2. Run `python magic.login --debug --no-bind` before touching the browser
3. If it works → report it as tested (generic)
4. If it fails → paste the debug log into an AI chat using the prompt in CONTRIBUTING.md
   to generate a YAML handler, then open an issue
