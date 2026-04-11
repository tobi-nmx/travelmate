# Tested portals

This page lists portals that have been verified to work with `magic.login`,
either through a dedicated handler in `magic.d/` or the built-in generic handler.

If you have tested a portal not listed here — or found that a listed portal no
longer works — please [open an issue](../../issues/new).

---

## Portal overview

| Portal | SSID | Handler Type | Handler | Region | Test Status | Notes |
|--------|------|--------------|---------|--------|-------------|-------|
| free-key.eu | free-key * | dedicated | `magic.d/freekey.yaml` | DE (towns, campsites) | ✅ tested | 4-step flow with session token and T&C |
| Deutsche Bahn WIFIonICE | WIFIonICE | dedicated | `magic.d/bahn.py` | DE/EU (ICE, IC trains) | ✅ tested | Onboard MAC-based auth |
| Deutsche Bahn stations | — | dedicated | `magic.d/bahn.py` | DE (stations) | ✅ tested | CNA REST API |
| BayernWLAN | @BayernWLAN | dedicated | `magic.d/bayernwlan.yaml` | DE (Bavaria) | ✅ tested | Free, T&C only |
| Telekom Hotspot | Telekom_FON_* | generic? | — | DE | ❓ untested | Captive portal with login form (credentials), likely redirect-based |
| Vodafone Hotspot | VodafoneWifi* | generic? | — | DE | ❓ untested | Similar to Telekom; captive + account login |
| Hotsplots | varies | generic? | — | DE | ❓ untested | Simple splash page with T&C checkbox |
| McDonald's / The Cloud | McDonaldsWifi | generic? | — | EU | ❓ untested | Usually single-step accept via provider |
| Autobahn / Tank & Rast | varies | generic? | — | DE | ❓ untested | Typically simple portals but inconsistent setups |
| Frankfurt Airport (FRA) | FRA Free WiFi | generic? | — | DE | ❓ untested | Likely redirect + session-based flow |
| Munich Airport (MUC) | MUC Free WiFi | generic? | — | DE | ❓ untested | Similar to FRA |
| Starbucks | StarbucksWiFi | dedicated? | — | EU | ❓ untested | Often federated login → may require YAML |

---

## Legend

### Handler Type
- **dedicated** → Requires specific handler in `magic.d/`
- **dedicated?** → Likely requires a handler, not yet confirmed
- **generic?** → Expected to work with built-in handler (not yet verified)

### Test Status
- ✅ **tested** → Confirmed working
- ❓ **untested** → Not yet verified

---

## Adding a tested portal

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In short:

1. Connect to the hotspot  
2. Run `python magic.login --debug --no-bind` before touching the browser  
3. If it works → report it as "tested (generic)"  
4. If it fails → paste the debug log into an AI chat using the prompt in CONTRIBUTING.md  
   to generate a YAML handler, then open an issue  
