# magic.d/mwlan.py — M-WLAN Munich captive portal handler
# ──────────────────────────────────────────────────────────────────────────────
# Covers the M-WLAN / Stadtwerke München (SWM) public WiFi network in Munich.
# Portal: https://hotspot.swm.de/<location_id>/portal/
# SSID:   M-WLAN Free WiFi
#
# Login flow (reverse-engineered from browser PCAP with TLS decryption):
#   1. POST portal_api.php  action=init&free_urls=
#      → returns portal configuration (location_id already in URL)
#   2. POST portal_api.php  action=subscribe&type=one&connect_policy_accept=true&...
#      → returns {"result":{"user_login":"...","user_password":"..."}}
#   3. POST portal_api.php  action=authenticate&login=...&password=...
#                           &policy_accept=true&private_policy_accept=false
#                           &from_ajax=true&wispr_mode=false
#      → returns {"result":"ok"} or similar on success
#
# No user credentials required — the portal issues a temporary login/password
# via the subscribe call and authenticates with those automatically.
# ──────────────────────────────────────────────────────────────────────────────
# Required exports:  can_handle(portal_url, html) -> bool
#                    handle(portal_url, html, *, ticket, username, password) -> bool
# Optional export:   PRIORITY (int, default 50 — lower = checked first)
# Core helpers injected via _ctx at load time; see magic.login dispatcher.
# ──────────────────────────────────────────────────────────────────────────────

PRIORITY = 20

_ctx = {}   # populated by dispatcher


def can_handle(portal_url, html):
    ul = portal_url.lower()
    h  = (html or '').lower()
    return 'hotspot.swm.de' in ul or 'hotspot.swm.de' in h


def handle(portal_url, html, ticket=None, username=None, password=None):
    log          = _ctx['log']
    dbg          = _ctx['dbg']
    http_post    = _ctx['http_post']
    _make_opener = _ctx['_make_opener']
    _connectivity_ok = _ctx['_connectivity_ok']
    json         = _ctx['json']
    urllib_parse = _ctx['urllib_parse']
    time         = _ctx['time']

    log('[M-WLAN] Detected SWM hotspot portal')

    opener, _ = _make_opener()
    api_url = 'https://hotspot.swm.de/portal_api.php'

    # Step 1 — init
    log('[M-WLAN] Step 1: init')
    body, _, resp = http_post(api_url, 'action=init&free_urls=',
                              opener=opener, _dbg_label='mwlan_init')
    if body is None:
        log('[M-WLAN] init request failed')
        return False
    dbg('[M-WLAN] init response: %r' % body[:200])

    # Step 2 — anonymous subscribe, returns temporary credentials
    log('[M-WLAN] Step 2: subscribe')
    subscribe_data = (
        'action=subscribe'
        '&type=one'
        '&connect_policy_accept=true'
        '&user_login='
        '&user_password='
        '&user_password_confirm='
        '&email_address='
        '&prefix='
        '&phone='
        '&private_policy_accept=false'
        '&gender='
        '&interests='
    )
    body2, _, resp2 = http_post(api_url, subscribe_data,
                                opener=opener, _dbg_label='mwlan_subscribe')
    if body2 is None:
        log('[M-WLAN] subscribe request failed')
        return False
    dbg('[M-WLAN] subscribe response: %r' % body2[:300])

    # Parse temporary credentials from JSON response
    # Expected: {"result":{"user_login":"...","user_password":"..."}}
    tmp_login = tmp_password = None
    try:
        data = json.loads(body2)
        result = data.get('result', {})
        if isinstance(result, dict):
            tmp_login    = result.get('user_login')
            tmp_password = result.get('user_password')
    except Exception as e:
        dbg('[M-WLAN] Could not parse subscribe response as JSON: %s' % e)

    if not tmp_login or not tmp_password:
        log('[M-WLAN] No credentials in subscribe response — cannot authenticate')
        log('[M-WLAN] Response was: %r' % body2[:300])
        return False

    log('[M-WLAN] Received temporary credentials (login=%r)' % tmp_login)

    # Step 3 — authenticate with temporary credentials
    log('[M-WLAN] Step 3: authenticate')
    auth_data = urllib_parse.urlencode({
        'action':                  'authenticate',
        'login':                   tmp_login,
        'password':                tmp_password,
        'policy_accept':           'true',
        'private_policy_accept':   'false',
        'from_ajax':               'true',
        'wispr_mode':              'false',
    })
    body3, _, resp3 = http_post(api_url, auth_data,
                                opener=opener, _dbg_label='mwlan_authenticate')
    if body3 is None:
        log('[M-WLAN] authenticate request failed')
        return False
    log('[M-WLAN] authenticate response: %r' % body3[:200])

    # Check for explicit failure in authenticate response
    try:
        data3 = json.loads(body3)
        result3 = data3.get('result', '')
        if isinstance(result3, str) and result3.lower() in ('error', 'fail', 'failed'):
            log('[M-WLAN] Authentication failed: result=%r' % result3)
            return False
        if isinstance(result3, dict) and result3.get('error'):
            log('[M-WLAN] Authentication error: %s' % result3)
            return False
    except Exception:
        pass

    # Wait for MAC authorization to propagate
    for delay in [2, 3, 5, 5, 5]:
        time.sleep(delay)
        log('[M-WLAN] Checking connectivity ...')
        if _connectivity_ok(opener):
            log('[M-WLAN] Online!')
            return True

    log('[M-WLAN] Not online after all retries')
    return False
