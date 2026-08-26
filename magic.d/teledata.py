# magic.d/teledata.py — Teledata WLAN Hotspot captive portal handler
# ─────────────────────────────────────────────────────────────────────────────
# Covers the "Teledata | WLAN Internet Hotspot" portal used at many German
# campsites/parks (e.g. SSID "WLAN Park-Camping"). Confirmed via TLS MITM
# pcap (PCAPdroid + keylog) of a real browser login.
#
# This is NOT a plain HTML-form portal: the actual login runs through a
# JSON-RPC style AJAX API at /Ajax/service/ on teledata.wifi.teledata.de.
# The generic HTML form handler cannot drive this, because:
#   - the login button, AGB acceptance, and credential exchange all happen
#     via JSON POSTs with a fixed JSON envelope (model/method/params), not
#     via a normal <form> submission
#   - the actual router login credentials (username/password) are generated
#     server-side and returned in the JSON response of the "login" AJAX call
#     — they do not exist anywhere in the HTML beforehand
#
# Flow (confirmed via decrypted pcap):
#   1. GET  https://teledata.wifi.teledata.de/customer/landingpage
#            -> sets the lum_session cookie used by all further AJAX calls
#   2. POST https://teledata.wifi.teledata.de/Ajax/service/
#            {"method":"getButtonContent","params":{"buttonNumber":"1"}}
#            -> returns (JSON-wrapped) HTML for the "One-Click-Login" /
#               free-WiFi button, containing the AGB checkbox field name
#               (e.g. "policy_13") and the login <form> id/name
#   3. POST https://teledata.wifi.teledata.de/Ajax/service/
#            {"method":"loginOverLoginModule",
#             "formData":{"policy_13":1,"submit_login":"Login"}, ...}
#            -> ticks the AGB checkbox and clicks "Login"; response JSON
#               contains a freshly generated username/password pair
#   4. POST https://hotspot.wifi.teledata.de/login
#            username=<generated>&password=<generated>   (Content-Type: text/plain)
#            -> the AP authorizes the client MAC
#
# The AGB checkbox field name ("policy_13") and the form id/name are parsed
# out of step 2's response rather than hard-coded, since Teledata may change
# the policy field number between deployments/versions.
#
# No credentials required — this is the free/anonymous login path.
# ─────────────────────────────────────────────────────────────────────────────
# This file is a magic.login Python plugin.
# Required exports:  can_handle(portal_url, html) -> bool
#                    handle(portal_url, html, *, ticket, username, password) -> bool
# Optional export:   PRIORITY (int, default 50 — lower = checked first)
# ─────────────────────────────────────────────────────────────────────────────

PRIORITY = 15  # check before the generic handler; after bahn.py/freekey.yaml

_ctx = {}   # populated by dispatcher: log, dbg, http_get, http_post,
            # _make_opener, _connectivity_ok, origin_of, json, time,
            # urllib_parse, urllib_error, HEADERS, _wlan_nameservers,
            # _resolve_host_via_wlan_dns, _resolve_url_host

_LANDING_URL   = 'https://teledata.wifi.teledata.de/customer/landingpage'
_AJAX_URL      = 'https://teledata.wifi.teledata.de/Ajax/service/'
_HOTSPOT_LOGIN = 'https://hotspot.wifi.teledata.de/login'


def can_handle(portal_url, html):
    ul = portal_url.lower()
    h = (html or '').lower()
    return (
        'teledata.wifi.teledata.de' in ul or
        'teledata.wifi.teledata.de' in h or
        'hotspot.wifi.teledata.de'  in ul or
        ('teledata' in h and 'wlan internet hotspot' in h)
    )


def _extract_form_meta(html):
    """Pull action/id/name of the <form ...> tag, AGB checkbox field name(s),
    and the submit button name/value out of the getButtonContent HTML.
    Returns a dict; missing pieces default to the values seen in the field.
    """
    import re
    meta = {
        'form_id':   'formLoginOneClickLogin',
        'form_name': 'loginoneclicklogin',
        'policies':  [],
        'submit_name':  'submit_login',
        'submit_value': 'Login',
    }
    if not html:
        return meta

    m = re.search(r'<form([^>]*)>', html, re.I)
    if m:
        tag = m.group(1)
        mi = re.search(r'\bid="([^"]+)"', tag)
        mn = re.search(r'\bname="([^"]+)"', tag)
        if mi:
            meta['form_id'] = mi.group(1)
        if mn:
            meta['form_name'] = mn.group(1)

    meta['policies'] = re.findall(
        r'<input\s+type="checkbox"\s+name="(policy_\d+)"', html, re.I)

    ms = re.search(
        r'<input\s+type="submit"\s+name="([^"]+)"[^>]*\bvalue="([^"]+)"',
        html, re.I)
    if ms:
        meta['submit_name']  = ms.group(1)
        meta['submit_value'] = ms.group(2)

    return meta


def handle(portal_url, html, ticket=None, username=None, password=None):
    log          = _ctx['log']
    dbg          = _ctx['dbg']
    http_get     = _ctx['http_get']
    http_post    = _ctx['http_post']
    _make_opener = _ctx['_make_opener']
    _connectivity_ok = _ctx['_connectivity_ok']
    json         = _ctx['json']

    log('[Teledata] Starting login')
    opener, jar = _make_opener()

    # 1. Load the landing page fresh — this is what sets lum_session.
    #    The portal_url/html handed in by the dispatcher may be an
    #    intermediate hotspot.* page rather than the CMS landing page,
    #    so we always start from a known-good URL.
    _, final, _ = http_get(_LANDING_URL, opener=opener,
                           _dbg_label='teledata_landingpage')
    if final is None:
        log('[Teledata] Could not load landing page')
        return False

    ajax_headers = {
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': _LANDING_URL,
    }
    ajax_content_type = 'application/x-www-form-urlencoded; charset=UTF-8'

    # 2. Fetch the "One-Click-Login" / free-WiFi button content, which
    #    contains the actual AGB checkbox field name and form id/name.
    button_req = json.dumps({
        'model': 'customers',
        'method': 'getButtonContent',
        'requestType': 'htmlResponse',
        'isSubstition': True,
        'countPageImpression': True,
        'params': {'buttonNumber': '1'},
    })
    body, _, _ = http_post(_AJAX_URL, button_req, opener=opener,
                           content_type=ajax_content_type,
                           extra_headers=ajax_headers,
                           _dbg_label='teledata_button_content')
    if not body:
        log('[Teledata] getButtonContent failed')
        return False
    try:
        button_json = json.loads(body)
    except Exception as e:
        log('[Teledata] Could not parse getButtonContent response: %s' % e)
        return False
    if not button_json.get('success'):
        log('[Teledata] getButtonContent returned success=false')
        return False

    meta = _extract_form_meta(button_json.get('result', ''))
    if not meta['policies']:
        log('[Teledata] No AGB checkbox field found — assuming none required')
    dbg('[Teledata] Form meta: %s' % meta)

    # 3. Tick every AGB checkbox found and submit the login form via the
    #    loginOverLoginModule AJAX call.
    form_data = {p: 1 for p in meta['policies']}
    form_data[meta['submit_name']] = meta['submit_value']

    login_req = json.dumps({
        'model': 'customers',
        'method': 'loginOverLoginModule',
        'formName': meta['form_name'],
        'formData': form_data,
        'requestType': 'formValidation',
        'params': {'formID': meta['form_id'], 'data': form_data},
        'countPageImpression': True,
    })
    body, _, _ = http_post(_AJAX_URL, login_req, opener=opener,
                           content_type=ajax_content_type,
                           extra_headers=ajax_headers,
                           _dbg_label='teledata_login_over_module')
    if not body:
        log('[Teledata] loginOverLoginModule failed')
        return False
    try:
        login_json = json.loads(body)
    except Exception as e:
        log('[Teledata] Could not parse loginOverLoginModule response: %s' % e)
        return False
    if not login_json.get('success'):
        log('[Teledata] loginOverLoginModule returned success=false: %s' %
            login_json.get('message'))
        return False

    login_process = login_json.get('result', {}).get('loginProcess', {})
    gen_user = login_process.get('username')
    gen_pass = login_process.get('password')
    if not gen_user or gen_pass is None:
        log('[Teledata] No generated username/password in response')
        return False
    log('[Teledata] Received generated router credentials')

    # 4. Submit the generated credentials to the AP itself, exactly as the
    #    browser does — as a raw "key=value&key=value" body with
    #    Content-Type: text/plain (not the usual urlencoded form type).
    router_body = 'username=%s&password=%s' % (gen_user, gen_pass)
    _, final, _ = http_post(_HOTSPOT_LOGIN, router_body, opener=opener,
                            content_type='text/plain',
                            extra_headers={'Referer': 'https://teledata.wifi.teledata.de/'},
                            _dbg_label='teledata_router_login')
    log('[Teledata] Router login response from %s' % final)

    return _connectivity_ok(opener)
