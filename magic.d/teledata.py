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
# DNS note: both hostnames are sometimes only resolvable via the WLAN-
# assigned DNS server, not the system resolver. magic.login's built-in
# _resolve_url_host() handles this for the generic handler by substituting
# a raw IP into the URL — but that breaks this portal specifically, because
# teledata.wifi.teledata.de is a shared, name-based Apache vhost: with the
# IP in the URL, the Host header (and TLS SNI) no longer says
# "teledata.wifi.teledata.de", so Apache serves its default/fallback site
# instead of the real portal (a suspiciously identical ~106 byte response
# for every request is the symptom). Instead, this plugin keeps the real
# hostname in every URL and only overrides where the *socket* connects to,
# via a temporary socket.getaddrinfo() patch scoped to each request. This
# keeps Host header, TLS SNI, and certificate-hostname validation all
# correct, and (unlike _resolve_url_host()) does not require disabling
# certificate verification.
#
# No credentials required — this is the free/anonymous login path.
# ─────────────────────────────────────────────────────────────────────────────
# This file is a magic.login Python plugin.
# Required exports:  can_handle(portal_url, html) -> bool
#                    handle(portal_url, html, *, ticket, username, password) -> bool
# Optional export:   PRIORITY (int, default 50 — lower = checked first)
# ─────────────────────────────────────────────────────────────────────────────

import contextlib
import re
import socket as _socket

PRIORITY = 15  # check before the generic handler; after bahn.py/freekey.yaml

_ctx = {}   # populated by dispatcher: log, dbg, http_get, http_post,
            # _make_opener, _connectivity_ok, origin_of, json, time,
            # urllib_parse, urllib_error, HEADERS, _wlan_nameservers,
            # _resolve_host_via_wlan_dns, _resolve_url_host

_LANDING_HOST  = 'teledata.wifi.teledata.de'
_HOTSPOT_HOST  = 'hotspot.wifi.teledata.de'
_LANDING_URL   = 'https://%s/customer/landingpage' % _LANDING_HOST
_AJAX_URL      = 'https://%s/Ajax/service/' % _LANDING_HOST
_HOTSPOT_LOGIN = 'https://%s/login' % _HOTSPOT_HOST


def can_handle(portal_url, html):
    ul = portal_url.lower()
    h = (html or '').lower()
    return (
        _LANDING_HOST in ul or
        _LANDING_HOST in h or
        _HOTSPOT_HOST in ul or
        ('teledata' in h and 'wlan internet hotspot' in h)
    )


@contextlib.contextmanager
def _dns_override(hostname, ip):
    """Temporarily force socket.getaddrinfo() to resolve `hostname` to `ip`.

    Unlike substituting the IP directly into the request URL (what
    magic.login's core _resolve_url_host() does), this keeps the real
    hostname in the URL throughout — so the HTTP Host header, TLS SNI, and
    certificate-hostname validation are all unaffected. Only the actual
    socket connection is redirected. This is required for portals where
    the hostname is DNS-hijacked/portal-internal-DNS-only *and* the server
    relies on name-based virtual hosting to pick the right site.

    No-op (yields immediately) if ip is falsy, so callers can pass through
    a failed WLAN-DNS lookup without extra branching.
    """
    if not ip:
        yield
        return
    orig_getaddrinfo = _socket.getaddrinfo

    def _patched(host, *args, **kwargs):
        if host == hostname:
            host = ip
        return orig_getaddrinfo(host, *args, **kwargs)

    _socket.getaddrinfo = _patched
    try:
        yield
    finally:
        _socket.getaddrinfo = orig_getaddrinfo


_MAC_REDIRECT_RE = re.compile(
    r"getHostname\(\)\s*\+\s*['\"]([^'\"]*?/mac/[0-9A-Fa-f:]{17})['\"]")
_HOSTNAME_FN_RE = re.compile(
    r'function\s+getHostname\s*\([^)]*\)\s*(?://[^\n]*\n\s*)*\{'
    r'[^}]*?return\s*["\']([^"\']+)["\']', re.S)


def _extract_mac_bind_url(html):
    """Some Teledata deployments serve an initial hotspot.* login page
    (fetched by detect_portal() before dispatch — this is exactly the
    `html` handed to handle()) whose onload JS checks that cookies work,
    then redirects the browser to
    https://<hostname>/customer/index/mk-hotspot/<id>/mac/<MAC>
    to bind the session to the client's MAC address at the cloud CMS.

    Without this hit first, /customer/landingpage bounces in an endless
    meta-refresh loop back to the site root — the cloud session is never
    considered valid for this client. The location ID (e.g. "id-2020")
    and the client MAC are parsed out rather than hard-coded, since both
    vary per deployment/client. Returns the full URL, or None if this
    pattern isn't present (e.g. a different portal variant, or a client
    already known to the AP).
    """
    if not html:
        return None
    path_match = _MAC_REDIRECT_RE.search(html)
    if not path_match:
        return None
    host_match = _HOSTNAME_FN_RE.search(html)
    hostname = host_match.group(1) if host_match else _LANDING_HOST
    return 'https://%s%s' % (hostname, path_match.group(1))


def _extract_meta_refresh(html, base_url, urllib_parse):
    """Return the target URL of a <meta http-equiv="refresh"> redirect, or
    None. Some Teledata deployments bounce a cold HTTPS hit to
    /customer/landingpage back to the plain-HTTP site root first
    (presumably to (re-)establish MAC/session binding) before serving the
    real landing page — this follows that hop.
    """
    m = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']'
        r'\d+;\s*url=["\']?([^"\'>\s]+)["\']?', html or '', re.I)
    if not m:
        return None
    return urllib_parse.urljoin(base_url, m.group(1).strip('"\''))


def _fetch_landing_page(http_get, opener, resolve_fn, urllib_parse, log,
                        max_hops=5):
    """GET the landing page, following meta-refresh redirects (which may
    hop between hosts, e.g. HTTPS teledata.wifi.teledata.de/customer/
    landingpage -> plain HTTP teledata.wifi.teledata.de/) until a page
    with no further meta-refresh is reached. Each hop is resolved via
    the WLAN DNS server and connected to via _dns_override(), keeping
    the real hostname in the URL/Host header/SNI throughout.
    """
    url = _LANDING_URL
    for hop in range(max_hops):
        hostname = urllib_parse.urlparse(url).hostname
        ip = resolve_fn(hostname) if hostname else None
        with _dns_override(hostname, ip):
            body, final, resp = http_get(
                url, opener=opener,
                _dbg_label='teledata_landingpage_hop%d' % hop)
        if body is None:
            return None, None, resp
        redirect = _extract_meta_refresh(body, final, urllib_parse)
        if not redirect:
            return body, final, resp
        log('[Teledata] Following meta-refresh redirect (hop %d): %s'
            % (hop, redirect))
        url = redirect
    log('[Teledata] Too many meta-refresh hops (>%d) — giving up' % max_hops)
    return None, None, None


def _extract_form_meta(html):
    """Pull action/id/name of the <form ...> tag, AGB checkbox field name(s),
    and the submit button name/value out of the getButtonContent HTML.
    Returns a dict; missing pieces default to the values seen in the field.
    """
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
    _resolve_host_via_wlan_dns = _ctx['_resolve_host_via_wlan_dns']
    urllib_parse = _ctx['urllib_parse']
    json         = _ctx['json']

    log('[Teledata] Starting login')
    opener, jar = _make_opener()

    # Resolve both hostnames once via the WLAN-assigned DNS server. If the
    # system resolver already handles them fine, _dns_override() is a no-op
    # (ip will be None and it just yields through).
    landing_ip = _resolve_host_via_wlan_dns(_LANDING_HOST)
    hotspot_ip = _resolve_host_via_wlan_dns(_HOTSPOT_HOST)
    if landing_ip:
        log('[Teledata] %s -> %s (via WLAN DNS)' % (_LANDING_HOST, landing_ip))
    if hotspot_ip:
        log('[Teledata] %s -> %s (via WLAN DNS)' % (_HOTSPOT_HOST, hotspot_ip))

    # 1. If the initial hotspot.* page (already fetched by detect_portal()
    #    before dispatch, handed to us as `html`) contains the cookie-check
    #    JS redirect, bind the session to the client's MAC first. Skipping
    #    this causes /customer/landingpage to bounce forever between itself
    #    and the plain-HTTP site root (session never considered valid).
    #
    #    detect_portal()'s own fetch of this page uses a plain http_get()
    #    with no WLAN-DNS override, so it intermittently fails outright
    #    ("Name does not resolve") depending on how quickly the WLAN's
    #    DHCP-assigned DNS becomes available after association — in that
    #    case `html` here is None. Re-fetch the same URL ourselves (with
    #    DNS override) before giving up on the MAC-bind step.
    mac_bind_url = _extract_mac_bind_url(html)
    if not mac_bind_url:
        hotspot_host = urllib_parse.urlparse(portal_url).hostname or _HOTSPOT_HOST
        hotspot_page_ip = _resolve_host_via_wlan_dns(hotspot_host)
        log('[Teledata] No usable hotspot page HTML yet — re-fetching %s'
            % portal_url)
        with _dns_override(hotspot_host, hotspot_page_ip):
            fresh_body, _, fresh_resp = http_get(
                portal_url, opener=opener,
                _dbg_label='teledata_hotspot_refetch')
        if fresh_body:
            mac_bind_url = _extract_mac_bind_url(fresh_body)
        else:
            log('[Teledata] Could not fetch hotspot login page (%s)'
                % fresh_resp)

    if mac_bind_url:
        log('[Teledata] Binding session to client MAC via %s' % mac_bind_url)
        mac_host = urllib_parse.urlparse(mac_bind_url).hostname
        mac_ip = _resolve_host_via_wlan_dns(mac_host)
        with _dns_override(mac_host, mac_ip):
            mbody, _, mresp = http_get(mac_bind_url, opener=opener,
                                       _dbg_label='teledata_mac_bind')
        if mbody is None:
            log('[Teledata] MAC-bind request failed (%s) — continuing anyway'
                % mresp)
    else:
        log('[Teledata] No MAC-bind redirect found — assuming session '
            'already bound')

    # 2. Load the landing page — this is what sets lum_session. A cold hit
    #    straight to the HTTPS /customer/landingpage URL sometimes gets a
    #    meta-refresh bounce to the plain-HTTP site root first (presumably
    #    to (re-)establish MAC/session binding); follow that before
    #    treating the page as loaded.
    body, final, resp = _fetch_landing_page(http_get, opener,
                                            _resolve_host_via_wlan_dns,
                                            urllib_parse, log)
    if body is None:
        log('[Teledata] Could not load landing page (%s)' % resp)
        return False

    ajax_headers = {
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': _LANDING_URL,
    }
    ajax_content_type = 'application/x-www-form-urlencoded; charset=UTF-8'

    # 2. Fetch the "One-Click-Login" / free-WiFi button content, which
    #    contains the actual AGB checkbox field name and form id/name.
    button_req = urllib_parse.urlencode({'request': json.dumps({
        'model': 'customers',
        'method': 'getButtonContent',
        'requestType': 'htmlResponse',
        'isSubstition': True,
        'countPageImpression': True,
        'params': {'buttonNumber': '1'},
    }, separators=(',', ':'))})
    with _dns_override(_LANDING_HOST, landing_ip):
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

    login_req = urllib_parse.urlencode({'request': json.dumps({
        'model': 'customers',
        'method': 'loginOverLoginModule',
        'formName': meta['form_name'],
        'formData': form_data,
        'requestType': 'formValidation',
        'params': {'formID': meta['form_id'], 'data': form_data},
        'countPageImpression': True,
    }, separators=(',', ':'))})
    with _dns_override(_LANDING_HOST, landing_ip):
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
    with _dns_override(_HOTSPOT_HOST, hotspot_ip):
        _, final, _ = http_post(_HOTSPOT_LOGIN, router_body, opener=opener,
                                content_type='text/plain',
                                extra_headers={'Referer': 'https://%s/' % _LANDING_HOST},
                                _dbg_label='teledata_router_login')
    log('[Teledata] Router login response from %s' % final)

    return _connectivity_ok(opener)
