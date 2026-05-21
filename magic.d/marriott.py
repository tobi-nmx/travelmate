# magic.d/marriott.py — Marriott hotel captive portal handler
# ─────────────────────────────────────────────────────────────────────────────
# Antlabs IG portal used in Marriott conference/hotel WiFi.
#
# Login flow:
#   1. GET  portal page (10.254.254.254/HTML/free/login.html) — done by detect_portal()
#   2. POST credentials to Appweb auth host (10.252.1.252:9997/login)
#          username=<access-code>  password=Hotspot (fixed)
#   3. Auth host returns an HTML page with a JS image load that triggers MAC
#      authorization:
#          img.src = "/_allowuser.jsp?cid=<dynamic>&username=<code>&url=<orig>"
#      This GET must be sent to the portal Apache host (not the Appweb host).
#      A browser fires it automatically; we extract and follow it explicitly.
#
# Access code is supplied as the ticket argument:
#   magic.login [--debug] [--force] <access-code>
# or via /etc/captive-credentials.conf:
#   Hotspot*  ticket  <access-code>
#
# Credentials: access code only, no username/password.
# ─────────────────────────────────────────────────────────────────────────────

import re as _re

PRIORITY = 30

_ctx = {}   # injected by dispatcher: log, dbg, http_get, http_post,
            # _make_opener, _connectivity_ok, origin_of, urllib_parse,
            # urllib_error


def can_handle(portal_url, html):
    ul = portal_url.lower()
    h  = (html or '').lower()
    return '/html/free/login.html' in ul or 'marriottlogo' in h


def handle(portal_url, html, ticket=None, username=None, password=None):
    log              = _ctx['log']
    dbg              = _ctx['dbg']
    http_get         = _ctx['http_get']
    http_post        = _ctx['http_post']
    _make_opener     = _ctx['_make_opener']
    _connectivity_ok = _ctx['_connectivity_ok']
    origin_of        = _ctx['origin_of']
    urllib_parse     = _ctx['urllib_parse']
    urllib_error     = _ctx['urllib_error']

    access_code = ticket or username
    if not access_code:
        log('[Marriott] No access code provided — supply it as a ticket argument')
        return False

    log('[Marriott] Starting login (access code: %r)' % access_code)
    opener, jar = _make_opener()
    portal_origin = origin_of(portal_url)   # e.g. http://10.254.254.254

    # ── Step 1: parse the login form from the portal page ────────────────────
    # detect_portal() already fetched this page; html is passed in.
    # Extract the form action (Appweb host:port) from the HTML.
    m = _re.search(r"action=['\"]([^'\"]+)['\"]", html or '', _re.I)
    if not m:
        log('[Marriott] Could not find form action in portal page')
        return False
    action_url = m.group(1)
    if not action_url.startswith('http'):
        action_url = urllib_parse.urljoin(portal_url, action_url)
    log('[Marriott] Auth endpoint: %s' % action_url)

    # ── Step 2: POST credentials to Appweb auth host ─────────────────────────
    post_data = {'username': access_code, 'password': 'Hotspot'}
    log('[Marriott] POSTing credentials')
    body, final, resp = http_post(
        action_url, post_data, opener=opener,
        extra_headers={'Referer': portal_url},
        _dbg_label='marriott_login',
    )

    if body is None or isinstance(resp, urllib_error.HTTPError):
        log('[Marriott] Login POST failed')
        return False

    # ── Step 3: extract and follow the _allowuser.jsp MAC-auth GET ───────────
    # The response body contains:  img.src = "/_allowuser.jsp?cid=...&..."
    # This GET is what actually authorizes the MAC address on the AP.
    m = _re.search(r'img\.src\s*=\s*["\']([^"\']+)["\']', body)
    if not m:
        log('[Marriott] Could not find _allowuser.jsp URL in login response')
        log('[Marriott] Response body: %r' % body[:300])
        return False

    allow_path = m.group(1)
    # The img.src is a relative URL in a page served by the Appweb host
    # (10.252.1.252:9997). Browsers resolve it against that origin, so the
    # correct target is http://10.252.1.252:9997/_allowuser.jsp — not the
    # Apache portal host (10.254.254.254).
    appweb_origin = origin_of(action_url)
    allow_url = urllib_parse.urljoin(appweb_origin + '/', allow_path.lstrip('/'))
    log('[Marriott] Sending MAC-auth request: %s' % allow_url)

    # Send via the same opener (carries the Appweb session cookie) with a
    # Referer pointing back to the login endpoint, matching browser behaviour.
    import urllib.request as _ur
    try:
        req = _ur.Request(allow_url, headers={'Referer': action_url})
        resp = opener.open(req, timeout=10)
        allow_body  = resp.read().decode('utf-8', errors='replace')
        allow_final = resp.geturl()
    except Exception as _e:
        allow_body  = ''
        allow_final = allow_url
        dbg('[Marriott] _allowuser.jsp: %s' % _e)
    dbg('[Marriott] _allowuser response from %s  (%d bytes)' % (
        allow_final, len(allow_body or '')))

    # ── Connectivity check ────────────────────────────────────────────────────
    import time as _time
    for attempt, delay in enumerate([2, 3, 5, 5], 1):
        _time.sleep(delay)
        log('[Marriott] Connectivity check %d/4 ...' % attempt)
        if _connectivity_ok(opener):
            return True

    log('[Marriott] Login failed — not online after all retries')
    return False
