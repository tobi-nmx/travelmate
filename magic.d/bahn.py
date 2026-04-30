# magic.d/bahn.py — Deutsche Bahn captive portal handler
# ─────────────────────────────────────────────────────────────────────────────
# Covers three DB portal variants:
#
#   WIFIonICE / Ombord  — ICE and IC long-distance trains (SSID: WIFIonICE)
#                         Portal: login.wifionice.de → ombord.info backend
#                         MAC-based auth via CGI endpoint, no form needed.
#                         Verified via JSONP user-info endpoint.
#
#   CNA (local)         — DB stations and some regional trains
#                         Vue SPA frontend, REST API at /services/cna-portal/v1/
#                         api_type from /config determines the auth method.
#                         /config may return 404 on some deployments — in that
#                         case api_type defaults to 'local' and /cna/logon is
#                         used directly.
#
#   CNA (Ombord)        — Some trains use the CNA frontend but Ombord backend
#                         (api_type = 'ombord' or 'emailreg')
#
# No credentials required for any variant.
# ─────────────────────────────────────────────────────────────────────────────
# This file is a magic.login Python plugin.
# Required exports:  can_handle(portal_url, html) -> bool
#                    handle(portal_url, html, *, ticket, username, password) -> bool
# Optional export:   PRIORITY (int, default 50 — lower = checked first)
# The plugin receives the core helpers injected via _ctx at import time;
# see magic.login dispatcher for details.
# ─────────────────────────────────────────────────────────────────────────────

PRIORITY = 10   # check before YAML handlers

# Core helpers are injected by the dispatcher before can_handle() is called.
# Accessing them via module globals keeps the plugin self-contained.
_ctx = {}   # populated by dispatcher: log, dbg, http_get, http_post,
            # _make_opener, _connectivity_ok, origin_of, json, time,
            # urllib_parse, urllib_error


def _make_legacy_ssl_opener():
    """Return an opener that tolerates legacy TLS renegotiation.

    wifi.bahn.de uses unsafe legacy renegotiation which Python's ssl module
    rejects by default since OpenSSL 3.0. OP_LEGACY_SERVER_CONNECT re-enables
    it for this specific opener without affecting the rest of the script.
    Falls back to a standard opener if the option is unavailable (older OpenSSL).
    """
    import ssl as _ssl
    import urllib.request as _ur
    import http.cookiejar as _cj
    _make_opener = _ctx['_make_opener']
    try:
        ctx = _ssl.create_default_context()
        ctx.options |= _ssl.OP_LEGACY_SERVER_CONNECT
        jar = _cj.CookieJar()
        opener = _ur.build_opener(
            _ur.HTTPCookieProcessor(jar),
            _ur.HTTPSHandler(context=ctx),
        )
        opener.addheaders = list(_ctx['HEADERS'].items())
        return opener, jar
    except AttributeError:
        # OP_LEGACY_SERVER_CONNECT not available — fall back to standard opener
        _ctx['dbg']('[DB] OP_LEGACY_SERVER_CONNECT unavailable, using standard opener')
        return _make_opener()


def can_handle(portal_url, html):
    ul = portal_url.lower()
    h  = (html or '').lower()
    return (
        'ombord.info'              in ul or 'ombord.info'          in h or
        'wifionice'                in ul or 'wifionice'            in h or
        'wifi.bahn.de'             in ul or 'bahn.de'              in ul or
        'cna-portal'               in h  or
        '/services/cna-portal/v1/' in h  or
        'cna-portal-frontend'      in h
    )


def handle(portal_url, html, ticket=None, username=None, password=None):
    ul = portal_url.lower()
    h  = (html or '').lower()
    if 'ombord.info' in ul or 'ombord.info' in h:
        return _handle_ombord(portal_url, ticket=ticket)
    if 'wifionice' in ul or 'wifionice' in h:
        return _handle_ombord(portal_url, ticket=ticket)
    return _handle_cna(portal_url, ticket=ticket,
                       username=username, password=password)


def _handle_ombord(portal_url, ticket=None):
    """DB ICE (Ombord backend) — MAC-based, no form needed."""
    log          = _ctx['log']
    dbg          = _ctx['dbg']
    http_get     = _ctx['http_get']
    _make_opener = _ctx['_make_opener']
    time         = _ctx['time']
    urllib_parse = _ctx['urllib_parse']

    log('[DB/Ombord] Logging in via Ombord CGI')
    opener, _ = _make_legacy_ssl_opener()
    venue_enc   = urllib_parse.quote(portal_url, safe='')
    onerror_enc = urllib_parse.quote(portal_url + '?onerror=true', safe='')
    login_url   = ('https://www.ombord.info/hotspot/hotspot.cgi?method=login'
                   '&url=%s&onerror=%s' % (venue_enc, onerror_enc))
    body, final, _ = http_get(login_url, opener=opener,
                              _dbg_label='db_ombord_login')
    if body is None:
        log('[DB/Ombord] Request failed')
        return False
    log('[DB/Ombord] Login CGI response from %s' % final)

    # Verify via JSONP user-info endpoint
    time.sleep(1)
    info, _, _ = http_get('https://www.ombord.info/api/jsonp/user/',
                          opener=opener, _dbg_label='db_ombord_userinfo')
    if info and ('"authenticated":"1"' in info or "'authenticated':'1'" in info):
        log('[DB/Ombord] Authenticated!')
        return True

    # MAC auth has no explicit error indication — treat any response as success
    log('[DB/Ombord] No explicit confirmation, assuming success')
    return body is not None


def _handle_cna(portal_url, ticket=None, username=None, password=None):
    """DB CNA portal (stations / regional trains) — Vue SPA, REST API."""
    log          = _ctx['log']
    dbg          = _ctx['dbg']
    http_get     = _ctx['http_get']
    http_post    = _ctx['http_post']
    _make_opener = _ctx['_make_opener']
    json         = _ctx['json']
    urllib_error = _ctx['urllib_error']
    origin_of    = _ctx['origin_of']

    log('[DB/CNA] Detected DB CNA portal')
    base   = origin_of(portal_url)
    opener, _ = _make_legacy_ssl_opener()

    # 1. Fetch portal config to determine api_type.
    #    /config may return 404 on some deployments (e.g. DB stations) — in
    #    that case we skip api_type detection and go straight to /cna/logon.
    cfg_body, _, cfg_resp = http_get('%s/services/cna-portal/v1/config' % base,
                                     opener=opener, _dbg_label='db_cna_config')
    api_type = 'local'
    if cfg_body:
        if isinstance(cfg_resp, urllib_error.HTTPError):
            log('[DB/CNA] /config returned HTTP %d — assuming api_type=local'
                % cfg_resp.code)
        else:
            try:
                api_type = (json.loads(cfg_body)
                            .get('result', {})
                            .get('api_type', 'local'))
                log('[DB/CNA] api_type = %s' % api_type)
            except Exception:
                log('[DB/CNA] Could not parse config JSON — assuming api_type=local')

    # 2. ICE trains that use the CNA frontend but Ombord backend
    if api_type in ('ombord', 'emailreg'):
        return _handle_ombord(portal_url, ticket=ticket)

    # 3. local / local_otp / local_test → POST to /cna/logon
    logon_url = '%s/cna/logon' % base
    log('[DB/CNA] POSTing to %s' % logon_url)
    body, final, resp = http_post(
        logon_url, '{}', opener=opener,
        content_type='application/json',
        extra_headers={
            'X-Real-IP':        '192.168.64.0',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Csrf-Token':     'csrf',
            'X-Reserve-Id':     '1',
        },
        _dbg_label='db_cna_logon',
    )
    log('[DB/CNA] Logon response from %s' % final)
    return body is not None and not isinstance(resp, urllib_error.HTTPError)

