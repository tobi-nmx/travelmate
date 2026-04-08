#!/usr/bin/env python3
"""
captive-login.py  —  Universal captive portal login for OpenWrt/Travelmate

Usage:
  captive-login.py                      # checkbox / free portals (no credentials)
  captive-login.py <ticket>             # ticket / voucher portals
  captive-login.py <username> <password>  # username+password portals

Supported portals (specific handlers):
  - DB Bahn ICE trains     (Ombord backend)
  - DB Bahn stations/city  (CNA/local REST API)
  - Hotsplots              (used by BayernWLAN, many venues)
  - Telekom Hotspot        (t-online.de, hotspot.t-)
  - Vodafone Hotspot
  - Generic HTML form      (fallback for all others: Edeka, airports, hotels, …)

Travelmate integration — central (recommended):
  1. Set a single global script in /etc/config/travelmate:
       config travelmate 'global'
           option trm_captivescript '/usr/bin/captive-login.py'

  2. For credential-based SSIDs, add entries to /etc/captive-credentials.conf:
       # SSID (or fnmatch pattern)   type      credential(s)
       Telekom_FON_*                 userpass  max.mustermann@t-online.de  s3cr3t
       VodafoneWifi*                 userpass  myuser  mypassword
       HotSpotsVenue                 ticket    ABCD-1234

     The script reads the current SSID from Travelmate's runtime JSON
     (/tmp/trm_runtime.json) and matches it against this file automatically.
     Free/checkbox SSIDs need no entry — they are handled without credentials.

  Per-uplink override (alternative):
     Add  option trm_captivescript '/usr/bin/captive-login.py ticket_or_user pass'
     to the relevant wifi-iface section in /etc/config/wireless.
     Travelmate passes those extra words as argv to the script.
"""

import sys
import re
import json
import time
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser

# ── Debug mode ───────────────────────────────────────────────────────────────

DEBUG = False          # set to True by --debug flag
_debug_log_fh = None   # open file handle when --debug is active
_debug_step   = 0      # sequential counter for HTML dump files
DEBUG_DIR     = '/tmp/captive-debug'

def _init_debug():
    """Create debug directory and open the log file."""
    global _debug_log_fh
    import os
    os.makedirs(DEBUG_DIR, exist_ok=True)
    path = f'{DEBUG_DIR}/session.log'
    _debug_log_fh = open(path, 'w', buffering=1)
    log(f'[debug] Writing debug log to {path}')
    log(f'[debug] HTML dumps go to {DEBUG_DIR}/step_*.html')

def log(msg):
    """Print to stdout (always) and to debug log file (if debug active)."""
    print(msg, flush=True)
    if _debug_log_fh:
        import datetime
        ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        _debug_log_fh.write(f'{ts}  {msg}\n')

def dbg(msg):
    """Debug-only log — printed and written only when --debug is active."""
    if DEBUG:
        log(f'[DBG] {msg}')

def dbg_html(label, url, html, forms=None, cookies=None, headers=None):
    """
    Dump a full HTML page + metadata to a numbered file in DEBUG_DIR.
    Also writes a compact summary to the log.
    """
    if not DEBUG:
        return
    global _debug_step
    _debug_step += 1
    import os, datetime
    fname = '%s/step_%02d_%s.html' % (DEBUG_DIR, _debug_step, label)
    lines = []
    lines.append('<!-- URL: %s -->' % url)
    lines.append('<!-- Time: %s -->' % datetime.datetime.now().isoformat())
    if headers:
        lines.append('<!-- Response headers:')
        hdr_items = headers.items() if hasattr(headers, 'items') else headers
        for k, v in hdr_items:
            lines.append('     %s: %s' % (k, v))
        lines.append('-->')
    if cookies:
        lines.append('<!-- Cookies: %s -->' % cookies)
    if forms:
        lines.append('<!-- Forms found: %d' % len(forms))
        for i, frm in enumerate(forms):
            lines.append('     Form %d: method=%s action=%r' % (i, frm['method'], frm['action']))
            for fn2, fld in frm['fields'].items():
                lines.append('       %s: type=%s value=%r' % (fn2, fld['type'], fld['value']))
        lines.append('-->')
    lines.append(html or '')
    with open(fname, 'w') as f:
        f.write('\n'.join(lines))
    dbg('HTML dump -> %s  (%d bytes, %d form(s))' % (fname, len(html or ''), len(forms or [])))
    if cookies:
        dbg('Cookies: %s' % cookies)
    if headers:
        hdr_items = headers.items() if hasattr(headers, 'items') else {}
        interesting = {k: v for k, v in hdr_items
                       if k.lower() in ('location', 'set-cookie', 'content-type', 'x-cache', 'server')}
        if interesting:
            dbg('Notable headers: %s' % interesting)




# ── Configuration ─────────────────────────────────────────────────────────────

# HTTP URLs used to probe for a captive portal redirect.
# Must be plain HTTP (not HTTPS) so the portal can intercept them.
PROBE_URLS = [
    'http://connectivitycheck.gstatic.com/generate_204',
    'http://detectportal.firefox.com/success.txt',
    'http://captive.apple.com/hotspot-detect.html',
    'http://www.msftncsi.com/ncsi.txt',
    'http://neverssl.com/',
]

# Responses at PROBE_URLS that mean "you are online, no portal"
ONLINE_SIGNATURES = {
    'http://connectivitycheck.gstatic.com/generate_204': '',        # 204 No Content
    'http://detectportal.firefox.com/success.txt':       'success',
    'http://captive.apple.com/hotspot-detect.html':      'Success',
    'http://www.msftncsi.com/ncsi.txt':                  'Microsoft NCSI',
}

TIMEOUT = 15  # seconds per request

HEADERS = {
    'User-Agent':      'Mozilla/5.0 (Linux; Android 11; OpenWrt) AppleWebKit/537.36',
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'identity',
    'Connection':      'keep-alive',
}

# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args():
    """Return (ticket, username, password) — at most one pair is non-None.
    Strips --debug from argv and sets the global DEBUG flag.
    """
    global DEBUG
    args = [a for a in sys.argv[1:] if a != '--debug']
    if '--debug' in sys.argv:
        DEBUG = True
        _init_debug()
        dbg(f'argv: {sys.argv}')
    if len(args) == 0:
        return None, None, None
    if len(args) == 1:
        return args[0], None, None        # ticket / voucher
    if len(args) == 2:
        return None, args[0], args[1]    # username, password
    die(f'Usage: {sys.argv[0]} [--debug] [ticket | username password]')


# ── HTTP helpers ──────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Intercept the first redirect instead of following it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _make_jar():
    return http.cookiejar.CookieJar()


def _make_opener(jar=None, follow_redirects=True):
    """Build a urllib opener with cookie support."""
    jar = jar or _make_jar()
    handlers = [urllib.request.HTTPCookieProcessor(jar)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = list(HEADERS.items())
    return opener, jar


def http_get(url, opener=None, timeout=TIMEOUT, _dbg_label=None):
    """GET url; return (body_str, final_url, response_or_error)."""
    if opener is None:
        opener, _ = _make_opener()
    dbg(f'GET {url}')
    try:
        resp = opener.open(url, timeout=timeout)
        body = resp.read().decode('utf-8', errors='replace')
        final = resp.geturl()
        if _dbg_label and body:
            cookies = {c.name: c.value for c in getattr(opener, '_cookies', [])}
            dbg_html(_dbg_label, final, body, headers=resp.headers)
        elif final != url:
            dbg(f'  → redirected to {final}')
        return body, final, resp
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        dbg(f'  HTTP {e.code} error')
        if _dbg_label and body:
            dbg_html(_dbg_label + f'_err{e.code}', url, body, headers=e.headers)
        return body, url, e
    except Exception as e:
        dbg(f'  Exception: {e}')
        return None, url, e


def http_post(url, data, opener=None, timeout=TIMEOUT,
              content_type='application/x-www-form-urlencoded',
              extra_headers=None, _dbg_label=None):
    """POST data to url; data may be dict, str, or bytes."""
    if opener is None:
        opener, _ = _make_opener()
    if isinstance(data, dict):
        payload = urllib.parse.urlencode(data).encode()
        dbg(f'POST {url}  data={dict((k, "***" if "pass" in k.lower() else v) for k,v in data.items())}')
    elif isinstance(data, str):
        payload = data.encode('utf-8')
        dbg(f'POST {url}  body={data[:200]!r}')
    else:
        payload = data
        dbg(f'POST {url}  (raw bytes, {len(payload)} bytes)')
    req = urllib.request.Request(url, data=payload)
    req.add_header('Content-Type', content_type)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
        dbg(f'  extra headers: {extra_headers}')
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode('utf-8', errors='replace')
        final = resp.geturl()
        if final != url:
            dbg(f'  → redirected to {final}')
        if _dbg_label and body:
            dbg_html(_dbg_label, final, body, headers=resp.headers)
        return body, final, resp
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        dbg(f'  HTTP {e.code} error')
        if _dbg_label and body:
            dbg_html(_dbg_label + f'_err{e.code}', url, body, headers=e.headers)
        return body, url, e
    except Exception as e:
        dbg(f'  Exception: {e}')
        return None, url, e


def origin_of(url):
    """Return scheme://host from a full URL."""
    p = urllib.parse.urlparse(url)
    return f'{p.scheme}://{p.netloc}'


# ── Portal detection ──────────────────────────────────────────────────────────

def detect_portal():
    """
    Probe known HTTP check-URLs without following redirects.
    Returns (portal_url, html_body) or (None, None) if already online.
    """
    no_redir_opener, _ = _make_opener(follow_redirects=False)

    for probe in PROBE_URLS:
        try:
            resp = no_redir_opener.open(probe, timeout=TIMEOUT)
            # Got a 200-level response — might already be online
            body = resp.read().decode('utf-8', errors='replace')
            expected = ONLINE_SIGNATURES.get(probe)
            if expected is not None and expected in body:
                log('[detect] Already online (probe succeeded without redirect)')
                return None, None
            # 200 but wrong content → transparent proxy / portal that returns 200
            final = resp.geturl()
            if final != probe:
                log(f'[detect] Redirect to {final}')
                html, fu, _ = http_get(final, _dbg_label='detect_portal')
                return fu, html
            # Probably online but unexpected content — treat as online
            return None, None

        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location') or e.headers.get('location') or ''
            if loc:
                loc = urllib.parse.urljoin(probe, loc)
                log(f'[detect] Portal redirect: {loc}')
                html, fu, _ = http_get(loc, _dbg_label='detect_portal')
                return fu, html
            # 204 with no redirect = online
            if e.code == 204:
                return None, None
            # Other HTTP error on probe — try next

        except Exception:
            pass  # network error or timeout — try next

    log('[detect] All probes failed — not connected or captive portal blocks all traffic')
    return None, None


# ── Success detection ─────────────────────────────────────────────────────────

SUCCESS_WORDS = [
    'now connected', 'nowconnected', 'verbunden', 'erfolgreich', 'angemeldet',
    'success', 'welcome', 'willkommen', 'enjoy', 'you are online',
    'internet access', 'internetzugang', 'you\'re connected', 'connected',
    'logout', 'abmelden', 'signed in', 'authorized',
]

# Words that indicate failure — override any SUCCESS_WORDS match
FAILURE_WORDS = [
    'session has expired', 'session expired', 'sitzung abgelaufen',
    'please reconnect', 'bitte erneut verbinden',
    'login failed', 'anmeldung fehlgeschlagen',
    'invalid', 'ungültig', 'error', 'fehler',
    'access denied', 'zugriff verweigert',
    'wrong password', 'falsches passwort',
    'incorrect', 'not authorized', 'unauthorized',
]

def looks_like_success(html, final_url=''):
    """Heuristic: does the response body/URL indicate a successful login?"""
    if html is None:
        return False
    lower = html.lower()
    url_lower = final_url.lower()

    # Check for failure indicators first — they override success words
    if any(w in lower for w in FAILURE_WORDS):
        log(f'[success-check] Failure keyword detected — treating as failed')
        return False

    if any(w in lower for w in SUCCESS_WORDS):
        return True
    if any(w in url_lower for w in ['success', 'connected', 'welcome', 'now-connected', 'online']):
        return True
    return False


# ── HTML form parser ──────────────────────────────────────────────────────────

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()

        if t == 'form':
            self._cur = {
                'action': a.get('action', ''),
                'method': a.get('method', 'get').upper(),
                'fields': {},
                'id':     a.get('id', ''),
            }

        elif t == 'input' and self._cur is not None:
            name = a.get('name') or a.get('id', '')
            typ  = (a.get('type') or 'text').lower()
            val  = a.get('value', '')
            if name:
                self._cur['fields'][name] = {
                    'type':    typ,
                    'value':   val,
                    'checked': 'checked' in a,
                    'id':      a.get('id', ''),
                }

        elif t == 'select' and self._cur is not None:
            self._cur['_sel'] = a.get('name', '')

        elif t == 'option' and self._cur is not None:
            sel = self._cur.get('_sel', '')
            if sel and 'selected' in a and sel not in self._cur['fields']:
                self._cur['fields'][sel] = {
                    'type': 'select', 'value': a.get('value', ''), 'checked': False, 'id': '',
                }

        elif t == 'textarea' and self._cur is not None:
            name = a.get('name', '')
            if name:
                self._cur['fields'][name] = {
                    'type': 'textarea', 'value': '', 'checked': False, 'id': '',
                }

    def handle_endtag(self, tag):
        if tag.lower() == 'form' and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def best_form(self):
        """Return the form most likely to be the login/connect form."""
        candidates = []
        for form in self.forms:
            fields = form['fields']
            names  = [k.lower() for k in fields]
            score  = 0
            score += 3 * any('pass'    in n or 'pwd'     in n for n in names)
            score += 2 * any('user'    in n or 'login'   in n or 'email' in n for n in names)
            score += 2 * any('ticket'  in n or 'voucher' in n or 'code'  in n
                             or 'pin'  in n or 'key'     in n for n in names)
            score += 1 * any(v['type'] == 'checkbox' for v in fields.values())
            score -= 2 * (form['method'] == 'GET' and len(fields) <= 1)
            candidates.append((score, form))

        candidates.sort(key=lambda x: -x[0])
        # Prefer POST forms; fall back to highest-score GET form
        for _, form in candidates:
            if form['method'] == 'POST':
                return form
        return candidates[0][1] if candidates else None


def parse_forms(html):
    p = _FormParser()
    p.feed(html)
    return p.forms, p.best_form()


# ── Form filling ──────────────────────────────────────────────────────────────

# Heuristic field-name patterns
_TICKET_RE  = re.compile(
    r'ticket|voucher|coupon|code|pin|passcode|access.?key|token|freekey|free.?key', re.I)
_USER_RE    = re.compile(r'user|login|email|mail|account|name|uid', re.I)
_PASS_RE    = re.compile(r'pass|pwd|secret|credential', re.I)

# Field types that count as "visible credential inputs"
_VISIBLE_INPUT_TYPES = {'text', 'tel', 'number', 'search', 'email', 'textarea'}


def fill_form(form, ticket=None, username=None, password=None):
    """Build submission payload from a form, injecting credentials."""
    data = {}
    submit_included = False
    ticket_placed   = False
    username_placed = False

    for name, field in form['fields'].items():
        typ = field['type']
        val = field['value']
        nl  = name.lower()

        if typ == 'hidden':
            data[name] = val

        elif typ == 'submit':
            # Include only the first submit button value (simulates a click)
            if not submit_included and val:
                data[name] = val
                submit_included = True

        elif typ in ('button', 'image'):
            pass  # skip non-submit buttons

        elif typ == 'checkbox':
            # Always tick — accepting T&C is the whole point
            data[name] = val if val else 'on'

        elif typ == 'radio':
            # Keep pre-selected value; if none selected pick first
            if field['checked'] or name not in data:
                data[name] = val

        elif typ == 'password':
            data[name] = password or ''

        elif _TICKET_RE.search(nl):
            data[name] = ticket or val
            if ticket:
                ticket_placed = True

        elif _USER_RE.search(nl):
            data[name] = username or val
            if username:
                username_placed = True

        else:
            data[name] = val

    # Fallback: if we have a ticket/username that wasn't placed by name-pattern
    # matching, find the single remaining empty visible text field and use it.
    # This handles portals with unusual field names (e.g. free-key.eu uses "key").
    if ticket and not ticket_placed:
        empty_text_fields = [
            n for n, f in form['fields'].items()
            if f['type'] in _VISIBLE_INPUT_TYPES and not data.get(n)
        ]
        if len(empty_text_fields) == 1:
            data[empty_text_fields[0]] = ticket
            ticket_placed = True

    if username and not username_placed and not ticket_placed:
        empty_text_fields = [
            n for n, f in form['fields'].items()
            if f['type'] in _VISIBLE_INPUT_TYPES and not data.get(n)
        ]
        if len(empty_text_fields) == 1:
            data[empty_text_fields[0]] = username

    return data


def resolve_action(base_url, action):
    """Resolve a form action relative to the page URL."""
    if not action:
        return base_url
    if action.startswith('http://') or action.startswith('https://'):
        return action
    return urllib.parse.urljoin(base_url, action)


# ── Portal handlers ───────────────────────────────────────────────────────────

def handle_ombord(portal_url, ticket=None):
    """
    DB ICE train WiFi — Ombord backend.
    Authentication is MAC-based; just hitting the login CGI is enough.
    """
    log('[DB/Ombord] Logging in via Ombord hotspot CGI')

    # Build the login URL the same way the JS does:
    #   T1(base, encodeURIComponent(venue_url), encodeURIComponent(onerror_url))
    # We use the portal URL as the redirect target.
    venue_enc  = urllib.parse.quote(portal_url, safe='')
    onerror_enc = urllib.parse.quote(portal_url + '?onerror=true', safe='')
    login_url = (
        f'https://www.ombord.info/hotspot/hotspot.cgi?method=login'
        f'&url={venue_enc}&onerror={onerror_enc}'
    )

    opener, _ = _make_opener()
    body, final, resp = http_get(login_url, opener=opener)

    if body is None:
        log('[DB/Ombord] Request failed')
        return False

    log(f'[DB/Ombord] Response from {final}')

    # Verify via JSONP user info endpoint
    time.sleep(1)
    info_body, _, _ = http_get('https://www.ombord.info/api/jsonp/user/', opener=opener)
    if info_body and 'authenticated' in info_body:
        # JSONP: callback({...,"authenticated":"1",...})
        if '"authenticated":"1"' in info_body or "'authenticated':'1'" in info_body:
            log('[DB/Ombord] Authenticated!')
            return True

    # Treat as success if we got a response (MAC auth has no error indication)
    return body is not None


def handle_db_cna(portal_url, ticket=None, username=None, password=None):
    """
    DB CNA portal — used at DB stations and some regional trains.
    The portal is a Vue SPA; we bypass JS and call the REST API directly.
    """
    log('[DB/CNA] Detected DB CNA portal')
    base = origin_of(portal_url)
    opener, jar = _make_opener()

    # 1. Fetch portal config to determine api_type
    cfg_url = f'{base}/services/cna-portal/v1/config'
    cfg_body, _, _ = http_get(cfg_url, opener=opener)

    api_type = 'local'
    if cfg_body:
        try:
            result = json.loads(cfg_body).get('result', {})
            api_type = result.get('api_type', 'local')
            log(f'[DB/CNA] api_type = {api_type}')
        except (json.JSONDecodeError, AttributeError):
            log('[DB/CNA] Could not parse config, assuming local')

    # 2. Ombord-type (ICE trains that use the CNA frontend but Ombord backend)
    if api_type in ('ombord', 'emailreg'):
        return handle_ombord(portal_url, ticket=ticket)

    # 3. local / local_otp / local_test → POST to /cna/logon
    logon_url = f'{base}/cna/logon'
    log(f'[DB/CNA] POSTing to {logon_url}')

    cna_headers = {
        'X-Real-IP':        '192.168.64.0',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Csrf-Token':     'csrf',
        'X-Reserve-Id':     '1',
    }
    body, final, resp = http_post(
        logon_url, '{}', opener=opener,
        content_type='application/json',
        extra_headers=cna_headers,
    )
    log(f'[DB/CNA] Logon response from {final}')
    return body is not None and (
        isinstance(resp, urllib.error.HTTPError) is False or resp.code < 400
    )


def handle_freekey(portal_url, html, ticket=None, username=None, password=None):
    """
    free-key.eu captive portal handler.

    The portal flow:
      1. Browser lands on hotspot.free-key.eu/login?dst=...
         which immediately redirects to service.free-key-de.eu/?FREEKEYWIFI=<token>&...
      2. That page shows the actual login form (checkbox / T&C acceptance).
      3. Submitting the form POSTs back to service.free-key-de.eu/ with the
         FREEKEYWIFI token preserved as a hidden field.
      4. On success the portal redirects to the original dst URL.

    The generic handler may mis-detect "Welcome to free-key" as success, or
    follow the form to the wrong URL. This handler extracts the service URL
    with the session token and submits directly.
    """
    log('[free-key] Using dedicated free-key handler')
    opener, jar = _make_opener()

    # ── Step 1: use the HTML already fetched by detect_portal() ─────────────
    # detect_portal() already downloaded the login page — reuse it directly
    # to avoid a redundant HTTP request.
    service_url = portal_url
    if html:
        log(f'[free-key] Reusing portal page from detect_portal() ({len(html)} bytes)')
        log(f'[free-key] Page snippet: {html[:300].strip()!r}')
        dbg_html('freekey_step1_login_reused', portal_url, html)
    else:
        # Fallback: fetch if not provided (e.g. called directly)
        log(f'[free-key] Fetching portal page from {portal_url}')
        html, service_url, resp1 = http_get(portal_url, opener=opener,
                                            _dbg_label='freekey_step1_login')
        if html is None:
            log('[free-key] Could not fetch portal page')
            return False
        log(f'[free-key] Landed on: {service_url}')

    # Bail out if the page says the session has expired — nothing we can do
    if html and ('session has expired' in html.lower() or 'please reconnect' in html.lower()):
        log('[free-key] Session expired — portal requires a fresh connection (re-associate to AP)')
        return False

    # ── Step 2: parse + submit form ──────────────────────────────────────────
    forms, best = parse_forms(html)
    if DEBUG and html:
        cookies = {c.name: c.value for c in jar}
        dbg_html('freekey_step1_parsed', service_url, html, forms=forms, cookies=cookies)
    if not best:
        log('[free-key] No form found — trying connectivity check anyway')
        return _connectivity_ok(opener)

    log(f'[free-key] Form: method={best["method"]} action={best["action"]!r}  '
        f'fields={list(best["fields"].keys())}')

    # Extract status URL from form for later connectivity fallback check
    # (Mikrotik/Coova portals include link-status as a hidden field)
    status_url = None
    for name, field in best['fields'].items():
        if 'status' in name.lower() and (field.get('value') or '').startswith('http'):
            status_url = field['value']
            log(f'[free-key] Found status URL: {status_url}')
            break

    data = fill_form(best, ticket=ticket, username=username, password=password)

    # The router sets link-orig empty in the actual form HTML;
    # fill_form may copy the dst URL from the portal URL — clear it to match browser
    if 'link-orig' in data:
        data['link-orig'] = ''

    action_url = resolve_action(service_url, best['action'])
    log(f'[free-key] Submitting to {action_url}')
    log(f'[free-key] POST data: { {k: v for k, v in data.items() if k != "password"} }')

    # Log cookies collected so far
    cookies = {c.name: c.value for c in jar}
    log(f'[free-key] Cookies in jar: {cookies}')

    # Mimic the JS auto-submit: browser sets Referer to the login page
    extra_headers = {'Referer': service_url}
    body2, final2, resp2 = http_post(action_url, data, opener=opener,
                                     extra_headers=extra_headers,
                                     _dbg_label='freekey_step2_router_post')
    log(f'[free-key] Response URL: {final2}')
    if hasattr(resp2, 'headers'):
        log(f'[free-key] Response headers: {dict(resp2.headers)}')
    if body2:
        log(f'[free-key] Response snippet: {body2[:400].strip()!r}')

    if body2 and ('session has expired' in body2.lower() or 'please reconnect' in body2.lower()):
        log('[free-key] Portal returned session-expired after POST — session token is stale')
        return False

    # ── Step 2b: second form (FREEKEYWIFI token + action=auth) ───────────────
    # service.free-key-de.eu responds to the first POST with a new form that
    # contains a FREEKEYWIFI session token and action=auth. We must submit that
    # second form to actually authenticate the MAC address.
    if body2 and 'FREEKEYWIFI' in body2:
        log('[free-key] Got FREEKEYWIFI token form — submitting auth step')
        forms2, best2 = parse_forms(body2)
        if best2:
            log(f'[free-key] Auth form fields: {list(best2["fields"].keys())}')
            data2 = fill_form(best2)
            action2 = resolve_action(final2, best2['action'])
            log(f'[free-key] Auth POST data: {data2}')
            extra_headers2 = {'Referer': final2}
            body3, final3, resp3 = http_post(action2, data2, opener=opener,
                                             extra_headers=extra_headers2,
                                             _dbg_label='freekey_step3_auth')
            log(f'[free-key] Auth response URL: {final3}')
            if body3:
                # Log the meaningful part — skip HTML boilerplate
                import re as _re
                text_content = _re.sub(r'<[^>]+>', ' ', body3)
                text_content = ' '.join(text_content.split())
                log(f'[free-key] Auth response text: {text_content[:400]!r}')

            # ── Step 3: AGB/ToS acceptance form ──────────────────────────────
            # service.free-key-de.eu may return a ToS page that must be
            # submitted before the MAC is actually authorized.
            if body3 and 'FREEKEYWIFI' in body3:
                forms3, best3 = parse_forms(body3)
                if best3:
                    log(f'[free-key] ToS form fields: {list(best3["fields"].keys())}')
                    data3 = fill_form(best3)
                    # Tick any checkbox (AGB acceptance)
                    for name, field in best3['fields'].items():
                        if field['type'] == 'checkbox':
                            data3[name] = field['value'] if field['value'] else 'on'
                            log(f'[free-key] Ticking checkbox: {name}={data3[name]!r}')
                    action3 = resolve_action(final3, best3['action'])
                    log(f'[free-key] ToS POST to {action3} data={data3}')
                    body4, final4, resp4 = http_post(action3, data3, opener=opener,
                                                     extra_headers={'Referer': final3},
                                                     _dbg_label='freekey_step4_tos')
                    log(f'[free-key] ToS response URL: {final4}')
                    if body4:
                        import re as _re
                        text4 = _re.sub(r'<[^>]+>', ' ', body4)
                        text4 = ' '.join(text4.split())
                        log(f'[free-key] ToS response text: {text4[:400]!r}')
                        dbg_html('freekey_step4_tos_response', final4, body4)

                    # ── Step 5: final router login form ──────────────────────
                    # After ToS acceptance, service.free-key-de.eu returns a
                    # form POSTing back to hotspot.free-key.eu/login with
                    # username=<MAC> and password=freekey — this is what
                    # actually unlocks the MAC on the router.
                    if body4 and ('hotspot.free-key' in body4 or 'hotspot.free-key' in final4):
                        forms5, best5 = parse_forms(body4)
                        if best5 and best5.get('action', '').startswith('http://hotspot'):
                            log(f'[free-key] Final router login form: action={best5["action"]!r} '
                                f'fields={list(best5["fields"].keys())}')
                            data5 = fill_form(best5)
                            action5 = best5['action']
                            log(f'[free-key] Router login POST to {action5}')
                            body5, final5, resp5 = http_post(
                                action5, data5, opener=opener,
                                extra_headers={'Referer': final4},
                                _dbg_label='freekey_step5_router_login',
                            )
                            log(f'[free-key] Router login response URL: {final5}')
                            if body5:
                                import re as _re2
                                text5 = _re2.sub(r'<[^>]+>', ' ', body5)
                                text5 = ' '.join(text5.split())
                                log(f'[free-key] Router login response text: {text5[:200]!r}')
                        else:
                            log('[free-key] No router login form found in ToS response — '
                                'checking for generic next form')
                            # Fallback: any remaining form (some deployments vary)
                            if forms5 and best5:
                                log(f'[free-key] Submitting fallback form: {best5["action"]!r}')
                                data5 = fill_form(best5)
                                action5 = resolve_action(final4, best5['action'])
                                http_post(action5, data5, opener=opener,
                                          extra_headers={'Referer': final4},
                                          _dbg_label='freekey_step5_fallback')
                else:
                    log('[free-key] No ToS form found in auth response')
        else:
            log('[free-key] Could not parse FREEKEYWIFI form')

    # ── Step 4: wait for MAC to be authorized, then connectivity check ───────
    # Router login (step 5) is synchronous — the MAC is usually active within
    # 1-2s. We try quickly first, then fall back to longer waits if needed.
    delays = [1, 2, 3, 5, 5, 5, 5, 5, 5, 5]  # seconds between attempts
    for attempt, delay in enumerate(delays, 1):
        time.sleep(delay)
        log(f'[free-key] Connectivity check attempt {attempt}/{len(delays)} ...')
        if _connectivity_ok(opener, status_url=status_url):
            return True

    log('[free-key] MAC not authorized after 50s')
    return False


# Words on a portal status page that confirm the session is active,
# even if HTTP redirects are still flushing.
STATUS_SUCCESS_WORDS = [
    'bereits aktiv', 'already active', 'angemeldet', 'aktiv angemeldet',
    'you are connected', 'session active', 'logged in', 'authorized',
    'sitzungsstatistik', 'session statistic',
]

def _status_page_ok(status_url, opener):
    """Check a hotspot status URL for signs of an active session."""
    if not status_url:
        return False
    body, _, _ = http_get(status_url, opener=opener)
    if body and any(w in body.lower() for w in STATUS_SUCCESS_WORDS):
        log(f'[connectivity] ✓ Authorized via status page {status_url}')
        return True
    return False


def _connectivity_ok(opener=None, status_url=None):
    """
    Verify real internet access using multiple probes.
    Captive portals often intercept HTTP and fake a 204/200 response.
    We try several probes and require at least one unambiguous match.
    Optionally checks a portal status URL as fallback (works for Mikrotik/
    Coova-based portals that expose a /status endpoint).
    """
    log('[connectivity] Verifying actual internet access ...')
    if opener is None:
        opener, _ = _make_opener()

    checks = [
        # (url, expected_body_or_None, require_exact_url)
        # None means HTTP 204 expected (body must be empty string)
        ('http://connectivitycheck.gstatic.com/generate_204', None,             True),
        ('http://detectportal.firefox.com/success.txt',       'success',        True),
        ('http://captive.apple.com/hotspot-detect.html',      '<SUCCESS>',      False),
        ('http://www.msftncsi.com/ncsi.txt',                  'Microsoft NCSI', True),
    ]

    for probe, expected, require_exact_url in checks:
        body, final_url, resp = http_get(probe, opener=opener)
        log(f'[connectivity] Probe {probe}')
        log(f'[connectivity]   url={final_url}  body={repr((body or "")[:80])}')

        if require_exact_url and final_url != probe:
            log(f'[connectivity]   ✗ Redirected — portal still active')
            continue

        if expected is None:
            # HTTP 204: body must be strictly empty
            if body == '':
                log('[connectivity] ✓ Online (204 No Content)')
                return True
            log(f'[connectivity]   ✗ Expected empty 204 body but got content')
        else:
            if body is not None and expected in body:
                log(f'[connectivity] ✓ Online (found {expected!r})')
                return True
            log(f'[connectivity]   ✗ Expected {expected!r} not in body')

    # Fallback: if the caller provided a portal status URL, check it directly.
    # Some portals (Mikrotik/Coova/free-key) keep redirecting HTTP probes for
    # a while after auth, but their /status page already shows the session.
    if status_url and _status_page_ok(status_url, opener):
        return True

    log('[connectivity] ✗ All probes failed — not online')
    return False

def handle_generic(portal_url, html, ticket=None, username=None, password=None,
                   opener=None, jar=None, _depth=0):
    """
    Generic HTML-form handler.
    Parses the page, fills in credentials, submits, and follows up to 3
    further form steps (multi-page portals like Telekom, Hotsplots).
    """
    if not html:
        log('[Generic] No HTML received')
        return False
    if _depth > 3:
        log('[Generic] Too many form steps, stopping')
        return False

    if opener is None:
        opener, jar = _make_opener()

    forms, best = parse_forms(html)
    if DEBUG and html:
        dbg_html(f'generic_depth{_depth}_page', portal_url, html, forms=forms)
    if not best:
        log('[Generic] No form found on portal page')
        # Some portals just need a GET to the portal URL to authenticate (MAC-based)
        return looks_like_success(html, portal_url)

    log(f'[Generic] Form: method={best["method"]} action={best["action"]!r}  '
        f'fields={list(best["fields"].keys())}')

    data = fill_form(best, ticket=ticket, username=username, password=password)
    action_url = resolve_action(portal_url, best['action'])
    log(f'[Generic] Submitting to {action_url}')
    log(f'[Generic] POST data: { {k: v for k, v in data.items() if "pass" not in k.lower()} }')

    if best['method'] == 'POST':
        body2, final2, resp2 = http_post(action_url, data, opener=opener)
    else:
        qs = urllib.parse.urlencode({k: v for k, v in data.items() if v is not None})
        body2, final2, resp2 = http_get(f'{action_url}?{qs}' if qs else action_url,
                                        opener=opener)

    log(f'[Generic] Response URL: {final2}')
    if body2:
        log(f'[Generic] Response snippet: {body2[:300].strip()!r}')

    if looks_like_success(body2, final2):
        log('[Generic] Login successful!')
        return True

    # The portal may have redirected to a new page with another form
    if body2 and final2 != action_url:
        forms2, best2 = parse_forms(body2)
        if best2 and best2['fields']:
            log(f'[Generic] Following next form step at {final2}')
            return handle_generic(
                final2, body2,
                ticket=ticket, username=username, password=password,
                opener=opener, jar=jar,
                _depth=_depth + 1,
            )

    # Connectivity check after submission — maybe we're online now
    # Pass along any status URL found in the form (Mikrotik/Coova pattern)
    status_url = None
    for name, field in best['fields'].items():
        if 'status' in name.lower() and field['value'].startswith('http'):
            status_url = field['value']
            log(f'[Generic] Found status URL in form: {status_url}')
            break
    time.sleep(2)
    if _connectivity_ok(opener, status_url=status_url):
        log('[Generic] Connectivity confirmed after form submission')
        return True

    log('[Generic] Login outcome unclear')
    return False


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch(portal_url, html, ticket=None, username=None, password=None):
    """Route to the right handler based on the portal URL and page content."""
    ul = portal_url.lower()
    h  = (html or '').lower()

    # ── Deutsche Bahn / DB trains ─────────────────────────────────
    if 'ombord.info' in ul:
        return handle_ombord(portal_url, ticket=ticket)

    if ('wifi.bahn.de' in ul or 'bahn.de' in ul
            or 'cna-portal' in h or 'wifi.bahn.de' in h
            or ('/cna/' in ul and ('bahn' in ul or 'db' in ul))):
        return handle_db_cna(portal_url, ticket=ticket, username=username, password=password)

    # Detect CNA via JS reference in HTML (portal may redirect to wifi.bahn.de sub-path)
    if 'ombord.info' in h:
        return handle_ombord(portal_url, ticket=ticket)
    if '/services/cna-portal/v1/' in h or 'cna-portal-frontend' in h:
        return handle_db_cna(portal_url, ticket=ticket, username=username, password=password)

    # ── free-key.eu ───────────────────────────────────────────────
    if 'free-key.eu' in ul or 'free-key.eu' in h or 'freekey' in ul \
            or 'free-key-de.eu' in ul or 'free-key-de.eu' in h:
        log('[free-key.eu] Detected free-key.eu portal')
        return handle_freekey(portal_url, html, ticket=ticket, username=username, password=password)

    # ── Hotsplots (BayernWLAN, many venues) ───────────────────────
    if 'hotsplots' in ul or 'hotsplots' in h:
        log('[Hotsplots] Detected Hotsplots portal')
        return handle_generic(portal_url, html, ticket=ticket, username=username, password=password)

    # ── BayernWLAN (sometimes direct, sometimes via Hotsplots) ────
    if 'bayernwlan' in ul or 'bayernwlan' in h:
        log('[BayernWLAN] Detected BayernWLAN portal')
        return handle_generic(portal_url, html, ticket=ticket, username=username, password=password)

    # ── Telekom / T-Online hotspot ─────────────────────────────────
    if any(x in ul for x in ['t-online.de', 'hotspot.t-', 'telekom.de', 't-mobile']):
        log('[Telekom] Detected Telekom hotspot')
        return handle_generic(portal_url, html, ticket=ticket, username=username, password=password)

    # ── Vodafone hotspot ──────────────────────────────────────────
    if 'vodafone' in ul or 'vodafone' in h:
        log('[Vodafone] Detected Vodafone hotspot')
        return handle_generic(portal_url, html, ticket=ticket, username=username, password=password)

    # ── Generic fallback ──────────────────────────────────────────
    log(f'[Portal] Using generic handler for {portal_url}')
    return handle_generic(portal_url, html, ticket=ticket, username=username, password=password)


# ── Utilities ─────────────────────────────────────────────────────────────────

def die(msg, code=1):
    print(f'ERROR: {msg}', file=sys.stderr, flush=True)
    sys.exit(code)


# ── SSID detection (Travelmate runtime JSON) ──────────────────────────────────

TRM_RUNTIME = '/tmp/trm_runtime.json'

def current_ssid():
    """
    Return the SSID of the currently active Travelmate uplink, or None.
    Travelmate writes /tmp/trm_runtime.json while connected; the field is
    'station_id' in recent versions and 'travelmate_ssid' in older ones.
    """
    try:
        with open(TRM_RUNTIME) as f:
            data = json.load(f)
        # Different Travelmate versions use different field names
        return (data.get('station_id')
                or data.get('travelmate_ssid')
                or data.get('ssid'))
    except Exception:
        return None


# ── Credentials config file ───────────────────────────────────────────────────

CREDS_FILE = '/etc/captive-credentials.conf'

def load_credentials(ssid):
    """
    Look up credentials for the given SSID in CREDS_FILE.
    Returns (ticket, username, password) — same tuple as parse_args().

    File format (lines starting with # are comments, blank lines ignored):
      <ssid-pattern>   userpass   <username>   <password>
      <ssid-pattern>   ticket     <ticket>
      <ssid-pattern>   free

    ssid-pattern supports fnmatch wildcards: * ? [seq]
    The first matching line wins.

    Example:
      # Telekom public hotspot — credentials from your T-Online account
      Telekom_FON_*        userpass   max@t-online.de   hunter2
      # Vodafone hotspot
      VodafoneWifi*        userpass   myuser            mypass
      # Venue with daily voucher
      CoffeeShop_WLAN      ticket     ABCD-1234
      # Everything else is free
      *                    free
    """
    if ssid is None:
        return None, None, None
    try:
        from fnmatch import fnmatch
        with open(CREDS_FILE) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                pattern, ctype = parts[0], parts[1].lower()
                if not fnmatch(ssid, pattern):
                    continue
                if ctype == 'userpass' and len(parts) >= 4:
                    log(f'[creds] Matched SSID {ssid!r} → userpass for {parts[2]!r}')
                    return None, parts[2], parts[3]
                if ctype == 'ticket' and len(parts) >= 3:
                    log(f'[creds] Matched SSID {ssid!r} → ticket')
                    return parts[2], None, None
                if ctype == 'free':
                    log(f'[creds] Matched SSID {ssid!r} → free/checkbox')
                    return None, None, None
    except FileNotFoundError:
        pass  # no config file is fine — free-portal mode
    except Exception as e:
        log(f'[creds] Could not read {CREDS_FILE}: {e}')
    return None, None, None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ticket, username, password = parse_args()

    # If no credentials were passed on the command line, try the config file,
    # keyed by the SSID that Travelmate is currently connected to.
    if not ticket and not username:
        ssid = current_ssid()
        if ssid:
            log(f'[*] Active SSID: {ssid!r}')
            ticket, username, password = load_credentials(ssid)

    if ticket:
        log(f'[*] Mode: ticket login  (ticket={ticket!r})')
    elif username:
        log(f'[*] Mode: username/password login  (user={username!r})')
    else:
        log('[*] Mode: free / checkbox login')

    if DEBUG:
        import subprocess, datetime
        dbg(f'=== captive-login debug session {datetime.datetime.now().isoformat()} ===')
        for cmd in ['uname -a', 'ip route show', 'ip addr show phy1-sta0 2>/dev/null || ip addr show']:
            try:
                out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
                dbg('$ %s\n%s' % (cmd, out.strip()))
            except Exception as e:
                dbg(f'$ {cmd} → error: {e}')

    log('[*] Detecting captive portal ...')
    portal_url, html = detect_portal()

    if portal_url is None:
        log('[*] No captive portal detected — already online')
        sys.exit(0)

    log(f'[*] Portal: {portal_url}')

    ok = dispatch(portal_url, html,
                  ticket=ticket, username=username, password=password)

    if ok:
        log('[*] Login successful')
        sys.exit(0)
    else:
        log('[!] Login may have failed — check portal manually')
        sys.exit(1)


if __name__ == '__main__':
    main()
