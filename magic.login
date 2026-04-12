#!/usr/bin/env python3
"""
magic.login  —  Universal captive portal login for OpenWrt/Travelmate

Dependencies:
  python3-yaml  (opkg install python3-yaml)

Usage:
  magic.login [--debug] [--force]                         # free / checkbox portals
  magic.login [--debug] [--force] <ticket>                # ticket / voucher portals
  magic.login [--debug] [--force] <username> <password>   # username+password portals

Flags:
  --debug    Write detailed log and HTML dumps to /tmp/captive-debug/
  --force    Skip the fast online pre-check and always run the full login flow
  --no-bind  Skip SO_BINDTODEVICE interface binding
             Use this when running outside OpenWrt (e.g. on Android/Termux)

Cron usage (re-login when session expires, e.g. every 5 minutes):
  */5 * * * * /etc/travelmate/magic.login
  The script exits in ~1s if already online (fast pre-check).
  Use --force to always run the full login flow regardless.

Handler configuration:
  YAML files in /etc/travelmate/captive.d/ describe portal-specific login flows.
  Each file declares match patterns and a list of form-submission steps.
  Portals not matched by any YAML file fall back to the built-in generic handler.

  Install a new handler:    drop a .yaml file into /etc/travelmate/captive.d/
  Disable a handler:        rename the file to .yaml.disabled

Travelmate integration:
  config travelmate 'global'
      option trm_captivescript '/etc/travelmate/magic.login'
      option trm_captiveurl    'http://connectivitycheck.gstatic.com/generate_204'

Credentials file (/etc/captive-credentials.conf):
  # SSID-pattern         type      credential(s)
  Telekom_FON_*          userpass  max@t-online.de  s3cr3t
  VodafoneWifi*          userpass  myuser           mypass
  CoffeeShop_WLAN        ticket    ABCD-1234
  *                      free
"""

import sys
import os as _os
import urllib.request
import urllib.error

# Writable temp directory: /tmp on OpenWrt, current working directory on
# environments without /tmp (e.g. Termux on Android).
_TMP_DIR    = '/tmp' if _os.access('/tmp', _os.W_OK) else _os.getcwd()
_PROBE_BODY = _os.path.join(_TMP_DIR, 'magic_probe_body')

# ── Fast online pre-check ─────────────────────────────────────────────────────
# Runs before any heavy imports. Uses a raw socket-level HTTP request to avoid
# the overhead of building a full opener. If we get a clean 204 or the expected
# response without a redirect, we're online and exit immediately.
# This keeps the "already online" path to ~1s even on slow MIPS hardware.

def _detect_uplink_iface():
    """
    Find the active Travelmate uplink interface name (e.g. phy1-sta0).
    Reads /tmp/trm_runtime.json; falls back to scanning ip route for a
    non-loopback, non-LAN default-like route via a sta* interface.
    Returns the interface name string, or None if not found.
    """
    # Try Travelmate runtime JSON first
    try:
        with open('/tmp/trm_runtime.json') as f:
            import json as _json
            data = _json.load(f)
        iface = (data.get('sta_iface')        # wwan (logical)
                 or data.get('travelmate_iface')
                 or data.get('iface'))
        if iface:
            return iface
    except Exception:
        pass

    # Fall back: find sta* interface with a default or host route
    try:
        import subprocess as _sp
        out = _sp.check_output(['ip', 'route', 'show'],
                               stderr=_sp.DEVNULL).decode()
        for line in out.splitlines():
            # Look for lines like: "default via ... dev phy1-sta0 ..."
            # or "10.x.x.x dev phy1-sta0 ..."
            parts = line.split()
            if 'dev' in parts:
                dev = parts[parts.index('dev') + 1]
                if 'sta' in dev or 'wwan' in dev:
                    return dev
    except Exception:
        pass

    return None


def _fast_online_check():
    """
    Quick connectivity check via curl, bound to the Travelmate uplink interface.
    Using curl (rather than urllib) allows --interface binding, which ensures
    the check goes over the WiFi uplink even when LTE/mwan is also active.

    Returns True if internet access via the uplink interface is confirmed.

    For generate_204 we require:
      - HTTP 204 status code
      - Strictly empty body (any content = portal login page intercept)
    """
    import subprocess as _sp

    iface = _detect_uplink_iface()
    iface_args = ['--interface', iface] if iface else []
    if iface:
        print('[fast-check] Using interface: %s' % iface, flush=True)
    else:
        print('[fast-check] No uplink interface found — checking default route',
              flush=True)

    checks = [
        # (url, expected_body_or_None)
        # None = expect HTTP 204 with strictly empty body
        ('http://connectivitycheck.gstatic.com/generate_204', None),
        ('http://detectportal.firefox.com/success.txt',       'success'),
    ]

    for url, expected in checks:
        try:
            cmd = (['curl', '--silent', '--max-time', '3',
                    '--write-out', '%{http_code} %{url_effective}',
                    '--output', _PROBE_BODY,
                    '--location']          # follow redirects so we see final URL
                   + iface_args + [url])
            result = _sp.run(cmd, capture_output=True, text=True, timeout=5)
            meta   = result.stdout.strip()   # "200 http://..."
            try:
                code_str, final = meta.split(' ', 1)
                code = int(code_str)
            except ValueError:
                continue

            try:
                body = open(_PROBE_BODY).read()
            except Exception:
                body = ''

            # Redirect detected: final URL differs from probe URL
            if final.rstrip('/') != url.rstrip('/'):
                print('[fast-check] Redirected to %s — captive portal active' % final,
                      flush=True)
                return False

            if expected is None:
                # generate_204: must be HTTP 204 with empty body
                if code == 204 and body == '':
                    return True
                if body:
                    print('[fast-check] generate_204 returned %d bytes (HTTP %d) '
                          '— portal intercept' % (len(body), code), flush=True)
                else:
                    print('[fast-check] generate_204 returned HTTP %d '
                          '(expected 204)' % code, flush=True)
                return False
            else:
                if expected in body:
                    return True
                print('[fast-check] Expected %r not in response — portal intercept'
                      % expected, flush=True)
                return False

        except Exception as e:
            print('[fast-check] %s: %s' % (url, e), flush=True)

    return False

# Run early check before loading heavy modules.
# Skip if --debug or --force flags are present (we want full output then).
_ARGV     = sys.argv[1:]
_FORCE    = '--force'   in _ARGV
_DEBUG    = '--debug'   in _ARGV
_NO_BIND  = '--no-bind' in _ARGV   # skip SO_BINDTODEVICE (for use outside OpenWrt)

if not _FORCE and not _DEBUG:
    if _fast_online_check():
        print('[*] Already online (fast check)', flush=True)
        sys.exit(0)

# Heavy imports — only reached if we might need to log in
import re, json, time, glob
import http.cookiejar
import urllib.parse
from html.parser import HTMLParser

try:
    import yaml
except ImportError:
    yaml = None

# ── Debug ─────────────────────────────────────────────────────────────────────

DEBUG         = False
_debug_log_fh = None
_debug_step   = 0
DEBUG_DIR     = _os.path.join(_TMP_DIR, 'captive-debug')

def _init_debug():
    global _debug_log_fh
    _os.makedirs(DEBUG_DIR, exist_ok=True)
    path = '%s/session.log' % DEBUG_DIR
    _debug_log_fh = open(path, 'w', buffering=1)
    log('[debug] Writing debug log to %s' % path)
    log('[debug] HTML dumps go to %s/step_*.html' % DEBUG_DIR)

def log(msg):
    print(msg, flush=True)
    if _debug_log_fh:
        import datetime
        ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        _debug_log_fh.write('%s  %s\n' % (ts, msg))

def dbg(msg):
    if DEBUG:
        log('[DBG] %s' % msg)

def dbg_html(label, url, html, forms=None, cookies=None, headers=None):
    if not DEBUG:
        return
    global _debug_step
    _debug_step += 1
    import datetime
    fname = '%s/step_%02d_%s.html' % (DEBUG_DIR, _debug_step, label)
    lines = [
        '<!-- URL: %s -->' % url,
        '<!-- Time: %s -->' % datetime.datetime.now().isoformat(),
    ]
    if headers:
        lines.append('<!-- Response headers:')
        for k, v in (headers.items() if hasattr(headers, 'items') else headers):
            lines.append('     %s: %s' % (k, v))
        lines.append('-->')
    if cookies:
        lines.append('<!-- Cookies: %s -->' % cookies)
    if forms:
        lines.append('<!-- Forms found: %d' % len(forms))
        for i, frm in enumerate(forms):
            lines.append('     Form %d: method=%s action=%r' % (i, frm['method'], frm['action']))
            for fn, fld in frm['fields'].items():
                lines.append('       %s: type=%s value=%r' % (fn, fld['type'], fld['value']))
        lines.append('-->')
    lines.append(html or '')
    with open(fname, 'w') as f:
        f.write('\n'.join(lines))
    dbg('HTML dump -> %s  (%d bytes, %d form(s))' % (fname, len(html or ''), len(forms or [])))
    if cookies:
        dbg('Cookies: %s' % cookies)
    if headers:
        hdr = headers.items() if hasattr(headers, 'items') else {}
        notable = {k: v for k, v in hdr
                   if k.lower() in ('location','set-cookie','content-type','x-cache','server')}
        if notable:
            dbg('Notable headers: %s' % notable)

def die(msg, code=1):
    print('ERROR: %s' % msg, file=sys.stderr, flush=True)
    sys.exit(code)

# ── Configuration ─────────────────────────────────────────────────────────────

PROBE_URLS = [
    'http://connectivitycheck.gstatic.com/generate_204',
    'http://detectportal.firefox.com/success.txt',
    'http://captive.apple.com/hotspot-detect.html',
    'http://www.msftncsi.com/ncsi.txt',
]

ONLINE_SIGNATURES = {
    'http://connectivitycheck.gstatic.com/generate_204': None,      # 204, empty body
    'http://detectportal.firefox.com/success.txt':       'success',
    'http://captive.apple.com/hotspot-detect.html':      '<SUCCESS>',
    'http://www.msftncsi.com/ncsi.txt':                  'Microsoft NCSI',
}

TIMEOUT       = 15   # timeout for login form requests
PROBE_TIMEOUT = 5    # shorter timeout for portal detection probes
                     # (already-online case should respond in <1s;
                     #  if it takes longer, try the next probe URL)

HEADERS = {
    'User-Agent':      'Mozilla/5.0 (Linux; Android 11; OpenWrt) AppleWebKit/537.36',
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'identity',
    'Connection':      'keep-alive',
}

HANDLERS_DIR = '/etc/travelmate/magic.d'
TRM_RUNTIME  = '/tmp/trm_runtime.json'
CREDS_FILE   = '/etc/captive-credentials.conf'

# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args():
    global DEBUG
    args = [a for a in sys.argv[1:] if a not in ('--debug', '--force', '--no-bind')]
    if _DEBUG:
        DEBUG = True
        _init_debug()
        dbg('argv: %s' % sys.argv)
    if _FORCE:
        dbg('--force: skipping fast online check, running full login flow')
    if len(args) == 0:
        return None, None, None
    if len(args) == 1:
        return args[0], None, None
    if len(args) == 2:
        return None, args[0], args[1]
    die('Usage: magic.login [--debug] [--force] [--no-bind] [ticket | username password]')

# ── HTTP helpers ──────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _BoundHTTPHandler(urllib.request.HTTPHandler):
    """HTTP handler that binds the socket to a specific network interface.
    Uses SO_BINDTODEVICE so traffic is forced over the uplink (e.g. phy1-sta0)
    even when LTE/mwan provides a default route with lower metric."""

    def __init__(self, iface, *args, **kwargs):
        self._iface = iface.encode() if isinstance(iface, str) else iface
        super().__init__(*args, **kwargs)

    def http_open(self, req):
        return self.do_open(self._make_conn, req)

    def _make_conn(self, host, **kwargs):
        import http.client as _hc, socket as _sock
        conn = _hc.HTTPConnection(host, **kwargs)
        # Patch connect() to bind before connecting
        _iface = self._iface
        _orig_connect = conn.connect
        def _bound_connect():
            _orig_connect()
            try:
                import socket as _s
                conn.sock.setsockopt(
                    _s.SOL_SOCKET, _s.SO_BINDTODEVICE, _iface + bytes(1))
            except Exception:
                pass   # non-fatal: falls back to default routing
        conn.connect = _bound_connect
        return conn


# Active uplink interface — detected once at startup
_UPLINK_IFACE = _detect_uplink_iface()


def _make_jar():
    return http.cookiejar.CookieJar()

def _make_opener(jar=None, follow_redirects=True):
    jar = jar or _make_jar()
    handlers = [urllib.request.HTTPCookieProcessor(jar)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    if _UPLINK_IFACE and not _NO_BIND:
        handlers.append(_BoundHTTPHandler(_UPLINK_IFACE))
        dbg('Binding HTTP requests to interface: %s' % _UPLINK_IFACE)
    elif _NO_BIND:
        dbg('--no-bind: skipping interface binding (running outside OpenWrt)')
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = list(HEADERS.items())
    return opener, jar

def http_get(url, opener=None, timeout=TIMEOUT, _dbg_label=None):
    if opener is None:
        opener, _ = _make_opener()
    dbg('GET %s' % url)
    try:
        resp = opener.open(url, timeout=timeout)
        body = resp.read().decode('utf-8', errors='replace')
        final = resp.geturl()
        if _dbg_label and body:
            dbg_html(_dbg_label, final, body, headers=resp.headers)
        elif final != url:
            dbg('  -> redirected to %s' % final)
        return body, final, resp
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        dbg('  HTTP %d error' % e.code)
        if _dbg_label and body:
            dbg_html('%s_err%d' % (_dbg_label, e.code), url, body, headers=e.headers)
        return body, url, e
    except Exception as e:
        dbg('  Exception: %s' % e)
        return None, url, e

def http_post(url, data, opener=None, timeout=TIMEOUT,
              content_type='application/x-www-form-urlencoded',
              extra_headers=None, _dbg_label=None):
    if opener is None:
        opener, _ = _make_opener()
    if isinstance(data, dict):
        payload = urllib.parse.urlencode(data).encode()
        dbg('POST %s  data=%s' % (url, {k: '***' if 'pass' in k.lower() else v
                                         for k, v in data.items()}))
    elif isinstance(data, str):
        payload = data.encode('utf-8')
        dbg('POST %s  body=%r' % (url, data[:200]))
    else:
        payload = data
        dbg('POST %s  (%d raw bytes)' % (url, len(payload)))
    req = urllib.request.Request(url, data=payload)
    req.add_header('Content-Type', content_type)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
        dbg('  extra headers: %s' % extra_headers)
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode('utf-8', errors='replace')
        final = resp.geturl()
        if final != url:
            dbg('  -> redirected to %s' % final)
        if _dbg_label and body:
            dbg_html(_dbg_label, final, body, headers=resp.headers)
        return body, final, resp
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        dbg('  HTTP %d error' % e.code)
        if _dbg_label and body:
            dbg_html('%s_err%d' % (_dbg_label, e.code), url, body, headers=e.headers)
        return body, url, e
    except Exception as e:
        dbg('  Exception: %s' % e)
        return None, url, e

def origin_of(url):
    p = urllib.parse.urlparse(url)
    return '%s://%s' % (p.scheme, p.netloc)

# ── Portal detection ──────────────────────────────────────────────────────────

def detect_portal():
    no_redir, _ = _make_opener(follow_redirects=False)
    for probe in PROBE_URLS:
        try:
            resp = no_redir.open(probe, timeout=PROBE_TIMEOUT)
            body = resp.read().decode('utf-8', errors='replace')
            expected = ONLINE_SIGNATURES.get(probe)
            if expected is None:
                if body == '':
                    log('[detect] Already online (204 No Content)')
                    return None, None
            elif expected in body:
                log('[detect] Already online (probe succeeded without redirect)')
                return None, None
            final = resp.geturl()
            if final != probe:
                log('[detect] Redirect to %s' % final)
                html, fu, _ = http_get(final, _dbg_label='detect_portal')
                return fu, html
            return None, None
        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location') or e.headers.get('location') or ''
            if loc:
                loc = urllib.parse.urljoin(probe, loc)
                log('[detect] Portal redirect: %s' % loc)
                html, fu, _ = http_get(loc, _dbg_label='detect_portal')
                return fu, html
            if e.code == 204:
                return None, None
        except Exception:
            pass
    log('[detect] All probes failed')
    return None, None

# ── Failure detection ─────────────────────────────────────────────────────────

# Keywords that indicate a login attempt definitely failed.
# Checked after every form submission — triggers immediate abort.
FAILURE_WORDS = [
    # English
    'session has expired', 'session expired',
    'please reconnect', 'login failed', 'invalid',
    'access denied', 'wrong password', 'incorrect', 'not authorized',
    # German
    'sitzung abgelaufen', 'fehler', 'ungültig', 'zugang verweigert',
    'falsches passwort',
    # French
    'session expirée', 'accès refusé', 'mot de passe incorrect',
    # Italian
    'sessione scaduta', 'accesso negato', 'password errata',
    # Spanish
    'sesión expirada', 'acceso denegado', 'contraseña incorrecta',
    # Dutch
    'sessie verlopen', 'toegang geweigerd', 'onjuist wachtwoord',
]

def looks_like_failure(html):
    """Return True if the response clearly indicates a login failure."""
    if html is None:
        return False
    lower = html.lower()
    if any(w in lower for w in FAILURE_WORDS):
        dbg('Failure keyword detected in response')
        return True
    return False

_STATUS_SUCCESS_WORDS = [
    'bereits aktiv', 'already active', 'aktiv angemeldet',
    'you are connected', 'session active', 'logged in', 'authorized',
    'sitzungsstatistik', 'session statistic',
]

def _status_page_ok(status_url, opener):
    if not status_url:
        return False
    body, _, _ = http_get(status_url, opener=opener)
    if body and any(w in body.lower() for w in _STATUS_SUCCESS_WORDS):
        log('[connectivity] ✓ Authorized via status page %s' % status_url)
        return True
    return False

def _connectivity_ok(opener=None, status_url=None):
    log('[connectivity] Verifying actual internet access ...')
    if opener is None:
        opener, _ = _make_opener()
    for probe in PROBE_URLS:
        expected = ONLINE_SIGNATURES.get(probe)
        body, final_url, resp = http_get(probe, opener=opener)
        log('[connectivity] Probe %s' % probe)
        log('[connectivity]   url=%s  body=%r' % (final_url, (body or '')[:80]))
        if final_url != probe:
            log('[connectivity]   ✗ Redirected — portal still active')
            continue
        if expected is None:
            if body == '':
                log('[connectivity] ✓ Online (204 No Content)')
                return True
            log('[connectivity]   ✗ Expected empty 204 body')
        else:
            if body is not None and expected in body:
                log('[connectivity] ✓ Online (found %r)' % expected)
                return True
            log('[connectivity]   ✗ Expected %r not in body' % expected)
    if status_url and _status_page_ok(status_url, opener):
        return True
    log('[connectivity] ✗ All probes failed — not online')
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
            self._cur = {'action': a.get('action',''), 'method': a.get('method','get').upper(),
                         'fields': {}, 'id': a.get('id','')}
        elif t == 'input' and self._cur is not None:
            name = a.get('name') or a.get('id','')
            typ  = (a.get('type') or 'text').lower()
            if name:
                self._cur['fields'][name] = {'type': typ, 'value': a.get('value',''),
                                              'checked': 'checked' in a, 'id': a.get('id','')}
        elif t == 'select' and self._cur is not None:
            self._cur['_sel'] = a.get('name','')
        elif t == 'option' and self._cur is not None:
            sel = self._cur.get('_sel','')
            if sel and 'selected' in a and sel not in self._cur['fields']:
                self._cur['fields'][sel] = {'type':'select','value':a.get('value',''),
                                             'checked':False,'id':''}
        elif t == 'textarea' and self._cur is not None:
            name = a.get('name','')
            if name:
                self._cur['fields'][name] = {'type':'textarea','value':'','checked':False,'id':''}

    def handle_endtag(self, tag):
        if tag.lower() == 'form' and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def best_form(self):
        candidates = []
        for form in self.forms:
            fields = form['fields']
            names  = [k.lower() for k in fields]
            score  = 0
            score += 3 * any('pass'   in n or 'pwd'    in n for n in names)
            score += 2 * any('user'   in n or 'login'  in n or 'email' in n for n in names)
            score += 2 * any('ticket' in n or 'voucher'in n or 'code'  in n
                             or 'pin' in n or 'key'    in n for n in names)
            score += 1 * any(v['type'] == 'checkbox' for v in fields.values())
            score -= 2 * (form['method'] == 'GET' and len(fields) <= 1)
            candidates.append((score, form))
        candidates.sort(key=lambda x: -x[0])
        for _, form in candidates:
            if form['method'] == 'POST':
                return form
        return candidates[0][1] if candidates else None

def parse_forms(html):
    p = _FormParser()
    p.feed(html)
    return p.forms, p.best_form()

# ── Form filling ──────────────────────────────────────────────────────────────

_TICKET_RE = re.compile(r'ticket|voucher|coupon|code|pin|passcode|access.?key|token|freekey|free.?key', re.I)
_USER_RE   = re.compile(r'user|login|email|mail|account|name|uid', re.I)
_PASS_RE   = re.compile(r'pass|pwd|secret|credential', re.I)
_VISIBLE_INPUT_TYPES = {'text','tel','number','search','email','textarea'}

def fill_form(form, ticket=None, username=None, password=None):
    data = {}
    submit_included = False
    ticket_placed = username_placed = False
    for name, field in form['fields'].items():
        typ = field['type']
        val = field['value']
        nl  = name.lower()
        if typ == 'hidden':
            data[name] = val
        elif typ == 'submit':
            if not submit_included and val:
                data[name] = val
                submit_included = True
        elif typ in ('button','image'):
            pass
        elif typ == 'checkbox':
            data[name] = val if val else 'on'
        elif typ == 'radio':
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
    if ticket and not ticket_placed:
        empty = [n for n, f in form['fields'].items()
                 if f['type'] in _VISIBLE_INPUT_TYPES and not data.get(n)]
        if len(empty) == 1:
            data[empty[0]] = ticket
    if username and not username_placed and not ticket_placed:
        empty = [n for n, f in form['fields'].items()
                 if f['type'] in _VISIBLE_INPUT_TYPES and not data.get(n)]
        if len(empty) == 1:
            data[empty[0]] = username
    return data

def resolve_action(base_url, action):
    if not action:
        return base_url
    if action.startswith('http://') or action.startswith('https://'):
        return action
    return urllib.parse.urljoin(base_url, action)

# ── YAML-driven handler engine ────────────────────────────────────────────────

# Context dict injected into Python plugins so they can call core helpers
# without importing magic.login (which would cause circular imports).
def _make_plugin_ctx():
    return {
        'log':          log,
        'dbg':          dbg,
        'http_get':     http_get,
        'http_post':    http_post,
        '_make_opener': _make_opener,
        '_connectivity_ok': _connectivity_ok,
        'origin_of':    origin_of,
        'json':         json,
        'time':         time,
        'urllib_parse': urllib.parse,
        'urllib_error': urllib.error,
    }


def _load_handlers():
    """
    Load all *.yaml and *.py handler files from HANDLERS_DIR.
    Returns a unified list sorted by priority (default 50).
    Each entry is either:
      - a dict  (YAML handler, run by _run_yaml_handler)
      - a module (Python plugin, has can_handle() and handle())
    """
    handlers = []

    # ── YAML handlers ────────────────────────────────────────────────────────
    if yaml is None:
        log('[handlers] python3-yaml not available — YAML handlers disabled')
        log('[handlers] Install with: opkg install python3-yaml')
    else:
        for path in sorted(glob.glob(_os.path.join(HANDLERS_DIR, '*.yaml'))):
            try:
                with open(path) as f:
                    h = yaml.safe_load(f)
                if h and isinstance(h, dict):
                    h['_file'] = path
                    h['_type'] = 'yaml'
                    handlers.append(h)
                    dbg('Loaded YAML handler: %s (priority=%s)' % (
                        path, h.get('priority', 50)))
            except Exception as e:
                log('[handlers] Could not load %s: %s' % (path, e))

    # ── Python plugin handlers ────────────────────────────────────────────────
    import importlib.util as _ilu
    for path in sorted(glob.glob(_os.path.join(HANDLERS_DIR, '*.py'))):
        try:
            spec = _ilu.spec_from_file_location('magic_handler', path)
            mod  = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not (hasattr(mod, 'can_handle') and hasattr(mod, 'handle')):
                log('[handlers] %s missing can_handle/handle — skipped' % path)
                continue
            # Inject core helpers
            mod._ctx = _make_plugin_ctx()
            # Wrap as a lightweight dict-like entry for the sort
            handlers.append({
                '_file':    path,
                '_type':    'python',
                '_module':  mod,
                'priority': getattr(mod, 'PRIORITY', 50),
            })
            dbg('Loaded Python handler: %s (priority=%s)' % (
                path, getattr(mod, 'PRIORITY', 50)))
        except Exception as e:
            log('[handlers] Could not load %s: %s' % (path, e))

    handlers.sort(key=lambda h: h.get('priority', 50))
    return handlers

def _handler_matches(handler, portal_url, html):
    """Check if a handler's match patterns apply to the current portal."""
    ul = portal_url.lower()
    hl = (html or '').lower()
    for pattern in handler.get('match', []):
        p = pattern.lower()
        if p in ul or p in hl:
            return True
    return False

def _run_yaml_handler(handler, portal_url, html, ticket, username, password):
    """
    Execute a YAML-defined handler step by step.

    Each step in handler['steps'] is a dict with these keys:
      label:            string — used in log output and debug filenames
      action:           'from_form' or a literal URL
      method:           POST (default) or GET
      fields:           'from_form' (default) or a dict of literal key:value pairs
      clear_fields:     list of field names to set to '' before submitting
      check_boxes:      true — tick all checkboxes (AGB acceptance)
      only_if:          string — only run step if this string appears in the
                        last response body's form fields
      only_if_action:   string — only run step if form action URL contains this
      inject_fields:    dict of extra fields to add/override in the POST data
      is_final_login:   true — this step logs into the actual router/AP
                        (triggers connectivity check afterwards)
    """
    name = handler.get('name', handler.get('_file', '?'))
    log('[%s] Starting YAML handler' % name)

    opener, jar = _make_opener()
    current_url  = portal_url
    current_html = html
    status_url   = None

    # Extract status URL from the first form (Mikrotik/Coova pattern)
    if current_html:
        forms, _ = parse_forms(current_html)
        for frm in forms:
            for fn, fld in frm['fields'].items():
                if 'status' in fn.lower() and (fld.get('value') or '').startswith('http'):
                    status_url = fld['value']
                    log('[%s] Found status URL: %s' % (name, status_url))
                    break

    steps = handler.get('steps', [])

    for step in steps:
        label = step.get('label', 'step')

        # ── only_if guard ───────────────────────────────────────────────────
        only_if = step.get('only_if')
        if only_if and current_html and only_if not in current_html:
            dbg('[%s] Skipping step %r — only_if %r not in response' % (name, label, only_if))
            continue

        only_if_action = step.get('only_if_action')
        if only_if_action:
            forms, best = parse_forms(current_html or '')
            if not best or only_if_action.lower() not in best.get('action','').lower():
                dbg('[%s] Skipping step %r — only_if_action %r not in form action' % (name, label, only_if_action))
                continue

        log('[%s] Step: %s' % (name, label))

        # ── resolve form and action URL ─────────────────────────────────────
        forms, best = parse_forms(current_html or '')
        if DEBUG and current_html:
            dbg_html('%s_%s' % (name.replace(' ','_'), label),
                     current_url, current_html, forms=forms,
                     cookies={c.name: c.value for c in jar})

        action_cfg = step.get('action', 'from_form')
        if action_cfg == 'from_form':
            if not best:
                log('[%s] No form found for step %r' % (name, label))
                continue
            action_url = resolve_action(current_url, best['action'])
        else:
            action_url = action_cfg

        # ── build POST data ─────────────────────────────────────────────────
        fields_cfg = step.get('fields', 'from_form')
        if fields_cfg == 'from_form' and best:
            data = fill_form(best, ticket=ticket, username=username, password=password)
        elif isinstance(fields_cfg, dict):
            data = dict(fields_cfg)
        else:
            data = {}

        # Apply check_boxes
        if step.get('check_boxes') and best:
            for fn, fld in best['fields'].items():
                if fld['type'] == 'checkbox':
                    data[fn] = fld['value'] if fld['value'] else 'on'
                    log('[%s]   Ticking checkbox: %s=%r' % (name, fn, data[fn]))

        # Clear specified fields
        for fn in step.get('clear_fields', []):
            if fn in data:
                data[fn] = ''

        # Inject extra fields
        for fn, val in step.get('inject_fields', {}).items():
            data[fn] = val

        log('[%s]   Action: %s' % (name, action_url))
        log('[%s]   Fields: %s' % (name, {k: '***' if 'pass' in k.lower() else v
                                           for k, v in data.items()}))

        # ── submit ──────────────────────────────────────────────────────────
        method = step.get('method', 'POST').upper()
        extra_headers = {'Referer': current_url}
        dbg_label = '%s_%s' % (name.replace(' ','_'), label)

        if method == 'POST':
            body, final, resp = http_post(action_url, data, opener=opener,
                                          extra_headers=extra_headers,
                                          _dbg_label=dbg_label)
        else:
            qs = urllib.parse.urlencode({k: v for k, v in data.items() if v is not None})
            url_get = ('%s?%s' % (action_url, qs)) if qs else action_url
            body, final, resp = http_get(url_get, opener=opener, _dbg_label=dbg_label)

        log('[%s]   Response URL: %s' % (name, final))
        if body:
            import re as _re
            text = _re.sub(r'<[^>]+>', ' ', body)
            text = ' '.join(text.split())
            log('[%s]   Response text: %r' % (name, text[:200]))

        current_url  = final
        current_html = body

    # ── Connectivity check ──────────────────────────────────────────────────
    delays = handler.get('retry_delays', [1, 2, 3, 5, 5, 5, 5, 5])
    for attempt, delay in enumerate(delays, 1):
        time.sleep(delay)
        log('[%s] Connectivity check %d/%d ...' % (name, attempt, len(delays)))
        if _connectivity_ok(opener, status_url=status_url):
            return True

    log('[%s] Login failed — not online after all retries' % name)
    return False

# ── Generic HTML-form handler (Python fallback) ───────────────────────────────

_LOGIN_FIELD_TYPES = {'password', 'checkbox', 'submit'}

def _has_login_form(forms):
    """
    Return True if any parsed form looks like a pending login step.
    A form qualifies if it contains a password field, a checkbox, a submit
    button, or a field name matching the ticket/user patterns.
    Pure GET search forms (single text field, GET method) are ignored.
    """
    for form in forms:
        fields = form['fields']
        if not fields:
            continue
        # Ignore simple GET forms (e.g. search boxes)
        if form['method'] == 'GET' and len(fields) <= 1:
            continue
        for name, fld in fields.items():
            if fld['type'] in _LOGIN_FIELD_TYPES:
                return True
            if _TICKET_RE.search(name) or _USER_RE.search(name):
                return True
    return False

def handle_generic(portal_url, html, ticket=None, username=None, password=None,
                   opener=None, jar=None, _depth=0, _status_url=None):
    if not html:
        log('[Generic] No HTML received')
        return False
    if opener is None:
        opener, jar = _make_opener()

    forms, best = parse_forms(html)
    if DEBUG:
        dbg_html('generic_depth%d' % _depth, portal_url, html, forms=forms)

    # Extract status URL from form fields on the first call (Mikrotik/Coova pattern)
    if _status_url is None:
        for frm in forms:
            for fn, fld in frm['fields'].items():
                if 'status' in fn.lower() and (fld.get('value') or '').startswith('http'):
                    _status_url = fld['value']
                    dbg('[Generic] Found status URL: %s' % _status_url)
                    break

    if not best:
        # No form found — nothing left to submit, run connectivity check
        log('[Generic] No login form found — verifying connectivity')
        if _connectivity_ok(opener, status_url=_status_url):
            log('[Generic] Connectivity confirmed')
            return True
        log('[Generic] Login outcome unclear')
        return False

    log('[Generic] Form: method=%s action=%r  fields=%s' % (
        best['method'], best['action'], list(best['fields'].keys())))

    data = fill_form(best, ticket=ticket, username=username, password=password)
    action_url = resolve_action(portal_url, best['action'])

    log('[Generic] Submitting to %s' % action_url)
    log('[Generic] POST data: %s' % {k: v for k, v in data.items() if 'pass' not in k.lower()})

    if best['method'] == 'POST':
        body2, final2, _ = http_post(action_url, data, opener=opener,
                                     _dbg_label='generic_post_depth%d' % _depth)
    else:
        qs = urllib.parse.urlencode({k: v for k, v in data.items() if v is not None})
        body2, final2, _ = http_get(('%s?%s' % (action_url, qs)) if qs else action_url,
                                    opener=opener)

    log('[Generic] Response URL: %s' % final2)
    if body2:
        log('[Generic] Response snippet: %r' % body2[:300].strip())

    # Abort immediately if the response clearly signals a failure
    if looks_like_failure(body2):
        log('[Generic] Login failed — failure keyword in response')
        return False

    # If the response contains another login form and we have recursion budget,
    # follow it rather than running a connectivity check prematurely
    if body2 and _depth < 3:
        forms2, best2 = parse_forms(body2)
        if _has_login_form(forms2):
            log('[Generic] Another login form detected — following (depth %d)' % (_depth + 1))
            return handle_generic(final2, body2, ticket=ticket,
                                  username=username, password=password,
                                  opener=opener, jar=jar,
                                  _depth=_depth + 1, _status_url=_status_url)

    # No more login forms — verify actual connectivity
    if _connectivity_ok(opener, status_url=_status_url):
        log('[Generic] Connectivity confirmed after form submission')
        return True

    log('[Generic] Login outcome unclear')
    return False

# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch(portal_url, html, ticket=None, username=None, password=None):
    # Try all handlers from magic.d/ (both YAML and Python plugins),
    # sorted by priority. Falls back to the built-in generic handler.
    for handler in _load_handlers():
        htype = handler.get('_type', 'yaml')

        if htype == 'python':
            mod = handler['_module']
            if mod.can_handle(portal_url, html):
                log('[dispatch] Matched Python handler: %s' % handler['_file'])
                return mod.handle(portal_url, html,
                                  ticket=ticket, username=username,
                                  password=password)

        elif htype == 'yaml':
            if _handler_matches(handler, portal_url, html):
                log('[dispatch] Matched YAML handler: %s' % handler.get('name', handler['_file']))
                return _run_yaml_handler(handler, portal_url, html,
                                         ticket, username, password)

    # Generic Python fallback
    log('[dispatch] No specific handler matched — using generic form handler')
    return handle_generic(portal_url, html, ticket=ticket,
                          username=username, password=password)

# ── SSID / credentials helpers ────────────────────────────────────────────────

def current_ssid():
    try:
        with open(TRM_RUNTIME) as f:
            data = json.load(f)
        return data.get('station_id') or data.get('travelmate_ssid') or data.get('ssid')
    except Exception:
        return None

def load_credentials(ssid):
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
                    log('[creds] Matched SSID %r -> userpass for %r' % (ssid, parts[2]))
                    return None, parts[2], parts[3]
                if ctype == 'ticket' and len(parts) >= 3:
                    log('[creds] Matched SSID %r -> ticket' % ssid)
                    return parts[2], None, None
                if ctype == 'free':
                    log('[creds] Matched SSID %r -> free' % ssid)
                    return None, None, None
    except FileNotFoundError:
        pass
    except Exception as e:
        log('[creds] Could not read %s: %s' % (CREDS_FILE, e))
    return None, None, None

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ticket, username, password = parse_args()

    if not ticket and not username:
        ssid = current_ssid()
        if ssid:
            log('[*] Active SSID: %r' % ssid)
            ticket, username, password = load_credentials(ssid)

    if ticket:
        log('[*] Mode: ticket login  (ticket=%r)' % ticket)
    elif username:
        log('[*] Mode: username/password login  (user=%r)' % username)
    else:
        log('[*] Mode: free / checkbox login')

    if DEBUG:
        import subprocess, datetime
        dbg('=== captive-login debug session %s ===' % datetime.datetime.now().isoformat())
        for cmd in ['uname -a', 'ip route show',
                    'ip addr show phy1-sta0 2>/dev/null || ip addr show']:
            try:
                out = subprocess.check_output(cmd, shell=True,
                                              stderr=subprocess.STDOUT).decode()
                dbg('$ %s\n%s' % (cmd, out.strip()))
            except Exception as e:
                dbg('$ %s -> error: %s' % (cmd, e))

    log('[*] Detecting captive portal ...')
    portal_url, html = detect_portal()

    if portal_url is None:
        log('[*] No captive portal detected — already online')
        sys.exit(0)

    log('[*] Portal: %s' % portal_url)

    ok = dispatch(portal_url, html, ticket=ticket, username=username, password=password)

    if ok:
        log('[*] Login successful')
        sys.exit(0)
    else:
        log('[!] Login may have failed — check portal manually')
        sys.exit(1)

if __name__ == '__main__':
    main()
