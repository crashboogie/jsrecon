#!/usr/bin/env python3
"""
js_recon.py — JS/API surface extractor for pentest recon
Inputs:  Burp XML export(s), raw .js/.html files, or a directory of either
Output:  Compact JSON (default) or Markdown report

Usage:
  python3 js_recon.py burp_export.xml
  python3 js_recon.py target_dir/
  python3 js_recon.py *.js *.xml
  python3 js_recon.py burp.xml -o recon.json
  python3 js_recon.py burp.xml --stdout              # JSON to stdout
  python3 js_recon.py burp.xml --format md           # Markdown report
  python3 js_recon.py burp.xml --format md --stdout  # Markdown to stdout
  python3 js_recon.py burp.xml --format md -o recon.md --target acme.com

New in v4:
  - --scope flag: filter all output to matched domains/patterns only
      Accepts: exact domain, wildcard (*.target.com), CIDR (10.0.0.0/8),
      regex (/pattern/), or a file of scope entries (one per line)
      Applied at Burp XML read time (skips non-matching URLs entirely)
      and as a post-process pass over all extracted values

New in v3:
  - Markdown report mode (--format md) — dual-purpose: LLM paste or report notes
  - Expanded HTML surface extraction:
      href links, form actions + method, data-* API attributes,
      meta tags (CSP, description, generator), nonce attributes,
      <link> preload/prefetch hrefs, <base href>

New in v2:
  - Secret/credential expansion (Slack, GitHub, AWS, Stripe, high-entropy)
  - CORS configuration extraction
  - JWT decode (header + payload inline in output)
  - Client-side route table extraction (React Router, Vue Router, Angular, Next.js)
  - Feature flags / debug mode detection
  - Third-party integrations inventory (CDN scripts, analytics, etc.)
  - Error telemetry detection (Sentry, Bugsnag, Rollbar)
  - File upload/download surface
  - Prototype pollution sinks
  - GraphQL introspection query detection
  - OpenAPI/Swagger spec references
  - Dependency version fingerprinting
"""

import argparse
import base64
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------

class ScopeFilter:
    """
    Matches URLs and hostnames against a scope list.

    Accepted entry formats (one per line in a file, or one per --scope arg):
      target.com              — exact domain + all subdomains
      *.target.com            — wildcard subdomain only (no bare target.com)
      *.target.*              — any TLD: target.com, target.co.uk, target.de, etc.
      *.target.co.*           — locked second-level, any TLD: target.co.uk, target.co.nz
      ~walkme                 — substring match against hostname: catches walkme.com,
                                walkme.gov, walkmedev.com, my-walkme-app.io, etc.
      app.target.com          — exact host only
      10.0.0.0/8              — CIDR block (matched against IP literals in URLs)
      /regex/                 — arbitrary regex matched against the full URL
      https://app.target.com  — full URL prefix match
    """

    def __init__(self, entries: list[str]):
        self._matchers = []
        self._raw = entries
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            self._matchers.append(self._compile(entry))

    @staticmethod
    def _compile(entry: str):
        """Return a callable(url: str) -> bool for one scope entry."""
        # Regex literal /pattern/
        if entry.startswith("/") and entry.endswith("/") and len(entry) > 2:
            pattern = re.compile(entry[1:-1], re.IGNORECASE)
            return lambda url, p=pattern: bool(p.search(url))

        # CIDR block
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", entry):
            try:
                import ipaddress
                network = ipaddress.ip_network(entry, strict=False)
                def _cidr_match(url, net=network):
                    host = _extract_host(url)
                    try:
                        return ipaddress.ip_address(host) in net
                    except ValueError:
                        return False
                return _cidr_match
            except Exception:
                pass

        # Full URL prefix (starts with scheme)
        if entry.startswith(("http://", "https://")):
            prefix = entry.rstrip("/")
            return lambda url, p=prefix: url.startswith(p)

        # Substring hostname match: ~walkme
        # Matches any host that contains the term anywhere in the hostname.
        # Useful when a client has walkme.com, walkme.gov, walkmedev.com, etc.
        if entry.startswith("~"):
            term = entry[1:].lower()
            def _substring(url, t=term):
                host = _extract_host(url).lower()
                return t in host
            return _substring

        # Multi-wildcard: *.target.* or *.target.co.*
        # Any segment that is '*' becomes a wildcard label match
        if entry.count("*") >= 2 or (entry.startswith("*.") and entry.endswith(".*")):
            # Convert glob-style pattern to regex:
            #   *.target.*     → (^|\.)target\.[^.]+$
            #   *.target.co.*  → (^|\.)target\.co\.[^.]+$
            # Strategy: split on '.', escape literals, replace '*' with [^.]+ 
            parts = entry.split(".")
            regex_parts = []
            for part in parts:
                if part == "*":
                    regex_parts.append(r"[^.]+")
                else:
                    regex_parts.append(re.escape(part))
            # Build pattern: allow optional leading subdomain prefix.
            # Trailing * matches one or more dot-separated labels so *.jifflenow.*
            # catches both .com and .co.uk
            # Leading * similarly allows any subdomain depth.
            inner = r"\.".join(regex_parts)
            # Replace the trailing [^.]+ (from a trailing *) with .+ to allow
            # multi-label TLDs, and the leading [^.]+ with .+ to allow deep subdomains.
            # We do this by post-processing the joined string.
            if regex_parts and regex_parts[-1] == r"[^.]+":
                # Replace last label wildcard with multi-label match
                inner = r"\.".join(regex_parts[:-1]) + r"\..+"
            if regex_parts and regex_parts[0] == r"[^.]+":
                # Leading wildcard: allow any subdomain depth (or no subdomain)
                inner = r"(?:[^.]+\.)*" + r"\.".join(regex_parts[1:])
                # Re-apply trailing fix if needed
                if regex_parts[-1] == r"[^.]+" and len(regex_parts) > 1:
                    inner = r"(?:[^.]+\.)*" + r"\.".join(regex_parts[1:-1]) + r"\..+"
            pattern = re.compile(
                r"^" + inner + r"$",
                re.IGNORECASE,
            )
            def _multi_wildcard(url, p=pattern):
                host = _extract_host(url)
                return bool(p.search(host))
            return _multi_wildcard

        # Wildcard subdomain only: *.target.com
        if entry.startswith("*."):
            suffix = entry[1:]  # .target.com
            def _wildcard(url, s=suffix):
                host = _extract_host(url)
                return host.endswith(s) and host != s.lstrip(".")
            return _wildcard

        # Plain domain/host — match exact host or any subdomain of it
        domain = entry.lstrip(".")
        def _domain(url, d=domain):
            host = _extract_host(url)
            return host == d or host.endswith("." + d)
        return _domain

    def active(self) -> bool:
        return bool(self._matchers)

    def match_url(self, url: str) -> bool:
        """Return True if url is in scope (or no scope defined)."""
        if not self._matchers:
            return True
        return any(m(url) for m in self._matchers)

    def match_value(self, value: str) -> bool:
        """
        Return True if a string value (endpoint, external URL, hostname) is in scope.
        Relative paths (/api/...) are always kept — they have no host to filter on.
        """
        if not self._matchers:
            return True
        v = value.strip()
        # Relative paths: always in scope
        if v.startswith("/") or not v:
            return True
        # Absolute URLs or host-like strings
        if v.startswith(("http://", "https://", "wss://", "ws://")):
            return any(m(v) for m in self._matchers)
        # Raw hostname or "host:port"
        host = v.split(":")[0]
        synthetic = f"https://{host}/"
        return any(m(synthetic) for m in self._matchers)

    def summary_str(self) -> str:
        return ", ".join(self._raw) if self._raw else "(none)"


def _extract_host(url: str) -> str:
    """Pull the hostname from a URL, or return the input if it's already a host."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname or ""
    except Exception:
        return ""


def _load_scope(scope_args: list[str]) -> ScopeFilter:
    """
    Expand scope entries: if an entry is a readable file path, load its lines.
    Otherwise treat it as a literal scope entry.
    """
    entries = []
    for arg in scope_args:
        p = Path(arg)
        if p.is_file():
            entries.extend(p.read_text().splitlines())
            print(f"[*] Loaded scope from file: {arg} ({len(entries)} entries)", file=sys.stderr)
        else:
            entries.append(arg)
    return ScopeFilter(entries)


def _apply_scope_to_summary(summary: dict, scope: ScopeFilter) -> dict:
    """
    Post-process pass: drop out-of-scope values from all relevant summary fields.
    Relative paths (/api/...) are always kept.
    """
    if not scope.active():
        return summary

    def _filter_list(items: list) -> list:
        return [i for i in items if scope.match_value(i)]

    def _filter_list_prefixed(items: list) -> list:
        """For 'label: value' strings, extract the value part for scope check."""
        kept = []
        for item in items:
            if ": " in item:
                _, val = item.split(": ", 1)
                if scope.match_value(val.strip()):
                    kept.append(item)
            else:
                kept.append(item)  # no URL component, keep
        return kept

    url_fields = [
        "api_endpoints", "client_routes", "websockets", "workers",
        "external_scripts", "html_links", "html_forms", "html_data_attrs",
        "html_base_href",
    ]
    for field in url_fields:
        if field in summary:
            summary[field] = _filter_list(summary[field])

    # openapi_refs and source_maps carry "label: value" format
    for field in ("openapi_refs",):
        if field in summary:
            summary[field] = _filter_list_prefixed(summary[field])

    # GraphQL endpoints
    gql = summary.get("graphql")
    if gql and gql.get("endpoints"):
        gql["endpoints"] = _filter_list(gql["endpoints"])

    # Drop empty sections after filtering
    summary = {k: v for k, v in summary.items()
               if v is not None and v != [] and v != {} or k == "meta"}

    return summary


# ---------------------------------------------------------------------------
# Regex patterns — compiled once
# ---------------------------------------------------------------------------

# API endpoints
_RE_FETCH = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request)|
           \$\.(?:ajax|get|post)|
           XMLHttpRequest|
           (?:get|post|put|patch|delete)\s*\()\s*[\(`'"]
       (/[A-Za-z0-9_\-./{}:?&=%*]+)""",
    re.VERBOSE,
)
_RE_URL_STRING = re.compile(
    r"""['"`](/(?:api|v\d+|graphql|rest|service|endpoint|auth|oauth|token|
                  admin|internal|rpc|ws|webhook|upload|download|
                  search|query|user|account|session|config|health|status)
             [A-Za-z0-9_\-./{}:?&=%*]*)['"`]""",
    re.VERBOSE | re.IGNORECASE,
)

# GraphQL
_RE_GQL_ENDPOINT = re.compile(
    r"""['"`]((?:https?://[^'"`]+)?/graphql(?:[/?][^'"`]*)?)['"`]""",
    re.IGNORECASE,
)
_RE_GQL_OP = re.compile(
    r"""\b(query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]*)""",
    re.IGNORECASE,
)
_RE_GQL_TYPE = re.compile(r"""\btype\s+([A-Z][A-Za-z0-9_]+)\s*[{(]""")
_RE_GQL_FRAG = re.compile(r"""\bfragment\s+([A-Z][A-Za-z0-9_]+)\s+on\s+([A-Z][A-Za-z0-9_]+)""")
_RE_GQL_SCHEMA_KEY = re.compile(
    r"""['"`]?(query|mutation|subscription|fragment|__schema|__type)['"`]?\s*:""",
    re.IGNORECASE,
)
_RE_GQL_INTROSPECTION = re.compile(
    r"""__schema|__type\s*\(|IntrospectionQuery|getIntrospectionQuery""",
    re.IGNORECASE,
)

# Auth patterns
_RE_AUTH = [
    (re.compile(r"""['"` ]Authorization['"` ]\s*[:=]\s*['"` ]?Bearer""", re.IGNORECASE), "Bearer token (Authorization header)"),
    (re.compile(r"""['"` ]Authorization['"` ]\s*[:=]\s*['"` ]?Basic""", re.IGNORECASE), "Basic auth (Authorization header)"),
    (re.compile(r"""['"` ]Authorization['"` ]\s*[:=]\s*['"` ]?ApiKey""", re.IGNORECASE), "API key (Authorization header)"),
    (re.compile(r"""X-CSRF[-_]Token""", re.IGNORECASE), "CSRF token (X-CSRF-Token header)"),
    (re.compile(r"""X-Api-Key""", re.IGNORECASE), "API key (X-Api-Key header)"),
    (re.compile(r"""X-Auth-Token""", re.IGNORECASE), "Auth token (X-Auth-Token header)"),
    (re.compile(r"""localStorage\.(?:set|get)Item\s*\(\s*['"`](?:token|auth|jwt|access_token|refresh_token)""", re.IGNORECASE), "JWT/token stored in localStorage"),
    (re.compile(r"""sessionStorage\.(?:set|get)Item\s*\(\s*['"`](?:token|auth|jwt)""", re.IGNORECASE), "Token stored in sessionStorage"),
    (re.compile(r"""document\.cookie""", re.IGNORECASE), "Cookie-based auth pattern"),
    (re.compile(r"""oauth2?|openid.?connect|oidc""", re.IGNORECASE), "OAuth/OIDC flow"),
    (re.compile(r"""['"` ]api.?key['"` ]\s*[:=]""", re.IGNORECASE), "Hardcoded API key assignment"),
    (re.compile(r"""saml""", re.IGNORECASE), "SAML reference"),
]

# CORS patterns
_RE_CORS = [
    (re.compile(r"""Access-Control-Allow-Origin\s*[:=]\s*['"`]?\*['"`]?""", re.IGNORECASE), "CORS: wildcard origin (*)"),
    (re.compile(r"""Access-Control-Allow-Origin""", re.IGNORECASE), "CORS: Allow-Origin header set"),
    (re.compile(r"""withCredentials\s*:\s*true""", re.IGNORECASE), "CORS: withCredentials=true"),
    (re.compile(r"""cors\s*\(\s*\{[^}]*origin\s*:\s*true""", re.IGNORECASE), "CORS: origin: true (reflect all origins)"),
    (re.compile(r"""cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]""", re.IGNORECASE), "CORS: origin: '*' in config"),
    (re.compile(r"""Access-Control-Allow-Credentials\s*[:=]\s*['"`]?true['"`]?""", re.IGNORECASE), "CORS: Allow-Credentials: true"),
    (re.compile(r"""Access-Control-Allow-Methods""", re.IGNORECASE), "CORS: Allow-Methods header set"),
]

# JWT (for decoding)
_RE_JWT = re.compile(r"""eyJ[A-Za-z0-9+/\-_]{10,}\.eyJ[A-Za-z0-9+/\-_]{10,}\.[A-Za-z0-9+/\-_]*""")

# Secrets — expanded
_RE_SECRETS = [
    (re.compile(r"""(?:password|passwd|pwd|secret|private.?key)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]""", re.IGNORECASE), "Hardcoded credential"),
    (re.compile(r"""(AKIA[0-9A-Z]{16})"""), "AWS Access Key ID"),
    (re.compile(r"""(xox[baprs]-[0-9A-Za-z\-]{10,})"""), "Slack token"),
    (re.compile(r"""(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"""), "GitHub token"),
    (re.compile(r"""(sk_live_[A-Za-z0-9]{24,})"""), "Stripe live secret key"),
    (re.compile(r"""(pk_live_[A-Za-z0-9]{24,})"""), "Stripe live publishable key"),
    (re.compile(r"""(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})"""), "SendGrid API key"),
    (re.compile(r"""(AC[a-z0-9]{32}|SK[a-z0-9]{32})"""), "Twilio SID/key"),
    (re.compile(r"""(AIza[0-9A-Za-z\-_]{35})"""), "Google API key"),
    (re.compile(r"""(key-[a-zA-Z0-9]{32})"""), "Mailgun API key"),
    (re.compile(r"""bearer\s+([A-Za-z0-9\-_]{20,})""", re.IGNORECASE), "Hardcoded Bearer token value"),
]

# High-entropy string detection (skip short/common tokens)
_RE_ENTROPY_CANDIDATE = re.compile(r"""['"`]([A-Za-z0-9+/=_\-]{32,})['"`]""")
_ENTROPY_SKIP = re.compile(
    r"""^(?:[A-Z][a-z]+){3,}$|  # CamelCase words
        ^[a-z]+(?:[A-Z][a-z]+)+$|  # camelCase
        application/|text/|image/|  # MIME types
        [./\\]{2,}|  # paths
        [A-Za-z]{20,}$  # long all-alpha (prose)
    """,
    re.VERBOSE,
)

# Client-side routes
_RE_ROUTES = [
    # React Router v5/v6: <Route path="/foo">  or { path: '/foo' }
    re.compile(r"""(?:<Route[^>]+path\s*=\s*['"`]|path\s*:\s*['"`])(/[A-Za-z0-9_\-/:*?]+)['"`]"""),
    # Vue Router: { path: '/foo' }
    re.compile(r"""path\s*:\s*['"`](/[A-Za-z0-9_\-/:*?]+)['"`]"""),
    # Angular: { path: 'foo' } — often no leading slash
    re.compile(r"""path\s*:\s*['"`]([A-Za-z0-9_\-/:*?]+)['"`]"""),
    # Next.js getStaticPaths / router.push
    re.compile(r"""router\.(?:push|replace)\s*\(\s*['"`]([A-Za-z0-9_\-/:*?]+)['"`]"""),
    # Remix / next routes object
    re.compile(r"""['"`]((?:/[A-Za-z0-9_\-:*?]+){2,})['"`]"""),
]
_ROUTE_SKIP = re.compile(
    r"""^/(?:static|assets|images|fonts|icons|css|js|vendor|node_modules|
              favicon|robots|sitemap|manifest|sw\.js|workbox)""",
    re.IGNORECASE | re.VERBOSE,
)

# Feature flags / debug
_RE_FLAGS = [
    (re.compile(r"""(?:isDebug|debugMode|DEBUG|__DEV__|NODE_ENV\s*===?\s*['"`]development['"`])\s*[:=]\s*(true|['"`]development['"`])""", re.IGNORECASE), "Debug mode flag"),
    (re.compile(r"""(?:ENABLE_ADMIN|enableAdmin|isAdmin\s*=\s*true|isSuperAdmin\s*=\s*true)""", re.IGNORECASE), "Admin enable flag"),
    (re.compile(r"""featureFlag|feature_flag|FeatureFlag|FEATURE_""", re.IGNORECASE), "Feature flag system"),
    (re.compile(r"""launchDarkly|LaunchDarkly|ldClient"""), "LaunchDarkly feature flags"),
    (re.compile(r"""(?:showDevTools|devTools|devMode|DEV_MODE)\s*[:=]\s*true""", re.IGNORECASE), "Dev tools enabled"),
    (re.compile(r"""process\.env\.(?:REACT_APP|NEXT_PUBLIC|VUE_APP|VITE_)(\w+)"""), "Exposed env variable"),
    (re.compile(r"""__REDUX_DEVTOOLS_EXTENSION__|ReactQueryDevtools"""), "Dev tools extension hooked"),
]

# Third-party integrations (CDN/external JS loads)
_RE_THIRD_PARTY = [
    (re.compile(r"""segment\.(?:com|io)|analytics\.load\s*\(|window\.analytics""", re.IGNORECASE), "Segment (analytics)"),
    (re.compile(r"""intercom\.io|window\.Intercom|Intercom\s*\(""", re.IGNORECASE), "Intercom (chat/support)"),
    (re.compile(r"""hotjar\.com|hj\s*\(|window\.hj""", re.IGNORECASE), "Hotjar (session recording)"),
    (re.compile(r"""fullstory\.com|window\._fs_|FS\.identify""", re.IGNORECASE), "FullStory (session recording)"),
    (re.compile(r"""googletagmanager\.com|gtag\s*\(|dataLayer\.push""", re.IGNORECASE), "Google Tag Manager / GA"),
    (re.compile(r"""mixpanel\.com|mixpanel\.track|mixpanel\.identify""", re.IGNORECASE), "Mixpanel (analytics)"),
    (re.compile(r"""heap\.io|heap\.track|heap\.identify""", re.IGNORECASE), "Heap (analytics)"),
    (re.compile(r"""pendo\.io|pendo\.initialize""", re.IGNORECASE), "Pendo (product analytics)"),
    (re.compile(r"""amplitude\.com|amplitude\.getInstance""", re.IGNORECASE), "Amplitude (analytics)"),
    (re.compile(r"""stripe\.com/v3|loadStripe|Stripe\s*\(""", re.IGNORECASE), "Stripe (payments)"),
    (re.compile(r"""braintreegateway\.com|braintree\.setup""", re.IGNORECASE), "Braintree (payments)"),
    (re.compile(r"""paypal\.com/sdk|paypal\.Buttons""", re.IGNORECASE), "PayPal (payments)"),
    (re.compile(r"""recaptcha\.net|google\.com/recaptcha|grecaptcha""", re.IGNORECASE), "reCAPTCHA"),
    (re.compile(r"""hcaptcha\.com|hcaptcha\.render""", re.IGNORECASE), "hCaptcha"),
    (re.compile(r"""cloudflare\.com|turnstile\.render""", re.IGNORECASE), "Cloudflare Turnstile"),
    (re.compile(r"""auth0\.com|createAuth0Client|Auth0Provider""", re.IGNORECASE), "Auth0 (identity)"),
    (re.compile(r"""okta\.com|OktaAuth|oktaSignIn""", re.IGNORECASE), "Okta (identity)"),
    (re.compile(r"""cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com""", re.IGNORECASE), "CDN-loaded script"),
    (re.compile(r"""maps\.googleapis\.com|google\.maps""", re.IGNORECASE), "Google Maps"),
    (re.compile(r"""platform\.twitter\.com|twitter\.com/widgets""", re.IGNORECASE), "Twitter/X widget"),
    (re.compile(r"""connect\.facebook\.net|FB\.init""", re.IGNORECASE), "Facebook SDK"),
    (re.compile(r"""appleid\.apple\.com|AppleID\.auth""", re.IGNORECASE), "Sign in with Apple"),
    (re.compile(r"""accounts\.google\.com|google\.accounts""", re.IGNORECASE), "Sign in with Google"),
]

# Error telemetry
_RE_TELEMETRY = [
    (re.compile(r"""Sentry\.init|@sentry/|sentry\.io""", re.IGNORECASE), "Sentry"),
    (re.compile(r"""Bugsnag\.start|bugsnag\.com""", re.IGNORECASE), "Bugsnag"),
    (re.compile(r"""rollbar\.init|rollbar\.com""", re.IGNORECASE), "Rollbar"),
    (re.compile(r"""datadoghq\.com|DD_RUM|datadogRum""", re.IGNORECASE), "Datadog RUM"),
    (re.compile(r"""newrelic\.com|NREUM|newRelicAgent""", re.IGNORECASE), "New Relic"),
    (re.compile(r"""logrocket\.com|LogRocket\.init""", re.IGNORECASE), "LogRocket"),
    (re.compile(r"""TrackJS|trackjs\.com""", re.IGNORECASE), "TrackJS"),
    (re.compile(r"""console\.(error|warn)\s*\(.*stack""", re.IGNORECASE), "Stack trace logged to console"),
]

# File upload/download
_RE_FILEOPS = [
    (re.compile(r"""new FormData\s*\("""), "FormData construction"),
    (re.compile(r"""multipart/form-data""", re.IGNORECASE), "multipart/form-data upload"),
    (re.compile(r"""['"`]accept['"`]\s*:\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE), "File accept type filter"),
    (re.compile(r"""input\[type=['"` ]?file['"` ]?\]|type\s*=\s*['"`]file['"`]""", re.IGNORECASE), "File input element"),
    (re.compile(r"""Content-Disposition""", re.IGNORECASE), "Content-Disposition header (download trigger)"),
    (re.compile(r"""URL\.createObjectURL|createObjectURL"""), "createObjectURL (blob download)"),
    (re.compile(r"""new Blob\s*\("""), "Blob construction"),
    (re.compile(r"""\.download\s*=|a\.download"""), "HTML anchor download attribute"),
    (re.compile(r"""FileReader|readAsDataURL|readAsArrayBuffer"""), "FileReader API"),
    (re.compile(r"""application/octet-stream""", re.IGNORECASE), "Octet-stream (raw binary download)"),
    (re.compile(r"""chunked|multipart/byteranges|Content-Range""", re.IGNORECASE), "Chunked/range upload or download"),
]

# Prototype pollution sinks
_RE_PROTO_POLLUTION = [
    (re.compile(r"""Object\.assign\s*\(\s*(?:\{\}|target|\w+)\s*,"""), "Object.assign() merge"),
    (re.compile(r"""_\.merge\s*\(|lodash\.merge\s*\("""), "lodash _.merge() (deep merge)"),
    (re.compile(r"""\$\.extend\s*\(\s*true"""), "jQuery $.extend(deep) merge"),
    (re.compile(r"""Object\.setPrototypeOf|__proto__\s*[:=]|prototype\["""), "__proto__ / setPrototypeOf write"),
    (re.compile(r"""deepmerge\s*\(|deepMerge\s*\(|merge\s*\(\s*\{\}"""), "deepmerge() call"),
    (re.compile(r"""JSON\.parse\s*\([^)]*\)\s*\.\s*\w+\s*=|JSON\.parse.*spread""", re.IGNORECASE), "JSON.parse result spread/assign"),
    (re.compile(r"""constructor\s*\[|constructor\s*\.\s*prototype"""), "constructor.prototype access"),
]

# OpenAPI / Swagger spec references
_RE_OPENAPI = [
    (re.compile(r"""['"`](/(?:api-docs?|swagger(?:\.json|\.yaml|-ui|/index\.html)?|openapi(?:\.json|\.yaml)?|v\d+/docs?|redoc)[^'"`]*)['"`]""", re.IGNORECASE), "OpenAPI/Swagger endpoint"),
    (re.compile(r"""swagger(?:\.json|\.yaml)|openapi(?:\.json|\.yaml)|api-spec\.json""", re.IGNORECASE), "OpenAPI/Swagger file reference"),
    (re.compile(r"""SwaggerUIBundle|redoc\.standalone|ReDoc\.init""", re.IGNORECASE), "Swagger UI / ReDoc renderer"),
    (re.compile(r"""openapi\s*:\s*['"`]?3\.\d|swagger\s*:\s*['"`]?2\.\d""", re.IGNORECASE), "Inline OpenAPI spec version string"),
]

# Dependency version fingerprinting
_RE_DEP_VERSION = re.compile(
    r"""['"`]?(?:version|VERSION)\s*['"`]?\s*[:=]\s*['"`](\d+\.\d+[\.\d]*)['"`]""",
    re.IGNORECASE,
)
_RE_DEP_NAMED = re.compile(
    r"""(?:['"`](?P<pkg>react|vue|angular|next|svelte|axios|redux|lodash|
            jquery|bootstrap|tailwindcss|express|fastapi|django|
            socket\.io|graphql|apollo|webpack|vite|babel|typescript|
            moment|dayjs|rxjs|zustand|mobx|d3|chart\.js|three)['"`]
        \s*[,:]?\s*
        (?:['"`])?(?P<ver>\d+\.\d+[\.\d]*)['"`]?)""",
    re.VERBOSE | re.IGNORECASE,
)

# Framework/library fingerprints (unchanged from v1)
_RE_FRAMEWORKS = [
    (re.compile(r"""['"]react['"]|from ['"]react['"]|React\.createElement"""), "React"),
    (re.compile(r"""from ['"]react-dom['"]|ReactDOM\.render|createRoot\("""), "React DOM"),
    (re.compile(r"""from ['"]next['"]|next/router|next/navigation|getServerSideProps|getStaticProps"""), "Next.js"),
    (re.compile(r"""from ['"]@angular/core['"]|NgModule|@Component|@Injectable"""), "Angular"),
    (re.compile(r"""from ['"]vue['"]|createApp\(|\.vue['"]|Vue\.component"""), "Vue.js"),
    (re.compile(r"""from ['"]svelte['"]|SvelteComponent|\.svelte"""), "Svelte"),
    (re.compile(r"""from ['"]@apollo/client['"]|ApolloClient|useQuery|useMutation|gql`"""), "Apollo Client (GraphQL)"),
    (re.compile(r"""from ['"]@tanstack/react-query['"]|from ['"]react-query['"]|useQuery\("""), "React Query / TanStack Query"),
    (re.compile(r"""from ['"]axios['"]|require\(['"]axios['"]\)"""), "Axios"),
    (re.compile(r"""from ['"]redux['"]|createSlice|configureStore|useSelector|useDispatch"""), "Redux"),
    (re.compile(r"""from ['"]zustand['"]|create\(.*set =>"""), "Zustand"),
    (re.compile(r"""from ['"]socket\.io['"]|io\.connect|new WebSocket"""), "WebSocket / Socket.io"),
    (re.compile(r"""from ['"]@stripe/stripe-js['"]|loadStripe|Stripe\("""), "Stripe.js"),
    (re.compile(r"""from ['"]firebase['"]|initializeApp|getFirestore"""), "Firebase"),
    (re.compile(r"""from ['"]aws-amplify['"]|Amplify\.configure"""), "AWS Amplify"),
    (re.compile(r"""from ['"]@mui/material['"]|from ['"]@material-ui['"]"""), "Material UI"),
    (re.compile(r"""from ['"]lodash['"]|require\(['"]lodash['"]\)|_\."""), "Lodash"),
    (re.compile(r"""from ['"]jwt-decode['"]|jwtDecode|atob\(.*\.split\('\.'"""), "JWT decode"),
    (re.compile(r"""from ['"]crypto-js['"]|CryptoJS\."""), "CryptoJS"),
    (re.compile(r"""remix\.run|from ['"]@remix-run['"]"""), "Remix"),
    (re.compile(r"""nuxt\.config|from ['"]#app['"]|useNuxtApp"""), "Nuxt.js"),
    (re.compile(r"""from ['"]graphql['"]|buildSchema|gql\b"""), "GraphQL client lib"),
    (re.compile(r"""from ['"]@grpc/grpc-js['"]|grpc\.credentials"""), "gRPC"),
    (re.compile(r"""protobuf|proto\.Message|\.proto['"]"""), "Protocol Buffers"),
    (re.compile(r"""swagger|openapi|from ['"]@redocly['"]"""), "OpenAPI / Swagger"),
]

# Interesting / sensitive strings (v1 set, kept as-is)
_RE_INTERESTING = [
    (re.compile(r"""(?:staging|stage|dev|development|uat|qa|test)[-.](?:[a-z0-9.-]+)""", re.IGNORECASE), "Internal/staging hostname"),
    (re.compile(r"""(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"""), "Private IP address"),
    (re.compile(r"""localhost:\d{2,5}"""), "Localhost reference"),
    (re.compile(r"""console\.(log|debug|warn|error)\s*\("""), "console.log usage (debug output)"),
    (re.compile(r"""X-Debug|X-Internal|X-Request-Id|X-Forwarded|X-Real-IP""", re.IGNORECASE), "Debug/internal header"),
    (re.compile(r"""debugger;"""), "debugger statement"),
    (re.compile(r"""\.env\b|process\.env\."""), "Environment variable access"),
    (re.compile(r"""(?:role|permission|admin|superuser|isAdmin|isSuperAdmin)\s*[:=]""", re.IGNORECASE), "Role/permission check"),
    (re.compile(r"""(?:eval|Function)\s*\("""), "eval() / new Function() — potential injection sink"),
    (re.compile(r"""innerHTML\s*=|outerHTML\s*=|document\.write"""), "innerHTML/document.write — potential XSS sink"),
    (re.compile(r"""dangerouslySetInnerHTML"""), "dangerouslySetInnerHTML (React XSS risk)"),
    (re.compile(r"""postMessage\s*\("""), "postMessage (cross-origin messaging)"),
    (re.compile(r"""window\.location\s*=|location\.href\s*=|location\.replace"""), "Open redirect sink"),
]

# WebSocket endpoints
_RE_WS = re.compile(r"""['"`](wss?://[A-Za-z0-9._:/-]+)['"`]""")

# Source map references
_RE_SOURCEMAP = re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)""")

# Web worker / service worker (bonus — already noted, cheap to add)
_RE_WORKERS = re.compile(
    r"""new Worker\s*\(\s*['"`]([^'"`]+)['"`]|navigator\.serviceWorker\.register\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper: Shannon entropy
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_high_entropy(s: str, threshold: float = 4.2) -> bool:
    """Return True if string looks like a random secret rather than prose/code."""
    if len(s) < 32:
        return False
    if _ENTROPY_SKIP.search(s):
        return False
    return _shannon_entropy(s) >= threshold


# ---------------------------------------------------------------------------
# Helper: JWT decode
# ---------------------------------------------------------------------------

def _decode_jwt(token: str) -> dict | None:
    """Base64-decode JWT header and payload; return dict or None on failure."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    result = {}
    for i, part_name in enumerate(("header", "payload")):
        segment = parts[i]
        # Fix padding
        segment += "=" * (-len(segment) % 4)
        try:
            decoded = base64.urlsafe_b64decode(segment).decode("utf-8", errors="replace")
            result[part_name] = json.loads(decoded)
        except Exception:
            result[part_name] = segment  # keep raw if not JSON
    result["raw_token_prefix"] = token[:40] + "..."
    return result


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

def extract_from_js(content: str, source_label: str, result: dict):
    """Parse one JS blob and merge findings into result dict."""

    # --- v1 features ---

    # API endpoints
    for m in _RE_FETCH.finditer(content):
        result["api_endpoints"].add(m.group(1))
    for m in _RE_URL_STRING.finditer(content):
        result["api_endpoints"].add(m.group(1))

    # GraphQL
    for m in _RE_GQL_ENDPOINT.finditer(content):
        result["graphql"]["endpoints"].add(m.group(1))
    for m in _RE_GQL_OP.finditer(content):
        op_type, op_name = m.group(1).lower(), m.group(2)
        result["graphql"]["operations"].add(f"{op_type}:{op_name}")
    for m in _RE_GQL_TYPE.finditer(content):
        result["graphql"]["types"].add(m.group(1))
    for m in _RE_GQL_FRAG.finditer(content):
        result["graphql"]["fragments"].add(f"{m.group(1)} on {m.group(2)}")
    if _RE_GQL_SCHEMA_KEY.search(content):
        result["graphql"]["schema_document_present"] = True
    if _RE_GQL_INTROSPECTION.search(content):
        result["graphql"]["introspection_queries_present"] = True

    # Frameworks
    for pattern, label in _RE_FRAMEWORKS:
        if pattern.search(content):
            result["frameworks"].add(label)

    # Auth
    for pattern, label in _RE_AUTH:
        if pattern.search(content):
            result["auth_patterns"].add(label)

    # Interesting strings
    for pattern, label in _RE_INTERESTING:
        for m in pattern.finditer(content):
            hit = m.group(0)[:120]
            result["interesting"].add(f"{label}: {hit}")

    # WebSockets
    for m in _RE_WS.finditer(content):
        result["websockets"].add(m.group(1))

    # Source maps
    for m in _RE_SOURCEMAP.finditer(content):
        result["source_maps"].add(m.group(1))

    # --- v2 features ---

    # 1. Secrets — named patterns
    for pattern, label in _RE_SECRETS:
        for m in pattern.finditer(content):
            val = m.group(1) if m.lastindex else m.group(0)
            # Redact all but first/last 4 chars for output safety
            redacted = val[:4] + "*" * max(0, len(val) - 8) + val[-4:] if len(val) > 8 else "****"
            result["secrets"].add(f"{label}: {redacted}")

    # 1b. High-entropy strings
    for m in _RE_ENTROPY_CANDIDATE.finditer(content):
        val = m.group(1)
        if _is_high_entropy(val):
            redacted = val[:6] + "..." + val[-4:]
            result["secrets"].add(f"High-entropy string: {redacted}")

    # 2. CORS
    for pattern, label in _RE_CORS:
        if pattern.search(content):
            result["cors_issues"].add(label)

    # 3. JWT decode
    for m in _RE_JWT.finditer(content):
        token = m.group(0)
        decoded = _decode_jwt(token)
        if decoded:
            key = json.dumps(decoded.get("header", {}), sort_keys=True)
            if key not in result["_jwt_seen"]:
                result["_jwt_seen"].add(key)
                result["jwts_found"].append(decoded)

    # 4. Client-side routes
    for pattern in _RE_ROUTES:
        for m in pattern.finditer(content):
            route = m.group(1)
            if route and len(route) > 1 and not _ROUTE_SKIP.match(route):
                result["client_routes"].add(route)

    # 5. Feature flags / debug
    for pattern, label in _RE_FLAGS:
        for m in pattern.finditer(content):
            hit = m.group(0)[:100]
            result["feature_flags"].add(f"{label}: {hit}")

    # 6. Third-party integrations
    for pattern, label in _RE_THIRD_PARTY:
        if pattern.search(content):
            result["third_party"].add(label)

    # 7. Error telemetry
    for pattern, label in _RE_TELEMETRY:
        if pattern.search(content):
            result["telemetry"].add(label)

    # 8. File upload / download surface
    for pattern, label in _RE_FILEOPS:
        for m in pattern.finditer(content):
            hit = m.group(0)[:100]
            result["file_ops"].add(f"{label}: {hit}")

    # 9. Prototype pollution sinks
    for pattern, label in _RE_PROTO_POLLUTION:
        for m in pattern.finditer(content):
            hit = m.group(0)[:100]
            result["proto_pollution"].add(f"{label}: {hit}")

    # 10 (bonus). Web workers
    for m in _RE_WORKERS.finditer(content):
        url = m.group(1) or m.group(2)
        if url:
            result["workers"].add(url)

    # 13. OpenAPI / Swagger
    for pattern, label in _RE_OPENAPI:
        for m in pattern.finditer(content):
            hit = m.group(1) if m.lastindex else m.group(0)
            result["openapi_refs"].add(f"{label}: {hit[:120]}")

    # 15. Dependency versions
    for m in _RE_DEP_NAMED.finditer(content):
        pkg = m.group("pkg").lower()
        ver = m.group("ver")
        if pkg and ver:
            result["dep_versions"][pkg] = ver  # last-seen wins; bundles are consistent


def extract_from_html(content: str, source_label: str, result: dict):
    """Full HTML surface extraction — scripts, links, forms, meta, data-* attrs."""

    # --- External script srcs ---
    script_src_re = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    for m in script_src_re.finditer(content):
        result["external_scripts"].add(m.group(1))

    # --- Inline <script> blocks → full JS extraction ---
    inline_re = re.compile(r"""<script(?![^>]*src)[^>]*>(.*?)</script>""", re.DOTALL | re.IGNORECASE)
    for m in inline_re.finditer(content):
        extract_from_js(m.group(1), source_label + " [inline]", result)

    # --- <a href> links — internal paths only ---
    href_re = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"#?]+)['"]""", re.IGNORECASE)
    for m in href_re.finditer(content):
        href = m.group(1).strip()
        if href.startswith("/") and not _ROUTE_SKIP.match(href):
            result["html_links"].add(href)
        elif href.startswith("http"):
            result["external_scripts"].add(href)  # reuse external bucket for off-domain links

    # --- <form> actions + methods ---
    form_re = re.compile(
        r"""<form[^>]*(?:action\s*=\s*['"]([^'"]+)['"])?[^>]*(?:method\s*=\s*['"]([^'"]+)['"])?[^>]*>""",
        re.IGNORECASE,
    )
    for m in form_re.finditer(content):
        action = m.group(1) or ""
        method = (m.group(2) or "GET").upper()
        if action and not action.startswith("javascript:"):
            result["html_forms"].add(f"{method} {action}")
        elif not action:
            # formless action — method only, mark as implicit POST to current page
            result["html_forms"].add(f"{method} (no action — posts to current URL)")

    # --- data-* attributes that look like API paths or config ---
    data_attr_re = re.compile(
        r"""data-(?:api|url|endpoint|src|href|action|config|target)\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    for m in data_attr_re.finditer(content):
        val = m.group(1).strip()
        if val.startswith("/") or val.startswith("http"):
            result["html_data_attrs"].add(val)

    # --- <meta> tags: CSP, generator, description ---
    # CSP
    csp_re = re.compile(
        r"""<meta[^>]+http-equiv\s*=\s*['"]Content-Security-Policy['"][^>]+content\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    for m in csp_re.finditer(content):
        result["csp_meta_tags"].add(m.group(1)[:500])

    # Reverse-order CSP (content= before http-equiv=)
    csp_re2 = re.compile(
        r"""<meta[^>]+content\s*=\s*['"]([^'"]+)['"][^>]+http-equiv\s*=\s*['"]Content-Security-Policy['"]""",
        re.IGNORECASE,
    )
    for m in csp_re2.finditer(content):
        result["csp_meta_tags"].add(m.group(1)[:500])

    # Generator tag — framework/CMS fingerprint
    gen_re = re.compile(r"""<meta[^>]+name\s*=\s*['"]generator['"][^>]+content\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    for m in gen_re.finditer(content):
        result["frameworks"].add(f"Generator: {m.group(1)}")

    # --- nonce attributes (CSP nonce leakage) ---
    nonce_re = re.compile(r"""\bnonce\s*=\s*['"]([A-Za-z0-9+/=]{8,})['"]""", re.IGNORECASE)
    for m in nonce_re.finditer(content):
        result["html_nonces"].add(m.group(1))

    # --- <link> preload / prefetch / canonical hrefs ---
    link_re = re.compile(
        r"""<link[^>]+(?:rel\s*=\s*['"](?:preload|prefetch|stylesheet|canonical)['"]\s*)?[^>]*href\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    for m in link_re.finditer(content):
        href = m.group(1).strip()
        if href.startswith("/") and not _ROUTE_SKIP.match(href):
            result["html_links"].add(href)
        elif href.endswith(".js") or href.endswith(".css"):
            result["external_scripts"].add(href)

    # --- <base href> — changes relative URL resolution ---
    base_re = re.compile(r"""<base[^>]+href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    for m in base_re.finditer(content):
        result["html_base_href"].add(m.group(1))

    # --- input[type=hidden] names + values — often contain API tokens or IDs ---
    hidden_re = re.compile(
        r"""<input[^>]+type\s*=\s*['"]hidden['"][^>]*name\s*=\s*['"]([^'"]+)['"][^>]*(?:value\s*=\s*['"]([^'"]*)['"])?""",
        re.IGNORECASE,
    )
    for m in hidden_re.finditer(content):
        name = m.group(1)
        value = m.group(2) or ""
        entry = name if not value else f"{name}={value[:60]}"
        result["html_hidden_inputs"].add(entry)

    # --- <iframe> srcs — often internal app frames ---
    iframe_re = re.compile(r"""<iframe[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    for m in iframe_re.finditer(content):
        src = m.group(1)
        if src.startswith("/"):
            result["html_links"].add(src)
        elif src.startswith("http"):
            result["external_scripts"].add(src)


# ---------------------------------------------------------------------------
# Input readers
# ---------------------------------------------------------------------------

def _decode_burp_body(item_el):
    if item_el is None:
        return ""
    base64_attr = item_el.get("base64", "false").lower()
    text = item_el.text or ""
    if base64_attr == "true":
        try:
            text = base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def _strip_http_headers(body: str) -> str:
    if "\r\n\r\n" in body:
        return body.split("\r\n\r\n", 1)[1]
    if "\n\n" in body:
        return body.split("\n\n", 1)[1]
    return body


def process_burp_xml(path: str, result: dict, scope: "ScopeFilter | None" = None):
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] XML parse error in {path}: {e}", file=sys.stderr)
        return

    root = tree.getroot()
    items = root.findall(".//item")
    print(f"[*] {path}: {len(items)} Burp items", file=sys.stderr)

    js_count = html_count = skipped = 0
    for item in items:
        url_el = item.find("url")
        resp_el = item.find("response")
        mime_el = item.find("mimetype")

        url = url_el.text if url_el is not None else ""
        mime = (mime_el.text or "").lower()

        # Scope filter — skip out-of-scope URLs at read time
        if scope and scope.active() and not scope.match_url(url):
            skipped += 1
            continue

        body = _decode_burp_body(resp_el)
        if not body:
            continue
        body = _strip_http_headers(body)

        is_js = (
            "javascript" in mime
            or url.endswith(".js")
            or url.endswith(".mjs")
        )
        is_html = "html" in mime or url.endswith(".html") or url.endswith(".htm")

        if is_js:
            extract_from_js(body, url, result)
            result["js_files_analyzed"].add(url)
            js_count += 1
        elif is_html:
            extract_from_html(body, url, result)
            html_count += 1

    scope_note = f" | {skipped} out-of-scope skipped" if skipped else ""
    print(f"[*] {path}: {js_count} JS + {html_count} HTML responses analyzed{scope_note}", file=sys.stderr)


def process_js_file(path: str, result: dict):
    try:
        content = Path(path).read_text(errors="replace")
    except OSError as e:
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return
    extract_from_js(content, path, result)
    result["js_files_analyzed"].add(path)


def process_html_file(path: str, result: dict):
    try:
        content = Path(path).read_text(errors="replace")
    except OSError as e:
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return
    extract_from_html(content, path, result)


def process_path(path: str, result: dict, scope: "ScopeFilter | None" = None):
    p = Path(path)
    if p.is_dir():
        for child in sorted(p.rglob("*")):
            if child.suffix == ".xml":
                process_burp_xml(str(child), result, scope=scope)
            elif child.suffix in (".js", ".mjs", ".map"):
                process_js_file(str(child), result)
            elif child.suffix in (".html", ".htm"):
                process_html_file(str(child), result)
    elif p.suffix == ".xml":
        process_burp_xml(str(p), result, scope=scope)
    elif p.suffix in (".js", ".mjs", ".map"):
        process_js_file(str(p), result)
    elif p.suffix in (".html", ".htm"):
        process_html_file(str(p), result)
    else:
        print(f"[?] Skipping unrecognized file type: {path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Post-process helpers
# ---------------------------------------------------------------------------

def _normalize_endpoints(endpoints: set) -> list:
    seen = set()
    out = []
    uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
    num_re = re.compile(r"/\d+(?=/|$)")
    for ep in sorted(endpoints):
        norm = uuid_re.sub("{id}", ep)
        norm = num_re.sub("/{id}", norm)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _limit_set(items: set, cap: int = 40, per_label: int = 5) -> list:
    sorted_items = sorted(items, key=lambda x: (x.split(":")[0], len(x)))
    seen_labels = defaultdict(int)
    out = []
    for item in sorted_items:
        label = item.split(":")[0]
        if seen_labels[label] < per_label:
            out.append(item)
            seen_labels[label] += 1
        if len(out) >= cap:
            break
    return out


def _summarize_jwts(jwts: list) -> list:
    """Reduce JWT list to unique algorithms + notable claims."""
    seen_alg = set()
    out = []
    for jwt in jwts[:10]:  # cap at 10
        header = jwt.get("header", {})
        payload = jwt.get("payload", {})
        alg = header.get("alg", "unknown") if isinstance(header, dict) else "unknown"
        entry = {
            "alg": alg,
            "token_prefix": jwt.get("raw_token_prefix", ""),
        }
        if isinstance(payload, dict):
            # Extract notable claims only
            notable = {k: v for k, v in payload.items()
                       if k in ("sub", "iss", "aud", "exp", "iat", "role", "roles",
                                "scope", "scopes", "email", "user_id", "admin", "permissions")}
            if notable:
                entry["claims"] = notable
        sig = f"{alg}:{entry.get('claims', {}).get('iss', '')}"
        if sig not in seen_alg:
            seen_alg.add(sig)
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Build final summary
# ---------------------------------------------------------------------------

def build_summary(result: dict, inputs: list, scope: "ScopeFilter | None" = None) -> dict:
    gql = result["graphql"]
    ops_by_type = defaultdict(list)
    for op in sorted(gql["operations"]):
        t, name = op.split(":", 1)
        ops_by_type[t].append(name)

    summary = {
        "meta": {
            "inputs": inputs,
            "js_files_analyzed": len(result["js_files_analyzed"]),
            "scope": scope.summary_str() if scope and scope.active() else None,
        },
        "frameworks": sorted(result["frameworks"]),
        "dep_versions": result["dep_versions"] if result["dep_versions"] else None,
        "graphql": {
            "endpoints": sorted(gql["endpoints"]),
            "operations": dict(ops_by_type) if ops_by_type else None,
            "types_referenced": sorted(gql["types"])[:50],
            "fragments": sorted(gql["fragments"])[:20],
            "schema_document_detected": gql.get("schema_document_present", False),
            "introspection_queries_detected": gql.get("introspection_queries_present", False),
        } if (gql["endpoints"] or gql["operations"]) else None,
        "api_endpoints": _normalize_endpoints(result["api_endpoints"]),
        "client_routes": sorted(result["client_routes"]),
        "websockets": sorted(result["websockets"]),
        "workers": sorted(result["workers"]),
        "auth_patterns": sorted(result["auth_patterns"]),
        "cors_issues": sorted(result["cors_issues"]),
        "jwts_found": _summarize_jwts(result["jwts_found"]),
        "secrets": _limit_set(result["secrets"], cap=50, per_label=3),
        "openapi_refs": sorted(result["openapi_refs"]),
        "third_party": sorted(result["third_party"]),
        "telemetry": sorted(result["telemetry"]),
        "file_ops": _limit_set(result["file_ops"], cap=20, per_label=3),
        "proto_pollution_sinks": _limit_set(result["proto_pollution"], cap=20, per_label=3),
        "feature_flags": _limit_set(result["feature_flags"], cap=20, per_label=5),
        "external_scripts": sorted(result["external_scripts"]),
        "csp_meta_tags": sorted(result["csp_meta_tags"]),
        "html_links": sorted(result["html_links"]),
        "html_forms": sorted(result["html_forms"]),
        "html_data_attrs": sorted(result["html_data_attrs"]),
        "html_hidden_inputs": sorted(result["html_hidden_inputs"]),
        "html_nonces": sorted(result["html_nonces"]),
        "html_base_href": sorted(result["html_base_href"]),
        "source_maps": sorted(result["source_maps"]),
        "interesting": _limit_set(result["interesting"]),
    }

    # Drop empty/None sections
    summary = {k: v for k, v in summary.items()
               if v is not None and v != [] and v != {} or k == "meta"}
    if summary.get("graphql") is None:
        summary.pop("graphql", None)

    return summary


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _md_list(items: list, indent: str = "") -> str:
    """Render a list as markdown bullet points."""
    return "\n".join(f"{indent}- `{item}`" for item in items) if items else f"{indent}_none_"


def _md_section(title: str, content: str) -> str:
    return f"### {title}\n{content}\n"


def render_markdown(summary: dict, target: str = "") -> str:
    from datetime import datetime, timezone
    lines = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target_str = f" — {target}" if target else ""

    lines.append(f"# JS Recon Report{target_str}")
    lines.append(f"_Generated: {ts}_\n")

    # Meta
    meta = summary.get("meta", {})
    lines.append("## Overview")
    lines.append(f"- **Inputs:** {', '.join(meta.get('inputs', []))}")
    lines.append(f"- **JS files analyzed:** {meta.get('js_files_analyzed', 0)}")
    if meta.get("scope"):
        lines.append(f"- **Scope filter:** `{meta['scope']}`")
    lines.append("")

    # Quick-reference findings table — things most likely to yield findings
    lines.append("## ⚡ Priority Findings")
    lines.append("")
    priority_rows = []

    secrets = summary.get("secrets", [])
    if secrets:
        priority_rows.append(("🔴 Secrets / credentials", str(len(secrets)), "See Secrets section"))

    cors = summary.get("cors_issues", [])
    if any("wildcard" in c or "withCredentials" in c or "reflect" in c for c in cors):
        priority_rows.append(("🔴 CORS misconfiguration", "", "; ".join(cors)))

    jwts = summary.get("jwts_found", [])
    for jwt in jwts:
        alg = jwt.get("alg", "")
        if alg.lower() == "none":
            priority_rows.append(("🔴 JWT alg:none", "", f"Unsigned token, claims: {jwt.get('claims', {})}"))
        elif alg.upper() in ("HS256", "HS384", "HS512"):
            priority_rows.append(("🟡 JWT HMAC alg", alg, f"Symmetric sig — check secret strength. Claims: {jwt.get('claims', {})}"))

    proto = summary.get("proto_pollution_sinks", [])
    if proto:
        priority_rows.append(("🟡 Prototype pollution sinks", str(len(proto)), proto[0]))

    gql = summary.get("graphql", {})
    if gql.get("introspection_queries_detected"):
        priority_rows.append(("🟡 GraphQL introspection", "", "App sends __schema queries — introspection may be enabled"))

    openapi = summary.get("openapi_refs", [])
    if openapi:
        priority_rows.append(("🟡 OpenAPI/Swagger exposed", str(len(openapi)), openapi[0]))

    debug_flags = [f for f in summary.get("feature_flags", []) if "debug" in f.lower() or "admin" in f.lower()]
    if debug_flags:
        priority_rows.append(("🟡 Debug/admin flags", str(len(debug_flags)), debug_flags[0]))

    xss_sinks = [i for i in summary.get("interesting", []) if "XSS" in i or "innerHTML" in i or "dangerously" in i]
    if xss_sinks:
        priority_rows.append(("🟡 DOM XSS sinks", str(len(xss_sinks)), xss_sinks[0]))

    redirect_sinks = [i for i in summary.get("interesting", []) if "redirect" in i.lower()]
    if redirect_sinks:
        priority_rows.append(("🟡 Open redirect sinks", str(len(redirect_sinks)), redirect_sinks[0]))

    src_maps = summary.get("source_maps", [])
    if src_maps:
        priority_rows.append(("🟢 Source maps present", str(len(src_maps)), src_maps[0]))

    nonces = summary.get("html_nonces", [])
    if nonces:
        priority_rows.append(("🟡 CSP nonces in HTML", str(len(nonces)), "Nonce reuse or static nonces defeat CSP"))

    hidden = summary.get("html_hidden_inputs", [])
    sensitive_hidden = [h for h in hidden if any(k in h.lower() for k in ("token", "csrf", "auth", "secret", "key", "password"))]
    if sensitive_hidden:
        priority_rows.append(("🟡 Sensitive hidden inputs", str(len(sensitive_hidden)), sensitive_hidden[0]))

    if priority_rows:
        lines.append("| Severity | Finding | Detail |")
        lines.append("|----------|---------|--------|")
        for sev, count, detail in priority_rows:
            count_str = f" ({count})" if count else ""
            lines.append(f"| {sev}{count_str} | | {str(detail)[:120]} |")
    else:
        lines.append("_No high-priority findings automatically detected — review sections below._")
    lines.append("")

    # Stack / frameworks
    lines.append("## Tech Stack")
    fw = summary.get("frameworks", [])
    deps = summary.get("dep_versions", {})
    if fw or deps:
        lines.append("**Detected frameworks/libraries:**")
        lines.append(_md_list(fw))
        if deps:
            lines.append("\n**Pinned versions:**")
            for pkg, ver in sorted(deps.items()):
                lines.append(f"- `{pkg}` → `{ver}`")
    else:
        lines.append("_None detected._")
    lines.append("")

    # GraphQL
    if gql:
        lines.append("## GraphQL")
        lines.append(f"**Endpoint(s):** {', '.join(f'`{e}`' for e in gql.get('endpoints', []))}")
        lines.append(f"**Introspection queries present:** {'⚠️ Yes' if gql.get('introspection_queries_detected') else 'No'}")
        lines.append(f"**Schema document detected:** {'Yes' if gql.get('schema_document_detected') else 'No'}")
        ops = gql.get("operations") or {}
        if ops:
            lines.append("\n**Operations:**")
            for op_type, names in sorted(ops.items()):
                lines.append(f"- _{op_type}_: {', '.join(f'`{n}`' for n in names)}")
        types = gql.get("types_referenced", [])
        if types:
            lines.append(f"\n**Types referenced:** {', '.join(f'`{t}`' for t in types[:30])}")
        frags = gql.get("fragments", [])
        if frags:
            lines.append(f"\n**Fragments:** {', '.join(f'`{f}`' for f in frags)}")
        lines.append("")

    # API endpoints
    eps = summary.get("api_endpoints", [])
    if eps:
        lines.append("## API Endpoints")
        # Group by prefix for readability
        groups = defaultdict(list)
        for ep in eps:
            parts = ep.strip("/").split("/")
            prefix = "/" + parts[0] if parts else "/"
            groups[prefix].append(ep)
        for prefix in sorted(groups):
            lines.append(f"\n**`{prefix}/`**")
            for ep in groups[prefix]:
                lines.append(f"- `{ep}`")
        lines.append("")

    # Client routes
    routes = summary.get("client_routes", [])
    if routes:
        lines.append("## Client-Side Routes")
        admin_routes = [r for r in routes if "admin" in r.lower() or "superuser" in r.lower() or "staff" in r.lower()]
        other_routes = [r for r in routes if r not in admin_routes]
        if admin_routes:
            lines.append("**⚠️ Admin/privileged routes:**")
            lines.append(_md_list(admin_routes))
            lines.append("")
        if other_routes:
            lines.append("**Application routes:**")
            lines.append(_md_list(other_routes))
        lines.append("")

    # HTML surface
    html_links = summary.get("html_links", [])
    html_forms = summary.get("html_forms", [])
    html_data = summary.get("html_data_attrs", [])
    html_hidden = summary.get("html_hidden_inputs", [])
    html_nonces = summary.get("html_nonces", [])
    html_base = summary.get("html_base_href", [])
    if any([html_links, html_forms, html_data, html_hidden, html_nonces, html_base]):
        lines.append("## HTML Surface")
        if html_base:
            lines.append(f"**⚠️ `<base href>` present:** {', '.join(f'`{b}`' for b in html_base)}  \n_May affect all relative URL resolution._")
        if html_forms:
            lines.append("\n**Forms (action + method):**")
            lines.append(_md_list(html_forms))
        if html_hidden:
            lines.append("\n**Hidden inputs:**")
            lines.append(_md_list(html_hidden))
        if html_nonces:
            lines.append(f"\n**CSP nonces found ({len(html_nonces)}):** _{('Static/reused nonces defeat CSP. Verify they rotate per request.')}_")
            lines.append(_md_list(list(html_nonces)[:5]))
        if html_data:
            lines.append("\n**`data-*` API attributes:**")
            lines.append(_md_list(html_data))
        if html_links:
            lines.append("\n**Internal `href` links:**")
            lines.append(_md_list(html_links[:40]))
        lines.append("")

    # Auth
    auth = summary.get("auth_patterns", [])
    if auth:
        lines.append("## Authentication Patterns")
        lines.append(_md_list(auth))
        lines.append("")

    # CORS
    if cors:
        lines.append("## CORS Configuration")
        lines.append(_md_list(cors))
        lines.append("")

    # JWTs
    if jwts:
        lines.append("## JWTs Found")
        for jwt in jwts:
            alg = jwt.get("alg", "unknown")
            flag = " ⚠️ UNSIGNED — EXPLOITABLE" if alg.lower() == "none" else ""
            lines.append(f"- **alg:** `{alg}`{flag}")
            lines.append(f"  - Token prefix: `{jwt.get('token_prefix', '')}`")
            claims = jwt.get("claims", {})
            if claims:
                for k, v in claims.items():
                    lines.append(f"  - `{k}`: `{v}`")
        lines.append("")

    # Secrets
    if secrets:
        lines.append("## Secrets & Credentials")
        lines.append("> ⚠️ Values are redacted. Verify in source before reporting.")
        lines.append("")
        lines.append(_md_list(secrets))
        lines.append("")

    # OpenAPI
    if openapi:
        lines.append("## OpenAPI / Swagger")
        lines.append(_md_list(openapi))
        lines.append("")

    # WebSockets / Workers
    ws = summary.get("websockets", [])
    workers = summary.get("workers", [])
    if ws or workers:
        lines.append("## WebSockets & Workers")
        if ws:
            lines.append("**WebSocket endpoints:**")
            lines.append(_md_list(ws))
        if workers:
            lines.append("\n**Web/Service Workers:**")
            lines.append(_md_list(workers))
        lines.append("")

    # File ops
    file_ops = summary.get("file_ops", [])
    if file_ops:
        lines.append("## File Upload / Download Surface")
        lines.append(_md_list(file_ops))
        lines.append("")

    # Prototype pollution
    if proto:
        lines.append("## Prototype Pollution Sinks")
        lines.append(_md_list(proto))
        lines.append("")

    # Feature flags
    flags = summary.get("feature_flags", [])
    if flags:
        lines.append("## Feature Flags & Debug")
        lines.append(_md_list(flags))
        lines.append("")

    # Third-party
    third = summary.get("third_party", [])
    telemetry = summary.get("telemetry", [])
    ext_scripts = summary.get("external_scripts", [])
    if third or telemetry or ext_scripts:
        lines.append("## Third-Party & Telemetry")
        if third:
            lines.append("**Integrations:**")
            lines.append(_md_list(third))
        if telemetry:
            lines.append("\n**Error / session telemetry:**")
            lines.append(_md_list(telemetry))
        if ext_scripts:
            lines.append(f"\n**External scripts/links ({len(ext_scripts)}):**")
            lines.append(_md_list(ext_scripts[:20]))
        lines.append("")

    # CSP
    csp = summary.get("csp_meta_tags", [])
    if csp:
        lines.append("## Content Security Policy (meta tags)")
        for policy in csp:
            lines.append(f"```\n{policy}\n```")
        lines.append("")

    # Source maps
    if src_maps:
        lines.append("## Source Maps")
        lines.append("> Source maps allow full decompilation of minified code.")
        lines.append(_md_list(src_maps))
        lines.append("")

    # Interesting
    interesting = summary.get("interesting", [])
    if interesting:
        lines.append("## Other Interesting Findings")
        lines.append(_md_list(interesting))
        lines.append("")

    lines.append("---")
    lines.append("_Report generated by js_recon.py — for authorized security testing only._")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract API/JS attack surface from Burp XML exports and/or raw JS/HTML files."
    )
    parser.add_argument("inputs", nargs="+", help="Burp XML file(s), .js/.html file(s), or directories")
    parser.add_argument("-o", "--output", help="Write output to this file (default: <stem>_recon.json or .md)")
    parser.add_argument("--stdout", action="store_true", help="Print output to stdout instead of a file")
    parser.add_argument(
        "--format", choices=["json", "md"], default="json",
        help="Output format: json (default, for LLM paste) or md (Markdown report)"
    )
    parser.add_argument("--target", default="", help="Target name/domain shown in the Markdown report header")
    parser.add_argument(
        "--scope", metavar="ENTRY", action="append", default=[],
        help=(
            "Scope filter — can be specified multiple times. Accepted formats: "
            "domain (target.com), wildcard (*.target.com), TLD wildcard (*.target.*), "
            "substring (~walkme — matches walkme.com, walkme.gov, walkmedev.com, etc.), "
            "CIDR (10.0.0.0/8), regex (/pattern/), URL prefix (https://app.target.com), "
            "or a file path containing one entry per line. "
            "Out-of-scope URLs are skipped at Burp XML read time; "
            "all output fields are also filtered post-extraction."
        ),
    )
    args = parser.parse_args()
    scope = _load_scope(args.scope) if args.scope else ScopeFilter([])
    if scope.active():
        print(f"[*] Scope filter active: {scope.summary_str()}", file=sys.stderr)

    result = {
        "js_files_analyzed": set(),
        "frameworks": set(),
        "dep_versions": {},
        "graphql": {
            "endpoints": set(),
            "operations": set(),
            "types": set(),
            "fragments": set(),
        },
        "api_endpoints": set(),
        "client_routes": set(),
        "websockets": set(),
        "workers": set(),
        "auth_patterns": set(),
        "cors_issues": set(),
        "jwts_found": [],
        "_jwt_seen": set(),
        "secrets": set(),
        "openapi_refs": set(),
        "third_party": set(),
        "telemetry": set(),
        "file_ops": set(),
        "proto_pollution": set(),
        "feature_flags": set(),
        "external_scripts": set(),
        "csp_meta_tags": set(),
        "html_links": set(),
        "html_forms": set(),
        "html_data_attrs": set(),
        "html_hidden_inputs": set(),
        "html_nonces": set(),
        "html_base_href": set(),
        "source_maps": set(),
        "interesting": set(),
    }

    for inp in args.inputs:
        process_path(inp, result, scope=scope)

    summary = build_summary(result, args.inputs, scope=scope)
    summary = _apply_scope_to_summary(summary, scope)

    if args.format == "md":
        output_text = render_markdown(summary, target=args.target)
        default_ext = ".md"
    else:
        output_text = json.dumps(summary, indent=2)
        default_ext = ".json"

    if args.stdout:
        print(output_text)
    else:
        if args.output:
            out_path = args.output
        else:
            base = Path(args.inputs[0]).stem if len(args.inputs) == 1 else "recon"
            out_path = f"{base}_recon{default_ext}"
        Path(out_path).write_text(output_text)
        print(f"[+] {'Report' if args.format == 'md' else 'Summary'} written to: {out_path}", file=sys.stderr)

    ep_count = len(summary.get("api_endpoints", []))
    fw_count = len(summary.get("frameworks", []))
    sec_count = len(summary.get("secrets", []))
    gql = summary.get("graphql")
    gql_ops = sum(len(v) for v in gql["operations"].values()) if gql and gql.get("operations") else 0
    routes = len(summary.get("client_routes", []))
    html_forms = len(summary.get("html_forms", []))
    print(
        f"[+] Endpoints: {ep_count} | Routes: {routes} | Forms: {html_forms} "
        f"| Frameworks: {fw_count} | GQL ops: {gql_ops} | Secrets: {sec_count}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
