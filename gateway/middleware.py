"""
gateway.middleware
-------------------
Standard ASGI middleware convention throughout: `middleware(app) -> app`,
where `app(scope, receive, send)` is awaitable. Composed in a fixed order
(see gateway/__init__.py): request_id -> tracing -> security headers -> CORS
-> CSRF -> client_ip -> identity -> access_log.

request_id_middleware is OUTERMOST deliberately — every other middleware
(and the access log innermost of all) can then read
scope["state"]["arc_request_id"], and a request that is rejected early
(a CSRF failure, a 413 body-too-large) still carries the same correlation
id in its response as one that reached a handler.

tracing_middleware is second-outermost, right after request_id, for the
identical reason: its root span needs to cover every OTHER middleware in
the chain, including one that rejects a request early.

The identity-resolution slot (§3.3/§3.13) is unconditional — composed into
the pipeline always, resolving `kernel.get("authn")` lazily PER REQUEST
(see identity_middleware's own docstring for the boot-order bug the old
"only wired if kernel.has('authn') at register() time" design turned out
to be). The slot's contract, implemented for real by the authn plugin: an
object exporting `async def resolve_identity(scope) -> Any | None` — no
authn installed, or no valid credentials, both resolve to None; no dummy
anonymous-user object anywhere.

access_log_middleware is innermost deliberately — it reads
scope["state"]["arc_client_ip"]/["arc_identity"], both only populated by
the two middlewares ahead of it in the chain.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
import time
import uuid
from typing import Any, Awaitable, Callable

from .request import cookies_from_scope, get_header, headers_from_scope, send_json

_logger = logging.getLogger("gateway")

#: Per-request access lines are logged under a child of "gateway" so they can be
#: routed on their own: arc.log's category prefixes still send them to
#: logs/gateway.jsonl, while arc.log.file_only() can keep them off the console.
ACCESS_LOGGER_NAME = "gateway.access"
_access_logger = logging.getLogger(ACCESS_LOGGER_NAME)

#: Where each request's access line goes: only to logs/gateway.jsonl ("file", the
#: default), additionally to the console that `arc run` relays ("console"), or nowhere
#: ("off"; request metrics are still counted).
ACCESS_LOG_MODES = ("file", "console", "off")
DEFAULT_ACCESS_LOG_MODE = "file"


def apply_access_log_mode(mode: str) -> None:
    """Route access lines for `mode` and reject an unknown value loudly.

    "file" keeps them off the console. The console relay is a single Python
    thread in `arc run` reading every worker's stdout through one pipe; at a few
    thousand requests per second it saturates a core, the pipe fills, and the
    workers block in write() with their event loops frozen, which showed up as a
    p99 of ~70 ms against a ~2 ms median and capped throughput. "console" restores
    the old behaviour for anyone who wants to watch requests scroll by."""
    if mode not in ACCESS_LOG_MODES:
        raise ValueError(
            f"gateway_access_log must be one of {', '.join(ACCESS_LOG_MODES)}, got {mode!r}"
        )
    from arc import log as arc_log

    if mode == "console":
        arc_log.console_too(ACCESS_LOGGER_NAME)
    else:
        arc_log.file_only(ACCESS_LOGGER_NAME)

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]
Middleware = Callable[[ASGIApp], ASGIApp]


#: HTTP methods that never mutate anything — the same "safe" set HTTP
#: itself defines (RFC 9110 §9.2.1: GET/HEAD/OPTIONS/TRACE), plus ARC's own
#: QUERY convention (relay/whitelisting.py's _ETAG_ELIGIBLE_METHODS uses the
#: identical GET+QUERY pairing, for the identical "safe" reasoning). Anything
#: NOT in this set — POST/PUT/PATCH/DELETE, or a method this set has never
#: heard of — counts as a write: mutating-by-default is the safer
#: classification for a method nobody's told this set about yet.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "QUERY", "TRACE"})


class RequestMetrics:
    """Per-process, in-memory request counters — the same "this process's
    own self-report" posture as pgdb's pool_stats()/arc.events.stats():
    no cross-process aggregation, resets on restart, read through
    GatewayProvider.health() (arc.health.check() picks it up from there
    for free). Gateway is the only thing that ever sees every request, so
    the counting has to happen here regardless of what, if anything, ever
    reads it downstream — a future telemetry/observability layer would be
    a CONSUMER of these numbers via health(), not a reason to move the
    counting itself somewhere else."""

    def __init__(self) -> None:
        self._total = 0
        self._by_status_class: dict[str, int] = {}
        self._by_operation: dict[str, int] = {"read": 0, "write": 0}
        self._total_duration_ms = 0.0

    def record(self, status: int, duration_ms: float, method: str = "") -> None:
        self._total += 1
        bucket = f"{status // 100}xx" if status else "unknown"
        self._by_status_class[bucket] = self._by_status_class.get(bucket, 0) + 1
        operation = "read" if method.upper() in _READ_METHODS else "write"
        self._by_operation[operation] += 1
        self._total_duration_ms += duration_ms

    def snapshot(self) -> dict[str, Any]:
        avg = self._total_duration_ms / self._total if self._total else 0.0
        return {
            "total": self._total,
            "by_status_class": dict(self._by_status_class),
            "by_operation": dict(self._by_operation),
            "avg_duration_ms": round(avg, 1),
        }

    def metrics(self) -> dict[str, Any]:
        """Same underlying counters as snapshot(), reshaped for
        arc.metrics.aggregate()/collect() — the duck-typed convention
        arc.health.check() already established for health(). Exposes the
        raw SUM of durations, not a pre-divided average: summing an
        average across N processes is meaningless, whereas summing the
        raw total (this field) and the raw count (requests_total) lets
        the average be computed correctly AFTER cross-process
        aggregation — the same _sum/_count convention Prometheus's own
        histogram/summary types use, for exactly this reason.

        `requests_by_operation` (read vs write, by HTTP method) is what
        answers "is this app read-heavy or write-heavy" straight from
        /metrics — arc_gateway_requests_by_operation{bucket="read"} vs
        {bucket="write"}, summed across every worker."""
        return {
            "requests_total": self._total,
            "requests_by_status_class": dict(self._by_status_class),
            "requests_by_operation": dict(self._by_operation),
            "request_duration_ms_sum": round(self._total_duration_ms, 1),
        }


REQUEST_ID_HEADER = b"x-request-id"

# What an inbound X-Request-ID must look like to be trusted and reused.
# Deliberately strict: this value ends up in structured log lines, in a
# response header, and (via relay's CallContext) in a `_job_log` row — all
# places where an attacker-chosen string containing newlines, quotes, or
# control characters is a log-forging/injection concern, not just noise.
# Anything that doesn't match is silently REPLACED with a fresh id rather
# than rejected: a correlation id is a debugging aid, never a reason to
# fail a request the caller otherwise got right.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def new_request_id() -> str:
    return uuid.uuid4().hex


def request_id_middleware() -> Middleware:
    """Assigns every request a correlation id, readable downstream as
    `scope["state"]["arc_request_id"]` (gateway's dispatcher puts it on
    `Request.request_id`; relay copies it into its own CallContext so a
    background job enqueued by this request can be traced back to it) and
    echoed to the caller as an `X-Request-ID` response header.

    An inbound `X-Request-ID` is honored when it passes _SAFE_REQUEST_ID
    above, so a request traced across several services keeps ONE id
    end-to-end; anything else gets a fresh one. Always active — there is
    no meaningful "off" state for this, same reasoning as
    client_ip_middleware."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            raw = get_header(scope, REQUEST_ID_HEADER)
            inbound = raw.decode("latin-1", errors="replace") if raw else ""
            request_id = inbound if _SAFE_REQUEST_ID.match(inbound) else new_request_id()

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    if not any(k.lower() == REQUEST_ID_HEADER for k, _ in headers):
                        headers.append((REQUEST_ID_HEADER, request_id.encode("latin-1")))
                    message = {**message, "headers": headers}
                await send(message)

            scope = {**scope, "state": {**scope.get("state", {}), "arc_request_id": request_id}}
            await app(scope, receive, send_wrapper)

        return wrapped

    return middleware


def tracing_middleware(*, router: Any = None) -> Middleware:
    """Root span for the whole request — second-outermost, right after
    request_id_middleware (so `scope["state"]["arc_request_id"]` is
    already set) and wrapping everything else: security headers, CORS,
    CSRF, client_ip, identity, access_log, rate_limit, and _dispatch
    itself.

    A single `arc.tracing.get_tracer() is None` check up front is the
    ENTIRE cost when tracing is off — no span, no context extraction, no
    per-request work of any kind, not even a no-op object; this is what
    makes "tracing off" actually free rather than merely cheap.

    Extracts a real W3C `traceparent` header via OTel's own propagator
    (`opentelemetry.propagate.extract`) rather than hand-parsing it —
    the whole reason this uses the real SDK instead of a hand-rolled
    format is to not get this subtly wrong. A request with no inbound
    traceparent (the common case — nothing upstream is instrumented, or
    this is the first ARC-owned hop) simply starts a new trace; extract()
    returns an empty context either way, so there's no separate branch
    for "have header" vs "don't".

    `router` (2026-09-01, per-route tracing opt-out): this middleware
    wraps _dispatch, so it runs BEFORE _dispatch's own routing — the only
    way to honor a matched route's RouteEntry.trace=False is a second,
    independent gateway.router.Router.match() done right here, before
    the span is started. A pure, cheap trie lookup (no state, no I/O);
    doing it twice per request (once here, once in _dispatch) is a small,
    bounded cost against starting and exporting a whole span. `router`
    is `Any`-typed and optional (never None in practice — GatewayProvider
    always passes its own) specifically so this module doesn't need a
    hard import of router.py, matching the rest of this file's lazy-
    import posture; None just means "can't check, so trace everything",
    the same behavior this middleware always had before this parameter
    existed. An UNMATCHED request (no route at all — a genuine 404) is
    unaffected either way and still gets a span, same as always: there's
    no RouteEntry to carry False for it."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            import arc  # gateway has no module-level arc import, same lazy-import posture as elsewhere here

            tracer = arc.tracing.get_tracer()
            if tracer is None:
                return await app(scope, receive, send)

            if router is not None:
                match = router.match(scope["method"], scope["path"])
                if match.route is not None and not match.route.trace:
                    return await app(scope, receive, send)

            from opentelemetry.propagate import extract

            parent_ctx = extract(headers_from_scope(scope))
            status_holder: dict[str, int] = {}

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    status_holder["status"] = message["status"]
                await send(message)

            state = scope.get("state", {})
            method = scope["method"]
            path = scope["path"]
            # "{METHOD} {path}" — standard OTel HTTP-server span-naming
            # convention (what every OTel-instrumented HTTP framework
            # names its root span), deliberately NOT "arc."-prefixed, same
            # exemption as the http.*/db.* ATTRIBUTES below: this follows
            # an existing semantic convention rather than inventing one.
            # A fixed generic name here (what this used to be) means every
            # request's trace looks identical in a trace list until you
            # open it — this is what makes "POST /login" vs "GET
            # /openapi.json" distinguishable at a glance.
            with tracer.start_as_current_span(
                f"{method} {path}",
                context=parent_ctx,
                attributes={
                    "http.method": method,
                    "http.target": path,
                    "arc.request_id": state.get("arc_request_id") or "",
                },
            ) as root_span:
                try:
                    await app(scope, receive, send_wrapper)
                finally:
                    root_span.set_attribute("http.status_code", status_holder.get("status", 0))

        return wrapped

    return middleware


def security_headers_middleware(
    *, hsts: bool = False, csp: str | None = None, csp_report_only: bool = True
) -> Middleware:
    """Baseline headers on every response. HSTS only if the app is confident
    it's served over TLS (`gateway_force_https` setting) — sending it over
    plain HTTP is actively harmful (it forces HTTPS on future visits).

    Every header here is only ever ADDED — never appended on top of one the
    handler already set. Without that check, a handler returning its own
    `X-Frame-Options` (e.g. filer's serve_file, which sets SAMEORIGIN so a
    PDF can render in this app's own preview `<iframe>`) would end up with
    BOTH values on the wire; browsers treat duplicate X-Frame-Options
    headers as the most restrictive one wins, so the handler's own choice
    would be silently overridden by DENY no matter what it asked for —
    confirmed directly against a real PDF upload: the file served fine
    (200, correct bytes, correct content-type) but never rendered in the
    preview iframe, purely because of this unconditional append.
    x-content-type-options has no real handler-side counterpart today (no
    route sets its own), but it's guarded the same way on the same
    principle: a baseline middleware should never assume it's the only
    thing with an opinion on a given header.

    `csp` (`gateway_csp` setting) is sent Report-Only by default
    (`csp_report_only`, `gateway_csp_report_only`, defaults True) — a real
    policy strict enough to matter (no blanket 'unsafe-inline') would
    currently break wschat's own demo chat page, which still embeds an
    inline `<script>` (see api/chat.py's `_CHAT_HTML`; already documented
    as demo-only/not-production-safe, but still a real page that would
    stop working). authn's own `/impersonate` page used to be the same
    story — fixed by moving its script to a static, same-origin
    impersonate.js (auth_api.py) instead of embedding one inline, which is
    the template to follow for wschat's page too, if it's ever meant to
    survive an enforcing CSP. Report-Only observes real violations in
    production without breaking what's left, and gives an operator that's
    confirmed a policy is safe (or fixed the remaining inline-script case)
    a single setting to flip to enforcing."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    existing = {k.lower() for k, _ in headers}
                    if b"x-content-type-options" not in existing:
                        headers.append((b"x-content-type-options", b"nosniff"))
                    if b"x-frame-options" not in existing:
                        headers.append((b"x-frame-options", b"DENY"))
                    if hsts and b"strict-transport-security" not in existing:
                        headers.append(
                            (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
                        )
                    if csp:
                        csp_header = (
                            b"content-security-policy-report-only"
                            if csp_report_only
                            else b"content-security-policy"
                        )
                        if csp_header not in existing:
                            headers.append((csp_header, csp.encode("latin-1")))
                    message = {**message, "headers": headers}
                await send(message)

            await app(scope, receive, send_wrapper)

        return wrapped

    return middleware


def cors_middleware(allowed_origins: list[str] | None) -> Middleware:
    """No-op if allowed_origins is empty/None — apps opt in explicitly.
    Handles real preflight (OPTIONS + Access-Control-Request-Method) by
    short-circuiting before the request ever reaches routing."""
    origins = allowed_origins or []

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http" or not origins:
                return await app(scope, receive, send)

            origin = get_header(scope, b"origin")
            if origin is None:
                return await app(scope, receive, send)

            origin_str = origin.decode("latin-1")
            allow = "*" in origins or origin_str in origins
            allow_origin_value = b"*" if "*" in origins else origin

            is_preflight = (
                scope["method"] == "OPTIONS"
                and get_header(scope, b"access-control-request-method") is not None
            )

            # The Access-Control-Allow-Origin value below VARIES by request
            # (it echoes the caller's own Origin) whenever the allowlist
            # isn't the literal wildcard — without Vary: Origin, a shared
            # cache in front of this app (a CDN, a corporate proxy) is free
            # to store one origin's response, ACAO header included, and
            # replay it to a DIFFERENT origin's request. "*" needs no such
            # header: that response is identical for every origin already.
            vary_by_origin = allow and "*" not in origins

            if is_preflight:
                headers = []
                if allow:
                    headers.append((b"access-control-allow-origin", allow_origin_value))
                    headers.append(
                        (b"access-control-allow-methods", b"GET, POST, PUT, PATCH, DELETE, OPTIONS")
                    )
                    req_headers = get_header(scope, b"access-control-request-headers")
                    if req_headers:
                        headers.append((b"access-control-allow-headers", req_headers))
                    headers.append((b"access-control-max-age", b"600"))
                if vary_by_origin:
                    headers.append((b"vary", b"Origin"))
                await send({"type": "http.response.start", "status": 204, "headers": headers})
                await send({"type": "http.response.body", "body": b""})
                return

            async def send_wrapper(message):
                if message["type"] == "http.response.start" and allow:
                    headers = list(message.get("headers", []))
                    headers.append((b"access-control-allow-origin", allow_origin_value))
                    if vary_by_origin:
                        headers.append((b"vary", b"Origin"))
                    message = {**message, "headers": headers}
                await send(message)

            await app(scope, receive, send_wrapper)

        return wrapped

    return middleware


def csrf_middleware(kernel: Any, *, enabled: bool, header_name: bytes = b"x-csrf-token") -> Middleware:
    """Default on (see register()'s own comment for why) — matters for
    cookie-session auth, not bearer tokens, so most API-only deployments
    never notice it. When enabled,
    unsafe methods carrying an `arc_session` cookie must also carry a
    `X-CSRF-Token` header matching a `csrf_token` cookie (the standard
    double-submit-cookie pattern) — STRENGTHENED to a signed double-
    submit when authn is installed: the expected header value is
    recomputed server-side from the session cookie itself
    (kernel.get("authn").verify_csrf_token, the same lazy, duck-typed,
    per-request lookup identity_middleware already uses — gateway never
    imports authn's own module), not read back off the csrf_token
    cookie's own content. A PLAIN double-submit is only as strong as
    "attacker can't READ a cookie for this origin" — but forging one
    never required reading the real value in the first place, only
    WRITING a chosen value as both cookie and header (a sibling-
    subdomain XSS, or a cookie-injection bug elsewhere, can often write
    a cookie for a shared scope without being able to read this
    origin's own). Recomputing the expected value from a secret the
    attacker never has closes that; see authn's own sign_csrf_token/
    verify_csrf_token docstrings for the full reasoning. Falls back to
    the old plain compare only when authn isn't installed at all — CSRF
    only ever matters for a session cookie, which nothing but authn
    mints, so this fallback is defensive, not a real gap in practice.

    Deliberately scoped to requests that already carry a session cookie —
    NOT every unsafe method. /login has no session cookie yet (that's the
    whole point of it), so gating on "unsafe method" alone made login
    itself permanently unreachable: a cookie that can only be minted by a
    successful login can't also be a prerequisite for calling it. A
    request with no arc_session cookie is either a pre-session endpoint
    (login/forgot-password/reset-password) or authenticated via
    X-API-Key, and CSRF (a forged *browser* request riding an existing
    session cookie) isn't a meaningful threat against either."""
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if not enabled or scope["type"] != "http" or scope["method"] not in unsafe_methods:
                return await app(scope, receive, send)

            cookies = cookies_from_scope(scope)
            session_token = cookies.get("arc_session")
            if session_token is None:
                return await app(scope, receive, send)

            token_header = get_header(scope, header_name)
            token_cookie = cookies.get("csrf_token")
            header_str = token_header.decode("latin-1") if token_header else None

            authn_provider = kernel.get("authn") if kernel.has("authn") else None
            verify_fn = getattr(authn_provider, "verify_csrf_token", None)
            if callable(verify_fn):
                valid = bool(token_cookie) and bool(header_str) and verify_fn(session_token, header_str)
            else:
                valid = bool(token_cookie) and bool(header_str) and hmac.compare_digest(
                    header_str, token_cookie
                )

            if not valid:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"error": "CSRF token missing or invalid"}',
                    }
                )
                return

            await app(scope, receive, send)

        return wrapped

    return middleware


def resolve_client_ip(
    scope: dict, *, trusted_proxies: set[str], forwarded_header: bytes
) -> str | None:
    """The anti-spoofing algorithm itself, factored out of
    client_ip_middleware below so gateway's WS handshake path
    (gateway/__init__.py's _dispatch_websocket) can resolve the same
    client_ip the SAME way, without either duplicating this logic or
    forcing a websocket scope through an HTTP-only middleware chain that
    every other middleware in this file no-ops on anyway.

    Walks the forwarded header from the RIGHTMOST entry (nearest hop)
    inward. Each hop must be in trusted_proxies to keep walking past it;
    the first untrusted hop found is the real client IP. Never trusts the
    leftmost entry directly — a client can put anything it wants there.

    The header is only ever consulted when the RAW, DIRECTLY-connected
    peer is itself a trusted proxy. A reverse proxy configured with
    $proxy_add_x_forwarded_for (arc deploy prod's own nginx template)
    APPENDS its own truthful observation to whatever X-Forwarded-For it
    received — it never discards a client-supplied one — so the header
    only carries any honest information at all once a trusted hop has
    actually touched it. A caller connecting straight to gateway,
    bypassing the proxy entirely, can hand it any X-Forwarded-For chain
    it likes; trusting that would let a direct connection spoof its way
    past allowed_ips, rate limiting, and every audit log built on
    client_ip — trusted_proxies naming the PROXY is meaningless if
    gateway never checks that the proxy is who's actually talking to it."""
    peer = scope.get("client")
    fallback_ip = peer[0] if peer else None
    ip = fallback_ip

    if trusted_proxies and fallback_ip in trusted_proxies:
        header = get_header(scope, forwarded_header)
        if header is not None:
            hops = [h.strip() for h in header.decode("latin-1").split(",") if h.strip()]
            ip = hops[0] if hops else fallback_ip  # all-trusted fallback: leftmost
            for hop in reversed(hops):
                if hop not in trusted_proxies:
                    ip = hop
                    break

    return ip


def client_ip_middleware(
    *, trusted_proxies: list[str] | None, forwarded_header: bytes
) -> Middleware:
    """Always active, unlike CORS/CSRF/identity — there's no meaningful
    "off" state, only "no proxies configured" (the default), which just
    means trust nothing and use the raw ASGI peer address. Must run BEFORE
    identity_middleware in the chain: authn's resolve_identity(scope) reads
    scope["state"]["arc_client_ip"] to enforce a user's allowed_ips, so it
    has to already be populated by the time identity resolution runs."""
    proxies = set(trusted_proxies or [])

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            ip = resolve_client_ip(scope, trusted_proxies=proxies, forwarded_header=forwarded_header)
            scope = {**scope, "state": {**scope.get("state", {}), "arc_client_ip": ip}}
            await app(scope, receive, send)

        return wrapped

    return middleware


def identity_middleware(kernel: Any) -> Middleware:
    """Always composed into the pipeline, unconditionally — looks up
    kernel.has("authn")/kernel.get("authn") lazily, per request, rather
    than once at GatewayProvider.__init__ time. This used to be gated on
    kernel.has("authn") at construction time, but that's actually unsound:
    arc's topological resolver only guarantees HARD requires load before a
    dependent (§3.1) — an optional_requires edge (gateway optionally wants
    authn) can lose to a hard-requires chain elsewhere (authn hard-requires
    relay, which hard-requires pgdb) and still boot fine, just in the
    "wrong" relative order for this specific optional preference (`arc
    doctor` prints an explicit warning when this happens). Concretely:
    gateway has zero hard requires, so the resolver is free to boot it
    first — and does — even when authn is installed, which meant
    kernel.has("authn") was always False by the time __init__ ran,
    silently disabling identity resolution on every request despite authn
    being fully present. A per-request kernel.get() lookup is the same
    small, real cost §3.2 already documents for every arc.<capability>
    access — cheap enough to just always pay here, and it's what actually
    stays correct regardless of boot order.

    Resolves identity once per request and attaches it to
    scope["state"]["arc_identity"], which gateway's dispatcher reads onto
    Request.identity. No authn installed (or none resolved this request)
    -> identity stays None — no dummy anonymous-identity object, per §3.3."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)
            authn_provider = kernel.get("authn") if kernel.has("authn") else None
            resolve = getattr(authn_provider, "resolve_identity", None)
            try:
                identity = await resolve(scope) if callable(resolve) else None
            except Exception:
                # resolve_identity's contract is "None, never raise" for
                # AUTH failures — but an infrastructure failure inside it
                # (Redis down, DB pool exhausted) used to escape here, past
                # gateway's dispatcher catch-all (middleware runs outside
                # it), straight to Granian as an unstructured 500 on every
                # credentialed request. Failing closed to None (401/403
                # downstream) with a server-side traceback is the correct
                # degradation; authn's own cache layer additionally degrades
                # cache errors to DB reads so this branch is a last resort.
                _logger.exception(
                    "identity resolution raised — treating request as unauthenticated"
                )
                identity = None
            scope = {**scope, "state": {**scope.get("state", {}), "arc_identity": identity}}
            await app(scope, receive, send)

        return wrapped

    return middleware


def access_log_middleware(metrics: RequestMetrics, *, mode: str = DEFAULT_ACCESS_LOG_MODE) -> Middleware:
    """One structured JSON line per request via `logging.getLogger
    ("gateway.access")` — arc.log routes anything logged under "gateway" or a
    child of it into logs/gateway.jsonl as real JSON, with any `extra={...}`
    kwarg becoming real structured fields (see arc.log's own docstring).
    `mode` ("off" skips the line entirely) is where the line goes beyond that;
    see apply_access_log_mode().
    Updates `metrics` at the same interception point — one wrapper serves
    both jobs, no second pass over every request.

    Innermost builtin middleware (see module docstring): reads
    scope["state"]["arc_client_ip"]/["arc_identity"]/["arc_request_id"],
    all only populated by client_ip/identity/request_id middleware ahead
    of it in the chain.

    Wrapped in try/finally, not a bare call — a request that raises all
    the way through (a bug even gateway's own dispatcher catch-all didn't
    catch) still gets logged and counted before the exception continues
    propagating, rather than silently vanishing from both."""
    log_requests = mode != "off"

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            status_holder: dict[str, int] = {}

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    status_holder["status"] = message["status"]
                await send(message)

            start = time.monotonic()
            try:
                await app(scope, receive, send_wrapper)
            finally:
                duration_ms = (time.monotonic() - start) * 1000
                status = status_holder.get("status", 0)
                state = scope.get("state", {})
                identity = state.get("arc_identity")
                method = scope["method"]
                path = scope["path"]
                # isEnabledFor() first: skip building the message and the extra={}
                # dict when the line would be dropped by log_level anyway.
                if log_requests and _access_logger.isEnabledFor(logging.INFO):
                    _access_logger.info(
                        f"{method} {path} -> {status} ({duration_ms:.0f}ms)",
                        extra={
                            "request_id": state.get("arc_request_id"),
                            "method": method,
                            "path": path,
                            "status": status,
                            "duration_ms": round(duration_ms, 1),
                            "client_ip": state.get("arc_client_ip"),
                            "identity": getattr(identity, "email", None),
                        },
                    )
                metrics.record(status, duration_ms, method)

        return wrapped

    return middleware


# In-process counters, attacker-growable (one entry per distinct key seen) —
# same prune-past-threshold posture as authn's own _rate_local (plugins/
# authn/authn/__init__.py), and the same number, not a coincidence: both
# are "how many distinct (ip/user) keys before we bother evicting stale
# ones", not a tuned-per-feature value.
_FALLBACK_PRUNE_THRESHOLD = 4096


class LocalRateLimiter:
    """In-process fixed-window counter — what rate_limit_middleware falls
    back to when redix isn't installed, or a redix call itself fails.
    Same shape as authn's own rate_limit() fallback, and for the identical
    reason (see that function's docstring): per-process, not distributed
    (a multi-worker deployment gets one independent counter PER WORKER, so
    the effective limit across the whole process group is `limit *
    worker_count`, not `limit`), and reset on restart. Weaker than redix's
    shared counter, but "some protection, degrading gracefully" beats
    either forcing Redis as a hard dependency or having no protection at
    all when it's absent — same posture as every redix-optional feature
    elsewhere in this codebase."""

    def __init__(self) -> None:
        self._counts: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            if len(self._counts) > _FALLBACK_PRUNE_THRESHOLD:
                self._counts = {
                    k: (c, start)
                    for k, (c, start) in self._counts.items()
                    if now - start < window_seconds
                }
            count, window_start = self._counts.get(key, (0, now))
            if now - window_start >= window_seconds:
                count, window_start = 0, now
            count += 1
            self._counts[key] = (count, window_start)
            return count <= limit


def rate_limit_key(identity: Any, client_ip: str | None) -> str:
    """Per-authenticated-identity when one resolved (user_id specifically,
    the same identifier relay's own CallContext uses elsewhere), falling
    back to client IP for anonymous traffic. Shared by every transport
    that rate-limits — HTTP requests (rate_limit_middleware below) and
    WebSocket connections/messages (gateway/__init__.py's
    _dispatch_websocket, gateway/websocket.py's WebSocketConnection) — so
    the SAME caller gets the SAME identity under any of them, not three
    independently-invented key formats."""
    user_id = getattr(identity, "user_id", None)
    return f"user:{user_id}" if user_id else f"ip:{client_ip or 'unknown'}"


async def check_rate_limit(
    kernel: Any, fallback: LocalRateLimiter, key: str, limit: int, window_seconds: int
) -> bool:
    """The one place "is this key still within budget" gets decided —
    redix when installed (looked up lazily, per call — see
    rate_limit_middleware's own docstring for why never once at
    construction time), degrading to the in-process fallback on any
    redix failure. Used by rate_limit_middleware (HTTP) and directly by
    gateway's WebSocket handshake/per-message checks, so all three share
    one decision instead of three copies of the same try/except."""
    redix = kernel.get("redix") if kernel.has("redix") else None
    if redix is not None:
        try:
            return await redix.rate_limit(key, limit, window_seconds)
        except Exception as exc:
            _logger.warning("redix rate_limit failed (%s) — using in-process fallback", exc)
    return await fallback.allow(key, limit, window_seconds)


def rate_limit_middleware(
    kernel: Any,
    *,
    enabled: bool,
    limit: int,
    window_seconds: int,
    fallback: LocalRateLimiter,
) -> Middleware:
    """Innermost of every builtin middleware (see gateway/__init__.py's own
    composition comment) — deliberately positioned so access_log_middleware
    wraps THIS, not the other way around: a 429 rejection here must still
    produce a real access-log line and update RequestMetrics like any other
    response, not vanish before ever reaching access_log because this
    short-circuited ahead of it.

    Keyed per authenticated identity when one resolved
    (scope["state"]["arc_identity"], set by identity_middleware ahead of
    this in the chain — user_id specifically, the same identifier relay's
    own CallContext uses elsewhere), falling back to client IP
    (scope["state"]["arc_client_ip"], set by client_ip_middleware) for
    anonymous traffic. Per-user beats per-IP whenever it's available — one
    NAT'd office or corporate VPN egress otherwise shares a single budget
    across everyone behind it.

    redix is looked up lazily, per request — never once when this closure
    is built. Same boot-order reasoning identity_middleware's own
    docstring documents at length: gateway optionally-requiring redix
    doesn't guarantee redix has already registered by the time this
    function runs, only that it's registered by the time a REQUEST is
    served. A redix call that raises (Redis down) degrades to the
    in-process fallback rather than failing every request — rate limiting
    is a protective layer, not something allowed to take the app down
    if Redis has a bad moment (same "cache/lock errors degrade, they
    never propagate" posture authn's own session cache already uses)."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if not enabled or scope["type"] != "http":
                return await app(scope, receive, send)

            state = scope.get("state", {})
            key = rate_limit_key(state.get("arc_identity"), state.get("arc_client_ip"))
            allowed = await check_rate_limit(kernel, fallback, key, limit, window_seconds)

            if not allowed:
                await send_json(
                    send,
                    429,
                    {"error": "rate limit exceeded", "code": "rate_limited"},
                    extra_headers={"Retry-After": str(window_seconds)},
                )
                return

            await app(scope, receive, send)

        return wrapped

    return middleware
