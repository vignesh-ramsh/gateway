"""
gateway.middleware
-------------------
Standard ASGI middleware convention throughout: `middleware(app) -> app`,
where `app(scope, receive, send)` is awaitable. Composed in a fixed order
(see gateway/__init__.py): request_id -> security headers -> CORS -> CSRF ->
client_ip -> identity -> access_log.

request_id_middleware is OUTERMOST deliberately — every other middleware
(and the access log innermost of all) can then read
scope["state"]["arc_request_id"], and a request that is rejected early
(a CSRF failure, a 413 body-too-large) still carries the same correlation
id in its response as one that reached a handler.

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

from .request import cookies_from_scope, get_header, send_json

_logger = logging.getLogger("gateway")

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]
Middleware = Callable[[ASGIApp], ASGIApp]


class RequestMetrics:
    """Per-process, in-memory request counters — the same "this process's
    own self-report" posture as psqldb's pool_stats()/arc.events.stats():
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
        self._total_duration_ms = 0.0

    def record(self, status: int, duration_ms: float) -> None:
        self._total += 1
        bucket = f"{status // 100}xx" if status else "unknown"
        self._by_status_class[bucket] = self._by_status_class.get(bucket, 0) + 1
        self._total_duration_ms += duration_ms

    def snapshot(self) -> dict[str, Any]:
        avg = self._total_duration_ms / self._total if self._total else 0.0
        return {
            "total": self._total,
            "by_status_class": dict(self._by_status_class),
            "avg_duration_ms": round(avg, 1),
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


def security_headers_middleware(*, hsts: bool = False) -> Middleware:
    """Baseline headers on every response. HSTS only if the app is confident
    it's served over TLS (`gateway_force_https` setting) — sending it over
    plain HTTP is actively harmful (it forces HTTPS on future visits).

    `X-Frame-Options: DENY` is the default, but only ever ADDED — never
    appended on top of one the handler already set. Without that check, a
    handler returning its own `X-Frame-Options` (e.g. filer's serve_file,
    which sets SAMEORIGIN so a PDF can render in this app's own preview
    `<iframe>`) would end up with BOTH values on the wire; browsers treat
    duplicate X-Frame-Options headers as the most restrictive one wins,
    so the handler's own choice would be silently overridden by DENY no
    matter what it asked for — confirmed directly against a real PDF
    upload: the file served fine (200, correct bytes, correct
    content-type) but never rendered in the preview iframe, purely
    because of this unconditional append. Same reasoning would apply to
    x-content-type-options, but nosniff has no legitimate reason for any
    route to ever want it disabled, so that one stays unconditional."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((b"x-content-type-options", b"nosniff"))
                    if not any(k.lower() == b"x-frame-options" for k, _ in headers):
                        headers.append((b"x-frame-options", b"DENY"))
                    if hsts:
                        headers.append(
                            (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
                        )
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
                await send({"type": "http.response.start", "status": 204, "headers": headers})
                await send({"type": "http.response.body", "body": b""})
                return

            async def send_wrapper(message):
                if message["type"] == "http.response.start" and allow:
                    headers = list(message.get("headers", []))
                    headers.append((b"access-control-allow-origin", allow_origin_value))
                    message = {**message, "headers": headers}
                await send(message)

            await app(scope, receive, send_wrapper)

        return wrapped

    return middleware


def csrf_middleware(*, enabled: bool, header_name: bytes = b"x-csrf-token") -> Middleware:
    """Default on (see register()'s own comment for why) — matters for
    cookie-session auth, not bearer tokens, so most API-only deployments
    never notice it. When enabled,
    unsafe methods carrying an `arc_session` cookie must also carry a
    `X-CSRF-Token` header matching a `csrf_token` cookie (the standard
    double-submit-cookie pattern).

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
            if "arc_session" not in cookies:
                return await app(scope, receive, send)

            token_header = get_header(scope, header_name)
            token_cookie = cookies.get("csrf_token")

            if (
                not token_header
                or not token_cookie
                or not hmac.compare_digest(token_header.decode("latin-1"), token_cookie)
            ):
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
    leftmost entry directly — a client can put anything it wants there."""
    peer = scope.get("client")
    fallback_ip = peer[0] if peer else None
    ip = fallback_ip

    if trusted_proxies:
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
    relay, which hard-requires psqldb) and still boot fine, just in the
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


def access_log_middleware(metrics: RequestMetrics) -> Middleware:
    """One structured JSON line per request via `logging.getLogger
    ("gateway")` — arc.log already routes anything logged under that name
    into logs/gateway.jsonl as real JSON, with any `extra={...}` kwarg
    becoming real structured fields (see arc.log's own docstring); this
    just has to actually call it, the infrastructure already exists.
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
                _logger.info(
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
                metrics.record(status, duration_ms)

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
