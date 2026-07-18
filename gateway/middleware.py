"""
gateway.middleware
-------------------
Standard ASGI middleware convention throughout: `middleware(app) -> app`,
where `app(scope, receive, send)` is awaitable. Composed in a fixed order
(see gateway/__init__.py): security headers -> CORS -> CSRF -> client_ip -> identity.

The identity-resolution slot (§3.3/§3.13) is unconditional — composed into
the pipeline always, resolving `kernel.get("authn")` lazily PER REQUEST
(see identity_middleware's own docstring for the boot-order bug the old
"only wired if kernel.has('authn') at register() time" design turned out
to be). The slot's contract, implemented for real by the authn plugin: an
object exporting `async def resolve_identity(scope) -> Any | None` — no
authn installed, or no valid credentials, both resolve to None; no dummy
anonymous-user object anywhere.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any, Awaitable, Callable

from .request import get_header

_logger = logging.getLogger("gateway")

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]
Middleware = Callable[[ASGIApp], ASGIApp]


def security_headers_middleware(*, hsts: bool = False) -> Middleware:
    """Baseline headers on every response. HSTS only if the app is confident
    it's served over TLS (`gateway_force_https` setting) — sending it over
    plain HTTP is actively harmful (it forces HTTPS on future visits)."""

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((b"x-content-type-options", b"nosniff"))
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
                    headers.append((b"access-control-allow-methods", b"GET, POST, PUT, PATCH, DELETE, OPTIONS"))
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
    """Opt-in (default off) — matters for cookie-session auth, not bearer
    tokens, so most API-only deployments never need it on. When enabled,
    unsafe methods must carry a `X-CSRF-Token` header matching a
    `csrf_token` cookie (the standard double-submit-cookie pattern)."""
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if not enabled or scope["type"] != "http" or scope["method"] not in unsafe_methods:
                return await app(scope, receive, send)

            token_header = get_header(scope, header_name)
            cookie_header = get_header(scope, b"cookie") or b""
            cookies = dict(
                pair.split(b"=", 1) for pair in cookie_header.split(b"; ") if b"=" in pair
            )
            token_cookie = cookies.get(b"csrf_token")

            if not token_header or not token_cookie or not hmac.compare_digest(token_header, token_cookie):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {"type": "http.response.body", "body": b'{"error": "CSRF token missing or invalid"}'}
                )
                return

            await app(scope, receive, send)

        return wrapped

    return middleware


def client_ip_middleware(*, trusted_proxies: list[str] | None, forwarded_header: bytes) -> Middleware:
    """Always active, unlike CORS/CSRF/identity — there's no meaningful
    "off" state, only "no proxies configured" (the default), which just
    means trust nothing and use the raw ASGI peer address. Must run BEFORE
    identity_middleware in the chain: authn's resolve_identity(scope) reads
    scope["state"]["arc_client_ip"] to enforce a user's allowed_ips, so it
    has to already be populated by the time identity resolution runs.

    Anti-spoofing algorithm: walk the forwarded header from the RIGHTMOST
    entry (nearest hop) inward. Each hop must be in trusted_proxies to keep
    walking past it; the first untrusted hop found is the real client IP.
    Never trust the leftmost entry directly — a client can put anything it
    wants there."""
    proxies = set(trusted_proxies or [])

    def middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)

            peer = scope.get("client")
            fallback_ip = peer[0] if peer else None
            ip = fallback_ip

            if proxies:
                header = get_header(scope, forwarded_header)
                if header is not None:
                    hops = [h.strip() for h in header.decode("latin-1").split(",") if h.strip()]
                    ip = hops[0] if hops else fallback_ip  # all-trusted fallback: leftmost
                    for hop in reversed(hops):
                        if hop not in proxies:
                            ip = hop
                            break

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
                _logger.exception("identity resolution raised — treating request as unauthenticated")
                identity = None
            scope = {**scope, "state": {**scope.get("state", {}), "arc_identity": identity}}
            await app(scope, receive, send)

        return wrapped

    return middleware