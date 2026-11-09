"""
gateway — ARC provider plugin: HTTP/WS transport (Architecture §2).

TODO(WS): "WS" above is aspirational — there is no WebSocket routing
surface yet (no `add_ws_route`, no ASGI websocket-scope handling).
Streaming today goes through `relay.stream()` / `StreamResponse` instead.
Either build real WS routing or drop "WS" from this docstring — see
Improvement Doc §4 issue 4 / §4 P2.

Exports `arc.gateway`: routing (add_route), middleware (add_middleware),
OpenAPI generation, and the ASGI 3.0 entrypoint an ASGI server (Granian)
actually serves. Deliberately transport-only — no authorization, no
business validation (§2: that needs the object model, which is Relay's
job). Boots and runs standalone with zero other plugins installed
(requires=[], optional_requires=["authn"]).

Lifecycle note: unlike pgdb/redix, Gateway's own ASGI "lifespan" protocol
is the natural home for the open()/close() calls those plugins otherwise
need called manually — see _open_all_capabilities/_close_all_capabilities
below. Any capability with an open()/close() method (duck-typed, same
pattern as health()) gets started/stopped automatically once Gateway is
actually served — closing the "manual lifecycle" gap flagged when
pgdb/redix were built. Gateway never knows these are "pgdb"/"redix".
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import mimetypes
import traceback
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import arc
from arc.settings import SettingsError

from . import bodies as _bodies
from . import middleware as _middleware
from .bodies import EARLY_AUTH_BODY_BYTES, BodyBudget, BodyBudgetBusy, body_size_hint, serve_and_drain
from .middleware import (
    DEFAULT_ACCESS_LOG_MODE,
    LocalRateLimiter,
    RequestMetrics,
    access_log_middleware,
    apply_access_log_mode,
    check_rate_limit,
    in_networks,
    parse_networks,
    rate_limit_exempt,
    client_ip_middleware,
    cors_middleware,
    csrf_middleware,
    identity_middleware,
    new_request_id,
    rate_limit_key,
    rate_limit_middleware,
    request_id_middleware,
    resolve_client_ip,
    security_headers_middleware,
    tracing_middleware,
)
from .error_pages import send_error
from .health import HEALTH_PATHS, ReadinessProbe
from .health import serve as serve_health
from .openapi import build_openapi_spec, render_openapi_css, render_openapi_html
from .request import (
    EncodedJSON,
    HTTPError,
    Request,
    Response,
    StreamResponse,
    cookies_from_scope,
    encode_json,
    get_header,
    headers_from_scope,
    query_params_from_scope,
    read_body,
    send_bytes,
    send_json,
    send_json_with_etag,
    send_stream,
)
from .router import WEBSOCKET_METHOD, Router, RouterError
from .websocket import MAINTENANCE, POLICY_VIOLATION, RATE_LIMITED, WebSocketConnection

CAPABILITY = "gateway"

CORS_ORIGINS_KEY = "gateway_cors_origins"
CSRF_ENABLED_KEY = "gateway_csrf_enabled"
FORCE_HTTPS_KEY = "gateway_force_https"
CSP_KEY = "gateway_csp"
CSP_REPORT_ONLY_KEY = "gateway_csp_report_only"
# No 'unsafe-inline' — deliberately real enough to matter against a stored/
# reflected XSS via filer-served, user-uploaded bytes on the same origin as
# the admin SPA (the audit finding this closes). frame-ancestors 'self'
# matches x-frame-options' own SAMEORIGIN default rather than tightening
# past it. Sent Report-Only by default (CSP_REPORT_ONLY_KEY) since a script-src
# this strict would currently block wschat's demo chat page, which
# still embeds an inline <script> — see security_headers_middleware's
# own docstring for the full reasoning, and why authn's /impersonate
# page no longer needs this exception.
DEFAULT_CSP = (
    "default-src 'self'; object-src 'none'; base-uri 'self'; "
    "frame-ancestors 'self'; form-action 'self'"
)
TRUSTED_PROXIES_KEY = "gateway_trusted_proxies"
FORWARDED_HEADER_KEY = "gateway_forwarded_header"
MAX_BODY_BYTES_KEY = "gateway_max_body_bytes"
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB — generous for a JSON API body,
# nowhere near "unbounded" (the bug this fixes)
#: The largest JSON body that is DECODED, on any route. Decoding
#: runs on the event loop and holds the GIL, so it stalls every other request on that worker for as
#: long as it takes: measured at about 7 ms per MB of ordinary object-heavy JSON (10 MB: 71 ms to
#: decode, an 80 ms pause). Moving it to a thread or another process does not help (the thread still
#: holds the GIL: a 60 ms pause; a process pool: 66 ms and slower overall), so the work is bounded
#: instead. 0 turns this ceiling off, leaving only `gateway_max_body_bytes`.
MAX_JSON_BODY_BYTES_KEY = "gateway_max_json_body_bytes"
DEFAULT_MAX_JSON_BODY_BYTES = 2 * 1024 * 1024

#: The most bytes of request bodies one web worker holds in memory at once (those over 64 KB; smaller
#: ones are not counted). A body is read whole before its handler runs, so without a bound a crowd of big
#: uploads is a crowd of big allocations: four anonymous 59 MB uploads took a worker from 425 to 594 MB
#: (about 0.7 MB of memory per MB of body). Requests beyond it wait briefly, then get 503 + Retry-After.
#: 0 = no bound.
MAX_INFLIGHT_BODY_BYTES_KEY = "gateway_max_inflight_body_bytes"
DEFAULT_MAX_INFLIGHT_BODY_BYTES = 256 * 1024 * 1024

ACCESS_LOG_KEY = "gateway_access_log"

RATE_LIMIT_ENABLED_KEY = "gateway_rate_limit_enabled"
RATE_LIMIT_REQUESTS_KEY = "gateway_rate_limit_requests"
RATE_LIMIT_WINDOW_SECONDS_KEY = "gateway_rate_limit_window_seconds"
RATE_LIMIT_EXEMPT_KEY = "gateway_rate_limit_exempt"

METRICS_TOKEN_KEY = "gateway_metrics_token"
# Deliberately a PLAIN setting, not secret=True: a scrape credential read
# on every single Prometheus scrape (every few seconds) would spam
# arc.store's reveal-only secret_access_log with pure noise if declared
# secret — that log exists for meaningful superuser reveals, not routine
# machine-to-machine polling. Empty/unset (the default) means /metrics is
# open, same posture as /openapi.json — protect it via network boundary/
# reverse proxy, or set this for an Authorization: Bearer <token> gate.

DEBUG_KEY = "gateway_debug"
DEBUG_ROLES_KEY = "gateway_debug_roles"
# "*" reuses the SAME sentinel relay's own RBAC check already gives this
# exact meaning to (WhitelistedFunction roles=["*"] -> "any authenticated
# identity", _wire_gateway_route's own `if "*" in wf.roles`) — every
# authenticated caller (not the ambient, always-available "Guest" — see
# that same check's own `caller_roles | {"Guest"}`) gets full exception
# detail on an unhandled 500 by default; an anonymous/no-identity caller
# never does, in any configuration. Narrow it to specific role names
# (comma-separated, e.g. "Superuser,Support") to restrict further — a
# caller whose own roles already include "*" (authn's Superuser
# convention) always qualifies regardless, same as it would for any
# other role-gated route.
DEFAULT_DEBUG_ROLES = "*"

MAINTENANCE_MODE_KEY = "gateway_maintenance_mode"
# 300 req/60s (5/sec sustained) — generous enough that normal admin-console
# usage (a page load firing several requests near-simultaneously, infinite
# scroll, debounced search/sort) never approaches it; only sustained
# scripted/abusive traffic does. Same "no ordinary request shape newly
# rejected" bar CSRF's own default-on comment sets, applied to volume
# instead of shape.
DEFAULT_RATE_LIMIT_REQUESTS = 300
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]

_logger = logging.getLogger("gateway")

#: Below this length a "secret" is almost certainly a placeholder/empty
#: value, not a real one — redacting it would risk blind-replacing short,
#: unrelated substrings (a stray "1", an empty string matching everywhere)
#: throughout the exception text instead of an actual leaked secret.
_MIN_REDACTABLE_SECRET_LENGTH = 8


def _shorten_project_paths(text: str, kernel: Any) -> str:
    """Strips the project root off every absolute path in `text` — a
    traceback frame reads `File "/home/user/.../plugins/gateway/gateway/
    __init__.py", line N` otherwise, which is both noisy and leaks the
    local machine's own username/directory layout for no benefit (the
    caller who's even allowed to see this detail already knows which
    project they're running). `kernel.project_root` is set at `arc.boot()`
    time to wherever THIS deployment actually lives, so this has no
    hardcoded path of its own — "plugins/gateway/gateway/__init__.py" is
    just whatever falls out of stripping that prefix, same for every
    deployment regardless of where it's checked out."""
    root = getattr(kernel, "project_root", None)
    if root is None:
        return text
    root_str = str(root)
    if not root_str.endswith("/"):
        root_str += "/"
    return text.replace(root_str, "")


def _redact_known_secrets(text: str, kernel: Any) -> str:
    """Replaces any exact occurrence of a currently-declared secret
    SETTING's real value (signing keys, DSNs, API tokens — anything this
    app itself manages via kernel.settings.declare(..., secret=True))
    with a placeholder, before exception detail ever reaches a response.
    Deliberately narrow: this can't catch a secret that was never a
    tracked setting in the first place (e.g. a user's own password typed
    into some ad-hoc string) — it closes the worst, most mechanical class
    of leak using infrastructure that already exists, not a general PII
    scanner.

    Reads through settings.secret_values_for_redaction() — one query, no
    audit-log write — rather than get(key, reveal=True) once per declared
    secret, which is what this used to do. That reveal path is the ONLY
    one that writes a secret_access_log row, so every redacted 500 was
    appending one unattributed row per declared secret (plus a master-key
    disk read, a Fernet construction, and a synchronous SQLite commit
    each). That let anyone able to trigger an error flood the reveal-only
    audit log and bury real superuser reveals underneath it — the exact
    thing METRICS_TOKEN_KEY's own comment above already refuses to do for
    routine machine reads; it just hadn't been applied here."""
    try:
        values = kernel.settings.secret_values_for_redaction()
    except Exception:
        return text
    for value in values:
        if isinstance(value, str) and len(value) >= _MIN_REDACTABLE_SECRET_LENGTH:
            text = text.replace(value, "***REDACTED***")
    return text


def _caller_gets_debug_detail(kernel: Any, identity: Any) -> bool:
    """Whether THIS caller should see real exception detail on an
    unhandled 500 — see DEBUG_ROLES_KEY's own comment for the "*" sentinel
    and the Guest/authenticated distinction. `gateway_debug` (unconditional,
    every caller) is a separate, OFF-by-default escape hatch for an
    authn-less deployment, where no identity/roles exist to gate on at
    all."""
    if kernel.settings.get(DEBUG_KEY):
        return True
    raw = (kernel.settings.get(DEBUG_ROLES_KEY) or "").strip()
    if not raw:
        return False
    if raw == "*":
        return identity is not None
    caller_roles = set(getattr(identity, "roles", None) or [])
    if "*" in caller_roles:
        return True
    configured = {r.strip() for r in raw.split(",") if r.strip()}
    return bool(caller_roles & configured)


class GatewayProvider:
    def __init__(
        self,
        kernel: Any,
        *,
        cors_origins: list[str] | None = None,
        csrf_enabled: bool = False,
        hsts: bool = False,
        csp: str | None = None,
        csp_report_only: bool = True,
        trusted_proxies: list[str] | None = None,
        forwarded_header: str = "X-Forwarded-For",
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_json_body_bytes: int | None = DEFAULT_MAX_JSON_BODY_BYTES,
        max_inflight_body_bytes: int = DEFAULT_MAX_INFLIGHT_BODY_BYTES,
        rate_limit_enabled: bool = True,
        rate_limit_requests: int = DEFAULT_RATE_LIMIT_REQUESTS,
        rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        rate_limit_exempt: list | None = None,
        access_log: str = DEFAULT_ACCESS_LOG_MODE,
    ) -> None:
        self._kernel = kernel
        #: Networks whose anonymous traffic is not counted by the per-IP request limit (and which
        #: authn does not hold to its failed-login budget): see rate_limit_exempt() in middleware.py.
        self._rate_limit_exempt = tuple(rate_limit_exempt or ())
        # Validates `access_log` (raises on an unknown value) and routes the
        # access lines: off the console unless access_log == "console".
        apply_access_log_mode(access_log)
        self._router = Router()
        self._spa_mounts: dict[str, Path] = {}
        # path -> (mtime_ns, bytes, content_type); see _try_serve_spa.
        self._spa_file_cache: dict[str, tuple[int, bytes, str]] = {}
        self._extra_middlewares: list[Callable[[ASGIApp], ASGIApp]] = []
        self._built_app: ASGIApp | None = None
        self._cors_origins = cors_origins or []
        self._trusted_proxies = trusted_proxies or []
        self._forwarded_header = forwarded_header
        self._max_body_bytes = max_body_bytes
        self._max_json_body_bytes = max_json_body_bytes or None
        self._body_budget = BodyBudget(max_inflight_body_bytes, wait_seconds=_bodies.BUDGET_WAIT_SECONDS)
        # OpenAPI documents built from the route table, kept until a route is added: name -> (generation, document)
        self._documents: dict[str, tuple[int, Any]] = {}
        self._metrics = RequestMetrics()
        self._readiness = ReadinessProbe(kernel)
        self._rate_limit_fallback = LocalRateLimiter()
        # Stored (not just handed to rate_limit_middleware's own closure
        # below) because _dispatch_websocket needs these too — a
        # WebSocket connection is routed around the HTTP middleware chain
        # entirely (see __call__), so it can't reach them through the
        # middleware the way an ordinary request does; it reads them
        # directly off self instead.
        self._rate_limit_enabled = rate_limit_enabled
        self._rate_limit_requests = rate_limit_requests
        self._rate_limit_window_seconds = rate_limit_window_seconds
        # channel -> every locally-held WebSocketConnection subscribed to
        # it (GatewayProvider.broadcast()/subscribe()'s own docstrings have
        # the full design). One redix pub/sub listener task per channel
        # that has at least one local subscriber, started lazily on the
        # first subscribe() and cancelled once the last one leaves.
        self._ws_channels: dict[str, set[WebSocketConnection]] = {}
        self._ws_redix_tasks: dict[str, asyncio.Task] = {}

        # Fixed order: request_id -> security headers -> CORS -> CSRF ->
        # client_ip -> identity -> access_log -> rate_limit. request_id is
        # OUTERMOST so every other middleware — and any early rejection
        # that never reaches a handler at all (a CSRF 403, a 413, a 429) —
        # still carries the same correlation id. Both client_ip and
        # identity are unconditional now — identity_middleware looks up
        # kernel.has("authn")/kernel.get("authn") lazily per request rather
        # than once here at construction time (see its own docstring): authn
        # optionally-requiring gateway doesn't guarantee gateway registers
        # AFTER authn (arc's resolver only orders HARD requires strictly,
        # §3.1) — `arc doctor` warns exactly this ordering can happen — so a
        # boot-time kernel.has("authn") check here could easily see False
        # even with authn fully installed, silently disabling identity
        # resolution. rate_limit_middleware follows the same lazy-lookup
        # reasoning for redix. access_log sits BETWEEN identity and
        # rate_limit, not after both — it reads scope["state"] fields only
        # request_id/client_ip/identity have populated by then, and it must
        # WRAP rate_limit (not the other way around) so a 429 rejection
        # still produces a real access-log line instead of short-circuiting
        # before ever reaching it.
        self._builtin_middlewares: list[Callable[[ASGIApp], ASGIApp]] = [
            request_id_middleware(),
            tracing_middleware(router=self._router),
            security_headers_middleware(hsts=hsts, csp=csp, csp_report_only=csp_report_only),
            cors_middleware(cors_origins),
            csrf_middleware(kernel, enabled=csrf_enabled),
            self._build_client_ip_middleware(),
        ]
        # Captured right where client_ip is appended, not derived from the
        # final list length — a "len(...) - N" offset (the previous
        # approach) silently breaks the moment anything is ever added
        # after it, exactly what rate_limit_middleware below now does.
        self._client_ip_mw_index = len(self._builtin_middlewares) - 1
        self._builtin_middlewares += [
            identity_middleware(kernel),
            access_log_middleware(self._metrics, mode=access_log),
            rate_limit_middleware(
                kernel,
                enabled=rate_limit_enabled,
                limit=rate_limit_requests,
                window_seconds=rate_limit_window_seconds,
                fallback=self._rate_limit_fallback,
                exempt_networks=self._rate_limit_exempt,
            ),
        ]

        self._register_builtin_routes()

    def _build_client_ip_middleware(self) -> Callable[[ASGIApp], ASGIApp]:
        return client_ip_middleware(
            trusted_proxies=self._trusted_proxies,
            forwarded_header=self._forwarded_header.encode("latin-1").lower(),
        )

    def configure(
        self, *, trusted_proxies: list[str] | None = None, forwarded_header: str | None = None
    ) -> None:
        """Set once during boot (another plugin's own register(), or before
        the app is ever served) — not intended for hot runtime
        reconfiguration mid-traffic."""
        if trusted_proxies is not None:
            self._trusted_proxies = trusted_proxies
        if forwarded_header is not None:
            self._forwarded_header = forwarded_header
        self._builtin_middlewares[self._client_ip_mw_index] = self._build_client_ip_middleware()
        self._built_app = None

    # ------------------------------------------------------------------ #
    # Public surface — what register(kernel) exports as arc.gateway
    # ------------------------------------------------------------------ #
    def add_route(
        self,
        method: str,
        path: str,
        handler: Callable[[Request], Any],
        *,
        request_schema: Any | None = None,
        validate_body: bool = True,
        trace: bool = True,
        response_schema: Any | None = None,
        summary: str | None = None,
        max_body_bytes: int | None = None,
        etag: bool = False,
        plugin: str | None = None,
        roles: frozenset[str] | None = None,
        authorize: Callable[[Any], None] | None = None,
    ) -> None:
        """Register a route. Relay (Phase 3) will call this the same way any
        other caller does — Gateway never hardcodes knowledge of Resources.

        `trace`: whether `tracing_middleware` should start a root span for
        a request that matches this route. True (the default) traces
        everything, same as before this flag existed. Pass False for an
        endpoint whose traces are pure noise in a real backend — a health
        check, a metrics scrape — without touching the global
        `tracing_otlp_endpoint`/`tracing_sample_rate_percent` settings,
        which still govern whether tracing happens at all/at what rate for
        every OTHER route. Independent of `validate_body` below despite
        the similar shape: this gates a middleware that runs BEFORE
        routing (so tracing_middleware does a second, cheap route lookup
        of its own to know this — see RouteEntry.trace's own docstring),
        that one gates a check `_dispatch` makes AFTER routing.

        `validate_body`: whether `_dispatch` should itself decode the raw
        body against `request_schema` before `handler` ever runs, populating
        `request.validated` (request.py's own docstring). True (the
        default) is right for a caller with no validation of its own.
        Relay's whitelisting layer passes False: it does its own, more
        complete validation (query string + body + path params merged,
        correct 400 on a bad value, works for a bodyless GET) before ever
        calling the whitelisted function, so a second, independent decode
        of just the raw body here was redundant at best — and, for a
        plain-kwargs function's hand-built /openapi docs schema (never a
        real msgspec-decodable type) or a GET carrying no body at all,
        outright broken: every such request 422'd regardless of what the
        caller sent. `request_schema` still gets used for the /openapi
        docs page either way — this only gates the live decode.

        `max_body_bytes`: None (default) means this route is bounded by the
        gateway-wide `gateway_max_body_bytes` ceiling like everything else;
        pass a value to give ONE route its own larger (or smaller) outer
        ASGI-level body limit — e.g. a file-upload endpoint that needs to
        accept much bigger requests than an ordinary JSON API call, without
        raising the shared ceiling every other endpoint is also bounded by.

        `etag`: conditional-GET support for this route's 200 JSON responses
        (see `_maybe_send_json_with_etag` in `_dispatch`) — a strong ETag
        (`arc.hash()` of the exact response body) is set on every 200, and a
        request whose `If-None-Match` matches gets a bodyless 304 instead.
        Purely a bandwidth optimization: the handler still runs in full on
        every request (there's no way to know the CURRENT body matches
        without producing it first) — this never skips computation, and it
        carries no caching policy of its own (every response still gets
        this class's own `Cache-Control: no-store` unless a handler sets its
        own). False for anything gateway itself registers; relay's
        whitelisting layer is the only caller that ever passes True, and
        only for a GET/QUERY route.

        `plugin`: which plugin owns this route, for the /openapi UI page to
        group by. None for anything gateway registers on its own behalf;
        relay's whitelisting layer passes its own WhitelistedFunction.plugin
        here, the only caller with a real plugin name to give.

        `roles`: documentation-only for an ordinary HTTP route — real
        enforcement already happens inside `handler` itself (relay's own
        RBAC check, before this method is ever reached); nothing in HTTP
        dispatch reads this field. Only a WebSocket route (add_ws_route)
        actually enforces it, at handshake time. Populated here so the
        /openapi UI can show "allowed roles" per route without a second,
        parallel channel for the same information.

        `authorize`: the route's own check of who may call it, called with a Request whose body is still
        empty and raising HTTPError to refuse. The gateway runs it before it reads a large request body
        (a declared 64 KB or more, or no declared length), so a caller who would be refused anyway does
        not get a worker to hold their upload in memory first. The route's handler must still do its
        own check: this one is early, not instead."""
        first_segment = next((s for s in path.strip("/").split("/") if s), None)
        if first_segment is not None and first_segment in self._spa_mounts:
            raise RouterError(
                f"cannot register route '{path}': '{first_segment}' is already "
                f"mounted as an SPA prefix"
            )
        self._router.add_route(
            method,
            path,
            handler,
            request_schema=request_schema,
            validate_body=validate_body,
            trace=trace,
            response_schema=response_schema,
            summary=summary,
            max_body_bytes=max_body_bytes,
            etag=etag,
            plugin=plugin,
            roles=roles,
            authorize=authorize,
        )
        self._built_app = None

    def add_ws_route(
        self,
        path: str,
        handler: Callable[[WebSocketConnection], Awaitable[None]],
        *,
        roles: list[str] | None = None,
        summary: str | None = None,
    ) -> None:
        """Register a WebSocket endpoint — the WS counterpart to add_route,
        but not routed through relay's whitelist() (see websocket.py's own
        module docstring for why: whitelist()'s body/response plumbing is
        single-request/response shaped and doesn't generalize to a
        connection that exchanges many messages over its lifetime).

        `handler(ws: WebSocketConnection)` is called once the connection
        has ALREADY passed its roles check below and is ready for the
        handler to `await ws.accept()` — never for a caller the roles
        check would have rejected.

        `roles`: the exact same sentinel convention relay.whitelist()
        already uses, deliberately not a new one — `roles=None` (the
        default) resolves to `{"*"}`, meaning any AUTHENTICATED identity
        may connect, any role — NOT anonymous/public, despite the
        wildcard name. An endpoint that should also accept anonymous
        connections must say so explicitly with `roles=["Guest"]`, same
        as an HTTP endpoint would. A caller whose own resolved roles
        include "*" (authn's convention for Superuser) always connects
        regardless of what this endpoint requires, symmetric with
        whitelist()'s own caller-side bypass."""
        first_segment = next((s for s in path.strip("/").split("/") if s), None)
        if first_segment is not None and first_segment in self._spa_mounts:
            raise RouterError(
                f"cannot register WS route '{path}': '{first_segment}' is already "
                f"mounted as an SPA prefix"
            )
        self._router.add_ws_route(
            path,
            handler,
            roles=frozenset(roles) if roles is not None else frozenset({"*"}),
            summary=summary,
        )
        self._built_app = None

    # ------------------------------------------------------------------ #
    # WebSocket broadcast — a channel is nothing but a string every
    # WebSocketConnection.subscribe()'d to it agrees on; gateway itself
    # never interprets one (a plugin might use "table:employee",
    # "user:{id}", anything). See websocket.py's own module docstring for
    # why this exists (relay.stream() only ever reaches the ONE connection
    # that made the request; this reaches every OTHER connection watching
    # too).
    # ------------------------------------------------------------------ #
    async def broadcast(self, channel: str, message: Any) -> None:
        """Push `message` (any arc.codec-encodable value) to every
        WebSocket connection currently subscribed to `channel` — across
        every worker process when redix is installed, a plain in-process
        call otherwise (reaching only THIS worker's own local subscribers
        — a WS connection is pinned to whichever worker accepted it, same
        per-process reality RequestMetrics/rate-limiting's fallback
        already document elsewhere in this codebase).

        Always round-trips through redix even for this worker's OWN local
        subscribers, rather than delivering locally AND publishing — one
        path, not two that could double-deliver or drift apart. This
        worker's own _pump_redix_channel task (started the moment it has
        its own first local subscriber) receives the just-published
        message back from redix exactly like every other worker would,
        Redis pub/sub not distinguishing "self" from any other subscriber."""
        encoded = arc.codec.encode(message).decode("utf-8")
        redix = self._kernel.get("redix") if self._kernel.has("redix") else None
        if redix is not None:
            try:
                await redix.publish(channel, encoded)
                return
            except Exception as exc:
                _logger.warning(
                    "redix publish to channel %r failed (%s) — broadcasting locally only",
                    channel,
                    exc,
                )
        await self._deliver_local(channel, encoded)

    async def _deliver_local(self, channel: str, encoded_text: str) -> None:
        for connection in list(self._ws_channels.get(channel, ())):
            try:
                await connection.send_text(encoded_text)
            except Exception:
                # A dead/dropped connection shouldn't stop delivery to
                # every OTHER subscriber on this channel — its own
                # disconnect handling (_dispatch_websocket's finally
                # block) is what actually removes it from this set; this
                # is just one failed send along the way, not fatal to the
                # broadcast as a whole.
                _logger.debug(
                    "failed to deliver a WS broadcast on channel %r", channel, exc_info=True
                )

    async def _pump_redix_channel(self, channel: str, redix: Any) -> None:
        """Runs for as long as `channel` has at least one local subscriber
        — one such task per channel, started by _ws_subscribe below on the
        first subscribe() and cancelled by _ws_unsubscribe once the last
        local subscriber leaves. Every message this worker's own
        broadcast() publishes to `channel` comes back through here too
        (see broadcast()'s own docstring), so _deliver_local is the ONE
        place a message actually reaches a connection's send_text."""
        try:
            pubsub = await redix.subscribe(channel)
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                data = msg["data"]
                text = data.decode("utf-8") if isinstance(data, bytes) else data
                await self._deliver_local(channel, text)
        except asyncio.CancelledError:
            raise
        except Exception:
            _logger.exception("redix pub/sub listener for WS channel %r died", channel)

    async def _ws_subscribe(self, connection: WebSocketConnection, channel: str) -> None:
        connections = self._ws_channels.setdefault(channel, set())
        is_first_local_subscriber = len(connections) == 0
        connections.add(connection)
        if is_first_local_subscriber:
            redix = self._kernel.get("redix") if self._kernel.has("redix") else None
            if redix is not None:
                self._ws_redix_tasks[channel] = asyncio.create_task(
                    self._pump_redix_channel(channel, redix)
                )

    async def _ws_unsubscribe(self, connection: WebSocketConnection, channel: str) -> None:
        connections = self._ws_channels.get(channel)
        if connections is None:
            return
        connections.discard(connection)
        if not connections:
            del self._ws_channels[channel]
            task = self._ws_redix_tasks.pop(channel, None)
            if task is not None:
                task.cancel()

    def mount_spa(self, dist_dir: str | Path, prefix: str) -> None:
        """Serve a pre-built SPA (e.g. a plugin's own `ui/dist/`) under
        `/<prefix>/*`, falling back to `<dist_dir>/index.html` for any
        sub-path that doesn't match a real file — standard SPA-hosting
        behavior, so client-side routes survive a page refresh.

        `prefix` is a single path segment, entirely the caller's choice —
        deliberately NOT derived from the calling plugin's own name (a
        plugin's package name and its desired UI route are different
        things; `payroll` the plugin might want `payroll_desk` the route).

        Fails at call time (registration), not at first request, matching
        this project's "boot-time, not request-time" error posture (§3.3):
        a duplicate prefix, a prefix colliding with an existing JSON route,
        or a dist_dir that doesn't exist are all rejected immediately."""
        prefix = prefix.strip("/")
        if not prefix or "/" in prefix:
            raise RouterError(
                f"invalid SPA mount prefix: {prefix!r} — must be a single, non-empty path segment"
            )
        if prefix in self._spa_mounts:
            raise RouterError(f"SPA prefix already mounted: '{prefix}'")
        if self._router.first_segment_registered(prefix):
            raise RouterError(
                f"cannot mount SPA prefix '{prefix}': a route already exists under it"
            )
        resolved_dir = Path(dist_dir).resolve()
        if not resolved_dir.is_dir():
            raise RouterError(f"SPA dist_dir does not exist or is not a directory: {resolved_dir}")
        self._spa_mounts[prefix] = resolved_dir

    def spa_mounts(self) -> dict[str, Path]:
        return dict(self._spa_mounts)

    def add_middleware(self, middleware: Callable[[ASGIApp], ASGIApp]) -> None:
        """Append a middleware, innermost of any added so far (closest to routing)."""
        self._extra_middlewares.append(middleware)
        self._built_app = None

    def routes(self) -> list:
        return self._router.all_routes()

    def proxy_facts(self) -> dict:
        """What a reverse proxy in front of this gateway needs to know, as plain data: the body
        ceiling that applies to every route without its own, and per route its method, path, own
        body ceiling (None = the shared one) and whether it is a WebSocket. `arc deploy prod` reads
        this (through `arc gateway routes --json`) to write nginx limits and timeouts per route,
        so the proxy cannot drift from what the routes actually declare."""
        return {
            "max_body_bytes": self._max_body_bytes,
            "routes": [
                {
                    "method": route.method,
                    "path": route.path,
                    "max_body_bytes": route.max_body_bytes,
                    "websocket": route.method == WEBSOCKET_METHOD,
                }
                for route in self._router.all_routes()
            ],
        }

    def openapi_spec(self) -> dict:
        return build_openapi_spec(self._router.all_routes())

    def _document(self, name: str, build: Callable[[], Any]) -> Any:
        """A document made from the route table (the OpenAPI JSON and page): built the first time it is
        asked for after a route was added, and kept until the next one. They are open to anyone, and
        rebuilding one for every request cost about 4.6 ms of CPU on a site with 205 routes - 450 requests
        a second used up both web workers."""
        generation = self._router.generation
        cached = self._documents.get(name)
        if cached is None or cached[0] != generation:
            cached = (generation, build())
            self._documents[name] = cached
        return cached[1]

    async def health(self) -> dict:
        """Reports on gateway itself ONLY — same as every other capability's
        health(). This used to walk and re-aggregate every OTHER capability
        too (it was arc.health's stand-in before arc.health existed); now
        that arc.health.check() is the one real aggregator, doing that here
        as well would nest a full copy of the whole system's health inside
        gateway's own entry every time something calls arc.health.check().

        `requests` is this PROCESS's own counters since it started (see
        RequestMetrics) — a multi-worker deployment has one independent
        set per worker, same posture as pgdb's pool_stats() and
        arc.events.stats(); no cross-process aggregation happens here."""
        return {
            "ok": True,
            "routes": len(self._router.all_routes()),
            "requests": self._metrics.snapshot(),
        }

    def metrics(self) -> dict:
        """arc.metrics.collect()'s duck-typed hook — same convention as
        health() above, sync rather than async since RequestMetrics.
        metrics() is a cheap in-memory read, no I/O. This PROCESS's own
        counters since it started; arc.metrics' own exporter/aggregate()
        machinery is what turns every worker's own call to this into one
        cross-process picture at /metrics, not this method itself."""
        return {
            **self._metrics.metrics(),
            # rate-limit checks redix could not answer, decided from this process's own counter instead
            # (redix down, or its connection pool full) - looked up on the module so it is always the live one
            "rate_limit_fallbacks_total": _middleware.RATE_LIMIT_FALLBACKS.total,
            # request bodies (over 64 KB) in memory now, waiting for room, and refused for lack of it
            "inflight_body_bytes": self._body_budget.in_flight,
            "inflight_body_waiting": self._body_budget.waiting,
            "inflight_body_rejected_total": self._body_budget.rejected_total,
        }

    # ------------------------------------------------------------------ #
    # ASGI 3.0 entrypoint
    # ------------------------------------------------------------------ #
    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            return await self._handle_lifespan(receive, send)
        if scope["type"] == "websocket":
            # Bypassed entirely around the HTTP middleware chain, not
            # threaded through it — every middleware in middleware.py
            # already no-ops on a non-"http" scope, so routing a websocket
            # scope through all seven of them first would just be seven
            # wasted no-op calls. _dispatch_websocket resolves request_id/
            # client_ip/identity itself, the same way each middleware
            # does, at the one point that actually needs them.
            return await self._dispatch_websocket(scope, receive, send)
        if scope["type"] == "http" and scope["path"] in HEALTH_PATHS:
            # /healthz and /readyz (gateway/health.py): answered here, ahead of the middleware
            # chain, so a load balancer polling them leaves no access-log line and no request
            # metrics, takes no rate-limit slot, and gets its answer under maintenance mode too.
            return await serve_health(scope, send, self._readiness)
        app = self._compiled_app()
        # Whatever the app leaves of a request body (it replied early: 429, 403, 404) is read and discarded
        # once the reply is out, or nginx, still sending it, fails with EPIPE and answers 502 instead.
        await serve_and_drain(app, scope, receive, send)

    def _compiled_app(self) -> ASGIApp:
        if self._built_app is not None:
            return self._built_app
        app: ASGIApp = self._dispatch
        for mw in reversed(self._extra_middlewares):
            app = mw(app)
        for mw in reversed(self._builtin_middlewares):
            app = mw(app)
        self._built_app = app
        return app

    async def _send_unhandled_exception(
        self, send: Callable, scope: dict, exc: Exception, method: str, path: str, route: str | None = None
    ) -> None:
        """The single place _dispatch sends a 500 for a genuine bug rather
        than a client mistake — always logged server-side, in full,
        regardless of what (if anything) also goes back in the response.
        Whether the RESPONSE itself carries real detail depends on the
        caller: see _caller_gets_debug_detail's own docstring — an
        anonymous or ordinary-role caller gets the same generic message
        this always returned; an authenticated caller matching
        gateway_debug_roles (any real identity, by default) gets the
        exception type/message/traceback instead, with known secrets
        redacted and file paths shortened to the project root first."""
        _logger.exception("unhandled exception in %s %s", method, path)
        # Counted, fingerprinted and (when configured) sent to the error tracker. The route TEMPLATE
        # (`/employee/{id}/documents`), never the raw path: ids in a path are data, and grouping needs
        # one value per route.
        arc.errors.capture(
            exc,
            source="gateway",
            method=method,
            route=route or "-",
            status=500,
            request_id=scope.get("state", {}).get("arc_request_id"),
        )
        identity = scope.get("state", {}).get("arc_identity")
        if _caller_gets_debug_detail(self._kernel, identity):
            raw = f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
            detail = _redact_known_secrets(_shorten_project_paths(raw, self._kernel), self._kernel)
            await send_json(send, 500, {"error": "internal server error", "detail": detail})
        else:
            await send_json(send, 500, {"error": "internal server error"})

    def is_rate_limit_exempt(self, client_ip: str | None) -> bool:
        """Is `client_ip` in a network listed in `gateway_rate_limit_exempt`? The list of networks an
        operator trusts not to be throttled per address; authn asks this too, so that one office
        listed once is exempt from both the request limit and the failed-login budget."""
        return in_networks(client_ip, self._rate_limit_exempt)

    async def _send_unavailable(self, send: Callable, exc: Exception, method: str, path: str) -> None:
        """An exception that says of itself `http_status = 503` (pgdb's PoolExhausted: no database
        connection was available) is capacity, not a bug: tell the caller to come back, with
        Retry-After, instead of a 500 that looks like a defect. Logged as one warning line — a
        traceback per rejected request would bury the log exactly when the server is busiest. The
        gateway does not know what raised it; the exception carries `http_status` and, optionally,
        `retry_after` (seconds)."""
        _logger.warning("503 for %s %s: %s", method, path, exc)
        retry_after = getattr(exc, "retry_after", None)
        await send_json(
            send,
            503,
            {"error": "service temporarily unavailable", "detail": "the server is busy — retry shortly"},
            extra_headers={"Retry-After": str(int(retry_after))} if retry_after else None,
        )

    async def _dispatch(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Route the request, then give back whatever it reserved of the request-body budget, however it
        ended (an answer, an error, the client going away)."""
        reservation = [0]
        try:
            await self._dispatch_routed(scope, receive, send, reservation)
        finally:
            self._body_budget.release(reservation[0])

    async def _dispatch_routed(self, scope: dict, receive: Callable, send: Callable, reservation: list[int]) -> None:
        method = scope["method"]
        path = scope["path"]

        # Read fresh every request, deliberately NOT baked into __init__
        # like every other setting on this class — a toggle only a
        # restarted process would ever see defeats the point of an
        # operational on/off switch a human flips during a live incident
        # or deploy. Cheap: SettingsManager.get() caches plain settings in
        # process and revalidates with `PRAGMA data_version` — a header
        # read that only changes once ANOTHER process (e.g. `arc
        # set-maintenance`) has actually committed — so this costs no real
        # query on the overwhelming majority of requests. (It genuinely
        # WAS a full SQLite SELECT per request for a while: this comment
        # used to describe the pre-SQLite arc.toml store's stat()-keyed
        # TOML cache and was left behind when settings moved into
        # arc.store.db, which is exactly what kept the cost invisible.)
        # Checked before routing,
        # SPA serving, or auth — a site under maintenance shows the same
        # page for every path and every caller, not just the ones that
        # would otherwise have resolved to a real route.
        if self._kernel.settings.get(MAINTENANCE_MODE_KEY):
            await send_error(
                send,
                scope,
                503,
                {"error": "service unavailable", "reason": "maintenance"},
                extra_headers={"Retry-After": "120"},
            )
            return

        if method == "GET" and self._spa_mounts:
            spa_hit = await self._try_serve_spa(path)
            if spa_hit is not None:
                body, content_type, cache_control = spa_hit
                await send_bytes(
                    send,
                    200,
                    body,
                    content_type=content_type,
                    extra_headers={"Cache-Control": cache_control},
                )
                return

        match = self._router.match(method, path)

        if match.route is None and not match.allowed_methods:
            await send_error(send, scope, 404, {"error": "not found", "path": path})
            return
        if match.route is None:
            await send_json(
                send,
                405,
                {"error": "method not allowed", "allowed": sorted(match.allowed_methods)},
                extra_headers={"Allow": ", ".join(sorted(match.allowed_methods))},
            )
            return

        route = match.route
        ceiling = route.max_body_bytes or self._max_body_bytes

        def build_request(body: bytes) -> Request:
            return Request(
                method=method,
                path=path,
                path_params=match.params,
                query_params=query_params_from_scope(scope),
                headers=headers_from_scope(scope),
                body=body,
                scope=scope,
                identity=scope.get("state", {}).get("arc_identity"),
                client_ip=scope.get("state", {}).get("arc_client_ip"),
                cookies=cookies_from_scope(scope),
                request_id=scope.get("state", {}).get("arc_request_id"),
                # What may be DECODED as JSON is bounded on every route, including one whose own ceiling
                # lets big uploads through: a large attachment never meant a large JSON payload.
                json_limit=self._max_json_body_bytes,
            )

        try:
            hint = body_size_hint(scope, ceiling=ceiling)
            if route.authorize is not None and hint >= EARLY_AUTH_BODY_BYTES:
                # A caller who would be refused anyway is refused before a worker holds their upload in memory.
                route.authorize(build_request(b""))
            # Counted against what this worker may hold at once; waits briefly for room, then 503.
            reservation[0] = await self._body_budget.reserve(hint)
            body = await read_body(receive, max_bytes=ceiling)
        except HTTPError as exc:
            await send_error(send, scope, exc.status_code, exc.detail)
            return
        except BodyBudgetBusy as exc:
            await self._send_unavailable(send, exc, method, path)
            return
        except Exception as exc:
            await self._send_unhandled_exception(send, scope, exc, method, path, route.path)
            return

        request = build_request(body)

        if route.request_schema is not None and route.validate_body:
            try:
                request.validated = request.json(route.request_schema)
            except HTTPError as exc:
                await send_error(send, scope, exc.status_code, exc.detail)
                return
            except Exception as exc:
                await send_json(send, 422, {"error": "validation failed", "detail": str(exc)})
                return

        try:
            result = await route.handler(request)
        except HTTPError as exc:
            await send_error(send, scope, exc.status_code, exc.detail)
            return
        except Exception as exc:
            if getattr(exc, "http_status", None) == 503:
                await self._send_unavailable(send, exc, method, path)
            else:
                await self._send_unhandled_exception(send, scope, exc, method, path, route.path)
            return

        if isinstance(result, StreamResponse):
            try:
                await send_stream(send, result)
            except Exception as stream_exc:
                # http.response.start (status 200) is already sent by this
                # point — there is no way to change status code mid-stream,
                # so the best this can do is log server-side (same as the
                # catch-all below) and try to end the body with one visible
                # error chunk rather than just going silent; a client
                # reading the stream sees a truncated/errored feed either
                # way, which is itself the signal something went wrong.
                _logger.exception("unhandled exception while streaming %s %s", method, path)
                arc.errors.capture(
                    stream_exc,
                    source="gateway",
                    method=method,
                    route=route.path,
                    stage="stream",
                    request_id=scope.get("state", {}).get("arc_request_id"),
                )
                try:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": encode_json({"error": "internal server error"}) + b"\n",
                            "more_body": False,
                        }
                    )
                except Exception:
                    pass
            return

        try:
            if isinstance(result, Response):
                # Cache-Control: no-store by default on every route-handler
                # response (never on the SPA-serving branch above, which
                # returns before reaching here, and deliberately sets its own
                # real Cache-Control) — a route that genuinely wants caching
                # can still set its own Cache-Control in result.headers, which
                # wins here since it's applied AFTER this default. Without
                # this, a browser's default fetch() cache mode can silently
                # serve a stale GET response for a whitelisted function (a
                # live, per-request computation, e.g. a connectivity check or
                # just-changed settings) instead of hitting the server again —
                # found exactly this way: ClamAV status and a just-saved
                # settings toggle both appeared "stuck" after a page refresh,
                # even though the backend was already correct and live.
                headers = {"Cache-Control": "no-store", **result.headers}
                if result.media_type == "application/json":
                    await send_json_with_etag(
                        send,
                        result.status_code,
                        result.content,
                        etag=route.etag,
                        if_none_match=request.headers.get("if-none-match"),
                        extra_headers=headers,
                        cookies=result.cookies,
                    )
                else:
                    body = (
                        result.content
                        if isinstance(result.content, bytes)
                        else str(result.content).encode("utf-8")
                    )
                    await send_bytes(
                        send,
                        result.status_code,
                        body,
                        content_type=result.media_type,
                        extra_headers=headers,
                        cookies=result.cookies,
                    )
            else:
                # Same default as above — this is the common case for a
                # whitelisted function that just returns a plain dict/list
                # (no Response object of its own), e.g. every example in this
                # session's own investigation (list_filer_settings,
                # get_filer_antivirus_status).
                await send_json_with_etag(
                    send,
                    200,
                    result,
                    etag=route.etag,
                    if_none_match=request.headers.get("if-none-match"),
                    extra_headers={"Cache-Control": "no-store"},
                )
        except Exception as exc:
            # A handler can return successfully and STILL fail here — e.g.
            # a return value encode_json can't serialize (an un-awaited
            # coroutine from a missing `await` is the single most common
            # real case: the handler itself never raises, so this is the
            # ONLY place that failure is ever observable at all). Before
            # this, that TypeError propagated straight out of _dispatch
            # uncaught — past every ASGI middleware, past access_log's own
            # send() wrapper (which is why a request like this shows
            # status=0 in the access log: it never saw a real
            # http.response.start), landing wherever Granian's own
            # top-level error handling sends it, with no coherent HTTP
            # response at all. Only safe to attempt here because
            # encode_json runs BEFORE send_bytes's own first `send()` call
            # in every path above — nothing has gone out on the wire yet
            # for the ordinary "bad return value" case this is actually
            # for; a failure from deeper inside an already-started send
            # (a broken client connection, not a serialization bug) can
            # still raise a second time out of this handler, same as
            # before this existed.
            await self._send_unhandled_exception(send, scope, exc, method, path, route.path)

    async def _dispatch_websocket(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Handshake -> roles/origin check -> handler, in that order —
        deliberately never accept() before both checks pass (see
        websocket.py's POLICY_VIOLATION and add_ws_route's own docstring):
        a rejected connection should never complete the WS upgrade at
        all, matching how relay's whitelist() checks roles before it ever
        touches a request body.

        Identity/client_ip/request_id are resolved here directly, not via
        the HTTP middleware chain (__call__ routes a websocket scope
        around it entirely) — same underlying functions
        identity_middleware/resolve_client_ip/new_request_id use for an
        ordinary HTTP request, just called once, at the one point in a
        WS connection's life that needs them, rather than per-message."""
        connect_event = await receive()
        if connect_event.get("type") != "websocket.connect":
            # Not a real deviation any spec-compliant ASGI server would
            # actually produce — defensive, not an expected path.
            return

        path = scope["path"]
        match = self._router.match(WEBSOCKET_METHOD, path)
        route = match.route

        async def reject(code: int) -> None:
            await send({"type": "websocket.close", "code": code})

        # Same live-read maintenance-mode check _dispatch does for HTTP —
        # see its own comment for why this is read fresh rather than baked
        # in at construction time. Checked before the roles/origin checks
        # below (and even before "route is None"): a site under
        # maintenance rejects every upgrade attempt uniformly, not just
        # ones that would otherwise have resolved to a real route.
        if self._kernel.settings.get(MAINTENANCE_MODE_KEY):
            await reject(MAINTENANCE)
            return

        if route is None:
            await reject(1000)
            return

        # WS-equivalent of CSRF: browsers don't enforce same-origin on a
        # WebSocket upgrade the way they do on fetch/XHR, so a page on
        # another origin could open a connection here riding the victim's
        # own session cookie unless the server checks Origin itself.
        # Reuses gateway_cors_origins rather than a second setting — the
        # same trusted-origins list already governs cross-origin access
        # to this app either way.
        #
        # An EMPTY gateway_cors_origins must mean "no cross-origin allowed"
        # here, unlike cors_middleware's own HTTP-side no-op for that same
        # empty case (that middleware's job is only ever to ADD a
        # permissive header on top of the browser's own same-origin
        # default for fetch/XHR — with nothing configured there is
        # nothing to add, and SOP itself still protects the request). A
        # WS upgrade has no SOP protecting it at all, so "nothing
        # configured" has to fall back to an explicit same-origin check
        # against Host instead of falling through open — the empty
        # default previously skipped this whole block, letting ANY origin
        # ride the victim's session cookie into an authenticated socket.
        origin = get_header(scope, b"origin")
        if origin is not None:
            origin_str = origin.decode("latin-1")
            if self._cors_origins:
                allowed = "*" in self._cors_origins or origin_str in self._cors_origins
            else:
                host = get_header(scope, b"host")
                allowed = host is not None and urlsplit(origin_str).netloc == host.decode(
                    "latin-1"
                )
            if not allowed:
                await reject(POLICY_VIOLATION)
                return

        authn_provider = self._kernel.get("authn") if self._kernel.has("authn") else None
        resolve = getattr(authn_provider, "resolve_identity", None)
        try:
            identity = await resolve(scope) if callable(resolve) else None
        except Exception as identity_exc:
            # Same "fail closed to unauthenticated, log server-side"
            # posture identity_middleware's own docstring documents at
            # length for the identical failure — an infrastructure error
            # inside resolve_identity must not crash the handshake.
            _logger.exception(
                "identity resolution raised during a WS handshake — treating as unauthenticated"
            )
            arc.errors.capture(identity_exc, source="gateway", stage="identity", method="WEBSOCKET")
            identity = None

        client_ip = resolve_client_ip(
            scope,
            trusted_proxies=set(self._trusted_proxies),
            forwarded_header=self._forwarded_header.encode("latin-1").lower(),
        )
        rl_key = rate_limit_key(identity, client_ip)

        # Rate-limited before the roles check, not after — a flood of
        # connection attempts shouldn't get to pay the (small but real)
        # cost of a roles decision before being turned away. Uses the
        # SAME budget an HTTP request from this identity/IP would draw
        # from (rate_limit_key returns the identical string either way):
        # one shared "how many things is this caller starting" counter
        # per identity/IP, not a separate invented pool just for WS.
        if self._rate_limit_enabled and not rate_limit_exempt(identity, client_ip, self._rate_limit_exempt):
            allowed = await check_rate_limit(
                self._kernel,
                self._rate_limit_fallback,
                rl_key,
                self._rate_limit_requests,
                self._rate_limit_window_seconds,
            )
            if not allowed:
                await reject(RATE_LIMITED)
                return

        # Same three-branch authorization relay.whitelist()'s own
        # _wire_gateway_route uses (relay/__init__.py) — not a
        # WS-specific reinterpretation of "*"/"Guest", the identical
        # meaning on both transports.
        caller_roles = set(getattr(identity, "roles", None) or [])
        if "*" in route.roles:
            authorized = identity is not None
        elif "*" in caller_roles:
            authorized = True
        else:
            authorized = bool((caller_roles | {"Guest"}) & route.roles)
        if not authorized:
            await reject(POLICY_VIOLATION)
            return

        async def check_message_rate() -> bool:
            # A DIFFERENT counter from the connection-attempt check above
            # (own key prefix) — sharing one budget between "how many
            # connections you've opened" and "how many messages you've
            # sent on an already-open one" would let a single active chat
            # session exhaust the same pool a fresh page load draws from.
            if rate_limit_exempt(identity, client_ip, self._rate_limit_exempt):
                return True
            return await check_rate_limit(
                self._kernel,
                self._rate_limit_fallback,
                f"ws-message:{rl_key}",
                self._rate_limit_requests,
                self._rate_limit_window_seconds,
            )

        connection = WebSocketConnection(
            scope,
            receive,
            send,
            identity=identity,
            client_ip=client_ip,
            request_id=new_request_id(),
            path_params=match.params,
            subscribe=self._ws_subscribe,
            unsubscribe=self._ws_unsubscribe,
            rate_limited=check_message_rate if self._rate_limit_enabled else None,
        )
        try:
            await route.handler(connection)
        except Exception as handler_exc:
            # Same "never let it escape unstructured to Granian" posture
            # _dispatch's own catch-all uses for an HTTP handler — a
            # WebSocket has no status code to report a 500 with at this
            # point (the handshake, if not the whole conversation, has
            # long since succeeded), so the best available signal is an
            # abnormal close code plus a server-side traceback.
            _logger.exception("unhandled exception in WS handler for %s", path)
            arc.errors.capture(
                handler_exc, source="gateway", method="WEBSOCKET", route=route.path, stage="websocket",
                request_id=connection.request_id,
            )
            await connection.close(1011)  # 1011 Internal Error
        finally:
            await connection.close()

    async def _try_serve_spa(self, path: str) -> tuple[bytes, str, str] | None:
        """Returns (body, content_type, cache_control) if `path` falls under
        a mounted SPA prefix, else None (falls through to ordinary
        routing/404). GET-only, by the caller above — HEAD isn't worth the
        "no body on a HEAD response" nuance for serving a handful of static
        SPA assets.

        Path-traversal guard: the resolved file must still live inside the
        mount's dist_dir — a `..`-laden path (however it got there) can
        never escape it. A resolved path that doesn't land on a real file
        (traversal attempt, directory, or a client-side SPA route with no
        matching asset) falls back to the mount's own index.html — the
        standard SPA-hosting behavior, and safe either way: it only ever
        serves a file already inside the mount, never anything else.

        Caching: bytes are held in a small in-memory cache keyed by
        (path, mtime_ns) — a Vite build's hashed assets are immutable, and
        re-reading them from disk per request was pure cost. index.html
        gets `no-cache` (the entry point must always revalidate so a new
        deploy is picked up); everything else — hashed filenames — gets a
        long immutable lifetime, so the browser stops re-requesting
        entirely."""
        segments = [s for s in path.strip("/").split("/") if s]
        if not segments or segments[0] not in self._spa_mounts:
            return None

        dist_dir = self._spa_mounts[segments[0]]
        sub_path = segments[1:]
        candidate = dist_dir.joinpath(*sub_path) if sub_path else dist_dir / "index.html"

        resolved = candidate.resolve()
        if not resolved.is_relative_to(dist_dir) or not resolved.is_file():
            resolved = dist_dir / "index.html"
            if not resolved.is_file():
                return None

        is_index = resolved.name == "index.html"
        cache_control = "no-cache" if is_index else "public, max-age=31536000, immutable"

        mtime_ns = resolved.stat().st_mtime_ns
        cache_key = str(resolved)
        cached = self._spa_file_cache.get(cache_key)
        if cached is not None and cached[0] == mtime_ns:
            body, content_type = cached[1], cached[2]
        else:
            content_type, _ = mimetypes.guess_type(str(resolved))
            content_type = content_type or "application/octet-stream"
            body = await asyncio.to_thread(resolved.read_bytes)
            self._spa_file_cache[cache_key] = (mtime_ns, body, content_type)
        return body, content_type, cache_control

    # ------------------------------------------------------------------ #
    # ASGI lifespan — the generic startup/shutdown hook every capability
    # with open()/close() benefits from automatically.
    # ------------------------------------------------------------------ #
    async def _handle_lifespan(self, receive: Callable, send: Callable) -> None:
        import arc as _arc  # gateway has no module-level arc import; events is a kernel service module

        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self._open_all_capabilities()
                    # This worker is a long-running ARC process: register it
                    # in .arc/runtime/processes (what `arc ps` lists and
                    # `arc reload` signals) and start the SIGUSR1 +
                    # reload-stamp bridge that turns cross-process
                    # notifications into a local system.reload event
                    # (arc.events' own docstring). AFTER open_all — the
                    # stamp poll reads through pgdb's pool.
                    _arc.events.install_process_bridge(role="gateway-worker")
                    _arc.metrics.start_exporter(role="gateway-worker")
                    _arc.tracing.start_exporter(role="gateway-worker")
                    _arc.log.set_role("gateway-worker")
                except Exception as exc:
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                try:
                    await _arc.events.uninstall_process_bridge()
                    await _arc.metrics.stop_exporter()
                    _arc.tracing.stop_exporter()
                    await self._close_all_capabilities()
                    await send({"type": "lifespan.shutdown.complete"})
                except Exception as exc:
                    await send({"type": "lifespan.shutdown.failed", "message": str(exc)})
                return

    async def _open_all_capabilities(self) -> None:
        for _name, cap in self._kernel.capabilities().items():
            open_fn = getattr(cap.instance, "open", None)
            if callable(open_fn):
                await open_fn()

    async def _close_all_capabilities(self) -> None:
        for _name, cap in self._kernel.capabilities().items():
            close_fn = getattr(cap.instance, "close", None)
            if callable(close_fn):
                await close_fn()

    # ------------------------------------------------------------------ #
    def _register_builtin_routes(self) -> None:
        async def _openapi_handler(request: Request) -> EncodedJSON:
            # Encoded once with the document; etag=True below lets a client that has it get a 304.
            return self._document("openapi.json", lambda: EncodedJSON(encode_json(self.openapi_spec())))

        self._router.add_route(
            "GET", "/openapi.json", _openapi_handler, summary="OpenAPI 3.0 document", etag=True
        )

        async def _openapi_ui_handler(request: Request) -> Response:
            text = self._document("openapi.html", lambda: render_openapi_html(self._router.all_routes()))
            return Response(content=text, media_type="text/html; charset=utf-8")

        self._router.add_route(
            "GET", "/openapi", _openapi_ui_handler, summary="Browsable API routes, grouped by plugin"
        )

        async def _openapi_css_handler(request: Request) -> Response:
            return Response(content=self._document("openapi.css", render_openapi_css), media_type="text/css; charset=utf-8")

        self._router.add_route(
            "GET", "/openapi.css", _openapi_css_handler, summary="Stylesheet for /openapi"
        )

        async def _metrics_handler(request: Request) -> Response:
            import arc as _arc  # gateway has no module-level arc import, see lifespan's own comment

            token = self._kernel.settings.get(METRICS_TOKEN_KEY)
            if token:
                auth = request.headers.get("authorization", "")
                # compare_digest, not `!=`: a plain string compare
                # short-circuits at the first differing byte, which is a
                # timing side-channel on the token itself. Matches what
                # every other secret comparison in this project already
                # does — csrf_middleware's own double-submit check below,
                # authn's session token check, arc.verify_hash, filer's
                # signed-URL check. This was the one that didn't.
                if not hmac.compare_digest(auth, f"Bearer {token}"):
                    return Response(
                        content="unauthorized\n",
                        status_code=401,
                        media_type="text/plain; charset=utf-8",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            snapshots = _arc.metrics.read_all(self._kernel.project_root)
            text = _arc.metrics.format_prometheus(_arc.metrics.aggregate(snapshots))
            return Response(content=text, media_type="text/plain; version=0.0.4; charset=utf-8")

        self._router.add_route(
            "GET",
            "/metrics",
            _metrics_handler,
            summary="Prometheus text-exposition metrics, aggregated across every ARC process",
        )


def register(kernel: Any) -> None:
    # Typed declare (matching authn's own adoption of this, arc/arc/
    # settings.py's declare()) — every get() below already comes back as
    # the right type, already defaulted, so there's no more hand-rolled
    # int()/lower()-in-(...)/`or DEFAULT` per setting here. A bad value
    # (e.g. gateway_max_body_bytes set to "ten megabytes") now fails at
    # arc.boot() with a clear message naming the setting, instead of
    # surfacing wherever the first request happens to read it. Only
    # cors_origins/trusted_proxies stay untyped — both are comma-separated
    # LISTS, and declare()'s `type` only covers int/float/bool/str, no
    # list support, so there's nothing to hand those two off to.
    kernel.settings.declare(
        CORS_ORIGINS_KEY,
        doc="Comma-separated allowed cross-origin hosts, or '*'. Empty/unset disables CORS.",
    )
    kernel.settings.declare(
        CSRF_ENABLED_KEY,
        type=bool,
        default=True,
        # Defaults ON (unlike force_https below) — the CSRF middleware
        # itself only ever acts on a request that ALREADY carries an
        # arc_session cookie (see csrf_middleware's own docstring: a
        # bearer/API-key-only deployment, or a request with no session
        # yet such as /login, is untouched either way), so there is no
        # ordinary request shape this newly starts rejecting.
        doc="Double-submit CSRF check on unsafe methods carrying a session cookie.",
    )
    kernel.settings.declare(
        FORCE_HTTPS_KEY,
        type=bool,
        default=False,
        doc="Send Strict-Transport-Security — only enable once served over TLS.",
    )
    kernel.settings.declare(
        CSP_KEY,
        default=DEFAULT_CSP,
        doc="Content-Security-Policy value. Empty disables it entirely.",
    )
    kernel.settings.declare(
        CSP_REPORT_ONLY_KEY,
        type=bool,
        default=True,
        doc="Send CSP as Content-Security-Policy-Report-Only instead of "
        "enforcing it. See DEFAULT_CSP's own comment for why this defaults on.",
    )
    kernel.settings.declare(
        TRUSTED_PROXIES_KEY,
        doc="Comma-separated trusted reverse-proxy IPs, for X-Forwarded-For parsing.",
    )
    kernel.settings.declare(
        FORWARDED_HEADER_KEY,
        default="X-Forwarded-For",
        doc="Which header to trust for the client IP when trusted_proxies is set.",
    )
    kernel.settings.declare(
        MAX_BODY_BYTES_KEY,
        type=int,
        default=DEFAULT_MAX_BODY_BYTES,
        doc="Global request body size ceiling, in bytes.",
    )
    kernel.settings.declare(
        MAX_JSON_BODY_BYTES_KEY,
        type=int,
        default=DEFAULT_MAX_JSON_BODY_BYTES,
        doc="Largest JSON request body, in bytes, that is decoded (413 above it), on every route: "
        "a route's own max_body_bytes lets big uploads in, not big JSON. Decoding runs on the event loop and costs about 7 ms per MB, "
        "pausing every other request on that worker meanwhile. 0 = no separate ceiling "
        "(gateway_max_body_bytes applies). Restart to apply.",
    )
    kernel.settings.declare(
        MAX_INFLIGHT_BODY_BYTES_KEY,
        type=int,
        default=DEFAULT_MAX_INFLIGHT_BODY_BYTES,
        doc="Most bytes of request bodies (those over 64 KB) one web worker holds in memory at once, "
        "default 256 MiB, 0 = no bound. A body is read whole before its handler runs, so a crowd of big "
        "uploads is a crowd of big allocations (about 0.7 MB of memory per MB of body). A request that does "
        "not fit waits up to 5 s for room, then gets 503 with Retry-After; one bigger than the whole bound "
        "is let in alone. Restart to apply.",
    )
    kernel.settings.declare(
        ACCESS_LOG_KEY,
        default=DEFAULT_ACCESS_LOG_MODE,
        doc="Where each request's access line goes: 'file' (default; only "
        "logs/gateway.jsonl), 'console' (also the terminal/journal via `arc "
        "run`; at thousands of requests per second the relay becomes the "
        "bottleneck), or 'off'. Request metrics are kept in every mode. "
        "Restart to apply.",
    )
    kernel.settings.declare(
        RATE_LIMIT_ENABLED_KEY,
        type=bool,
        default=True,
        # Defaults ON, same bar CSRF's own default-on note above sets,
        # just applied to request volume instead of request shape — see
        # DEFAULT_RATE_LIMIT_REQUESTS's own comment for why 300/60s
        # clears ordinary usage without meaningfully weakening the
        # protection.
        doc="Per-identity/IP request-volume limiting.",
    )
    kernel.settings.declare(
        RATE_LIMIT_REQUESTS_KEY,
        type=int,
        default=DEFAULT_RATE_LIMIT_REQUESTS,
        doc="Requests allowed per window before a 429.",
    )
    kernel.settings.declare(
        RATE_LIMIT_WINDOW_SECONDS_KEY,
        type=int,
        default=DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        doc="Rate-limit window length, in seconds.",
    )
    kernel.settings.declare(
        RATE_LIMIT_EXEMPT_KEY,
        doc="Networks (comma-separated IP addresses or CIDR ranges, e.g. '203.0.113.0/24,10.1.2.3') "
        "whose ANONYMOUS traffic is not counted by the per-IP request limit - an office of "
        "hundreds behind one public address otherwise shares one budget of "
        "gateway_rate_limit_requests - and which authn does not hold to its failed-login budget. "
        "Signed-in users keep their own per-user limit. The address is the one the gateway sees: "
        "set gateway_trusted_proxies first when running behind nginx, or it is nginx's own.",
    )
    kernel.settings.declare(
        MAINTENANCE_MODE_KEY,
        type=bool,
        default=False,
        # Deliberately NOT read here and baked into GatewayProvider.__init__
        # like every setting above — see _dispatch's own comment. Toggle it
        # with `arc set-maintenance on|off`, not by hand-editing arc.toml
        # (works either way; the CLI command is just the documented path).
        doc="While on, every request gets a 503 (maintenance page to a "
        "browser, JSON to an API client) instead of routing normally. "
        "Read fresh per request — takes effect immediately, no restart.",
    )
    kernel.settings.declare(
        DEBUG_KEY,
        type=bool,
        default=False,
        doc="Include exception type/message/traceback in EVERY caller's 500 "
        "response, authenticated or not. Off by default — prefer "
        "gateway_debug_roles instead; this exists for an authn-less "
        "deployment with no identity/roles to gate on at all.",
    )
    kernel.settings.declare(
        DEBUG_ROLES_KEY,
        default=DEFAULT_DEBUG_ROLES,
        doc="Comma-separated roles that get full exception detail on an "
        "unhandled 500, instead of the generic message. Default '*' means "
        "any authenticated caller (never an anonymous/no-identity one, "
        "in any configuration) — narrow to specific role names (e.g. "
        "'Superuser,Support') to restrict further. Known secret SETTINGS "
        "are redacted from the detail either way, but it can still surface "
        "internal structure (table/column/variable names) — grant with "
        "that in mind. Read fresh per request, no restart needed.",
    )
    kernel.settings.declare(
        METRICS_TOKEN_KEY,
        default="",
        doc="Bearer token required on GET /metrics. Empty/unset (default) "
        "leaves /metrics open — protect it via network boundary/reverse "
        "proxy instead, or set this for an Authorization: Bearer <token> "
        "gate. Read fresh per request, no restart needed.",
    )

    raw_origins = kernel.settings.get(CORS_ORIGINS_KEY)
    cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()] if raw_origins else None
    raw_proxies = kernel.settings.get(TRUSTED_PROXIES_KEY)
    trusted_proxies = (
        [p.strip() for p in raw_proxies.split(",") if p.strip()] if raw_proxies else None
    )

    try:
        exempt_networks = parse_networks(RATE_LIMIT_EXEMPT_KEY, kernel.settings.get(RATE_LIMIT_EXEMPT_KEY))
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc
    if exempt_networks and not trusted_proxies:
        kernel.advise(
            f"gateway: {RATE_LIMIT_EXEMPT_KEY} is set but gateway_trusted_proxies is not, so the address "
            f"checked against it is the immediate peer's - behind nginx that is nginx itself, and the "
            f"exemption would match nobody (or, if 127.0.0.1 is listed, everybody). Set "
            f"gateway_trusted_proxies to the proxy's address."
        )
    max_json_body_bytes = kernel.settings.get(MAX_JSON_BODY_BYTES_KEY)
    if max_json_body_bytes < 0:
        raise SettingsError(
            f"{MAX_JSON_BODY_BYTES_KEY}: {max_json_body_bytes} is not a size in bytes (use 0 for no separate ceiling)."
        )
    max_inflight_body_bytes = kernel.settings.get(MAX_INFLIGHT_BODY_BYTES_KEY)
    if max_inflight_body_bytes < 0:
        raise SettingsError(
            f"{MAX_INFLIGHT_BODY_BYTES_KEY}: {max_inflight_body_bytes} is not a size in bytes (use 0 for no bound)."
        )
    provider = GatewayProvider(
        kernel,
        cors_origins=cors_origins,
        csrf_enabled=kernel.settings.get(CSRF_ENABLED_KEY),
        hsts=kernel.settings.get(FORCE_HTTPS_KEY),
        csp=kernel.settings.get(CSP_KEY),
        csp_report_only=kernel.settings.get(CSP_REPORT_ONLY_KEY),
        trusted_proxies=trusted_proxies,
        forwarded_header=kernel.settings.get(FORWARDED_HEADER_KEY),
        max_body_bytes=kernel.settings.get(MAX_BODY_BYTES_KEY),
        max_json_body_bytes=max_json_body_bytes,
        max_inflight_body_bytes=max_inflight_body_bytes,
        rate_limit_enabled=kernel.settings.get(RATE_LIMIT_ENABLED_KEY),
        rate_limit_requests=kernel.settings.get(RATE_LIMIT_REQUESTS_KEY),
        rate_limit_window_seconds=kernel.settings.get(RATE_LIMIT_WINDOW_SECONDS_KEY),
        rate_limit_exempt=exempt_networks,
        access_log=kernel.settings.get(ACCESS_LOG_KEY),
    )
    kernel.export(CAPABILITY, provider, requires=[], optional_requires=["authn", "redix"])
