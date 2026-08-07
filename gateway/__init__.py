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

Lifecycle note: unlike psqldb/redix, Gateway's own ASGI "lifespan" protocol
is the natural home for the open()/close() calls those plugins otherwise
need called manually — see _open_all_capabilities/_close_all_capabilities
below. Any capability with an open()/close() method (duck-typed, same
pattern as health()) gets started/stopped automatically once Gateway is
actually served — closing the "manual lifecycle" gap flagged when
psqldb/redix were built. Gateway never knows these are "psqldb"/"redix".
"""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from pathlib import Path
from typing import Any, Awaitable, Callable

import arc

from .middleware import (
    LocalRateLimiter,
    RequestMetrics,
    access_log_middleware,
    client_ip_middleware,
    cors_middleware,
    csrf_middleware,
    identity_middleware,
    new_request_id,
    rate_limit_middleware,
    request_id_middleware,
    resolve_client_ip,
    security_headers_middleware,
)
from .openapi import build_openapi_spec
from .request import (
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
    send_stream,
)
from .router import WEBSOCKET_METHOD, Router, RouterError
from .websocket import POLICY_VIOLATION, WebSocketConnection

CAPABILITY = "gateway"

CORS_ORIGINS_KEY = "gateway_cors_origins"
CSRF_ENABLED_KEY = "gateway_csrf_enabled"
FORCE_HTTPS_KEY = "gateway_force_https"
TRUSTED_PROXIES_KEY = "gateway_trusted_proxies"
FORWARDED_HEADER_KEY = "gateway_forwarded_header"
MAX_BODY_BYTES_KEY = "gateway_max_body_bytes"
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB — generous for a JSON API body,
# nowhere near "unbounded" (the bug this fixes)

RATE_LIMIT_ENABLED_KEY = "gateway_rate_limit_enabled"
RATE_LIMIT_REQUESTS_KEY = "gateway_rate_limit_requests"
RATE_LIMIT_WINDOW_SECONDS_KEY = "gateway_rate_limit_window_seconds"
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


class GatewayProvider:
    def __init__(
        self,
        kernel: Any,
        *,
        cors_origins: list[str] | None = None,
        csrf_enabled: bool = False,
        hsts: bool = False,
        trusted_proxies: list[str] | None = None,
        forwarded_header: str = "X-Forwarded-For",
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        rate_limit_enabled: bool = True,
        rate_limit_requests: int = DEFAULT_RATE_LIMIT_REQUESTS,
        rate_limit_window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self._kernel = kernel
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
        self._metrics = RequestMetrics()
        self._rate_limit_fallback = LocalRateLimiter()
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
            security_headers_middleware(hsts=hsts),
            cors_middleware(cors_origins),
            csrf_middleware(enabled=csrf_enabled),
            self._build_client_ip_middleware(),
        ]
        # Captured right where client_ip is appended, not derived from the
        # final list length — a "len(...) - N" offset (the previous
        # approach) silently breaks the moment anything is ever added
        # after it, exactly what rate_limit_middleware below now does.
        self._client_ip_mw_index = len(self._builtin_middlewares) - 1
        self._builtin_middlewares += [
            identity_middleware(kernel),
            access_log_middleware(self._metrics),
            rate_limit_middleware(
                kernel,
                enabled=rate_limit_enabled,
                limit=rate_limit_requests,
                window_seconds=rate_limit_window_seconds,
                fallback=self._rate_limit_fallback,
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
        response_schema: Any | None = None,
        summary: str | None = None,
        max_body_bytes: int | None = None,
    ) -> None:
        """Register a route. Relay (Phase 3) will call this the same way any
        other caller does — Gateway never hardcodes knowledge of Resources.

        `max_body_bytes`: None (default) means this route is bounded by the
        gateway-wide `gateway_max_body_bytes` ceiling like everything else;
        pass a value to give ONE route its own larger (or smaller) outer
        ASGI-level body limit — e.g. a file-upload endpoint that needs to
        accept much bigger requests than an ordinary JSON API call, without
        raising the shared ceiling every other endpoint is also bounded by."""
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
            response_schema=response_schema,
            summary=summary,
            max_body_bytes=max_body_bytes,
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

    def openapi_spec(self) -> dict:
        return build_openapi_spec(self._router.all_routes())

    async def health(self) -> dict:
        """Reports on gateway itself ONLY — same as every other capability's
        health(). This used to walk and re-aggregate every OTHER capability
        too (it was arc.health's stand-in before arc.health existed); now
        that arc.health.check() is the one real aggregator, doing that here
        as well would nest a full copy of the whole system's health inside
        gateway's own entry every time something calls arc.health.check().

        `requests` is this PROCESS's own counters since it started (see
        RequestMetrics) — a multi-worker deployment has one independent
        set per worker, same posture as psqldb's pool_stats() and
        arc.events.stats(); no cross-process aggregation happens here."""
        return {
            "ok": True,
            "routes": len(self._router.all_routes()),
            "requests": self._metrics.snapshot(),
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
        app = self._compiled_app()
        await app(scope, receive, send)

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

    async def _dispatch(self, scope: dict, receive: Callable, send: Callable) -> None:
        method = scope["method"]
        path = scope["path"]

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
            await send_json(send, 404, {"error": "not found", "path": path})
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
        try:
            body = await read_body(receive, max_bytes=route.max_body_bytes or self._max_body_bytes)
        except HTTPError as exc:
            await send_json(send, exc.status_code, exc.detail)
            return

        request = Request(
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
        )

        if route.request_schema is not None:
            try:
                request.validated = request.json(route.request_schema)
            except Exception as exc:
                await send_json(send, 422, {"error": "validation failed", "detail": str(exc)})
                return

        try:
            result = await route.handler(request)
        except HTTPError as exc:
            await send_json(send, exc.status_code, exc.detail)
            return
        except Exception as exc:
            # Anything else is a genuine bug, not a client mistake — log the
            # full traceback server-side (never exposed to the caller) and
            # return a generic 500 rather than letting it escape unstructured
            # to Granian, unlogged, with whatever detail happened to be in
            # the exception potentially reaching the response.
            _logger.exception("unhandled exception in %s %s", method, path)
            await send_json(send, 500, {"error": "internal server error"})
            return

        if isinstance(result, StreamResponse):
            try:
                await send_stream(send, result)
            except Exception:
                # http.response.start (status 200) is already sent by this
                # point — there is no way to change status code mid-stream,
                # so the best this can do is log server-side (same as the
                # catch-all below) and try to end the body with one visible
                # error chunk rather than just going silent; a client
                # reading the stream sees a truncated/errored feed either
                # way, which is itself the signal something went wrong.
                _logger.exception("unhandled exception while streaming %s %s", method, path)
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

        if isinstance(result, Response):
            if result.media_type == "application/json":
                await send_json(
                    send,
                    result.status_code,
                    result.content,
                    extra_headers=result.headers,
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
                    extra_headers=result.headers,
                    cookies=result.cookies,
                )
        else:
            await send_json(send, 200, result)

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
        origin = get_header(scope, b"origin")
        if self._cors_origins and origin is not None:
            origin_str = origin.decode("latin-1")
            if "*" not in self._cors_origins and origin_str not in self._cors_origins:
                await reject(POLICY_VIOLATION)
                return

        authn_provider = self._kernel.get("authn") if self._kernel.has("authn") else None
        resolve = getattr(authn_provider, "resolve_identity", None)
        try:
            identity = await resolve(scope) if callable(resolve) else None
        except Exception:
            # Same "fail closed to unauthenticated, log server-side"
            # posture identity_middleware's own docstring documents at
            # length for the identical failure — an infrastructure error
            # inside resolve_identity must not crash the handshake.
            _logger.exception(
                "identity resolution raised during a WS handshake — treating as unauthenticated"
            )
            identity = None

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

        client_ip = resolve_client_ip(
            scope,
            trusted_proxies=set(self._trusted_proxies),
            forwarded_header=self._forwarded_header.encode("latin-1").lower(),
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
        )
        try:
            await route.handler(connection)
        except Exception:
            # Same "never let it escape unstructured to Granian" posture
            # _dispatch's own catch-all uses for an HTTP handler — a
            # WebSocket has no status code to report a 500 with at this
            # point (the handshake, if not the whole conversation, has
            # long since succeeded), so the best available signal is an
            # abnormal close code plus a server-side traceback.
            _logger.exception("unhandled exception in WS handler for %s", path)
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
                    # stamp poll reads through psqldb's pool.
                    _arc.events.install_process_bridge(role="gateway-worker")
                    _arc.log.set_role("gateway-worker")
                except Exception as exc:
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                try:
                    await _arc.events.uninstall_process_bridge()
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
        async def _openapi_handler(request: Request) -> dict:
            return self.openapi_spec()

        self._router.add_route(
            "GET", "/openapi.json", _openapi_handler, summary="OpenAPI 3.0 document"
        )


def register(kernel: Any) -> None:
    kernel.settings.declare(CORS_ORIGINS_KEY)
    kernel.settings.declare(CSRF_ENABLED_KEY)
    kernel.settings.declare(FORCE_HTTPS_KEY)
    kernel.settings.declare(TRUSTED_PROXIES_KEY)
    kernel.settings.declare(FORWARDED_HEADER_KEY)
    kernel.settings.declare(MAX_BODY_BYTES_KEY)
    kernel.settings.declare(RATE_LIMIT_ENABLED_KEY)
    kernel.settings.declare(RATE_LIMIT_REQUESTS_KEY)
    kernel.settings.declare(RATE_LIMIT_WINDOW_SECONDS_KEY)

    raw_origins = kernel.settings.get(CORS_ORIGINS_KEY)
    cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()] if raw_origins else None
    # Defaults ON (unlike CORS/force-https above, which default off) — the
    # CSRF middleware itself only ever acts on a request that ALREADY
    # carries an arc_session cookie (see csrf_middleware's own docstring:
    # a bearer/API-key-only deployment, or a request with no session yet
    # such as /login, is untouched either way), so there is no ordinary
    # request shape this newly starts rejecting. An operator who genuinely
    # wants it off sets the setting to "false"/"0"/"no" explicitly — the
    # `or "true"` here only supplies the fallback when the setting has
    # never been touched at all (kernel.settings.get returns None/"").
    csrf_enabled = (kernel.settings.get(CSRF_ENABLED_KEY) or "true").lower() in ("1", "true", "yes")
    force_https = (kernel.settings.get(FORCE_HTTPS_KEY) or "").lower() in ("1", "true", "yes")
    raw_proxies = kernel.settings.get(TRUSTED_PROXIES_KEY)
    trusted_proxies = (
        [p.strip() for p in raw_proxies.split(",") if p.strip()] if raw_proxies else None
    )
    forwarded_header = kernel.settings.get(FORWARDED_HEADER_KEY) or "X-Forwarded-For"
    raw_max_body = kernel.settings.get(MAX_BODY_BYTES_KEY)
    max_body_bytes = int(raw_max_body) if raw_max_body else DEFAULT_MAX_BODY_BYTES
    # Defaults ON, same bar CSRF's own default-on comment above sets, just
    # applied to request volume instead of request shape — see
    # DEFAULT_RATE_LIMIT_REQUESTS's own comment for why 300/60s clears
    # ordinary usage without meaningfully weakening the protection.
    rate_limit_enabled = (
        kernel.settings.get(RATE_LIMIT_ENABLED_KEY) or "true"
    ).lower() in ("1", "true", "yes")
    raw_rate_limit_requests = kernel.settings.get(RATE_LIMIT_REQUESTS_KEY)
    rate_limit_requests = (
        int(raw_rate_limit_requests) if raw_rate_limit_requests else DEFAULT_RATE_LIMIT_REQUESTS
    )
    raw_rate_limit_window = kernel.settings.get(RATE_LIMIT_WINDOW_SECONDS_KEY)
    rate_limit_window_seconds = (
        int(raw_rate_limit_window) if raw_rate_limit_window else DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    )

    provider = GatewayProvider(
        kernel,
        cors_origins=cors_origins,
        csrf_enabled=csrf_enabled,
        hsts=force_https,
        trusted_proxies=trusted_proxies,
        forwarded_header=forwarded_header,
        max_body_bytes=max_body_bytes,
        rate_limit_enabled=rate_limit_enabled,
        rate_limit_requests=rate_limit_requests,
        rate_limit_window_seconds=rate_limit_window_seconds,
    )
    kernel.export(CAPABILITY, provider, requires=[], optional_requires=["authn", "redix"])
