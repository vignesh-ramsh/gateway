"""
gateway — ARC provider plugin: HTTP/WS transport (Architecture §2).

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

from typing import Any, Awaitable, Callable

from .middleware import (
    cors_middleware,
    csrf_middleware,
    identity_middleware,
    security_headers_middleware,
)
from .openapi import build_openapi_spec
from .request import (
    HTTPError,
    Request,
    Response,
    headers_from_scope,
    query_params_from_scope,
    read_body,
    send_json,
)
from .router import Router

CAPABILITY = "gateway"

CORS_ORIGINS_KEY = "gateway_cors_origins"
CSRF_ENABLED_KEY = "gateway_csrf_enabled"
FORCE_HTTPS_KEY = "gateway_force_https"

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]


class GatewayProvider:
    def __init__(
        self,
        kernel: Any,
        *,
        cors_origins: list[str] | None = None,
        csrf_enabled: bool = False,
        hsts: bool = False,
    ) -> None:
        self._kernel = kernel
        self._router = Router()
        self._extra_middlewares: list[Callable[[ASGIApp], ASGIApp]] = []
        self._built_app: ASGIApp | None = None

        # Fixed order: security headers -> CORS -> CSRF -> identity.
        self._builtin_middlewares: list[Callable[[ASGIApp], ASGIApp]] = [
            security_headers_middleware(hsts=hsts),
            cors_middleware(cors_origins),
            csrf_middleware(enabled=csrf_enabled),
        ]
        if kernel.has("authn"):
            self._builtin_middlewares.append(identity_middleware(kernel.get("authn")))
        # If authn isn't registered, the slot above is simply absent — no
        # dummy anonymous-identity object, per §3.3.

        self._register_builtin_routes()

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
    ) -> None:
        """Register a route. Relay (Phase 3) will call this the same way any
        other caller does — Gateway never hardcodes knowledge of Resources."""
        self._router.add_route(
            method, path, handler,
            request_schema=request_schema, response_schema=response_schema, summary=summary,
        )
        self._built_app = None

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
        gateway's own entry every time something calls arc.health.check()."""
        return {"ok": True, "routes": len(self._router.all_routes())}

    # ------------------------------------------------------------------ #
    # ASGI 3.0 entrypoint
    # ------------------------------------------------------------------ #
    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            return await self._handle_lifespan(receive, send)
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
        match = self._router.match(method, path)

        if match.route is None and not match.allowed_methods:
            await send_json(send, 404, {"error": "not found", "path": path})
            return
        if match.route is None:
            await send_json(
                send, 405,
                {"error": "method not allowed", "allowed": sorted(match.allowed_methods)},
                extra_headers={"Allow": ", ".join(sorted(match.allowed_methods))},
            )
            return

        route = match.route
        body = await read_body(receive)
        request = Request(
            method=method,
            path=path,
            path_params=match.params,
            query_params=query_params_from_scope(scope),
            headers=headers_from_scope(scope),
            body=body,
            scope=scope,
            identity=scope.get("state", {}).get("arc_identity"),
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

        if isinstance(result, Response):
            await send_json(send, result.status_code, result.content, extra_headers=result.headers)
        else:
            await send_json(send, 200, result)

    # ------------------------------------------------------------------ #
    # ASGI lifespan — the generic startup/shutdown hook every capability
    # with open()/close() benefits from automatically.
    # ------------------------------------------------------------------ #
    async def _handle_lifespan(self, receive: Callable, send: Callable) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self._open_all_capabilities()
                except Exception as exc:
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                try:
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

    raw_origins = kernel.settings.get(CORS_ORIGINS_KEY)
    cors_origins = (
        [o.strip() for o in raw_origins.split(",") if o.strip()] if raw_origins else None
    )
    csrf_enabled = (kernel.settings.get(CSRF_ENABLED_KEY) or "").lower() in ("1", "true", "yes")
    force_https = (kernel.settings.get(FORCE_HTTPS_KEY) or "").lower() in ("1", "true", "yes")

    provider = GatewayProvider(
        kernel, cors_origins=cors_origins, csrf_enabled=csrf_enabled, hsts=force_https
    )
    kernel.export(CAPABILITY, provider, requires=[], optional_requires=["authn"])