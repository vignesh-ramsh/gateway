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

import asyncio
import logging
import mimetypes
from pathlib import Path
from typing import Any, Awaitable, Callable

from .middleware import (
    client_ip_middleware,
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
    StreamResponse,
    encode_json,
    headers_from_scope,
    query_params_from_scope,
    read_body,
    send_bytes,
    send_json,
    send_stream,
)
from .router import Router, RouterError

CAPABILITY = "gateway"

CORS_ORIGINS_KEY = "gateway_cors_origins"
CSRF_ENABLED_KEY = "gateway_csrf_enabled"
FORCE_HTTPS_KEY = "gateway_force_https"
TRUSTED_PROXIES_KEY = "gateway_trusted_proxies"
FORWARDED_HEADER_KEY = "gateway_forwarded_header"
MAX_BODY_BYTES_KEY = "gateway_max_body_bytes"
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB — generous for a JSON API body,
                                            # nowhere near "unbounded" (the bug this fixes)

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
    ) -> None:
        self._kernel = kernel
        self._router = Router()
        self._spa_mounts: dict[str, Path] = {}
        # path -> (mtime_ns, bytes, content_type); see _try_serve_spa.
        self._spa_file_cache: dict[str, tuple[int, bytes, str]] = {}
        self._extra_middlewares: list[Callable[[ASGIApp], ASGIApp]] = []
        self._built_app: ASGIApp | None = None
        self._trusted_proxies = trusted_proxies or []
        self._forwarded_header = forwarded_header
        self._max_body_bytes = max_body_bytes

        # Fixed order: security headers -> CORS -> CSRF -> client_ip -> identity.
        # Both client_ip and identity are unconditional now — identity_middleware
        # looks up kernel.has("authn")/kernel.get("authn") lazily per request
        # rather than once here at construction time (see its own docstring):
        # authn optionally-requiring gateway doesn't guarantee gateway registers
        # AFTER authn (arc's resolver only orders HARD requires strictly, §3.1) —
        # `arc doctor` warns exactly this ordering can happen — so a boot-time
        # kernel.has("authn") check here could easily see False even with authn
        # fully installed, silently disabling identity resolution.
        self._client_ip_mw_index = 3
        self._builtin_middlewares: list[Callable[[ASGIApp], ASGIApp]] = [
            security_headers_middleware(hsts=hsts),
            cors_middleware(cors_origins),
            csrf_middleware(enabled=csrf_enabled),
            self._build_client_ip_middleware(),
            identity_middleware(kernel),
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
    ) -> None:
        """Register a route. Relay (Phase 3) will call this the same way any
        other caller does — Gateway never hardcodes knowledge of Resources."""
        first_segment = next((s for s in path.strip("/").split("/") if s), None)
        if first_segment is not None and first_segment in self._spa_mounts:
            raise RouterError(
                f"cannot register route '{path}': '{first_segment}' is already "
                f"mounted as an SPA prefix"
            )
        self._router.add_route(
            method, path, handler,
            request_schema=request_schema, response_schema=response_schema, summary=summary,
        )
        self._built_app = None

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

        if method == "GET" and self._spa_mounts:
            spa_hit = await self._try_serve_spa(path)
            if spa_hit is not None:
                body, content_type, cache_control = spa_hit
                await send_bytes(
                    send, 200, body, content_type=content_type,
                    extra_headers={"Cache-Control": cache_control},
                )
                return

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
        try:
            body = await read_body(receive, max_bytes=self._max_body_bytes)
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
                    await send({
                        "type": "http.response.body",
                        "body": encode_json({"error": "internal server error"}) + b"\n",
                        "more_body": False,
                    })
                except Exception:
                    pass
            return

        if isinstance(result, Response):
            await send_json(send, result.status_code, result.content, extra_headers=result.headers)
        else:
            await send_json(send, 200, result)

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

    raw_origins = kernel.settings.get(CORS_ORIGINS_KEY)
    cors_origins = (
        [o.strip() for o in raw_origins.split(",") if o.strip()] if raw_origins else None
    )
    csrf_enabled = (kernel.settings.get(CSRF_ENABLED_KEY) or "").lower() in ("1", "true", "yes")
    force_https = (kernel.settings.get(FORCE_HTTPS_KEY) or "").lower() in ("1", "true", "yes")
    raw_proxies = kernel.settings.get(TRUSTED_PROXIES_KEY)
    trusted_proxies = (
        [p.strip() for p in raw_proxies.split(",") if p.strip()] if raw_proxies else None
    )
    forwarded_header = kernel.settings.get(FORWARDED_HEADER_KEY) or "X-Forwarded-For"
    raw_max_body = kernel.settings.get(MAX_BODY_BYTES_KEY)
    max_body_bytes = int(raw_max_body) if raw_max_body else DEFAULT_MAX_BODY_BYTES

    provider = GatewayProvider(
        kernel, cors_origins=cors_origins, csrf_enabled=csrf_enabled, hsts=force_https,
        trusted_proxies=trusted_proxies, forwarded_header=forwarded_header,
        max_body_bytes=max_body_bytes,
    )
    kernel.export(CAPABILITY, provider, requires=[], optional_requires=["authn"])