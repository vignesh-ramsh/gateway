"""
gateway.router
-----------------
A pure-Python radix-tree router — v1 of the "Rust radix router" line in the
Architecture tech-stack table. The tech stack's own PyO3/maturin row is
explicit that Rust hot paths get a "pure-Python fallback" first; building
and packaging a real PyO3 extension is a materially bigger lift than the
rest of Gateway combined, so that's deferred rather than blocking Gateway's
actual job (correct routing/middleware/OpenAPI) on a Rust build pipeline.
The router's public interface (add_route/match) is exactly what a future
Rust implementation would need to preserve as a drop-in swap.

Static segments take priority over a param segment at the same tree level
(`/users/me` beats `/users/{id}` for the literal path "/users/me") — this
matches the common convention in Express/Starlette/FastAPI.

match() distinguishes two failure modes, both needed by the dispatcher:
  * no node reachable for this path at all           -> 404
  * the path resolves to a real registered endpoint,
    but not for this HTTP method                      -> 405, with the
                                                          actually-allowed
                                                          methods attached
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


#: Synthetic "method" a WebSocket route is filed under in the SAME radix
#: tree as ordinary HTTP routes — a WS path has no HTTP verb at all, but
#: reusing one tree means the static-beats-param priority, path-param
#: parsing, and 404-vs-405 distinction below are shared for free instead
#: of duplicated in a second router. Uppercase, unreachable as a real HTTP
#: method (ASGI/HTTP method tokens never contain a space or lowercase-only
#: convention issue here — it just needs to never collide with a real verb).
WEBSOCKET_METHOD = "WEBSOCKET"


@dataclass(frozen=True)
class RouteEntry:
    method: str
    path: str
    handler: Callable[..., Any]
    request_schema: Any | None = None
    # Whether _dispatch should actually decode+validate the body against
    # request_schema before calling handler (request.py's own docstring:
    # "Request.validated carries the arc.codec-decoded body"). True is the
    # right default for a caller with no validation of its own — gateway
    # does it for them. False for relay's whitelisted routes specifically
    # (relay/whitelisting.py's own _wire_gateway_route sets this): relay's
    # handler already does its own, more complete validation (query string
    # + body + path params merged, correct 400 — not 422 — on a bad value,
    # works for a bodyless GET) before ever calling wf.fn, so a SECOND,
    # independent decode of just the raw body against request_schema was
    # both redundant and actively wrong — request_schema there is relay's
    # own hand-built object schema for the /openapi docs page (see
    # relay.whitelisting._request_schema_for's own docstring), never a real
    # msgspec-decodable type for a plain-kwargs function, and even the
    # Struct-typed "payload" style has nothing to decode from an empty GET
    # body. Verified directly: this is what turned EVERY relay-whitelisted
    # route with any declared parameter into a permanent 422, regardless of
    # what the caller actually sent.
    validate_body: bool = True
    # Whether tracing_middleware should start a root span for a request
    # that matches this route (2026-09-01, Improvement Doc's telemetry
    # opt-out) — checked via a cheap extra router.match() done by that
    # middleware itself, BEFORE _dispatch's own (separate) match, since
    # tracing wraps _dispatch and every other middleware inside it and so
    # has no route to check without looking one up early. True (the
    # default) traces every route, same as before this flag existed — an
    # unmatched request (a genuine 404) is unaffected either way, and
    # still gets a span, since there's no route to carry False. Only
    # relay's whitelist(trace=False) (or a direct add_route(trace=False)
    # caller) ever sets this — e.g. a noisy health-check endpoint that
    # would otherwise dominate a trace backend with uniform, uninteresting
    # spans. Entirely independent of the GLOBAL tracing_otlp_endpoint/
    # tracing_sample_rate_percent settings (arc.tracing.declare) — those
    # decide whether tracing happens AT ALL and at what rate; this decides
    # whether ONE route ever participates, regardless of either.
    trace: bool = True
    response_schema: Any | None = None
    summary: str | None = None
    # None (the default) means "use the gateway-wide gateway_max_body_bytes
    # ceiling" — the same boot-time-only, restart-to-change posture that
    # global setting already has (gateway/__init__.py reads it once at
    # construction). A route that sets this (e.g. filer's file_upload)
    # gets its OWN outer ASGI-level ceiling instead — deliberately still a
    # fixed, boot-time value, not tied to any live-editable setting: this
    # is "how big can the wire request even be", not a business rule (the
    # business rule — how big a file filer actually accepts — stays a
    # live setting, checked after the body's already been read, in
    # arc.filer.upload() itself). Lets one route (large file uploads)
    # accept a much bigger body than every other endpoint without raising
    # the shared global ceiling that bounds ordinary JSON payloads too.
    max_body_bytes: int | None = None
    # ETag/conditional-GET support (2026-08-27) — always False for anything
    # gateway itself registers (the SPA mount path, the builtin routes) and
    # for a WebSocket route; only relay's whitelisting layer ever passes
    # True, and only for a GET/QUERY registration of a function that didn't
    # opt out (see relay/whitelisting.py's own _resolve_etag). Deliberately
    # a plain per-RouteEntry bool rather than gateway re-deriving "is this
    # method eligible" itself from `method` — that's a whitelisting-layer
    # POLICY decision (which verbs conditional-GET semantics apply to),
    # not something the generic transport layer should hardcode; gateway's
    # own _dispatch just does what this flag says.
    etag: bool = False
    # WebSocket routes only (method == WEBSOCKET_METHOD) — who's allowed to
    # open this connection, same shape as relay.whitelist()'s own `roles`
    # (None/"*" meaning any authenticated identity). An ordinary HTTP route
    # leaves this None: its own role check happens inside relay's whitelist
    # wrapper (the thing actually registered as `handler` for that route),
    # not here. WS has no such wrapper — nothing sits between a plugin's
    # handler and the wire — so gateway checks this itself, at handshake
    # time, before ever accepting the connection.
    roles: frozenset[str] | None = None
    # Which plugin registered this route, for anything that wants to GROUP
    # routes by owner rather than just list them flat — the /openapi UI
    # page being the first (only) consumer. None for anything gateway
    # registers on its own behalf (the builtin routes) — relay is the only
    # caller that ever has a real plugin name to pass (WhitelistedFunction.
    # plugin, already tracked there for its own error messages), so this
    # stays None unless relay's own _wire_gateway_route sets it explicitly.
    plugin: str | None = None


@dataclass
class MatchResult:
    route: RouteEntry | None
    params: dict[str, str] = field(default_factory=dict)
    # Non-empty only when the path matched but the method didn't (405 case).
    allowed_methods: frozenset[str] = frozenset()


class RouterError(RuntimeError):
    pass


class _Node:
    __slots__ = ("static", "param_name", "param_child", "routes")

    def __init__(self) -> None:
        self.static: dict[str, "_Node"] = {}
        self.param_name: str | None = None
        self.param_child: "_Node | None" = None
        self.routes: dict[str, RouteEntry] = {}


def _split_path(path: str) -> list[str]:
    # Leading/trailing slashes are normalized away — "/users" and "/users/"
    # address the same node. Simpler and matches common developer expectation
    # for a v1; revisit only if a real need for strict trailing-slash
    # distinction shows up.
    return [seg for seg in path.strip("/").split("/") if seg]


class Router:
    def __init__(self) -> None:
        self._root = _Node()

    def _ensure_node(self, path: str) -> _Node:
        node = self._root
        for seg in _split_path(path):
            if seg.startswith("{") and seg.endswith("}"):
                name = seg[1:-1]
                if not name:
                    raise RouterError(f"empty path parameter in '{path}'")
                if node.param_child is None:
                    node.param_child = _Node()
                    node.param_name = name
                elif node.param_name != name:
                    raise RouterError(
                        f"conflicting path parameter name at this position "
                        f"while registering '{path}': existing routes use "
                        f"'{{{node.param_name}}}', this one uses '{{{name}}}' "
                        f"— a single position can only bind one param name."
                    )
                node = node.param_child
            else:
                node = node.static.setdefault(seg, _Node())
        return node

    def add_route(
        self,
        method: str,
        path: str,
        handler: Callable[..., Any],
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
    ) -> None:
        method = method.upper()
        node = self._ensure_node(path)
        if method in node.routes:
            raise RouterError(f"route already registered: {method} {path}")
        node.routes[method] = RouteEntry(
            method=method,
            path=path,
            handler=handler,
            request_schema=request_schema,
            validate_body=validate_body,
            trace=trace,
            response_schema=response_schema,
            summary=summary,
            max_body_bytes=max_body_bytes,
            etag=etag,
            plugin=plugin,
            roles=roles,
        )

    def add_ws_route(
        self,
        path: str,
        handler: Callable[..., Any],
        *,
        roles: frozenset[str] | None = None,
        summary: str | None = None,
    ) -> None:
        node = self._ensure_node(path)
        if WEBSOCKET_METHOD in node.routes:
            raise RouterError(f"WebSocket route already registered: {path}")
        node.routes[WEBSOCKET_METHOD] = RouteEntry(
            method=WEBSOCKET_METHOD,
            path=path,
            handler=handler,
            summary=summary,
            roles=roles,
        )

    def match(self, method: str, path: str) -> MatchResult:
        method = method.upper()
        node = self._root
        params: dict[str, str] = {}

        for seg in _split_path(path):
            if seg in node.static:
                node = node.static[seg]
            elif node.param_child is not None:
                params[node.param_name] = seg  # type: ignore[index]
                node = node.param_child
            else:
                return MatchResult(None)

        if method in node.routes:
            return MatchResult(node.routes[method], params)
        if node.routes:
            return MatchResult(None, params, frozenset(node.routes))
        return MatchResult(None)

    def first_segment_registered(self, segment: str) -> bool:
        """Whether any route's first path segment is exactly this literal
        segment — used by GatewayProvider to guard an SPA mount prefix
        (gateway/__init__.py's mount_spa) against colliding with an
        existing JSON route, and vice versa."""
        return segment in self._root.static

    def all_routes(self) -> list[RouteEntry]:
        """Every registered route, for OpenAPI generation and `arc gateway routes`."""
        out: list[RouteEntry] = []

        def walk(node: _Node) -> None:
            out.extend(node.routes.values())
            for child in node.static.values():
                walk(child)
            if node.param_child is not None:
                walk(node.param_child)

        walk(self._root)
        out.sort(key=lambda r: (r.path, r.method))
        return out
