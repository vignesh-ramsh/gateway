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


@dataclass(frozen=True)
class RouteEntry:
    method: str
    path: str
    handler: Callable[..., Any]
    request_schema: Any | None = None
    response_schema: Any | None = None
    summary: str | None = None


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

    def add_route(
        self,
        method: str,
        path: str,
        handler: Callable[..., Any],
        *,
        request_schema: Any | None = None,
        response_schema: Any | None = None,
        summary: str | None = None,
    ) -> None:
        method = method.upper()
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

        if method in node.routes:
            raise RouterError(f"route already registered: {method} {path}")
        node.routes[method] = RouteEntry(
            method=method,
            path=path,
            handler=handler,
            request_schema=request_schema,
            response_schema=response_schema,
            summary=summary,
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