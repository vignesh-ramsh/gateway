"""
gateway.openapi
-------------------
Builds an OpenAPI 3.0 document from whatever routes are currently
registered. The only real content right now is hand-written demo routes —
that's the honest scope for Phase 2. Real Resource-derived schemas arrive
with Relay (Phase 3), which will call `add_route` the same way any other
caller does; this module doesn't need to change when that happens.
"""

from __future__ import annotations

from typing import Any

import arc

from .router import RouteEntry


def _schema_for(struct_type: Any) -> dict | None:
    if struct_type is None:
        return None
    try:
        return arc.codec.schema(struct_type)
    except TypeError:
        return None


def build_openapi_spec(
    routes: list[RouteEntry], *, title: str = "ARC Gateway", version: str = "0.1.0"
) -> dict:
    paths: dict[str, dict] = {}

    for route in routes:
        if route.path == "/openapi.json":
            continue  # don't document the documentation endpoint

        path_item = paths.setdefault(_to_openapi_path(route.path), {})
        operation: dict[str, Any] = {
            "summary": route.summary or f"{route.method} {route.path}",
            "responses": {"200": {"description": "Successful response"}},
        }

        response_schema = _schema_for(route.response_schema)
        if response_schema is not None:
            operation["responses"]["200"]["content"] = {
                "application/json": {"schema": response_schema}
            }

        request_schema = _schema_for(route.request_schema)
        if request_schema is not None:
            operation["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": request_schema}},
            }

        param_names = [seg[1:-1] for seg in route.path.split("/") if seg.startswith("{")]
        if param_names:
            operation["parameters"] = [
                {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                for name in param_names
            ]

        path_item[route.method.lower()] = operation

    return {
        "openapi": "3.0.3",
        "info": {"title": title, "version": version},
        "paths": paths,
    }


def _to_openapi_path(path: str) -> str:
    # Gateway's own {param} syntax already matches OpenAPI's — no translation needed.
    return path if path.startswith("/") else f"/{path}"