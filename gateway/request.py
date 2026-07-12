"""
gateway.request
-------------------
The small Request/Response surface handlers see. Deliberately minimal — this
is transport, not an application framework (§2: Gateway does not own business
validation). `Request.validated` carries the arc.codec-decoded body when a
route declared a `request_schema`; handlers that need raw access still have
`.body`/`.json()`.

Decoding/encoding goes through arc.codec (not msgspec directly, even though
that's what arc.codec itself uses underneath) — this used to import msgspec
and call it directly, which was the same job psqldb's jsonb columns were
independently reinventing with stdlib json. One shared codec now; gateway
no longer needs msgspec as its own dependency at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import arc


class HTTPError(Exception):
    """Raise from a handler to produce a specific HTTP status + JSON body."""

    def __init__(self, status_code: int, detail: Any = None) -> None:
        self.status_code = status_code
        self.detail = detail if detail is not None else {"error": _phrase(status_code)}
        super().__init__(f"HTTP {status_code}: {self.detail}")


@dataclass
class Response:
    """Return one of these from a handler for a non-200 status or custom headers.
    Otherwise, just return a plain JSON-serializable value (dict/list/Struct)
    and Gateway wraps it as a 200 automatically."""

    content: Any
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Request:
    method: str
    path: str
    path_params: dict[str, str]
    query_params: dict[str, list[str]]
    headers: dict[str, str]  # lowercase header names
    body: bytes
    scope: dict  # raw ASGI scope, for advanced/edge-case access
    validated: Any = None  # set when the matched route declared a request_schema
    identity: Any = None  # set by the identity-resolution middleware, if authn is present

    def json(self, schema: Any | None = None) -> Any:
        if schema is not None:
            return arc.codec.decode(self.body, type=schema)
        return arc.codec.decode(self.body)

    def query(self, name: str, default: str | None = None) -> str | None:
        values = self.query_params.get(name)
        return values[0] if values else default


async def read_body(receive) -> bytes:
    chunks = []
    while True:
        message = await receive()
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def headers_from_scope(scope: dict) -> dict[str, str]:
    return {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in scope.get("headers", [])
    }


def get_header(scope: dict, name: bytes) -> bytes | None:
    name = name.lower()
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v
    return None


def query_params_from_scope(scope: dict) -> dict[str, list[str]]:
    raw = scope.get("query_string", b"")
    if not raw:
        return {}
    return parse_qs(raw.decode("latin-1"), keep_blank_values=True)


def encode_json(value: Any) -> bytes:
    return arc.codec.encode(value)


_PHRASES = {
    200: "OK", 201: "Created", 204: "No Content",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 422: "Unprocessable Entity",
    500: "Internal Server Error",
}


def _phrase(status_code: int) -> str:
    return _PHRASES.get(status_code, "Error")


async def send_json(
    send,
    status_code: int,
    content: Any,
    *,
    extra_headers: dict[str, str] | None = None,
) -> None:
    body = encode_json(content)
    headers = [(b"content-type", b"application/json")]
    for k, v in (extra_headers or {}).items():
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    await send(
        {"type": "http.response.start", "status": status_code, "headers": headers}
    )
    await send({"type": "http.response.body", "body": body})