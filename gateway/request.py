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
and call it directly, which was the same job pgdb's jsonb columns were
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
class Cookie:
    """One Set-Cookie header. A plain `dict[str, str]` (like Response.headers)
    can only hold one value per key, but HTTP represents multiple cookies as
    multiple *separate* Set-Cookie header lines — so cookies are their own
    list, not folded into `headers`. `secure` defaults to True; pass False
    explicitly for plain-HTTP dev/localhost, where a Secure cookie is
    silently refused by the browser entirely (never sent, never stored) —
    real behavior to test against, not a theoretical footnote."""

    name: str
    value: str
    max_age: int | None = None  # seconds; None = session cookie (cleared on browser close)
    path: str = "/"
    http_only: bool = True
    secure: bool = True
    same_site: str = "Lax"

    @classmethod
    def cleared(cls, name: str, *, path: str = "/", secure: bool = True) -> "Cookie":
        """A Set-Cookie that deletes an existing cookie (Max-Age=0) —
        logout()'s own use, clearing both arc_session and csrf_token."""
        return cls(name=name, value="", max_age=0, path=path, secure=secure)

    def encode(self) -> bytes:
        parts = [f"{self.name}={self.value}", f"Path={self.path}"]
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        if self.http_only:
            parts.append("HttpOnly")
        if self.secure:
            parts.append("Secure")
        parts.append(f"SameSite={self.same_site}")
        return "; ".join(parts).encode("latin-1")


@dataclass
class Response:
    """Return one of these from a handler for a non-200 status or custom headers.
    Otherwise, just return a plain JSON-serializable value (dict/list/Struct)
    and Gateway wraps it as a 200 automatically."""

    content: Any
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[Cookie] = field(default_factory=list)
    # "application/json" (default) -> content is any JSON-encodable value,
    # sent via arc.codec through send_json, same as every plain-dict return.
    # Anything else -> content must already be str/bytes; sent as-is via
    # send_bytes with this as its Content-Type — e.g. authn's impersonate()
    # shell page, which needs to hand back real HTML a browser renders,
    # not a JSON string containing HTML.
    media_type: str = "application/json"


@dataclass
class StreamResponse:
    """Return one of these (or let arc.relay.stream()'s own wiring hand one
    back for you, see relay/__init__.py's _wire_gateway_route) to keep the
    connection open and send pieces as they're produced, instead of
    buffering the whole response first.

    `media_type="application/x-ndjson"` (the default): `source` is any
    async iterator of JSON-encodable chunks — each one is arc.codec-encoded
    and sent as one newline-delimited JSON line, chosen over SSE's
    `text/event-stream` since this isn't tied to GET/EventSource — a POST
    that runs a long action and reports its own progress on the same
    connection is the primary use case, not just GET-triggered live feeds.

    Any OTHER `media_type`: `source` is any async iterator of raw `bytes`
    chunks, sent as-is with NO JSON framing — for streaming genuinely
    binary content (e.g. filer's file downloads) at constant memory,
    instead of buffering the whole body first the way `Response`'s own
    non-JSON path (`media_type` there too) has to."""

    source: Any
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    media_type: str = "application/x-ndjson"


async def send_stream(send, response: "StreamResponse") -> None:
    """Sends `http.response.start` once, then one `http.response.body`
    message per item `response.source` yields (more_body=True throughout),
    then a final empty one (more_body=False) to close the response. Once
    the first message is sent, the status code can never change — an
    exception raised partway through `source` can't become a different
    HTTP status the way a normal handler's exception can; the caller
    (gateway._dispatch) is expected to log it and let the stream simply end
    (a truncated stream is itself the client-visible signal something went
    wrong, the same way a truncated file download is)."""
    headers = [(b"content-type", response.media_type.encode("latin-1"))]
    for k, v in (response.headers or {}).items():
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    await send({"type": "http.response.start", "status": response.status_code, "headers": headers})
    # ndjson (the default): each chunk is a JSON-able value, framed with a
    # trailing newline. Anything else: chunks already ARE the raw bytes to
    # send — no framing, no encoding, exactly what a binary stream needs.
    raw = response.media_type != "application/x-ndjson"
    async for chunk in response.source:
        body = chunk if raw else (encode_json(chunk) + b"\n")
        await send({"type": "http.response.body", "body": body, "more_body": True})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


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
    client_ip: str | None = None  # set by client_ip_middleware — proxy-aware if
    # trusted_proxies is configured, raw scope["client"]
    # otherwise
    json_limit: int | None = None  # largest body json() will decode; None = no limit of its own
    cookies: dict[str, str] = field(default_factory=dict)  # parsed from the Cookie header
    request_id: str | None = None  # set by request_id_middleware — one correlation id
    # per request, echoed back as the X-Request-ID
    # response header and carried into relay's own
    # CallContext (so a background job this request
    # enqueues can be traced back to it)

    def json(self, schema: Any | None = None) -> Any:
        """The body decoded as JSON (and validated against `schema` when given). Raises HTTPError 413
        for a body over `json_limit`, without decoding it: decoding runs on the event loop and holds
        the GIL, so its cost is every other request's wait. Raises arc.codec.CodecError for bad JSON."""
        if self.json_limit is not None and len(self.body) > self.json_limit:
            raise HTTPError(413, {"error": "JSON body too large", "limit_bytes": self.json_limit})
        if schema is not None:
            return arc.codec.decode(self.body, type=schema)
        return arc.codec.decode(self.body)

    def form(self) -> Any:
        """Parses `self.body` as multipart/form-data using this request's own
        Content-Type header (for the boundary). Lazy import to avoid a
        request.py <-> multipart.py circular import at module load time —
        multipart.py itself imports HTTPError from here."""
        from .multipart import parse_multipart_form

        return parse_multipart_form(self.body, self.headers.get("content-type", ""))

    def query(self, name: str, default: str | None = None) -> str | None:
        values = self.query_params.get(name)
        return values[0] if values else default


async def read_body(receive, *, max_bytes: int | None = None) -> bytes:
    """max_bytes=None means unbounded (today's original behavior) — callers
    that care about a size ceiling (gateway._dispatch, wired to the
    gateway_max_body_bytes setting) pass one explicitly. Once exceeded, stops
    ACCUMULATING further chunks (bounding memory) but keeps DRAINING the ASGI
    receive channel until more_body is False, so the connection is closed
    cleanly rather than left hanging with unread body still incoming."""
    chunks = []
    total = 0
    exceeded = False
    while True:
        message = await receive()
        chunk = message.get("body", b"")
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            exceeded = True
        else:
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    if exceeded:
        raise HTTPError(413, {"error": "payload too large", "limit_bytes": max_bytes})
    return b"".join(chunks)


def headers_from_scope(scope: dict) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def get_header(scope: dict, name: bytes) -> bytes | None:
    name = name.lower()
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v
    return None


def cookies_from_scope(scope: dict) -> dict[str, str]:
    """The one Cookie-header parser every cookie reader in gateway shares
    (csrf_middleware, _dispatch's own Request construction) — previously
    duplicated inline in csrf_middleware alone."""
    raw = get_header(scope, b"cookie")
    if not raw:
        return {}
    out: dict[str, str] = {}
    for part in raw.decode("latin-1").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def query_params_from_scope(scope: dict) -> dict[str, list[str]]:
    raw = scope.get("query_string", b"")
    if not raw:
        return {}
    return parse_qs(raw.decode("latin-1"), keep_blank_values=True)


class EncodedJSON(bytes):
    """JSON that is already encoded. Return one from a handler (or hand one to send_json) to have it sent
    as it is, with no second encode: for a document that is built once and served many times."""


def encode_json(value: Any) -> bytes:
    if isinstance(value, EncodedJSON):
        return value
    return arc.codec.encode(value)


_PHRASES = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
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
    cookies: "list[Cookie] | None" = None,
) -> None:
    body = encode_json(content)
    await send_bytes(
        send,
        status_code,
        body,
        content_type="application/json",
        extra_headers=extra_headers,
        cookies=cookies,
    )


def _parse_if_none_match(raw: str) -> str:
    """Bare hex digest from a client's If-None-Match value — strips the
    surrounding quotes every real ETag carries, and an optional leading
    `W/` (what a compressing intermediary like nginx rewrites a STRONG
    ETag into when it gzips the response on the fly, since nginx 1.7.3 —
    the compressed bytes are a different representation of the same
    content, so HTTP's weak-validator semantics apply; this is correct,
    spec-conforming behavior on the intermediary's part, not something to
    route around there). A client faithfully replaying back exactly what
    it was given still needs to match send_json_with_etag's own STRONG
    tag underneath that prefix, so it's stripped here before comparing.

    Doesn't parse a comma-separated multi-value If-None-Match (rare for a
    same-origin API client that's just replaying back a single value it
    was given) — an unparsed value simply never matches, which costs a
    redundant 200 instead of ever risking a wrong 304."""
    value = raw.strip()
    if value.startswith("W/"):
        value = value[2:]
    return value.strip('"')


async def send_json_with_etag(
    send,
    status_code: int,
    content: Any,
    *,
    etag: bool,
    if_none_match: str | None,
    extra_headers: dict[str, str] | None = None,
    cookies: "list[Cookie] | None" = None,
) -> None:
    """The one call site gateway._dispatch needs for BOTH its JSON
    branches — `etag` is `route.etag` (see GatewayProvider.add_route's
    own docstring), so this degrades to a plain send_json itself whenever
    the route didn't opt in, or the status isn't 200 (an error/redirect
    has no conditional-GET semantics to apply): callers never need their
    own if/else between this and send_json. `if_none_match` is the
    caller's raw If-None-Match header value (or None if it sent none) —
    gateway._dispatch is the one real caller, passing
    `request.headers.get("if-none-match")` straight through.

    The ETag itself is a STRONG validator: `arc.hash()` (SHA-256) of the
    exact body bytes about to be sent, quoted per RFC 9110 — genuinely
    content-addressed, not a weaker "semantically equivalent" claim. Pure
    bandwidth optimization, nothing else: the handler that produced
    `content` already ran in full by the time this is called (there is no
    way to know the CURRENT body matches without producing it first), and
    this sets no caching policy of its own — whatever Cache-Control the
    caller already put in `extra_headers` (gateway._dispatch's own
    "no-store" default, unless a handler set its own) is left untouched
    and applied to the 304 too, exactly as it would be to a 200."""
    if not etag or status_code != 200:
        await send_json(send, status_code, content, extra_headers=extra_headers, cookies=cookies)
        return

    body = encode_json(content)
    response_etag = f'"{arc.hash(body)}"'
    headers = {**(extra_headers or {}), "ETag": response_etag}

    if if_none_match is not None and arc.verify_hash(body, _parse_if_none_match(if_none_match)):
        await send_bytes(send, 304, b"", content_type="application/json", extra_headers=headers, cookies=cookies)
        return
    await send_bytes(send, status_code, body, content_type="application/json", extra_headers=headers, cookies=cookies)


async def send_bytes(
    send,
    status_code: int,
    body: bytes,
    *,
    content_type: str = "application/octet-stream",
    extra_headers: dict[str, str] | None = None,
    cookies: "list[Cookie] | None" = None,
) -> None:
    """The non-JSON counterpart to send_json — used for SPA-mount static
    file serving (gateway/__init__.py's _try_serve_spa), where the
    content-type is derived from the file itself, never hardcoded."""
    headers = [(b"content-type", content_type.encode("latin-1"))]
    for k, v in (extra_headers or {}).items():
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    # Each cookie is its OWN header line — a dict (extra_headers above) can
    # only hold one value per key, which is why cookies never went through
    # that path; the ASGI headers list has no such one-value-per-key limit.
    for cookie in cookies or []:
        headers.append((b"set-cookie", cookie.encode()))
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})
