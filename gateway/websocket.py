"""
gateway.websocket
-------------------
The ASGI websocket-scope counterpart to request.py's Request/Response —
wraps the raw (scope, receive, send) triple the ASGI spec hands a
websocket connection into a small, ergonomic object a plugin's handler
actually works with. Every JSON message goes through arc.codec, the same
shared serialization layer every HTTP body already routes through
(arc.codec's own docstring: "one shared implementation so plugins stop
reinventing serialization each their own way") — WS gets no separate,
second encoding convention.

ASGI's own websocket protocol, for reference (this module's entire job is
hiding this from a handler):
  connect    -> {"type": "websocket.connect"}                   (once, first)
  accept     <- {"type": "websocket.accept", ...}                or
  reject     <- {"type": "websocket.close", "code": ...}         (before accept)
  receive    -> {"type": "websocket.receive", "text"|"bytes": ...}
  disconnect -> {"type": "websocket.disconnect", "code": ...}
  send       <- {"type": "websocket.send", "text"|"bytes": ...}
  close      <- {"type": "websocket.close", "code": ...}
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable

import arc

# 1008 Policy Violation — the one standard WS close code that actually
# means "the server rejected this on authorization grounds", used when a
# handshake's roles check fails. 1000 (Normal Closure) is the default for
# everything else (an ordinary, expected close).
POLICY_VIOLATION = 1008


class WebSocketDisconnect(Exception):
    """Raised out of receive_raw()/receive_json()/iter_json() the moment
    the client disconnects (a real ASGI `websocket.disconnect` event) —
    lets a handler's own read loop end via a normal try/except (or, for
    iter_json(), not even that — see its own docstring) instead of having
    to type-check a sentinel after every single receive()."""

    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"WebSocket disconnected (code={code})")


class WebSocketConnection:
    """Handed to a plugin's own `add_ws_route` handler, already past the
    roles/origin checks (see gateway/__init__.py's _dispatch_websocket) —
    a handler never sees a connection it isn't authorized to have."""

    def __init__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
        *,
        identity: Any,
        client_ip: str | None,
        request_id: str,
        path_params: dict[str, str],
        subscribe: Callable[["WebSocketConnection", str], Awaitable[None]],
        unsubscribe: Callable[["WebSocketConnection", str], Awaitable[None]],
    ) -> None:
        self.scope = scope
        self.identity = identity
        self.client_ip = client_ip
        self.request_id = request_id
        self.path_params = path_params
        self._receive = receive
        self._send = send
        self._subscribe_hub = subscribe
        self._unsubscribe_hub = unsubscribe
        self._channels: set[str] = set()
        self.accepted = False
        self.closed = False
        # Distinct from `closed` on purpose: this means "the wire is
        # already gone, don't bother trying to send" (set by receive_raw
        # the moment a real websocket.disconnect arrives); `closed` means
        # "cleanup has already run" (set by close() itself). Conflating
        # them used to make close()'s own idempotency guard skip the
        # channel-unsubscribe loop entirely whenever the CLIENT
        # disconnected first — a connection that quit was never removed
        # from its channels' subscriber sets, a real leak caught live by
        # this module's own test suite.
        self._wire_dead = False

    # ------------------------------------------------------------------ #
    # Handshake / lifecycle
    # ------------------------------------------------------------------ #
    async def accept(self, *, subprotocol: str | None = None) -> None:
        if self.accepted:
            return
        await self._send({"type": "websocket.accept", "subprotocol": subprotocol})
        self.accepted = True

    async def close(self, code: int = 1000) -> None:
        # Idempotent on purpose: a handler's own cleanup path and this
        # connection's OWN disconnect handling (gateway/__init__.py's
        # _dispatch_websocket, in a finally block) both call close() —
        # the channel cleanup below must still run exactly once
        # regardless of which caller gets here first, or how the
        # connection ended (server closing it vs. the client having
        # already gone) — only the "send the actual close frame" part is
        # conditional on the wire still being alive.
        if self.closed:
            return
        self.closed = True
        for channel in list(self._channels):
            await self._unsubscribe_hub(self, channel)
        if self._wire_dead:
            return
        try:
            await self._send({"type": "websocket.close", "code": code})
        except Exception:
            # Already gone despite _wire_dead saying otherwise (a race,
            # or a connection that dropped some other way) — closing an
            # already-closed connection is a no-op, not an error a
            # handler's own cleanup path should have to guard against.
            pass

    # ------------------------------------------------------------------ #
    # Broadcast channels — a connection joins/leaves these explicitly
    # (a handler decides what a given connection cares about, e.g. from a
    # path param or the caller's own identity), rather than every
    # connection on a route implicitly sharing one fixed channel. See
    # GatewayProvider.broadcast()'s own docstring for the delivery side.
    # ------------------------------------------------------------------ #
    async def subscribe(self, channel: str) -> None:
        if channel in self._channels:
            return
        await self._subscribe_hub(self, channel)
        self._channels.add(channel)

    async def unsubscribe(self, channel: str) -> None:
        if channel not in self._channels:
            return
        await self._unsubscribe_hub(self, channel)
        self._channels.discard(channel)

    # ------------------------------------------------------------------ #
    # Receiving
    # ------------------------------------------------------------------ #
    async def receive_raw(self) -> dict:
        """One raw ASGI websocket event: `websocket.receive` (carries
        "text" or "bytes") or `websocket.disconnect`, raised here as
        WebSocketDisconnect rather than handed back as a message every
        caller has to remember to type-check first."""
        message = await self._receive()
        if message["type"] == "websocket.disconnect":
            self._wire_dead = True
            raise WebSocketDisconnect(message.get("code", 1000))
        return message

    async def receive_text(self) -> str:
        message = await self.receive_raw()
        if message.get("text") is not None:
            return message["text"]
        # A binary frame arrived where text was expected — decode as
        # UTF-8 rather than silently handing back the wrong type. Every
        # frame THIS module itself sends is text (send_json below), so a
        # well-behaved client speaking this protocol never actually hits
        # this branch; it only matters for a client that chose to send
        # its JSON as a binary frame instead.
        return (message.get("bytes") or b"").decode("utf-8")

    async def receive_json(self, *, type: Any = None) -> Any:
        raw = await self.receive_text()
        if type is not None:
            return arc.codec.decode(raw, type=type)
        return arc.codec.decode(raw)

    async def iter_json(self, *, type: Any = None) -> AsyncIterator[Any]:
        """Async-iterate every inbound message as decoded JSON until the
        client disconnects — the loop just ends, no exception escapes
        this iterator. Same "iterate until it's naturally over" ergonomics
        as any other async-for loop in this codebase, rather than every
        handler needing its own try/except WebSocketDisconnect around a
        hand-rolled `while True`."""
        try:
            while True:
                yield await self.receive_json(type=type)
        except WebSocketDisconnect:
            return

    # ------------------------------------------------------------------ #
    # Sending
    # ------------------------------------------------------------------ #
    async def send_text(self, text: str) -> None:
        await self._send({"type": "websocket.send", "text": text})

    async def send_bytes(self, data: bytes) -> None:
        await self._send({"type": "websocket.send", "bytes": data})

    async def send_json(self, value: Any) -> None:
        # Text frame, not binary: arc.codec.encode's msgspec output is
        # already valid UTF-8 JSON bytes, and a text frame is what a
        # browser's `ws.onmessage` hands back as a plain string
        # (`JSON.parse(event.data)` needs no extra Blob/ArrayBuffer
        # decoding step on the client) — the common case gets the
        # simplest client-side code.
        await self.send_text(arc.codec.encode(value).decode("utf-8"))
