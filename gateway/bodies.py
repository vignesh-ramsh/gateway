"""
gateway.bodies
--------------
What the gateway does about a big request body, before it is read and after the reply.

Found by a load test of a live site:

* The body was read into memory right after the route matched, before anything checked that the caller
  was allowed to send it, and without any limit on how many were in memory at once. Four anonymous 59 MB
  uploads took a worker from 425 to 594 MB, and nginx lets 60 MB through to an upload route (it cannot
  know who is asking). `BodyBudget` bounds the bytes of bodies one worker holds at once; the route's own
  `authorize` hook (relay passes its role check) is run first, so a caller who would be refused is
  refused before any of the body is read.
* A reply sent before the body was read made nginx, still sending it, fail with EPIPE and answer 502 in
  place of the real 403 or 429 (one upload in 693). `serve_and_drain` reads and discards what is left,
  after the reply has gone, so the client gets the status it earned.
"""

from __future__ import annotations

import asyncio
import collections
from collections.abc import Awaitable, Callable

#: A declared body at least this big has its caller authorized before it is read; below it the cost of
#: reading first is small and the order of the checks stays as it always was.
EARLY_AUTH_BODY_BYTES = 64 * 1024
#: Bodies below this are not counted against the budget (nor made to wait for it).
RESERVE_MIN_BYTES = 64 * 1024
#: How long a request waits for room in the budget before it is told to come back.
BUDGET_WAIT_SECONDS = 5.0
BUDGET_RETRY_AFTER_SECONDS = 2
#: The most that is read and thrown away after an early reply, and for how long. nginx has already
#: taken the whole body (and enforced its own ceiling) when it hands it over, so this is a few ms; the
#: limits only matter to a client talking to the gateway directly.
DRAIN_MAX_BYTES = 128 * 1024 * 1024
DRAIN_MAX_SECONDS = 5.0


def body_size_hint(scope: dict, *, ceiling: int) -> int:
    """How many bytes of body to plan for: the declared Content-Length (no more than `ceiling`), 0 when
    there is no body, and the ceiling itself when the size is not known up front (chunked, or a length
    that is not a number)."""
    length: bytes | None = None
    chunked = False
    for name, value in scope.get("headers", ()):
        name = name.lower()
        if name == b"content-length":
            length = value
        elif name == b"transfer-encoding":
            chunked = True
    if length is not None:
        try:
            declared = int(length)
        except ValueError:
            return ceiling
        return ceiling if declared < 0 else min(declared, ceiling)
    return ceiling if chunked else 0


def declared_body_length(scope: dict) -> int | None:
    """The Content-Length the client declared, or None when there is none (chunked, no body) or it is not a
    usable number. For a streamed body, where the length is a cheap early refusal, never a promise."""
    for name, value in scope.get("headers", ()):
        if name.lower() == b"content-length":
            try:
                declared = int(value)
            except ValueError:
                return None
            return declared if declared >= 0 else None
    return None


class BodyBudgetBusy(Exception):
    """No room in the budget within the wait. Says of itself that it is capacity, not a bug
    (`http_status`, `retry_after`): the gateway answers 503 with Retry-After, like a full database pool."""

    http_status = 503
    retry_after = BUDGET_RETRY_AFTER_SECONDS

    def __init__(self, in_flight: int, limit: int) -> None:
        super().__init__(f"{in_flight} bytes of request bodies in memory, limit {limit}")


class BodyBudget:
    """The bytes of request bodies one worker may hold at once. A request reserves what it declares
    (what its route allows, when it declares nothing) before reading, and gives it back when it is done.
    One that does not fit waits its turn, first come first served, and is refused as busy after
    `wait_seconds`. A body bigger than the whole budget is let in when nothing else is, rather than
    never. A limit of 0 turns all of this off.

    Single event loop, no threads: the counters need no lock, and `release` is plain (it must be safe in
    a `finally`, including one reached by cancellation)."""

    def __init__(self, limit_bytes: int, *, wait_seconds: float | None = None) -> None:
        self.limit = limit_bytes
        self._wait_seconds = BUDGET_WAIT_SECONDS if wait_seconds is None else wait_seconds
        self.in_flight = 0
        self.rejected_total = 0
        self._waiters: collections.deque[tuple[int, asyncio.Future]] = collections.deque()

    @property
    def waiting(self) -> int:
        return len(self._waiters)

    def _fits(self, nbytes: int) -> bool:
        return self.in_flight == 0 or self.in_flight + nbytes <= self.limit

    async def reserve(self, nbytes: int) -> int:
        """Take `nbytes` of the budget, waiting if need be. Returns what was taken (0 when the budget is
        off or the body is small): hand that to `release`. Raises BodyBudgetBusy after the wait."""
        if self.limit <= 0 or nbytes < RESERVE_MIN_BYTES:
            return 0
        if not self._waiters and self._fits(nbytes):
            self.in_flight += nbytes
            return nbytes
        entry = (nbytes, asyncio.get_running_loop().create_future())
        self._waiters.append(entry)
        try:
            await asyncio.wait_for(entry[1], self._wait_seconds)
        except BaseException as exc:
            if entry[1].done() and not entry[1].cancelled():
                self.release(nbytes)  # it was granted just as this gave up: nobody else will give it back
            else:
                try:
                    self._waiters.remove(entry)
                except ValueError:
                    pass
                self._grant_waiting()  # the one at the head may have been this one; the next may fit
            if isinstance(exc, TimeoutError):
                self.rejected_total += 1
                raise BodyBudgetBusy(self.in_flight, self.limit) from None
            raise
        return nbytes

    def release(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        self.in_flight = max(0, self.in_flight - nbytes)
        self._grant_waiting()

    def _grant_waiting(self) -> None:
        while self._waiters:
            nbytes, future = self._waiters[0]
            if future.done():  # gave up and not yet removed
                self._waiters.popleft()
                continue
            if not self._fits(nbytes):
                return
            self._waiters.popleft()
            self.in_flight += nbytes
            future.set_result(None)


async def serve_and_drain(
    app: Callable[[dict, Callable, Callable], Awaitable[None]],
    scope: dict,
    receive: Callable[[], Awaitable[dict]],
    send: Callable[[dict], Awaitable[None]],
    *,
    max_bytes: int = DRAIN_MAX_BYTES,
    max_seconds: float = DRAIN_MAX_SECONDS,
) -> None:
    """Run `app`; once it has returned (so its reply is out), read and discard whatever it left of the
    request body. Bounded by bytes and by time, and never a reason for the request to fail: it has been
    answered already. An `app` that raised propagates as it did, without draining."""
    finished = False

    async def tracking_receive() -> dict:
        nonlocal finished
        message = await receive()
        if message.get("type") != "http.request" or not message.get("more_body", False):
            finished = True
        return message

    await app(scope, tracking_receive, send)
    if finished:
        return
    try:
        await asyncio.wait_for(_discard(tracking_receive, max_bytes), max_seconds)
    except Exception:  # noqa: BLE001 - the reply is out; a failure here (a timeout included) changes nothing for the client
        pass


async def _discard(receive: Callable[[], Awaitable[dict]], max_bytes: int) -> None:
    total = 0
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            return  # the client went away
        total += len(message.get("body", b""))
        if not message.get("more_body", False) or total >= max_bytes:
            return
