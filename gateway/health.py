"""
gateway.health
-----------------
`GET /healthz` and `GET /readyz` — what a load balancer, a container orchestrator or a watchdog
asks to decide whether to send traffic to, or restart, a gateway process.

* `/healthz` (liveness): "this process is up and answering". Does no I/O at all, so it stays
  fast and green even when the database is down — a dead database is a reason to stop sending
  traffic (see `/readyz`), not to kill and restart every web worker.
* `/readyz` (readiness): "this process can do its job right now" — 200 when PostgreSQL and
  Redis (the ones that are installed) answer within a couple of seconds, 503 when one does not.

Both are unauthenticated, so what they say is deliberately thin: a check is "ok", "failed" or
"timeout", never the error text or the server version (those are logged, once per change).
They are answered before the middleware chain: no access-log line and no request metrics (a
balancer polls every second and would drown the real traffic), no rate limit, no session lookup,
and they keep answering while maintenance mode is on.

`/readyz` does real work per call, and anyone can call it, so the answer is shared: one check
runs at a time and its result is reused for a second.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from .request import encode_json

LIVENESS_PATH = "/healthz"
READINESS_PATH = "/readyz"
HEALTH_PATHS = frozenset({LIVENESS_PATH, READINESS_PATH})

#: The capabilities whose `health()` decides readiness. A gateway is useless without its
#: database and its cache/lock store; the others (mail, filer, ...) degrade a feature, not the
#: whole process.
READINESS_CAPABILITIES = ("pgdb", "redix")
#: Longest a single check may take before it counts as "timeout". Checks run side by side.
READINESS_CHECK_TIMEOUT_SECONDS = 2.0
#: How long one readiness answer is reused.
READINESS_CACHE_SECONDS = 1.0

_logger = logging.getLogger("gateway.health")

#: (ok?, {check name: "ok" | "failed" | "timeout"})
Readiness = tuple[bool, dict[str, str]]


class ReadinessProbe:
    """Asks the installed readiness capabilities whether they are healthy; shares one answer
    between concurrent and near-simultaneous callers."""

    def __init__(
        self,
        kernel: Any,
        *,
        timeout: float = READINESS_CHECK_TIMEOUT_SECONDS,
        cache_seconds: float = READINESS_CACHE_SECONDS,
    ) -> None:
        self._kernel = kernel
        self._timeout = timeout
        self._cache_seconds = cache_seconds
        self._answer: Readiness | None = None
        self._answered_at = 0.0
        self._running: asyncio.Future[Readiness] | None = None
        self._last: dict[str, str] = {}
        #: why each failing check failed: for the log only, never sent to the caller
        self._why: dict[str, str] = {}

    async def check(self) -> Readiness:
        if self._answer is not None and time.monotonic() - self._answered_at < self._cache_seconds:
            return self._answer
        if self._running is None:
            self._running = asyncio.ensure_future(self._run())
        # shield: a caller that hangs up must not cancel the check the others are waiting for
        return await asyncio.shield(self._running)

    async def _run(self) -> Readiness:
        try:
            names = [n for n in READINESS_CAPABILITIES if self._kernel.has(n)]
            outcomes = await asyncio.gather(*(self._one(n) for n in names))
            checks = dict(zip(names, outcomes))
            self._log_changes(checks)
            self._answer = (all(v == "ok" for v in checks.values()), checks)
            self._answered_at = time.monotonic()
            return self._answer
        finally:
            self._running = None

    async def _one(self, name: str) -> str:
        """One capability's state. A failure is asked once more straight away: the first call
        after a Redis or PostgreSQL restart finds the pooled connection dead and fails, which
        would otherwise keep /readyz at 503 for a whole poll after the server is back. A timeout
        is not retried: it has already used the whole budget."""
        state = await self._ask(name)
        return await self._ask(name) if state == "failed" else state

    async def _ask(self, name: str) -> str:
        health = getattr(self._kernel.get(name), "health", None)
        if not callable(health):
            return "ok"  # nothing to ask: not a reason to be unready
        try:
            result = await asyncio.wait_for(health(), timeout=self._timeout)
        except asyncio.TimeoutError:
            self._why[name] = f"no answer within {self._timeout:g}s"
            return "timeout"
        except Exception as exc:  # noqa: BLE001 - whatever it is, the answer is "not ready"
            self._why[name] = f"{type(exc).__name__}: {exc}"
            return "failed"
        if result.get("ok", True):
            return "ok"
        self._why[name] = str(result.get("error") or "reported itself unhealthy")
        return "failed"

    def _log_changes(self, checks: dict[str, str]) -> None:
        """One log line when a check changes state, not one per poll."""
        for name, state in checks.items():
            before = self._last.get(name, "ok")
            if state != before:
                if state == "ok":
                    _logger.info("readiness: %s is answering again", name)
                else:
                    _logger.warning(
                        "readiness: %s is %s (%s) — /readyz now answers 503",
                        name, state, self._why.get(name, "no detail"),
                    )
            self._last[name] = state
        self._why.clear()


async def serve(
    scope: dict, send: Callable[[dict], Awaitable[None]], probe: ReadinessProbe
) -> None:
    """Answer one request to a health path. GET gets a body, HEAD the same headers without one."""
    method = scope["method"]
    if method not in ("GET", "HEAD"):
        await _respond(send, 405, {"error": "method not allowed"}, head=False, allow="GET, HEAD")
        return
    if scope["path"] == LIVENESS_PATH:
        await _respond(send, 200, {"status": "ok"}, head=method == "HEAD")
        return
    ready, checks = await probe.check()
    await _respond(
        send,
        200 if ready else 503,
        {"status": "ok" if ready else "unavailable", "checks": checks},
        head=method == "HEAD",
    )


async def _respond(
    send: Callable[[dict], Awaitable[None]],
    status: int,
    content: dict,
    *,
    head: bool,
    allow: str | None = None,
) -> None:
    body = encode_json(content)
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        # an answer must never be cached by a proxy in front: it is only true right now
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
    ]
    if allow:
        headers.append((b"allow", allow.encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b"" if head else body})
