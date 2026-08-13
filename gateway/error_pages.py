"""
gateway.error_pages
--------------------
HTML error pages for 404/403/503, shown only to an actual browser
navigation — every other caller (a JS fetch(), a mobile app, curl, another
service) keeps getting the plain JSON body gateway has always returned, so
no existing API client's error handling changes.

Negotiation is deliberately simple: a browser navigating to a URL always
sends `Accept: text/html,...` explicitly (every major browser does this for
a top-level navigation); a `fetch()`/XHR call only does that if the caller
wrote it that way on purpose, and the fetch() default with no headers set
is `Accept: */*` — no literal "text/html" substring. So "the Accept header
mentions text/html" is a reliable enough signal for "show the pretty page",
without needing a full RFC 7231 q-value parser for what is, in the end, a
cosmetic decision — worst case for a misclassified request is a JSON body
instead of an HTML one (or vice versa), never a broken request.

Only 404/403/503 get a custom page — send_error() falls back to gateway's
ordinary send_json() for every other status code, so nothing else in
gateway's error handling has to know this module exists.
"""

from __future__ import annotations

from typing import Any

from .request import get_header, send_bytes, send_json

_PAGES: dict[int, tuple[str, str, str]] = {
    404: (
        "Page not found",
        "404",
        "The page you're looking for doesn't exist, or it may have moved.",
    ),
    403: (
        "Access denied",
        "403",
        "You don't have permission to view this page.",
    ),
    503: (
        "Down for maintenance",
        "503",
        "We're making some improvements and will be back shortly.",
    ),
}


def _wants_html(scope: dict) -> bool:
    accept = get_header(scope, b"accept")
    return accept is not None and b"text/html" in accept.lower()


def _render(status_code: int) -> bytes:
    title, code, message = _PAGES[status_code]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  html, body {{
    height: 100%; margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: #f6f7f5; color: #1c1f1d;
  }}
  @media (prefers-color-scheme: dark) {{
    html, body {{ background: #141613; color: #e9ebe6; }}
    .code {{ color: #5fb0a8 !important; }}
    .card {{ background: #1c1f1b !important; border-color: #2b2f29 !important; }}
  }}
  body {{ display: flex; align-items: center; justify-content: center; padding: 1.5rem; }}
  .card {{
    max-width: 26rem; width: 100%; text-align: center;
    background: #ffffff; border: 1px solid #e3e6df; border-radius: 10px;
    padding: 2.5rem 2rem;
  }}
  .code {{
    font-size: 3rem; font-weight: 700; letter-spacing: -0.02em;
    color: #3d7a70; margin: 0 0 0.5rem;
  }}
  h1 {{ font-size: 1.25rem; margin: 0 0 0.6rem; }}
  p {{ font-size: 0.95rem; line-height: 1.5; color: inherit; opacity: 0.75; margin: 0; }}
</style>
</head>
<body>
  <div class="card">
    <div class="code">{code}</div>
    <h1>{title}</h1>
    <p>{message}</p>
  </div>
</body>
</html>
""".encode("utf-8")


async def send_error(
    send,
    scope: dict,
    status_code: int,
    json_body: Any,
    *,
    extra_headers: dict[str, str] | None = None,
) -> None:
    """Drop-in replacement for `await send_json(send, status_code, json_body,
    extra_headers=extra_headers)` at any of gateway's error-emitting call
    sites — identical JSON behavior for anything that isn't a browser
    navigating to one of the three status codes above."""
    if status_code in _PAGES and _wants_html(scope):
        await send_bytes(
            send, status_code, _render(status_code), content_type="text/html; charset=utf-8",
            extra_headers=extra_headers,
        )
        return
    await send_json(send, status_code, json_body, extra_headers=extra_headers)
