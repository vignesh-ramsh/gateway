"""
gateway.csp
-----------
A Content-Security-Policy for a page that carries its own inline `<style>`/`<script>`.

The global policy (`gateway_csp`) has no 'unsafe-inline', so an inline block is refused by the
browser. The few pages ARC serves with one (its error pages, wschat's demo page) used to be the
reason the policy could only run in Report-Only mode. Instead each of them sends a policy of its
own, built here from the page itself: the sha256 of each inline block is listed, so exactly that
code runs and nothing else does - an injected `<script>` has a different hash and is still refused.

The gateway adds the global policy only to a response that does not already have one, so a page
that sends this loses nothing and the rest of the site keeps the strict default.
"""

from __future__ import annotations

import base64
import hashlib
import re

_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
# an inline script has no src attribute; a <script src=...> is covered by 'self'
_SCRIPT_BLOCK = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def source_hash(code: str) -> str:
    """The CSP hash source for one inline block: `'sha256-<base64 of the SHA-256 of its text>'`."""
    digest = hashlib.sha256(code.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def inline_page_csp(html: str, *, connect: str = "") -> str:
    """The policy for `html`: nothing is allowed except its own inline `<style>` and `<script>`
    blocks (by hash). `connect` is what fetch/XHR/WebSocket may reach (`connect-src`); empty means
    nothing at all."""
    styles = " ".join(source_hash(block) for block in _STYLE_BLOCK.findall(html))
    scripts = " ".join(source_hash(block) for block in _SCRIPT_BLOCK.findall(html))
    parts = ["default-src 'none'"]
    if scripts:
        parts.append(f"script-src {scripts}")
    if styles:
        parts.append(f"style-src {styles}")
    if connect:
        parts.append(f"connect-src {connect}")
    parts += ["base-uri 'none'", "form-action 'none'", "frame-ancestors 'self'"]
    return "; ".join(parts)
