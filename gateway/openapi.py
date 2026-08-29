"""
gateway.openapi
-------------------
Builds an OpenAPI 3.0 document from whatever routes are currently
registered. The only real content right now is hand-written demo routes —
that's the honest scope for Phase 2. Real Resource-derived schemas arrive
with Relay (Phase 3), which will call `add_route` the same way any other
caller does; this module doesn't need to change when that happens.

Also renders a small, static, server-side HTML page (render_openapi_html)
that wraps the same route data as a human-browsable UI — a sidebar of
every plugin, one row per PATH (every method it supports as badges on
that one row, not a separate row each), and a click-to-open modal per
route showing request/response schema and allowed roles, tabbed by
method when there's more than one — GET /openapi, alongside the raw GET
/openapi.json this module already produced.

Deliberately NOT a vendored Swagger UI/ReDoc, and NO JAVASCRIPT AT ALL:
gateway's default CSP has no script-src/style-src exception, so an
inline <script> would just be silently blocked by the browser (see
security_headers_middleware/DEFAULT_CSP) — rather than special-case this
one page's CSP, the modal (CSS :target) and the tabs (radio inputs +
:checked ~ sibling selectors, purely positional — see _METHOD_ORDER)
are both built with CSS alone. No new dependency either. CSS lives in
its own same-origin file (GET /openapi.css) for the same CSP reason."""

from __future__ import annotations

import html
import json
from typing import Any

import arc

from .router import WEBSOCKET_METHOD, RouteEntry


def _schema_for(value: Any) -> dict | None:
    if value is None:
        return None
    if isinstance(value, dict):
        # Already a schema-shaped dict — relay's own hand-built object
        # schema for a plain-kwargs whitelisted function (no single Struct
        # type to derive one from; see relay.whitelisting._request_schema_for).
        return value
    try:
        return arc.codec.schema(value)
    except TypeError:
        return None


#: The documentation surface's own routes — never listed by themselves,
#: in either the JSON spec or the HTML page below.
_DOC_PATHS = frozenset({"/openapi.json", "/openapi", "/openapi.css"})


def build_openapi_spec(
    routes: list[RouteEntry], *, title: str = "ARC Gateway", version: str = "0.1.0"
) -> dict:
    paths: dict[str, dict] = {}

    for route in routes:
        if route.path in _DOC_PATHS:
            continue  # don't document the documentation endpoints

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


#: Fixed display order for a grouped row's method badges / a modal's tabs —
#: also the CSS's own positional contract (see _OPENAPI_CSS's nth-of-type
#: rules below): however many of these a given path actually has, they
#: always appear in THIS order, so "1st radio -> 1st panel" etc. holds
#: regardless of which specific methods are present.
_METHOD_ORDER = ["GET", "QUERY", "POST", "PUT", "PATCH", "DELETE", WEBSOCKET_METHOD]


def _slugify(text: str) -> str:
    out: list[str] = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-") or "x"


def _method_label(method: str) -> str:
    return "WS" if method == WEBSOCKET_METHOD else method


def render_openapi_html(
    routes: list[RouteEntry], *, title: str = "ARC Gateway", version: str = "0.1.0"
) -> str:
    """A static, server-rendered HTML page: a sidebar listing every plugin
    (RouteEntry.plugin — None means gateway itself, "Core"), and a main
    panel grouping that plugin's routes ONE ROW PER PATH — every method a
    path supports shown as badges on that single row, not a separate row
    each. Clicking a row opens a modal (request/response schema per
    method as tabs when there's more than one, allowed roles, no tab
    chrome at all for a single-method route) via CSS :target — no JS
    anywhere (see this module's own docstring for why), so this still
    works under the default CSP unmodified."""
    groups: dict[str | None, list[RouteEntry]] = {}
    for route in routes:
        if route.path in _DOC_PATHS:
            continue
        groups.setdefault(route.plugin, []).append(route)

    plugin_names = sorted(name for name in groups if name is not None)
    ordered_keys: list[str | None] = ([None] if None in groups else []) + plugin_names

    sidebar_links: list[str] = []
    sections: list[str] = []
    modals: list[str] = []
    for key in ordered_keys:
        display_name = "Core" if key is None else key
        anchor = "core" if key is None else _slugify(key)
        plugin_slug = anchor

        by_path: dict[str, list[RouteEntry]] = {}
        for route in groups[key]:
            by_path.setdefault(route.path, []).append(route)

        rows: list[str] = []
        for path in sorted(by_path):
            group = sorted(
                by_path[path], key=lambda r: _METHOD_ORDER.index(r.method) if r.method in _METHOD_ORDER else 99
            )
            modal_id = f"modal-{plugin_slug}-{_slugify(path)}"
            badges = "".join(
                f'<span class="method method-{_method_label(r.method).lower()}">{_method_label(r.method)}</span>'
                for r in group
            )
            summary = next((r.summary for r in group if r.summary), "")
            rows.append(
                f'<a href="#{modal_id}" class="grid-row">'
                f'<span class="methods-cell">{badges}</span>'
                f'<span class="path-cell">{html.escape(path)}</span>'
                f'<span class="summary-cell">{html.escape(summary)}</span>'
                f"</a>"
            )
            modals.append(_render_route_modal(modal_id, path, group))

        sidebar_links.append(
            f'<a href="#{anchor}">{html.escape(display_name)} '
            f'<span class="sidebar-count">{len(by_path)}</span></a>'
        )
        sections.append(
            f'<section id="{anchor}"><h2>{html.escape(display_name)}</h2>'
            f'<div class="routes-grid">{"".join(rows)}</div></section>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — API Routes</title>
<link rel="stylesheet" href="/openapi.css">
</head>
<body>
<div class="layout">
<nav class="sidebar">
<h1>{html.escape(title)}</h1>
<p class="version">v{html.escape(version)}</p>
<p><a href="/openapi.json">raw OpenAPI 3.0 spec (JSON)</a></p>
<div class="sidebar-links">{"".join(sidebar_links)}</div>
</nav>
<main class="content">{"".join(sections)}</main>
</div>
{"".join(modals)}
</body>
</html>
"""


def _render_route_modal(modal_id: str, path: str, group: list[RouteEntry]) -> str:
    multi = len(group) > 1
    radio_group = f"tabs-{modal_id}"
    radios: list[str] = []
    labels: list[str] = []
    panels: list[str] = []

    for i, route in enumerate(group):
        label = _method_label(route.method)
        tab_id = f"tab-{modal_id}-{label.lower()}"
        if multi:
            checked = " checked" if i == 0 else ""
            radios.append(f'<input type="radio" class="tab-radio" name="{radio_group}" id="{tab_id}"{checked}>')
            labels.append(f'<label for="{tab_id}" class="tab-label">{html.escape(label)}</label>')

        roles_text = ", ".join(sorted(route.roles)) if route.roles else "any authenticated caller"
        request_schema = _schema_for(route.request_schema)
        response_schema = _schema_for(route.response_schema)
        body = [f'<p class="modal-roles"><strong>Allowed roles:</strong> {html.escape(roles_text)}</p>']
        body.append("<h4>Request</h4>")
        body.append(
            f"<pre>{html.escape(json.dumps(request_schema, indent=2))}</pre>"
            if request_schema
            else '<p class="none">No request payload.</p>'
        )
        body.append("<h4>Response</h4>")
        body.append(
            f"<pre>{html.escape(json.dumps(response_schema, indent=2))}</pre>"
            if response_schema
            else '<p class="none">No documented response schema.</p>'
        )
        panel_class = "tab-panel" if multi else "tab-panel tab-panel-solo"
        panels.append(f'<div class="{panel_class}">{"".join(body)}</div>')

    tabs_html = "".join(radios) + "".join(labels) if multi else ""
    return (
        f'<div class="modal-overlay" id="{modal_id}">'
        # Click-outside-to-close, no JS: this backdrop link is a full-
        # viewport <a href="#"> sitting BEHIND the modal box (lower
        # z-index, see _OPENAPI_CSS) — a click anywhere in the dimmed
        # area outside the box hits this and clears the #target,
        # closing the modal; a click inside the box hits the box (or its
        # own children) first, since it stacks above this layer, so nothing
        # inside the modal is intercepted by it.
        f'<a href="#" class="modal-backdrop" aria-label="Close"></a>'
        f'<div class="modal">'
        f'<a href="#" class="modal-close" aria-label="Close">&times;</a>'
        f"<h3>{html.escape(path)}</h3>"
        f'<div class="modal-tabs">{tabs_html}{"".join(panels)}</div>'
        f"</div></div>"
    )


_OPENAPI_CSS = """\
/* Every color is a custom property, resolved once — every rule below
   reads var(--x), never a hardcoded hex, and ONLY the two blocks here
   ever set what --x actually IS. This is deliberate, not decoration: an
   earlier version of this file redefined colors per-selector inside the
   dark media query (e.g. ".tab-label { background: #222 }"), and lost
   silently to plain CSS cascade/specificity rules — a same-specificity
   selector appearing LATER in source order (the light-mode base rule,
   which came after the dark media block) wins regardless of the media
   query matching, and ".tab-label" vs the base rule's "label.tab-label"
   aren't even equal specificity to begin with. Custom properties have
   no such trap: every consumer reads the SAME variable, so there is
   only ever one place a color can be wrong.*/
:root {
  color-scheme: light dark;
  --bg: #fff;
  --fg: #1a1a1a;
  --muted: #666;
  --border: #ddd;
  --border-soft: #eee;
  --sidebar-bg: transparent;
  --hover-bg: rgba(128, 128, 128, 0.1);
  --modal-bg: #fff;
  --modal-backdrop: rgba(0, 0, 0, 0.55);
  --pre-bg: #f6f6f6;
  --tab-bg: #f2f2f2;
  --tab-active-bg: #fff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111;
    --fg: #e8e8e8;
    --muted: #999;
    --border: #333;
    --border-soft: #2a2a2a;
    --sidebar-bg: #161616;
    --hover-bg: rgba(255, 255, 255, 0.08);
    --modal-bg: #1a1a1a;
    --modal-backdrop: rgba(0, 0, 0, 0.7);
    --pre-bg: #0d0d0d;
    --tab-bg: #222;
    --tab-active-bg: #1a1a1a;
  }
}
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  margin: 0; color: var(--fg); background: var(--bg);
}
.layout { display: flex; align-items: flex-start; min-height: 100vh; }
.sidebar {
  width: 240px; flex-shrink: 0; position: sticky; top: 0; height: 100vh;
  overflow-y: auto; padding: 1.5rem 1.25rem; border-right: 1px solid var(--border);
  background: var(--sidebar-bg);
}
.sidebar h1 { font-size: 1.25rem; margin: 0 0 0.25rem; }
.sidebar .version { color: var(--muted); margin: 0 0 1rem; font-size: 0.9rem; }
.sidebar-links { display: flex; flex-direction: column; margin-top: 1.5rem; }
.sidebar-links a {
  display: flex; justify-content: space-between; padding: 0.4rem 0.5rem;
  border-radius: 4px; text-decoration: none; color: inherit; font-weight: 600;
}
.sidebar-links a:hover { background: var(--hover-bg); }
.sidebar-count { color: var(--muted); font-weight: normal; }
.content { flex: 1; min-width: 0; padding: 1.5rem 2rem 4rem; }
section { margin-bottom: 2.5rem; scroll-margin-top: 1rem; }
section h2 { border-bottom: 2px solid var(--border); padding-bottom: 0.4rem; }
.routes-grid { display: flex; flex-direction: column; }
.grid-row {
  display: grid; grid-template-columns: 11rem 1fr 2fr; gap: 0.75rem;
  align-items: center; padding: 0.55rem 0.5rem; border-bottom: 1px solid var(--border-soft);
  text-decoration: none; color: inherit; cursor: pointer;
}
.grid-row:hover { background: var(--hover-bg); }
.methods-cell { display: flex; gap: 0.3rem; flex-wrap: wrap; }
.method {
  font-weight: bold; font-family: ui-monospace, monospace; font-size: 0.78rem;
  padding: 0.1rem 0.4rem; border-radius: 3px; display: inline-block;
}
.method-get, .method-query { color: #2eaf5a; background: rgba(10, 125, 44, 0.15); }
.method-post { color: #d99022; background: rgba(176, 96, 0, 0.15); }
.method-put, .method-patch { color: #a685e8; background: rgba(122, 79, 201, 0.15); }
.method-delete { color: #e3675a; background: rgba(192, 57, 43, 0.15); }
.method-ws { color: #4ea3d9; background: rgba(26, 110, 168, 0.15); }
.path-cell { font-family: ui-monospace, monospace; }
.summary-cell { color: var(--muted); }

/* Modal — CSS :target, no JS */
.modal-overlay {
  display: none; position: fixed; inset: 0;
  align-items: center; justify-content: center; z-index: 100; padding: 1.5rem;
}
.modal-overlay:target { display: flex; }
/* Click-outside-to-close: this full-viewport link sits BEHIND .modal
   (z-index 1 vs 2) and IS the dimmed backdrop — a click anywhere outside
   the modal box hits it and clears #target; a click inside the box hits
   the box (stacked above) first, so it's never intercepted. */
.modal-backdrop {
  position: absolute; inset: 0; z-index: 1; background: var(--modal-backdrop);
}
.modal {
  background: var(--modal-bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 1.5rem; max-width: 700px; width: 100%; max-height: 85vh; overflow-y: auto;
  position: relative; z-index: 2;
}
.modal-close {
  position: absolute; top: 0.5rem; right: 0.85rem; font-size: 1.5rem;
  text-decoration: none; color: inherit; line-height: 1;
}
.modal h3 { font-family: ui-monospace, monospace; margin-top: 0; padding-right: 1.5rem; }
.modal h4 { margin-bottom: 0.3rem; }
.modal-roles { color: var(--muted); }
.modal pre {
  background: var(--pre-bg); border: 1px solid var(--border-soft); border-radius: 4px;
  padding: 0.75rem; overflow-x: auto; font-size: 0.85rem; color: inherit;
}
.modal .none { color: var(--muted); font-style: italic; }

/* CSS-only tabs — purely positional (Nth radio checked -> Nth panel shown),
   so these fixed rules work for every modal regardless of which specific
   methods it has; see _METHOD_ORDER's own comment. */
.modal-tabs { display: flex; flex-wrap: wrap; }
input.tab-radio { position: absolute; opacity: 0; pointer-events: none; }
label.tab-label {
  order: 1; cursor: pointer; padding: 0.4rem 0.9rem; margin-right: 0.3rem;
  border: 1px solid var(--border); border-bottom: none; border-radius: 6px 6px 0 0;
  background: var(--tab-bg); font-family: ui-monospace, monospace; font-weight: bold;
}
.tab-panel {
  order: 2; flex-basis: 100%; display: none; border: 1px solid var(--border);
  border-radius: 0 6px 6px 6px; padding: 1rem;
}
.tab-panel.tab-panel-solo { display: block; border-radius: 6px; }
input.tab-radio:nth-of-type(1):checked ~ label.tab-label:nth-of-type(1),
input.tab-radio:nth-of-type(2):checked ~ label.tab-label:nth-of-type(2),
input.tab-radio:nth-of-type(3):checked ~ label.tab-label:nth-of-type(3),
input.tab-radio:nth-of-type(4):checked ~ label.tab-label:nth-of-type(4),
input.tab-radio:nth-of-type(5):checked ~ label.tab-label:nth-of-type(5),
input.tab-radio:nth-of-type(6):checked ~ label.tab-label:nth-of-type(6),
input.tab-radio:nth-of-type(7):checked ~ label.tab-label:nth-of-type(7) {
  background: var(--tab-active-bg); border-bottom: 1px solid var(--tab-active-bg); margin-bottom: -1px;
}
input.tab-radio:nth-of-type(1):checked ~ .tab-panel:nth-of-type(1),
input.tab-radio:nth-of-type(2):checked ~ .tab-panel:nth-of-type(2),
input.tab-radio:nth-of-type(3):checked ~ .tab-panel:nth-of-type(3),
input.tab-radio:nth-of-type(4):checked ~ .tab-panel:nth-of-type(4),
input.tab-radio:nth-of-type(5):checked ~ .tab-panel:nth-of-type(5),
input.tab-radio:nth-of-type(6):checked ~ .tab-panel:nth-of-type(6),
input.tab-radio:nth-of-type(7):checked ~ .tab-panel:nth-of-type(7) {
  display: block;
}
"""


def render_openapi_css() -> str:
    return _OPENAPI_CSS
