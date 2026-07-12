"""
gateway._asgi_entrypoint
-------------------------
What `granian --interface asgi gateway._asgi_entrypoint:app` actually
imports. Boots arc once at import time — Granian imports this fresh in
every worker process it spawns, so this correctly re-boots per worker,
matching §3.6's "safe to run on every replica simultaneously".
"""

from __future__ import annotations

import arc

arc.boot()
app = arc.gateway