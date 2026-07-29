"""
gateway._asgi_entrypoint
-------------------------
What `granian --interface asgi gateway._asgi_entrypoint:app` actually
imports. Boots arc once at import time — Granian imports this fresh in
every worker process it spawns, so this correctly re-boots per worker,
matching §3.6's "safe to run on every replica simultaneously".

The ArcAdvisory suppression below matches every OTHER arc.boot() call
site in this project (every CLI command, every test fixture) — this file
was the one place that never got it, which is why a real `arc run` used
to print each advisory's full raw Python-warnings traceback (file, line,
source snippet) once per Granian worker process — 8 times over for an
8-worker gateway, none of it captured anywhere for later review. Advisories
still fully exist (Kernel.advisories, and now also logs/system.jsonl via
Kernel.advise() itself) — this only silences the RAW, per-process console
dump that duplicated them here.
"""

from __future__ import annotations

import warnings

import arc

with warnings.catch_warnings():
    warnings.simplefilter("ignore", arc.ArcAdvisory)
    arc.boot()
app = arc.gateway
