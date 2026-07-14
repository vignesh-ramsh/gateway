"""
gateway.multipart
------------------
Multipart/form-data parsing — a transport-level primitive only. Nothing in
Gateway registers a route that uses this yet (no whitelisted upload API, no
attachment storage) — that's a separate, later phase. This just makes
Gateway capable of turning a multipart body into fields/files when a future
handler asks for it via `Request.form()`.

Deliberately covers the common case browsers/curl/httpx actually produce —
a single-level "multipart/form-data" body, one part per field/file — not a
full RFC 2046 implementation (no nested multipart, no header line-folding).
Widen if a real client ever needs more.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .request import HTTPError


@dataclass
class UploadedFile:
    filename: str
    content_type: str
    content: bytes


@dataclass
class MultipartForm:
    fields: dict[str, str] = field(default_factory=dict)
    files: dict[str, UploadedFile] = field(default_factory=dict)


def parse_multipart_form(body: bytes, content_type: str) -> MultipartForm:
    """`content_type` is the raw request header value, e.g.
    'multipart/form-data; boundary=----WebKitFormBoundaryABC123'."""
    boundary = _extract_boundary(content_type)
    delimiter = b"--" + boundary
    form = MultipartForm()

    # Splitting on the delimiter leaves the preamble (before the first
    # occurrence) and the epilogue ("--\r\n", left over from the closing
    # "--boundary--") as the first/last elements — neither is a real part.
    raw_parts = body.split(delimiter)
    for raw in raw_parts[1:-1]:
        # Each real part is exactly "\r\n" + headers + "\r\n\r\n" + content +
        # "\r\n" (that trailing CRLF immediately precedes the next
        # delimiter and is not part of the content) — strip exactly those
        # two bytes on each end, never a repeated/blind strip, so real
        # trailing whitespace inside an uploaded file's own bytes survives.
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        if not raw:
            continue

        header_blob, sep, content = raw.partition(b"\r\n\r\n")
        if not sep:
            raise HTTPError(400, {"error": "malformed multipart part: no header/body separator"})

        headers = _parse_part_headers(header_blob)
        disposition = headers.get("content-disposition", "")
        name = _param(disposition, "name")
        if name is None:
            raise HTTPError(400, {"error": "malformed multipart part: missing name"})

        filename = _param(disposition, "filename")
        if filename is not None:
            form.files[name] = UploadedFile(
                filename=filename,
                content_type=headers.get("content-type", "application/octet-stream"),
                content=content,
            )
        else:
            form.fields[name] = content.decode("utf-8", errors="replace")

    return form


def _extract_boundary(content_type: str) -> bytes:
    if "boundary=" not in content_type:
        raise HTTPError(400, {"error": "missing multipart boundary"})
    boundary = content_type.split("boundary=", 1)[1].split(";", 1)[0].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    return boundary.encode("latin-1")


def _parse_part_headers(blob: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in blob.split(b"\r\n"):
        if not line:
            continue
        key, _, value = line.decode("latin-1").partition(":")
        headers[key.strip().lower()] = value.strip()
    return headers


def _param(header_value: str, name: str) -> str | None:
    for piece in header_value.split(";"):
        piece = piece.strip()
        if piece.startswith(f"{name}="):
            value = piece[len(name) + 1 :]
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            return value
    return None
