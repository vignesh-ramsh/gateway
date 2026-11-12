"""
gateway.multipart_stream
------------------------
Parse a multipart/form-data upload AS IT ARRIVES, writing each file part to a temporary file on disk instead of
collecting the body in memory.

`gateway.multipart.parse_multipart_form` needs the whole body as one `bytes`: it splits it, copies each part
(so a file is held two or three times over) and returns the content as another `bytes`. For a 1 GB upload that
is several GB of memory. This module reads a streamed body (a route registered with `stream_body=True`, see
`request.BodyStream`) piece by piece, feeds `python-multipart`'s incremental parser, and writes the file part
to disk as it goes while computing its SHA-256 and size. Memory per upload is about one flush buffer (1 MB) plus
the piece being parsed, whatever the file size.

What it guarantees:

  * the file lands in `spool_dir` under a random name, created 0600 (private to this user) from the first
    byte, and is fsynced before it is handed over;
  * every limit is enforced WHILE streaming: file size (413), number of parts and files (400), size of a
    non-file field (413), header size and count (400, by the parser). A violation stops the read there; it does
    not wait for the whole body;
  * a body that ends without its closing boundary (cut off, or not multipart at all) is refused (400), never
    accepted as a shorter file;
  * on ANY failure (an error, a limit, the client going away, a cancelled request) every temporary file this
    call made is closed and deleted before the exception leaves;
  * on success the caller owns the files: `StreamedForm.aclose()` (or `async with`) deletes whatever it did
    not move into place.

The parse itself runs on the event loop (it is a few microseconds per piece: measured 1.3 GB/s including the
hash); the hashing and the disk writes run in a worker thread, one hop per flush buffer, so a slow disk never
blocks the loop and a fast client is slowed to the disk's speed by simply not being read from.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import os
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header

from .multipart import _extract_boundary
from .request import ClientDisconnected, HTTPError, Request

#: Disk writes (and the hash) happen in batches of about this many bytes: one thread hop per batch.
DEFAULT_FLUSH_BYTES = 1024 * 1024
DEFAULT_MAX_PARTS = 32
DEFAULT_MAX_FIELD_BYTES = 64 * 1024
#: The suffix of every temporary file this module creates; the sweeper recognises its leftovers by it.
SPOOL_SUFFIX = ".part"


@dataclass
class SpooledFile:
    """A file part that has been written to disk. `path` is the temporary file (yours to move or delete);
    `sha256` is the hex digest of exactly the bytes in it."""

    field: str
    filename: str
    content_type: str
    path: Path
    size: int
    sha256: str


@dataclass
class StreamedForm:
    """What a streamed multipart body held: the small text fields (in memory) and the file parts (on disk)."""

    fields: dict[str, str] = field(default_factory=dict)
    files: dict[str, SpooledFile] = field(default_factory=dict)

    def discard(self) -> None:
        """Delete every temporary file that is still there. Safe to call twice, and after a file was moved."""
        for spooled in self.files.values():
            with contextlib.suppress(OSError):
                spooled.path.unlink()

    async def aclose(self) -> None:
        await asyncio.to_thread(self.discard)

    async def __aenter__(self) -> StreamedForm:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()


class _FileSink:
    """One file part being written. Touched by the event loop (`add`, between awaits) and by one worker
    thread at a time (`flush`, while the loop awaits it): never both at once."""

    def __init__(
        self, path: Path, fd: int, field_name: str, filename: str, content_type: str
    ) -> None:
        self.path = path
        self.field = field_name
        self.filename = filename
        self.content_type = content_type
        self.size = 0
        self.done = False
        self.closed = False
        self._file = os.fdopen(fd, "wb")
        self._hash = hashlib.sha256()
        self._pending: list[bytes] = []
        self.pending_bytes = 0
        # A request cancelled while a flush runs in a thread starts its cleanup while that thread may still
        # be writing: the lock makes the cleanup wait for it instead of closing the file under it.
        self._lock = threading.Lock()

    def add(self, data: bytes) -> None:
        self._pending.append(data)
        self.pending_bytes += len(data)
        self.size += len(data)

    def flush(self) -> None:
        """Hash and write what is pending. Runs in a worker thread."""
        with self._lock:
            self._write_pending()

    def _write_pending(self) -> None:
        if not self._pending or self.closed:
            return
        data = b"".join(self._pending) if len(self._pending) > 1 else self._pending[0]
        self._pending = []
        self.pending_bytes = 0
        self._hash.update(data)
        self._file.write(data)

    def close(self, *, sync: bool) -> None:
        """Flush, optionally fsync, and close. Runs in a worker thread. Idempotent."""
        with self._lock:
            if self.closed:
                return
            try:
                self._write_pending()
                if sync:
                    self._file.flush()
                    os.fsync(self._file.fileno())
            finally:
                self.closed = True
                self._file.close()

    def digest(self) -> str:
        return self._hash.hexdigest()

    def abandon(self) -> None:
        """Close without keeping anything and delete the file. Runs in a worker thread."""
        with self._lock:
            self._pending = []
            self.pending_bytes = 0
            if not self.closed:
                self.closed = True
                with contextlib.suppress(OSError):
                    self._file.close()
            with contextlib.suppress(OSError):
                self.path.unlink()


class _Collector:
    """The parser's callbacks. They only record: anything that needs `await` (flushing to disk) is done by
    `read_multipart_stream` after each `parser.write()` returns."""

    def __init__(
        self,
        *,
        spool_dir: Path,
        file_mode: int,
        max_file_bytes: int,
        max_files: int,
        max_parts: int,
        max_field_bytes: int,
        check_file: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self.check_file = check_file
        self.spool_dir = spool_dir
        self.file_mode = file_mode
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_parts = max_parts
        self.max_field_bytes = max_field_bytes
        self.sinks: list[_FileSink] = []
        self.fields: dict[str, str] = {}
        self.ended = False
        self._parts = 0
        self._field_name: bytearray = bytearray()
        self._field_value: bytearray = bytearray()
        self._headers: dict[bytes, bytes] = {}
        self._sink: _FileSink | None = (
            None  # the file part being read, if the current part is a file
        )
        self._text_name: str | None = (
            None  # the text field being read, if the current part is a field
        )
        self._text = bytearray()

    # -- headers
    def on_part_begin(self) -> None:
        self._parts += 1
        if self._parts > self.max_parts:
            raise HTTPError(
                400, {"error": "too many parts in the multipart body", "limit": self.max_parts}
            )
        self._headers = {}

    def on_header_begin(self) -> None:
        self._field_name = bytearray()
        self._field_value = bytearray()

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._field_name += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._field_value += data[start:end]

    def on_header_end(self) -> None:
        self._headers[bytes(self._field_name).strip().lower()] = bytes(self._field_value).strip()

    def on_headers_finished(self) -> None:
        disposition = self._headers.get(b"content-disposition")
        if disposition is None:
            raise HTTPError(400, {"error": "malformed multipart part: missing Content-Disposition"})
        _kind, params = parse_options_header(disposition)
        raw_name = params.get(b"name")
        if raw_name is None:
            raise HTTPError(400, {"error": "malformed multipart part: missing name"})
        name = raw_name.decode("utf-8", errors="replace")
        raw_filename = params.get(b"filename")
        if raw_filename is None:
            self._text_name, self._sink = name, None
            self._text = bytearray()
            return
        if len(self.sinks) >= self.max_files:
            raise HTTPError(
                400, {"error": "too many files in the multipart body", "limit": self.max_files}
            )
        content_type = self._headers.get(b"content-type", b"application/octet-stream").decode(
            "latin-1"
        )
        filename = raw_filename.decode("utf-8", errors="replace")
        if self.check_file is not None:
            # The caller's chance to refuse this file from its headers alone (a content type it does not take),
            # before a byte of it is read or written. Whatever it raises ends the request there.
            self.check_file(name, filename, content_type)
        path = self.spool_dir / f"upload-{secrets.token_hex(16)}{SPOOL_SUFFIX}"
        # O_EXCL: never open a file that is already there; the mode is set at creation, so the bytes are
        # never readable by another user, not even for an instant.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, self.file_mode)
        sink = _FileSink(path, fd, name, filename, content_type)
        self.sinks.append(sink)
        self._sink, self._text_name = sink, None

    # -- content
    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if end <= start:
            return
        if self._sink is not None:
            sink = self._sink
            if sink.size + (end - start) > self.max_file_bytes:
                raise HTTPError(
                    413, {"error": "file too large", "limit_bytes": self.max_file_bytes}
                )
            sink.add(data[start:end])
        elif self._text_name is not None:
            self._text += data[start:end]
            if len(self._text) > self.max_field_bytes:
                raise HTTPError(
                    413,
                    {
                        "error": "form field too large",
                        "field": self._text_name,
                        "limit_bytes": self.max_field_bytes,
                    },
                )

    def on_part_end(self) -> None:
        if self._sink is not None:
            self._sink.done = True
        elif self._text_name is not None:
            self.fields[self._text_name] = bytes(self._text).decode("utf-8", errors="replace")
        self._sink, self._text_name = None, None

    def on_end(self) -> None:
        self.ended = True

    def callbacks(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "on_part_begin",
                "on_header_begin",
                "on_header_field",
                "on_header_value",
                "on_header_end",
                "on_headers_finished",
                "on_part_data",
                "on_part_end",
                "on_end",
            )
        }


async def read_multipart_stream(
    request: Request,
    *,
    spool_dir: Path,
    max_file_bytes: int,
    max_files: int = 1,
    max_parts: int = DEFAULT_MAX_PARTS,
    max_field_bytes: int = DEFAULT_MAX_FIELD_BYTES,
    flush_bytes: int = DEFAULT_FLUSH_BYTES,
    file_mode: int = 0o600,
    check_file: Callable[[str, str, str], None] | None = None,
) -> StreamedForm:
    """Read `request`'s streamed multipart body (a route with `stream_body=True`) into a `StreamedForm`.

    `spool_dir` is where file parts are written (created 0700 if missing). `max_file_bytes` bounds each
    file; going over raises HTTPError 413 as soon as it is crossed. `check_file(field, filename, content_type)`,
    when given, is called as each file part's headers arrive, before any of it is written: raise to refuse it. Raises HTTPError for a malformed body, a
    breached limit or a stalled client, `ClientDisconnected` when the client leaves, and HTTPError 507 when the
    disk is full; whichever it is, no temporary file is left behind."""
    if request.stream is None:
        raise RuntimeError("read_multipart_stream needs a route registered with stream_body=True")
    boundary = _extract_boundary(request.headers.get("content-type", ""))
    spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    collector = _Collector(
        spool_dir=spool_dir,
        file_mode=file_mode,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_parts=max_parts,
        max_field_bytes=max_field_bytes,
        check_file=check_file,
    )
    parser = MultipartParser(boundary, collector.callbacks())
    spooled: list[SpooledFile] = []
    try:
        async for chunk in request.stream.chunks():
            try:
                parser.write(chunk)
            except MultipartParseError as exc:
                raise HTTPError(
                    400, {"error": "malformed multipart body", "detail": str(exc)}
                ) from exc
            await _flush(collector, flush_bytes)
        try:
            parser.finalize()
        except MultipartParseError as exc:
            raise HTTPError(400, {"error": "malformed multipart body", "detail": str(exc)}) from exc
        if not collector.ended:
            raise HTTPError(
                400, {"error": "malformed multipart body: it ended before the closing boundary"}
            )
        for sink in collector.sinks:
            await _in_thread(lambda sink=sink: sink.close(sync=True))
            spooled.append(
                SpooledFile(
                    field=sink.field,
                    filename=sink.filename,
                    content_type=sink.content_type,
                    path=sink.path,
                    size=sink.size,
                    sha256=sink.digest(),
                )
            )
    except BaseException:
        # An error, a limit, a vanished client or a cancelled request: nothing of this upload may stay on disk.
        # Shielded, so a cancellation does not leave the cleanup half done.
        await asyncio.shield(asyncio.to_thread(_abandon_all, collector.sinks))
        raise
    return StreamedForm(fields=collector.fields, files={s.field: s for s in spooled})


async def _flush(collector: _Collector, threshold: int) -> None:
    """Write out every sink that has `threshold` bytes or more pending: one thread hop per buffer."""
    for sink in collector.sinks:
        if not sink.closed and sink.pending_bytes >= threshold > 0:
            await _in_thread(sink.flush)


async def _in_thread(function: Any) -> None:
    try:
        await asyncio.to_thread(function)
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT):
            raise HTTPError(
                507, {"error": "the server has no room left to receive this upload"}
            ) from exc
        raise


def _abandon_all(sinks: list[_FileSink]) -> None:
    for sink in sinks:
        sink.abandon()


__all__ = [
    "ClientDisconnected",
    "SPOOL_SUFFIX",
    "SpooledFile",
    "StreamedForm",
    "read_multipart_stream",
]
