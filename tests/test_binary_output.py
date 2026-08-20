"""
Regression test for binary-safe stdout output.

Before: print(data.decode()) — appends a newline and raises UnicodeDecodeError
        on binary responses (gzip, images, etc.)
After:  sys.stdout.buffer.write(data) — passes bytes through verbatim.

Run with:  python3 tests/test_binary_output.py
"""
import sys
import os
import asyncio
import unittest
from io import BytesIO, StringIO
from unittest.mock import MagicMock, AsyncMock, patch
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Stub aioquic
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.dirname(__file__))
import _aioquic_stub
_aioquic_stub.install()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import h3 as h3mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _AsyncCtx:
    def __init__(self, client):
        self._client = client
    async def __aenter__(self):
        return self._client
    async def __aexit__(self, *_):
        pass


def _run(data):
    h3mod.CONFIG.show_headers = False
    h3mod.CONFIG.verbose = False
    h3mod.CONFIG.insecure = False
    h3mod.CONFIG.max_datagram_size = 1350
    h3mod.CONFIG.debug = False

    url = urlparse('https://example.com/')
    client = MagicMock()
    client.send_http_request = AsyncMock(return_value=(data, {':status': '200'}))

    stdout_buf = BytesIO()

    class _Cap:
        buffer = stdout_buf
        def write(self, text):
            stdout_buf.write(text.encode() if isinstance(text, str) else text)
        def flush(self): pass

    def _connect(**kw):
        return _AsyncCtx(client)

    with patch.object(h3mod, 'connect', side_effect=_connect), \
         patch('sys.stdout', _Cap()), \
         patch('sys.stderr', StringIO()):
        asyncio.run(h3mod.send_request(url.hostname, 443, url))

    return stdout_buf.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBinaryOutput(unittest.TestCase):

    def test_plain_text_no_trailing_newline(self):
        """Body bytes are written verbatim — no extra newline appended."""
        self.assertEqual(_run(b'hello'), b'hello')

    def test_binary_data_passed_through_unchanged(self):
        """All 256 byte values survive the output path without corruption."""
        payload = bytes(range(256))
        self.assertEqual(_run(payload), payload)

    def test_non_utf8_bytes_do_not_raise(self):
        """Bytes that are invalid UTF-8 must not raise UnicodeDecodeError."""
        non_utf8 = b'\xff\xfe\xfd'
        try:
            result = _run(non_utf8)
        except UnicodeDecodeError:
            self.fail("UnicodeDecodeError raised for non-UTF-8 response body")
        self.assertEqual(result, non_utf8)

    def test_gzip_magic_bytes_preserved(self):
        """Gzip response starts with the correct magic bytes after output."""
        gzip_magic = b'\x1f\x8b\x08\x00'
        result = _run(gzip_magic + b'\x00' * 20)
        self.assertTrue(result.startswith(gzip_magic))

    def test_empty_body_produces_no_output(self):
        self.assertEqual(_run(b''), b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
