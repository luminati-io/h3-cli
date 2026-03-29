"""
Regression tests for HTTP redirect-following in send_request() (-L / --follow-redirects).

Run with:  python3 -m pytest tests/  OR  python3 tests/test_follow_redirects.py
"""
import sys
import types
import asyncio
import unittest
from io import BytesIO, StringIO
from unittest.mock import MagicMock, AsyncMock, patch
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Stub aioquic (not installed in the dev environment)
# ---------------------------------------------------------------------------

def _stub(name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod

_QuicCfg = type('QuicConfiguration', (), {
    '__init__': lambda self, **kw: None,
    'alpn_protocols': None, 'max_datagram_size': 1350,
    'max_datagram_frame_size': 0, 'verify_mode': None, 'server_name': None,
})

_stub('aioquic')
_stub('aioquic.asyncio', connect=MagicMock())
_stub('aioquic.asyncio.protocol', QuicConnectionProtocol=object)
_stub('aioquic.h3.connection', H3_ALPN=['h3'], H3Connection=object)
_stub('aioquic.h3.events',
      HeadersReceived=object, DataReceived=object,
      H3Event=object, DatagramReceived=object)
_stub('aioquic.quic.connection', QuicConnection=object)
_stub('aioquic.quic.configuration', QuicConfiguration=_QuicCfg)
_stub('aioquic.quic.events', ConnectionTerminated=object, HandshakeCompleted=object)
_stub('aioquic.quic.logger', QuicFileLogger=object)
sys.modules['aioquic'].tls = _stub('aioquic.tls')

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import h3 as h3mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _CaptureStdout:
    """Captures both print() (text) and sys.stdout.buffer.write() (binary)."""
    def __init__(self):
        self._inner = BytesIO()
        self.buffer = self._inner
    def write(self, text):
        self._inner.write(text.encode() if isinstance(text, str) else text)
    def flush(self):
        pass
    def getvalue(self):
        return self._inner.getvalue()


class _AsyncCtx:
    """Minimal async context manager wrapping a mock client."""
    def __init__(self, client):
        self._client = client
    async def __aenter__(self):
        return self._client
    async def __aexit__(self, *_):
        pass


def _connect_factory(responses, url_log=None):
    """
    Return a connect() side-effect that cycles through *responses*
    (list of (data_bytes, headers_dict) tuples).
    Optionally appends the URL string of each call to *url_log*.
    """
    idx = [0]
    def _connect(**kwargs):
        n = idx[0]
        idx[0] += 1
        data, hdrs = responses[min(n, len(responses) - 1)]
        client = MagicMock()
        if url_log is None:
            client.send_http_request = AsyncMock(return_value=(data, hdrs))
        else:
            async def _send(req_url, *a, **kw):
                url_log.append(req_url.geturl() if hasattr(req_url, 'geturl') else str(req_url))
                return (data, hdrs)
            client.send_http_request = _send
        return _AsyncCtx(client)
    return _connect, idx


def _run_send(url_str, responses, *, method='GET', content=None,
              follow=False, url_log=None):
    """
    Drive send_request() with mocked connect() and captured stdout/stderr.
    Returns (stdout_bytes, stderr_str, connect_call_count).
    """
    h3mod.CONFIG.follow_redirects = follow
    url = urlparse(url_str)
    connect_fn, idx = _connect_factory(responses, url_log)

    cap = _CaptureStdout()
    stderr_buf = StringIO()
    with patch.object(h3mod, 'connect', side_effect=connect_fn), \
         patch('sys.stdout', cap), \
         patch('sys.stderr', stderr_buf):
        asyncio.run(
            h3mod.send_request(url.hostname, url.port or 443, url,
                               method=method, content=content)
        )
    return cap.getvalue(), stderr_buf.getvalue(), idx[0]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNoRedirectByDefault(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def test_302_not_followed_without_flag(self):
        """Without -L, a 302 response is returned as-is (no second request)."""
        responses = [
            (b'', {':status': '302', 'location': 'https://example.com/new'}),
        ]
        _, _, call_count = _run_send('https://example.com/old', responses, follow=False)
        self.assertEqual(call_count, 1,
                         "connect() should be called exactly once when not following redirects")

    def test_non_redirect_response_not_followed(self):
        """200 response never triggers redirect logic regardless of -L."""
        responses = [(b'body', {':status': '200'})]
        _, _, call_count = _run_send('https://example.com/', responses, follow=True)
        self.assertEqual(call_count, 1)


class TestFollowSingleRedirect(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def test_single_302_followed(self):
        """With -L, one 302 causes a second request; body of final response is returned."""
        url_log = []
        responses = [
            (b'', {':status': '302', 'location': 'https://example.com/new'}),
            (b'final body', {':status': '200'}),
        ]
        stdout, _, call_count = _run_send(
            'https://example.com/old', responses, follow=True, url_log=url_log)

        self.assertEqual(call_count, 2)
        self.assertEqual(url_log[0], 'https://example.com/old')
        self.assertEqual(url_log[1], 'https://example.com/new')
        self.assertIn(b'final body', stdout)

    def test_301_redirect_followed(self):
        """301 redirects are also followed with -L."""
        url_log = []
        responses = [
            (b'', {':status': '301', 'location': 'https://example.com/moved'}),
            (b'ok', {':status': '200'}),
        ]
        _run_send('https://example.com/old', responses, follow=True, url_log=url_log)
        self.assertEqual(len(url_log), 2)
        self.assertEqual(url_log[1], 'https://example.com/moved')

    def test_307_redirect_followed(self):
        """307 redirects are followed (method preserved)."""
        url_log = []
        responses = [
            (b'', {':status': '307', 'location': 'https://example.com/temp'}),
            (b'ok', {':status': '200'}),
        ]
        _run_send('https://example.com/old', responses, follow=True, url_log=url_log)
        self.assertEqual(len(url_log), 2)
        self.assertEqual(url_log[1], 'https://example.com/temp')


class TestRelativeLocationResolution(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def test_absolute_path_resolved(self):
        """Absolute-path location (/foo?bar) is resolved to same origin."""
        url_log = []
        responses = [
            (b'', {':status': '302', 'location': '/static/file.gz?sig=abc123'}),
            (b'data', {':status': '200'}),
        ]
        _run_send('https://cdn.example.com/static/file.gz',
                  responses, follow=True, url_log=url_log)
        self.assertEqual(url_log[1], 'https://cdn.example.com/static/file.gz?sig=abc123')

    def test_relative_path_resolved(self):
        """Relative location (../other) is resolved against the current URL."""
        url_log = []
        responses = [
            (b'', {':status': '302', 'location': '../other/resource'}),
            (b'ok', {':status': '200'}),
        ]
        _run_send('https://example.com/a/b/page',
                  responses, follow=True, url_log=url_log)
        self.assertEqual(url_log[1], 'https://example.com/a/other/resource')

    def test_absolute_url_location(self):
        """Absolute URL in location is used verbatim."""
        url_log = []
        responses = [
            (b'', {':status': '302', 'location': 'https://other.host.com/file'}),
            (b'ok', {':status': '200'}),
        ]
        _run_send('https://example.com/old', responses, follow=True, url_log=url_log)
        self.assertEqual(url_log[1], 'https://other.host.com/file')


class TestMethodDowngrade(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def _method_tracking_factory(self, responses):
        """connect() side-effect that records (method, content) per call."""
        captured = []
        idx = [0]
        def _connect(**kwargs):
            n = idx[0]
            idx[0] += 1
            data, hdrs = responses[min(n, len(responses) - 1)]
            client = MagicMock()
            async def _send(req_url, method, hdrs_arg, content, *a, **kw):
                captured.append({'method': method, 'content': content})
                return (data, hdrs)
            client.send_http_request = _send
            return _AsyncCtx(client)
        return _connect, captured, idx

    def test_301_post_downgrades_to_get(self):
        """POST + 301 → follow-up must be GET with no body."""
        responses = [
            (b'', {':status': '301', 'location': 'https://example.com/done'}),
            (b'ok', {':status': '200'}),
        ]
        connect_fn, captured, _ = self._method_tracking_factory(responses)
        url = urlparse('https://example.com/submit')
        h3mod.CONFIG.follow_redirects = True
        with patch.object(h3mod, 'connect', side_effect=connect_fn), \
             patch('sys.stdout') as m:
            m.buffer = BytesIO()
            asyncio.run(
                h3mod.send_request(url.hostname, 443, url,
                                   method='POST', content=b'field=value'))

        self.assertEqual(len(captured), 2)
        self.assertEqual(captured[0]['method'], 'POST')
        self.assertEqual(captured[1]['method'], 'GET')
        self.assertIsNone(captured[1]['content'])

    def test_302_post_downgrades_to_get(self):
        """POST + 302 → follow-up must be GET."""
        responses = [
            (b'', {':status': '302', 'location': 'https://example.com/done'}),
            (b'ok', {':status': '200'}),
        ]
        connect_fn, captured, _ = self._method_tracking_factory(responses)
        url = urlparse('https://example.com/submit')
        h3mod.CONFIG.follow_redirects = True
        with patch.object(h3mod, 'connect', side_effect=connect_fn), \
             patch('sys.stdout') as m:
            m.buffer = BytesIO()
            asyncio.run(
                h3mod.send_request(url.hostname, 443, url,
                                   method='POST', content=b'a=b'))

        self.assertEqual(captured[1]['method'], 'GET')
        self.assertIsNone(captured[1]['content'])

    def test_307_preserves_method(self):
        """POST + 307 → follow-up must still be POST with the original body."""
        responses = [
            (b'', {':status': '307', 'location': 'https://example.com/new'}),
            (b'ok', {':status': '200'}),
        ]
        connect_fn, captured, _ = self._method_tracking_factory(responses)
        url = urlparse('https://example.com/submit')
        h3mod.CONFIG.follow_redirects = True
        with patch.object(h3mod, 'connect', side_effect=connect_fn), \
             patch('sys.stdout') as m:
            m.buffer = BytesIO()
            asyncio.run(
                h3mod.send_request(url.hostname, 443, url,
                                   method='POST', content=b'payload'))

        self.assertEqual(captured[0]['method'], 'POST')
        self.assertEqual(captured[1]['method'], 'POST')
        self.assertEqual(captured[1]['content'], b'payload')


class TestRedirectLimit(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def test_too_many_redirects_prints_error(self):
        """After MAX_REDIRECTS hops an error is written to stderr and we stop."""
        # Always redirect back to same URL → infinite loop without the guard
        loop_response = (b'', {':status': '302', 'location': 'https://example.com/loop'})
        responses = [loop_response]
        _, stderr_out, call_count = _run_send(
            'https://example.com/loop', responses, follow=True)

        self.assertEqual(call_count, h3mod.MAX_REDIRECTS + 1,
                         f"Expected {h3mod.MAX_REDIRECTS + 1} connect() calls, got {call_count}")
        self.assertIn('Too many redirects', stderr_out)

    def test_exactly_max_redirects_succeeds(self):
        """A chain of exactly MAX_REDIRECTS hops (then 200) should succeed."""
        n = h3mod.MAX_REDIRECTS
        responses = [
            (b'', {':status': '302', 'location': f'https://example.com/step{i+1}'})
            for i in range(n)
        ] + [(b'done', {':status': '200'})]

        stdout, stderr_out, call_count = _run_send(
            'https://example.com/step0', responses, follow=True)

        self.assertEqual(call_count, n + 1)
        self.assertNotIn('Too many redirects', stderr_out)
        self.assertIn(b'done', stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
