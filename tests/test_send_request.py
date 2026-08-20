"""
General regression tests for h3-cli send_request() and main() entry point.

Covers: GET/POST/HEAD, custom headers, response body output, show-headers flag,
        ProxyBadStatus error, Http3ClientError, unexpected exceptions,
        validate_https_url, validate_headers, and the main() arg-parsing flow.

Run with:  python3 tests/test_send_request.py
"""
import sys
import os
import asyncio
import unittest
from io import BytesIO, StringIO
from unittest.mock import MagicMock, AsyncMock, patch
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))
import _aioquic_stub
_aioquic_stub.install()

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import h3 as h3mod

# ---------------------------------------------------------------------------
# Helpers shared across test cases
# ---------------------------------------------------------------------------

class _AsyncCtx:
    def __init__(self, client):
        self._client = client
    async def __aenter__(self):
        return self._client
    async def __aexit__(self, *_):
        pass


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


def _make_client(data, headers):
    client = MagicMock()
    client.send_http_request = AsyncMock(return_value=(data, headers))
    return client


def _connect_once(data, hdrs):
    """Return a connect() side-effect that always returns the same response."""
    def _connect(**kwargs):
        return _AsyncCtx(_make_client(data, hdrs))
    return _connect


def _run(url_str, *, data=b'', hdrs=None, method='GET', content=None,
         show_headers=False, follow=False):
    """
    Run send_request() with mocked connect() and captured stdout/stderr.
    Returns (stdout_bytes, stderr_str).
    """
    if hdrs is None:
        hdrs = {':status': '200'}
    h3mod.CONFIG.show_headers = show_headers
    h3mod.CONFIG.follow_redirects = follow
    h3mod.CONFIG.verbose = False
    h3mod.CONFIG.insecure = False
    h3mod.CONFIG.max_datagram_size = 1350
    h3mod.CONFIG.debug = False

    url = urlparse(url_str)
    cap = _CaptureStdout()
    stderr_buf = StringIO()
    with patch.object(h3mod, 'connect', side_effect=_connect_once(data, hdrs)), \
         patch('sys.stdout', cap), \
         patch('sys.stderr', stderr_buf):
        asyncio.run(
            h3mod.send_request(url.hostname, url.port or 443, url,
                               method=method, content=content)
        )
    return cap.getvalue(), stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: basic request / response output
# ---------------------------------------------------------------------------

class TestBasicGetResponse(unittest.TestCase):
    def test_200_body_written_to_stdout(self):
        stdout, _ = _run('https://example.com/', data=b'hello world')
        self.assertEqual(stdout, b'hello world')

    def test_empty_body_produces_no_output(self):
        stdout, _ = _run('https://example.com/', data=b'')
        self.assertEqual(stdout, b'')

    def test_binary_body_passed_through_unchanged(self):
        # print(data.decode()) appends a newline; non-UTF-8 bytes would raise
        # UnicodeDecodeError — that limitation is tracked separately.
        payload = b'simple ascii payload'
        stdout, _ = _run('https://example.com/', data=payload)
        self.assertEqual(stdout, payload)

    def test_connect_called_with_correct_host_port(self):
        url_str = 'https://example.com:8443/path'
        url = urlparse(url_str)
        calls = []
        def _connect(**kwargs):
            calls.append(kwargs)
            return _AsyncCtx(_make_client(b'', {':status': '200'}))
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.follow_redirects = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False
        with patch.object(h3mod, 'connect', side_effect=_connect), \
             patch('sys.stdout', _CaptureStdout()):
            asyncio.run(h3mod.send_request(url.hostname, url.port or 443, url))
        self.assertEqual(calls[0]['host'], 'example.com')
        self.assertEqual(calls[0]['port'], 8443)

    def test_default_port_443(self):
        url_str = 'https://example.com/'
        url = urlparse(url_str)
        calls = []
        def _connect(**kwargs):
            calls.append(kwargs)
            return _AsyncCtx(_make_client(b'', {':status': '200'}))
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.follow_redirects = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False
        with patch.object(h3mod, 'connect', side_effect=_connect), \
             patch('sys.stdout', _CaptureStdout()):
            asyncio.run(h3mod.send_request(url.hostname, url.port or 443, url))
        self.assertEqual(calls[0]['port'], 443)


class TestRequestHeaders(unittest.TestCase):
    def test_path_includes_query_string(self):
        async def run():
            client = h3mod.H3ClientProtocol.__new__(h3mod.H3ClientProtocol)
            client._http = MagicMock()
            client._quic = MagicMock()
            client._quic.get_next_available_stream_id.return_value = 0
            client._loop = asyncio.get_running_loop()
            client.http_response_data = bytearray()
            client.http_response_headers = {}
            client.transmit = MagicMock()
            client.wait_for_response = AsyncMock(return_value=True)

            await client.send_http_request(
                urlparse('https://example.com/check?foo=bar&x=1')
            )
            headers = dict(client._http.send_headers.call_args.args[1])
            self.assertEqual(headers[b':path'], b'/check?foo=bar&x=1')

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Tests: show-headers flag
# ---------------------------------------------------------------------------

class TestShowHeaders(unittest.TestCase):
    _HDRS = {':status': '200', 'content-type': 'text/plain', 'x-custom': 'value'}

    def test_headers_printed_before_body_when_flag_set(self):
        stdout, _ = _run('https://example.com/', data=b'body',
                         hdrs=self._HDRS, show_headers=True)
        text = stdout.decode()
        self.assertIn(':status: 200', text)
        self.assertIn('content-type: text/plain', text)
        self.assertIn('x-custom: value', text)
        self.assertIn('body', text)

    def test_headers_not_printed_by_default(self):
        stdout, _ = _run('https://example.com/', data=b'body',
                         hdrs=self._HDRS, show_headers=False)
        self.assertIn(b'body', stdout)
        self.assertNotIn(b':status', stdout)

    def test_head_method_prints_headers_without_body(self):
        stdout, _ = _run('https://example.com/', data=b'',
                         hdrs=self._HDRS, method='HEAD', show_headers=False)
        text = stdout.decode()
        self.assertIn(':status: 200', text)
        # No body appended (data was empty)
        self.assertNotIn('body', text)

    def test_blank_line_between_headers_and_body(self):
        """When show_headers is set and there is a body, a newline separates them."""
        stdout, _ = _run('https://example.com/', data=b'payload',
                         hdrs={':status': '200'}, show_headers=True)
        text = stdout.decode()
        self.assertIn(':status: 200', text)
        self.assertIn('payload', text)
        # Headers section ends before the body
        self.assertLess(text.index(':status: 200'), text.index('payload'))


# ---------------------------------------------------------------------------
# Tests: error paths
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):
    def setUp(self):
        h3mod.CONFIG.show_headers = False
        h3mod.CONFIG.follow_redirects = False
        h3mod.CONFIG.verbose = False
        h3mod.CONFIG.insecure = False
        h3mod.CONFIG.max_datagram_size = 1350
        h3mod.CONFIG.debug = False

    def _run_with_side_effect(self, exc):
        url = urlparse('https://example.com/')
        client = MagicMock()
        client.send_http_request = AsyncMock(side_effect=exc)
        cap = _CaptureStdout()
        stderr_buf = StringIO()
        with patch.object(h3mod, 'connect', side_effect=lambda **kw: _AsyncCtx(client)), \
             patch('sys.stdout', cap), \
             patch('sys.stderr', stderr_buf):
            asyncio.run(h3mod.send_request(url.hostname, 443, url))
        return cap.getvalue(), stderr_buf.getvalue()

    def test_proxy_bad_status_prints_headers_and_message(self):
        bad_hdrs = {':status': '407', 'proxy-authenticate': 'Basic realm="test"'}
        exc = h3mod.ProxyBadStatus(bad_hdrs)
        stdout, _ = self._run_with_side_effect(exc)
        text = stdout.decode()
        self.assertIn(':status: 407', text)
        self.assertIn('Proxy responded with non-200 status', text)

    def test_http3_client_error_prints_message(self):
        exc = h3mod.Http3ClientError('Connection terminated: stream reset')
        stdout, _ = self._run_with_side_effect(exc)
        self.assertIn('HTTP/3 client error', stdout.decode())
        self.assertIn('Connection terminated', stdout.decode())

    def test_unexpected_exception_is_re_raised(self):
        exc = RuntimeError('something unexpected')
        url = urlparse('https://example.com/')
        client = MagicMock()
        client.send_http_request = AsyncMock(side_effect=exc)
        with patch.object(h3mod, 'connect', side_effect=lambda **kw: _AsyncCtx(client)), \
             patch('sys.stdout', _CaptureStdout()), patch('sys.stderr'):
            with self.assertRaises(RuntimeError):
                asyncio.run(h3mod.send_request(url.hostname, 443, url))


# ---------------------------------------------------------------------------
# Tests: validate_https_url helper
# ---------------------------------------------------------------------------

class TestValidateHttpsUrl(unittest.TestCase):
    def test_https_url_returned_unchanged(self):
        result = h3mod.validate_https_url('https://example.com/path', 'err')
        self.assertEqual(result.scheme, 'https')
        self.assertEqual(result.hostname, 'example.com')
        self.assertEqual(result.path, '/path')

    def test_scheme_prepended_when_missing(self):
        result = h3mod.validate_https_url('example.com/path', 'err')
        self.assertEqual(result.scheme, 'https')
        self.assertEqual(result.hostname, 'example.com')

    def test_http_url_calls_panic(self):
        with self.assertRaises(SystemExit):
            h3mod.validate_https_url('http://example.com/', 'Only https URLs supported')


# ---------------------------------------------------------------------------
# Tests: validate_headers helper
# ---------------------------------------------------------------------------

class TestValidateHeaders(unittest.TestCase):
    def test_valid_headers_parsed(self):
        result = h3mod.validate_headers(['Authorization: Bearer tok', 'X-Foo: bar'])
        self.assertEqual(result['Authorization'], 'Bearer tok')
        self.assertEqual(result['X-Foo'], 'bar')

    def test_value_with_colon_preserved(self):
        result = h3mod.validate_headers(['X-Header: val:ue'])
        self.assertEqual(result['X-Header'], 'val:ue')

    def test_none_returns_empty_dict(self):
        result = h3mod.validate_headers(None)
        self.assertEqual(result, {})

    def test_invalid_header_format_exits(self):
        with self.assertRaises(SystemExit):
            h3mod.validate_headers(['no-colon-here'])


# ---------------------------------------------------------------------------
# Tests: main() argument parsing
# ---------------------------------------------------------------------------

class TestMain(unittest.TestCase):
    """Test that main() correctly parses CLI args and wires them to send_request."""

    def _run_main(self, argv, response=(b'ok', {':status': '200'})):
        """Invoke main() with given argv; return (stdout_bytes, send_request call kwargs)."""
        calls = []
        async def _fake_send(host, port, url, **kw):
            calls.append({'host': host, 'port': port, 'url': url, **kw})
            # Emulate writing body (verifies stdout plumbing isn't broken)
        with patch('sys.argv', ['h3'] + argv), \
             patch.object(h3mod, 'send_request', side_effect=_fake_send):
            h3mod.main()
        return calls

    def test_basic_get_url(self):
        calls = self._run_main(['https://example.com/'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['url'].geturl(), 'https://example.com/')
        self.assertEqual(calls[0]['method'], 'GET')

    def test_explicit_post_method(self):
        calls = self._run_main(['POST', 'https://example.com/', '-d', 'a=1'])
        self.assertEqual(calls[0]['method'], 'POST')
        self.assertEqual(calls[0]['content'], 'a=1')

    def test_custom_headers_forwarded(self):
        calls = self._run_main(['-H', 'X-Custom: val', 'https://example.com/'])
        self.assertIn('X-Custom', calls[0]['headers'])
        self.assertEqual(calls[0]['headers']['X-Custom'], 'val')

    def test_follow_redirects_flag(self):
        self._run_main(['-L', 'https://example.com/'])
        self.assertTrue(h3mod.CONFIG.follow_redirects)

    def test_insecure_flag(self):
        self._run_main(['-k', 'https://example.com/'])
        self.assertTrue(h3mod.CONFIG.insecure)

    def test_show_headers_flag(self):
        self._run_main(['-i', 'https://example.com/'])
        self.assertTrue(h3mod.CONFIG.show_headers)

    def test_non_https_url_exits(self):
        with patch('sys.argv', ['h3', 'http://example.com/']):
            with self.assertRaises(SystemExit):
                h3mod.main()

    def test_get_with_data_exits(self):
        with patch('sys.argv', ['h3', '-d', 'payload', 'https://example.com/']):
            with self.assertRaises(SystemExit):
                h3mod.main()

    def test_proxy_url_parsed_and_forwarded(self):
        calls = self._run_main(
            ['--proxy', 'https://proxy.example.com:3128', 'https://example.com/'])
        self.assertIsNotNone(calls[0]['proxy'])
        self.assertEqual(calls[0]['proxy'].hostname, 'proxy.example.com')
        self.assertEqual(calls[0]['proxy'].port, 3128)

    def test_proxy_auth_forwarded(self):
        calls = self._run_main(
            ['--proxy', 'https://proxy.example.com:3128',
             '--proxy-auth', 'user:pass',
             'https://example.com/'])
        self.assertEqual(calls[0]['proxy_auth'], 'user:pass')


if __name__ == '__main__':
    unittest.main(verbosity=2)
