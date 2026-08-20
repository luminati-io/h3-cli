"""
Tests for the --connect-timeout stall detection and the proxy datagram pump.

Covers: wait_for_response() returning on success, failing on a silent peer,
        tolerating slow-but-alive transfers, propagating connection errors,
        and H3ProxyProtocol forwarding tunneled datagrams to the inner connection.

Run with:  python3 tests/test_connect_timeout.py
"""
import sys
import os
import types
import asyncio
import argparse
import unittest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub aioquic (not installed in dev environment)
# ---------------------------------------------------------------------------

def _stub(name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


class _BaseProtocol:
    """Stand-in for aioquic's QuicConnectionProtocol."""
    def __init__(self, quic=None, **kwargs):
        self._quic = quic
        self._loop = asyncio.get_event_loop()
        self.received_datagrams = []

    def datagram_received(self, data, addr):
        self.received_datagrams.append((data, addr))


class _H3Connection:
    def __init__(self, quic, client):
        self.quic = quic


class _DatagramReceived:
    def __init__(self, data, stream_id=0):
        self.data = data
        self.stream_id = stream_id


class _HeadersReceived:
    def __init__(self, headers):
        self.headers = headers


_QuicCfg = type('QuicConfiguration', (), {
    '__init__': lambda self, **kw: None,
    'alpn_protocols': None, 'max_datagram_size': 1350,
    'max_datagram_frame_size': 0, 'verify_mode': None, 'server_name': None,
})

_stub('aioquic')
_stub('aioquic.asyncio', connect=MagicMock())
_stub('aioquic.asyncio.protocol', QuicConnectionProtocol=_BaseProtocol)
_stub('aioquic.h3.connection', H3_ALPN=['h3'], H3Connection=_H3Connection)
_stub('aioquic.h3.events',
      HeadersReceived=_HeadersReceived, DataReceived=object,
      H3Event=object, DatagramReceived=_DatagramReceived)
_stub('aioquic.quic.connection', QuicConnection=object)
_stub('aioquic.quic.configuration', QuicConfiguration=_QuicCfg)
_stub('aioquic.quic.events', ConnectionTerminated=object, HandshakeCompleted=object)
_stub('aioquic.quic.logger', QuicFileLogger=object)
sys.modules['aioquic'].tls = _stub('aioquic.tls')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import h3 as h3mod  # noqa: E402

TIMEOUT = 0.05


def _configure(**overrides):
    settings = dict(verbose=False, debug=False, connect_timeout=TIMEOUT)
    settings.update(overrides)
    h3mod.CONFIG = argparse.Namespace(**settings)


class WaitForResponseTests(unittest.TestCase):
    def setUp(self):
        _configure()

    def test_returns_once_the_response_completes(self):
        async def scenario():
            proto = h3mod.H3ClientProtocol(quic=MagicMock())
            proto._loop.call_later(TIMEOUT / 5, proto._request_waiter.set_result, True)
            await proto.wait_for_response('example.com')
            return proto

        proto = asyncio.run(scenario())
        self.assertTrue(proto._request_waiter.done())

    def test_fails_when_the_peer_never_answers(self):
        async def scenario():
            proto = h3mod.H3ClientProtocol(quic=MagicMock())
            with self.assertRaises(h3mod.Http3ClientError) as ctx:
                await proto.wait_for_response('dead.example.com')
            return str(ctx.exception), proto

        message, proto = asyncio.run(scenario())
        self.assertIn('dead.example.com', message)
        self.assertIn(str(TIMEOUT), message)
        # the abandoned waiter is cancelled so a later termination cannot raise
        self.assertTrue(proto._request_waiter.cancelled())

    def test_slow_transfer_is_not_interrupted(self):
        """Arriving datagrams reset the stall timer, so a long transfer survives."""
        async def scenario():
            proto = h3mod.H3ClientProtocol(quic=MagicMock())

            async def feed():
                for _ in range(10):
                    await asyncio.sleep(TIMEOUT / 2)
                    proto.datagram_received(b'chunk', ('example.com', 443))
                proto._request_waiter.set_result(True)

            feeder = asyncio.ensure_future(feed())
            await proto.wait_for_response('example.com')
            await feeder
            return proto

        loop_time = asyncio.run(self._timed(scenario()))
        elapsed, proto = loop_time
        # the whole transfer took far longer than a single timeout window
        self.assertGreater(elapsed, TIMEOUT * 2)
        self.assertEqual(len(proto.received_datagrams), 10)

    @staticmethod
    async def _timed(coro):
        loop = asyncio.get_running_loop()
        start = loop.time()
        result = await coro
        return loop.time() - start, result

    def test_connection_error_is_propagated(self):
        """A real failure surfaces instead of being masked by the stall timeout."""
        async def scenario():
            proto = h3mod.H3ClientProtocol(quic=MagicMock())
            proto._loop.call_later(
                TIMEOUT / 5,
                proto._request_waiter.set_exception,
                h3mod.Http3ClientError('Connection terminated: boom'))
            with self.assertRaises(h3mod.Http3ClientError) as ctx:
                await proto.wait_for_response('example.com')
            return str(ctx.exception)

        self.assertIn('boom', asyncio.run(scenario()))

    def test_each_wait_starts_a_fresh_window(self):
        async def scenario():
            proto = h3mod.H3ClientProtocol(quic=MagicMock())
            proto.received_since_wait = True
            with self.assertRaises(h3mod.Http3ClientError):
                await proto.wait_for_response('example.com')

        asyncio.run(scenario())


class ProxyDatagramPumpTests(unittest.TestCase):
    def setUp(self):
        _configure()

    def _proxy(self):
        proxy = h3mod.H3ProxyProtocol(quic=MagicMock())
        proxy_http = MagicMock()
        proxy.tunnels[0] = (proxy_http, ('example.com', 443))
        return proxy, proxy_http

    def test_tunneled_datagram_is_handed_to_the_inner_connection(self):
        async def scenario():
            proxy, proxy_http = self._proxy()
            proxy.http_event_received(_DatagramReceived(b'\x00payload', stream_id=0))
            return proxy, proxy_http

        proxy, proxy_http = asyncio.run(scenario())
        # the context-ID byte is stripped before the inner connection sees it
        proxy_http.datagram_received.assert_called_once_with(
            b'payload', ('example.com', 443))

    def test_proxy_response_headers_are_still_handled(self):
        async def scenario():
            proxy, proxy_http = self._proxy()
            proxy.http_headers_received = MagicMock()
            event = _HeadersReceived([(b':status', b'200')])
            proxy.http_event_received(event)
            return proxy, proxy_http, event

        proxy, proxy_http, event = asyncio.run(scenario())
        proxy.http_headers_received.assert_called_once_with(event)
        proxy_http.datagram_received.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
