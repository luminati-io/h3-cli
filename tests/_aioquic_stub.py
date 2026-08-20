"""
Shared aioquic stub for tests, since the dev environment doesn't have aioquic
installed and the real thing isn't needed to exercise h3-cli's own logic.

Call install() once, before `import h3`, from each test module. Pass overrides
for any class a test needs to be a real (non-`object`) stand-in.
"""
import sys
import types
from unittest.mock import MagicMock


def _stub(name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


def install(*, quic_connection_protocol=object, h3_connection=object,
            headers_received=object, data_received=object, h3_event=object,
            datagram_received=object):
    quic_cfg = type('QuicConfiguration', (), {
        '__init__': lambda self, **kw: None,
        'alpn_protocols': None, 'max_datagram_size': 1350,
        'max_datagram_frame_size': 0, 'verify_mode': None, 'server_name': None,
    })

    _stub('aioquic')
    _stub('aioquic.asyncio', connect=MagicMock())
    _stub('aioquic.asyncio.protocol', QuicConnectionProtocol=quic_connection_protocol)
    _stub('aioquic.h3.connection', H3_ALPN=['h3'], H3Connection=h3_connection)
    _stub('aioquic.h3.events',
          HeadersReceived=headers_received, DataReceived=data_received,
          H3Event=h3_event, DatagramReceived=datagram_received)
    _stub('aioquic.quic.connection', QuicConnection=object)
    _stub('aioquic.quic.configuration', QuicConfiguration=quic_cfg)
    _stub('aioquic.quic.events', ConnectionTerminated=object, HandshakeCompleted=object)
    _stub('aioquic.quic.logger', QuicFileLogger=object)
    sys.modules['aioquic'].tls = _stub('aioquic.tls')
