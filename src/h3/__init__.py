#!/usr/bin/python3
import asyncio
import ssl
import base64
import argparse
import sys
import types
import copy
from collections import OrderedDict
from urllib.parse import urlparse
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, H3Event, DatagramReceived
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
from aioquic.quic.logger import QuicFileLogger
import aioquic.tls as tls


DEFAULT_PORT = 443
CONFIG = argparse.Namespace()


class Http3ClientError(Exception):
    pass

def create_quic_configuration():
    config = QuicConfiguration(is_client=True)
    config.alpn_protocols = H3_ALPN
    if CONFIG.verbose:
        print('* ALPN', config.alpn_protocols)
    config.max_datagram_size = CONFIG.max_datagram_size
    config.max_datagram_frame_size = 10000
    if CONFIG.insecure:
        config.verify_mode = ssl.CERT_NONE
    return config

def wrap_tls_context_methods(context):
    _handle_reassembled_message = context._handle_reassembled_message
    def wrapped_handle_reassembled_message(
        self, message_type, input_buf, output_buf
    ):
        handshake_type = tls.HandshakeType(message_type)
        print(f'* TLSv1.3 (IN) {handshake_type.name}({handshake_type.value}):')
        _handle_reassembled_message(message_type, input_buf, output_buf)
    context._handle_reassembled_message = types.MethodType(wrapped_handle_reassembled_message, context)

    _set_state = context._set_state
    def wrapped_set_state(self, state):
        state = tls.State(state)
        print(f'* TLSv1.3 (STATE) {state.name}({state.value}):')
        _set_state(state)
    context._set_state = types.MethodType(wrapped_set_state, context)

def wrap_tls_events(quic):
    if quic._connect_called:
        return wrap_tls_context_methods(quic.tls)
    fn = quic._connect
    def _connect(self, now):
        fn(now)
        client_hello = tls.HandshakeType.CLIENT_HELLO
        print(f'* TLSv1.3 (OUT) {client_hello.name}({client_hello.value}):')
        wrap_tls_context_methods(self.tls)
    quic._connect = types.MethodType(_connect, quic)


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic, True)
        self._request_waiter = self._loop.create_future()
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()
        if CONFIG.verbose:
            wrap_tls_events(self._quic)

    def http_event_received(self, event: H3Event) -> None:
        if CONFIG.debug:
            print(self.__class__.__name__, 'http_event_received', event)
        if isinstance(event, DataReceived):
            self.http_response_data.extend(event.data)
        elif isinstance(event, HeadersReceived):
            self.http_response_headers.update(
                {k.decode(): v.decode() for k, v in event.headers}
            )
        if event.stream_ended and not self._request_waiter.done():
            self._request_waiter.set_result(True)

    def quic_event_received(self, event):
        if CONFIG.debug:
            print(self.__class__.__name__, 'quic_event_received', event)
        for http_event in self._http.handle_event(event):
            self.http_event_received(http_event)
        
        if isinstance(event, HandshakeCompleted) and CONFIG.verbose:
            print(f'* ALPN server accepted', event.alpn_protocol)
            cert = self._quic.tls._peer_certificate
            print('* Server certificate:')
            print(f'*  subject: {cert.subject.rfc4514_string()}')
            print(f'*  start date: {cert.not_valid_before_utc}')
            print(f'*  expire date: {cert.not_valid_after_utc}')
            print(f'*  issuer: {cert.issuer.rfc4514_string()}')
            for k, v in self.sent_headers:
                print(f'> {k.decode()}: {v.decode()}')
            print('>')

        if isinstance(event, ConnectionTerminated) and not self._request_waiter.done():
            error_message = 'Connection terminated'
            if event.reason_phrase:
                error_message += f': {event.reason_phrase}'
            self._request_waiter.set_exception(Http3ClientError(error_message))

    async def send_http_request(self, url, method='GET', headers=None, content=None, proxy=None, 
                                proxy_auth=None):
        if method == 'HEAD':
            self._http._check_content_length = types.MethodType(
                lambda self, stream: None, self._http)

        self.sent_headers = [
            (b':method', method.encode()),
            (b':scheme', b'https'),
            (b':authority', url.hostname.encode()),
            (b':path', (url.path or '/').encode()),
        ] + [(k.encode(), v.encode()) for k, v in (headers or {}).items()]

        stream_id = self._quic.get_next_available_stream_id()

        self._http.send_headers(stream_id, self.sent_headers, end_stream=not content)
        if content:
            self.sent_data = content
            self._http.send_data(stream_id, data=content.encode(), end_stream=True)
        self.transmit()
        await asyncio.shield(self._request_waiter)
        return self.http_response_data, self.http_response_headers


class ProxyBadStatus(Http3ClientError):
    def __init__(self, headers):
        self.headers = headers


class HTTPProxiedTransport:
    def __init__(self, http, stream_id, transmit):
        self.http = http
        self.stream_id = stream_id
        self.transmit = transmit

    def sendto(self, data, addr):
        self.http.send_datagram(self.stream_id, b'\x00'+data)
        self.transmit()


class H3ProxyProtocol(H3ClientProtocol):
    def http_headers_received(self, event: HeadersReceived):
        headers = {k.decode(): v.decode() for k, v in event.headers}
        self.http_response_headers = headers
        if headers[':status'] == '200' and headers['capsule-protocol'] == '?1':
            self._request_waiter.set_result(True)
        else:
            self._request_waiter.set_exception(ProxyBadStatus(headers))

    def http_event_received(self, event: H3Event) -> None:
        if CONFIG.debug:
            print(self.__class__.__name__, 'http_event_received', event)
        if isinstance(event, DatagramReceived):
            self.proxy_quic.receive_datagram(event.data[1:], self.proxy_addr, self._loop.time())
        elif isinstance(event, HeadersReceived):
            self.http_headers_received(event)

    async def send_http_request(self, url, method='GET', headers=None, content=None, proxy=None, 
                                proxy_auth=None):
        if CONFIG.verbose:
            print('* Connecting to proxy')
        stream_id = self._quic.get_next_available_stream_id()
        template_url = f'/.well-known/masque/udp/{url.hostname}/{url.port or DEFAULT_PORT}/'
        proxy_headers = [
            (b':method', b'CONNECT'),
            (b':scheme', b'https'),
            (b':authority', proxy.hostname.encode()),
            (b':path', template_url.encode()),
            (b':protocol', b'connect-udp'),
            (b'capsule-protocol', b'?1'),
        ]

        if proxy_auth:
            token = base64.b64encode(proxy_auth.encode())
            proxy_headers.append((b'proxy-authorization', b'Basic '+token))

        self.sent_headers = proxy_headers
        self._http.send_headers(stream_id, self.sent_headers, end_stream=False)
        self.transmit()
        await asyncio.shield(self._request_waiter)

        if CONFIG.verbose:
            print('* Request completely sent off')
            for k, v in self.http_response_headers.items():
                print(f'< {k}: {v}')
            print('<')
            local_port = self._transport._sock.getsockname()[1]
            print(f'* Proxy connected: 127.0.0.1:{local_port} -> {proxy.netloc} -> {url.netloc}')
            print('* Starting request')

        configuration = create_quic_configuration()
        configuration.max_datagram_size = 1200
        configuration.server_name = url.hostname
        self.proxy_quic = QuicConnection(configuration=configuration)
        self.proxy_addr = (url.hostname, url.port or DEFAULT_PORT)
        self.proxy_quic.connect(self.proxy_addr, self._loop.time())
        self.proxy_http = H3ClientProtocol(self.proxy_quic)
        self.proxy_http._transport = HTTPProxiedTransport(self._http, stream_id, self.transmit)

        return await self.proxy_http.send_http_request(url, method, headers, content)


async def send_request(host, port, url, method='GET', content=None, headers=None,
                       proxy=None, proxy_auth=None):
    async with connect(
        host=host,
        port=port,
        create_protocol=H3ProxyProtocol if proxy else H3ClientProtocol,
        configuration=create_quic_configuration(),
        wait_connected=False
    ) as client:
        try:
            data, headers = await client.send_http_request(url, method, headers, content, proxy, proxy_auth)
            if CONFIG.show_headers or method == 'HEAD':
                print("\n".join([f'{k}: {v}' for k, v in headers.items()]))
            if data:
                if CONFIG.show_headers:
                    print()
                print(data.decode())
        except ProxyBadStatus as e:
            print("\n".join([f'{k}: {v}' for k, v in e.headers.items()]))
            print("Proxy responded with non-200 status")
        except Http3ClientError as e:
            print(f"HTTP/3 client error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            raise


class CapitalisedHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = 'Usage: '
        action_usage = []
        for action in actions:
            if not action.option_strings:
                continue
            action = copy.copy(action)
            action.option_strings = action.option_strings[:1]
            formatted = self._format_action_invocation(action)
            action_usage.append(f'[{formatted}]')
        usage_actions = ' '.join(action_usage)
        usage = f'{self._prog} {usage_actions} [method] <url>'
        return super().add_usage(usage, actions, groups, prefix)
    def add_argument(self, action):
        if action.dest == 'url':
            action.metavar = 'url (required)'
        return super().add_argument(action)

def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=CapitalisedHelpFormatter,
        description=(
            'Python based, CURL-like client that can make HTTP3 request '
            'to a given URL - including proxy support per RFC 9298. Note that '
            'this client sends only HTTP3 requests and is not backwards compatible '
            'with HTTP2/HTTP1.1'
        )
    )
    parser.add_argument('url', type=str,
        help=(
            'The URL to which the HTTP3 request will be made. This '
            'is a required argument. Example: https://example.com. '
            'The URL scheme must be either "https://" or left '
            'unspecified, in which case "https://" will be '
            'automatically added.'
    ))
    parser.add_argument('method', nargs='?', default='GET',
        help=(
            'The HTTP method to use for the request. The default method is GET. '
            'Other common methods include POST, PUT, DELETE, PATCH, etc.'
        ))
    parser.add_argument('-H', dest='headers', action='append',
        help=(
            'HTTP headers to send with the request. '
            'Provide each header in the format "Key: Value". '
            'Multiple headers can be provided by repeating the -H option. '
            'Example: -H "User-Agent: CustomAgent" -H "Authorization: Bearer <token>"'
        ))
    parser.add_argument('-d', '--data', type=str,
         help=(
            'The request payload (data) to send with the request. '
            'This is typically used for POST, PUT, or PATCH requests to send data in the body. '
            'Example: -d "name=John&age=30"'
        ))
    parser.add_argument('-i', '--show-headers', action='store_true',
        help=(
            'Shows the response headers in the output. '
            'This can help you debug the HTTP3 request and inspect details like status codes, content type, '
            'cookies, etc. The response body will not be shown unless explicitly requested.'
        ))
    parser.add_argument('--proxy', type=str,
        help=(
            'Specify the HTTP3 proxy server address to use for making the request. '
            'The proxy MUST SUPPORT the CONNECT-UDP protocol, which is compatible with HTTP3 connections. '
            'Provide the proxy in the format "hostname:port". '
            'Example: --proxy "https://proxy.example.com:8888"'
        ))
    parser.add_argument('--proxy-auth', type=str,
        help=(
            'Proxy authentication credentials, provided in the format "username:password". '
            'This is used to authenticate against the proxy server if it requires authentication.'
        ))
    parser.add_argument('-k', '--insecure', action='store_true',
        help=(
            'Skips SSL certificate verification for QUIC connections. '
            'This is useful when testing with self-signed certificates or untrusted certificate authorities. '
            'Be cautious as this reduces security.'
        ))
    parser.add_argument('--max-datagram-size', default=1350, type=int,
        help=(
            'Sets the maximum datagram size for QUIC connections. '
            'This can be useful for networks with a small maximum transmission unit (MTU). '
            'The default is 1350 bytes.'
        ))
    parser.add_argument('-v', '--verbose', action='store_true',
        help=(
            'Enables verbose output, which provides more detailed logs of the request process, '
            'including headers, payloads, and connection details.'
        ))
    parser.add_argument('--debug', action='store_true',
        help=(
            'Enables debugging output. This will show extremely detailed logs, including internal processes, networking details, '
            'and possibly lower-level debug information from the HTTP3 client.'
        ))
    return parser.parse_args()

def panic(message):
    print(message)
    sys.exit(1)

def validate_headers(headers):
    valid_headers = {}
    for kv in headers or []:
        try:
            key, value = kv.split(':', 1)
            valid_headers[key.strip()] = value.strip()
        except ValueError:
            panic(f"Invalid header format: '{kv}'. Headers must be in 'key:value' format.")
    return valid_headers

def validate_https_url(url, panic_message):
    if not urlparse(url).scheme:
        url = 'https://' + url
    url = urlparse(url)
    if url.scheme != 'https':
        panic(panic_message)
    return url

def main():
    args = parse_args()

    for k, v in args._get_kwargs():
        setattr(CONFIG, k, v)

    args.method = args.method.upper()

    url = validate_https_url(args.url, 'Only https:// URLs are supported')
    proxy = validate_https_url(args.proxy, 'Proxy supports only https:// scheme') \
        if args.proxy else None

    headers = validate_headers(args.headers)
    if args.data:
        if args.method == 'GET':
            panic('Payload cant be used with GET method')
        headers['content-length'] = str(len(args.data))

    host = proxy.hostname if proxy else url.hostname
    port = proxy.port if proxy else url.port or DEFAULT_PORT

    asyncio.run(send_request(
        host, port, url, method=args.method, headers=headers,
        content=args.data, proxy=proxy, proxy_auth=args.proxy_auth
    ))


if __name__ == '__main__':
    main()
