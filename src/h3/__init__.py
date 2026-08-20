#!/usr/bin/python3
"""
h3 — HTTP/3 command-line client.

Entry point: :func:`main` (registered as the ``h3`` console script).

Core async function: :func:`send_request` — opens a QUIC connection and performs
a single HTTP/3 request, optionally following redirects when ``CONFIG.follow_redirects``
is set.  All output is written to ``sys.stdout`` (binary via ``sys.stdout.buffer`` for
the response body, text via ``print()`` for headers and diagnostic messages).

Proxy support uses the MASQUE CONNECT-UDP protocol (:class:`H3ProxyProtocol`).

Global configuration is stored in the :data:`CONFIG` ``argparse.Namespace`` object,
populated by :func:`main` before ``asyncio.run(send_request(...))`` is called.
"""
import asyncio
import ssl
import base64
import argparse
import sys
import types
import copy
from collections import OrderedDict
from urllib.parse import urlparse, urljoin
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
MAX_REDIRECTS = 10
CONFIG = argparse.Namespace()


class Http3ClientError(Exception):
    """Raised when an HTTP/3 connection is terminated abnormally."""
    pass

def create_quic_configuration():
    """Build a :class:`QuicConfiguration` from the current :data:`CONFIG` settings."""
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
        self.received_since_wait = False
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()
        if CONFIG.verbose:
            wrap_tls_events(self._quic)

    def datagram_received(self, data, addr):
        self.received_since_wait = True
        super().datagram_received(data, addr)

    def reset_for_next_request(self):
        """Reset per-request state so this protocol can send another request."""
        self._request_waiter = self._loop.create_future()
        self.received_since_wait = False
        self.http_response_headers = OrderedDict()
        self.http_response_data = bytearray()

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

    async def wait_for_response(self, peer):
        """Give up on a silent peer instead of stalling until the QUIC idle timeout."""
        timeout = CONFIG.connect_timeout
        while True:
            self.received_since_wait = False
            try:
                return await asyncio.wait_for(
                    asyncio.shield(self._request_waiter), timeout)
            except asyncio.TimeoutError:
                if not self.received_since_wait:
                    self._request_waiter.cancel()
                    raise Http3ClientError(
                        f'No response from {peer} after {timeout}s')

    async def send_http_request(self, url, method='GET', headers=None, content=None, proxy=None, 
                                proxy_auth=None):
        self.reset_for_next_request()
        if method == 'HEAD':
            self._http._check_content_length = types.MethodType(
                lambda self, stream: None, self._http)

        path = (url.path or '/') + (f'?{url.query}' if url.query else '')
        self.sent_headers = [
            (b':method', method.encode()),
            (b':scheme', b'https'),
            (b':authority', url.hostname.encode()),
            (b':path', path.encode()),
        ] + [(k.encode(), v.encode()) for k, v in (headers or {}).items()]

        stream_id = self._quic.get_next_available_stream_id()

        self._http.send_headers(stream_id, self.sent_headers, end_stream=not content)
        if content:
            self.sent_data = content
            self._http.send_data(stream_id, data=content.encode(), end_stream=True)
        self.transmit()
        await self.wait_for_response(url.hostname)
        return self.http_response_data, self.http_response_headers


class ProxyBadStatus(Http3ClientError):
    """Raised when the MASQUE proxy responds with a non-200 CONNECT-UDP status.

    Attributes:
        headers: Response headers dict returned by the proxy.
    """
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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # maps the CONNECT stream_id to its tunneled (proxy_http, proxy_addr)
        self.tunnels = {}

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
            tunnel = self.tunnels.get(event.stream_id)
            if tunnel is not None:
                proxy_http, proxy_addr = tunnel
                # the tunneled connection has no real transport, so hand it the datagram directly
                proxy_http.datagram_received(event.data[1:], proxy_addr)
        elif isinstance(event, HeadersReceived):
            self.http_headers_received(event)

    async def send_http_request(self, url, method='GET', headers=None, content=None, proxy=None, 
                                proxy_auth=None):
        self.reset_for_next_request()
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
        await self.wait_for_response(proxy.hostname)

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
        proxy_quic = QuicConnection(configuration=configuration)
        proxy_addr = (url.hostname, url.port or DEFAULT_PORT)
        proxy_quic.connect(proxy_addr, self._loop.time())
        proxy_http = H3ClientProtocol(proxy_quic)
        proxy_http._transport = HTTPProxiedTransport(self._http, stream_id, self.transmit)
        self.tunnels[stream_id] = (proxy_http, proxy_addr)

        return await proxy_http.send_http_request(url, method, headers, content)


async def send_request(host, port, url, method='GET', content=None, headers=None,
                       proxy=None, proxy_auth=None):
    """
    Perform an HTTP/3 request and write the response to stdout.

    Parameters
    ----------
    host : str
        QUIC peer hostname (the proxy host when *proxy* is set, otherwise the
        target URL hostname).
    port : int
        QUIC peer port.
    url : :class:`urllib.parse.ParseResult`
        Parsed target URL (always the final destination, even when proxying).
    method : str
        HTTP method (default ``'GET'``).  Automatically upper-cased by :func:`main`.
    content : str or None
        Request body string.  ``None`` for bodyless requests.
    headers : dict or None
        Extra request headers as ``{name: value}`` strings.
    proxy : :class:`urllib.parse.ParseResult` or None
        Parsed MASQUE proxy URL.  When set, :class:`H3ProxyProtocol` is used.
    proxy_auth : str or None
        Proxy ``username:password`` credential string.

    Redirect following
    ------------------
    When ``CONFIG.follow_redirects`` is ``True``, 3xx responses whose ``location``
    header is present are re-requested automatically:

    - 301 / 302 / 303 → method becomes ``GET``, body is dropped.
    - 307 / 308 → method and body are preserved.
    - At most :data:`MAX_REDIRECTS` hops are followed; exceeding this prints an
      error to ``stderr`` and returns.
    - Redirects to non-``https://`` URLs are rejected with an error message.
    """
    for hop in range(MAX_REDIRECTS + 1):
        async with connect(
            host=host,
            port=port,
            create_protocol=H3ProxyProtocol if proxy else H3ClientProtocol,
            configuration=create_quic_configuration(),
            wait_connected=False
        ) as client:
            try:
                data, resp_headers = await client.send_http_request(url, method, headers, content, proxy, proxy_auth)
            except ProxyBadStatus as e:
                print("\n".join([f'{k}: {v}' for k, v in e.headers.items()]))
                print("Proxy responded with non-200 status")
                return
            except Http3ClientError as e:
                print(f"HTTP/3 client error: {e}")
                return
            except Exception as e:
                print(f"Unexpected error: {e}")
                raise

        status = resp_headers.get(':status', '')
        if getattr(CONFIG, 'follow_redirects', False) and status.startswith('3') and 'location' in resp_headers:
            if hop == MAX_REDIRECTS:
                print(f"Too many redirects (max {MAX_REDIRECTS})", file=sys.stderr)
                return
            location = resp_headers['location']
            new_url_str = urljoin(url.geturl(), location)
            new_parsed = urlparse(new_url_str)
            if new_parsed.scheme != 'https':
                print(f"Redirect to non-https URL not supported: {new_url_str}", file=sys.stderr)
                return
            if CONFIG.verbose:
                print(f'* Redirecting to: {new_url_str}', file=sys.stderr)
            url = new_parsed
            if not proxy:
                host = url.hostname
                port = url.port or DEFAULT_PORT
            if status in ('301', '302', '303'):
                method = 'GET'
                content = None
                if headers and 'content-length' in headers:
                    del headers['content-length']
            continue

        if CONFIG.show_headers or method == 'HEAD':
            print("\n".join([f'{k}: {v}' for k, v in resp_headers.items()]))
        if data:
            if CONFIG.show_headers:
                print()
            sys.stdout.buffer.write(data)
        return


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
    parser.add_argument('method', nargs='?', default='GET',
        help=(
            'The HTTP method to use for the request. The default method is GET. '
            'Other common methods include POST, PUT, DELETE, PATCH, etc.'
        ))
    parser.add_argument('url', type=str,
        help=(
            'The URL to which the HTTP3 request will be made. This '
            'is a required argument. Example: https://example.com. '
            'The URL scheme must be either "https://" or left '
            'unspecified, in which case "https://" will be '
            'automatically added.'
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
    parser.add_argument('-L', '--follow-redirects', action='store_true',
        help=(
            'Follow HTTP redirects (3xx responses). '
            'By default, redirects are not followed. '
            'This option enables automatic redirect following, up to a maximum of '
            f'{MAX_REDIRECTS} hops.'
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
    parser.add_argument('--connect-timeout', default=10.0, type=float,
        help=(
            'Seconds to wait for data from the peer before giving up. The timer resets on '
            'every datagram received, so slow transfers are not interrupted; it only fires when '
            'the peer goes completely silent, which would otherwise stall until the QUIC idle '
            'timeout. The default is 10 seconds.'
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
