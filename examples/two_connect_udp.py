#!/usr/bin/python3
"""
Experiment: open a single HTTP/3 connection to the MASQUE proxy and issue
two CONNECT-UDP tunnels over it, one after another, each performing a
full HTTP/3 request to the target host through its own tunnel.

Usage:
    python3 two_connect_udp.py --proxy https://host:port \
        --proxy-auth user:pass https://target1.example https://target2.example
"""
import argparse
import asyncio

from aioquic.asyncio import connect

from h3 import (
    CONFIG, DEFAULT_PORT, H3ProxyProtocol, Http3ClientError, ProxyBadStatus,
    create_quic_configuration, validate_https_url,
)


async def run_two_requests(proxy, proxy_auth, url1, url2):
    host = proxy.hostname
    port = proxy.port or DEFAULT_PORT

    async with connect(
        host=host,
        port=port,
        create_protocol=H3ProxyProtocol,
        configuration=create_quic_configuration(),
        wait_connected=False,
    ) as client:
        for i, url in enumerate((url1, url2), start=1):
            print(f'\n=== Request {i}: CONNECT-UDP tunnel -> {url.hostname} ===')
            try:
                data, headers = await client.send_http_request(
                    url, method='GET', headers=None, content=None,
                    proxy=proxy, proxy_auth=proxy_auth,
                )
            except ProxyBadStatus as e:
                print("\n".join(f'{k}: {v}' for k, v in e.headers.items()))
                print(f'Request {i}: proxy responded with non-200 status')
                continue
            except Http3ClientError as e:
                print(f'Request {i}: HTTP/3 client error: {e}')
                continue

            print("\n".join(f'{k}: {v}' for k, v in headers.items()))
            print(f'Request {i}: {len(data)} bytes of body received')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('urls', nargs=2, help='Two target URLs to request')
    parser.add_argument('--proxy', required=True)
    parser.add_argument('--proxy-auth')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-k', '--insecure', action='store_true')
    parser.add_argument('--max-datagram-size', default=1350, type=int)
    parser.add_argument('--connect-timeout', default=10.0, type=float)
    parser.add_argument('--show-headers', action='store_true', default=True)
    args = parser.parse_args()

    for k, v in args._get_kwargs():
        setattr(CONFIG, k, v)
    CONFIG.follow_redirects = False

    proxy = validate_https_url(args.proxy, 'Proxy supports only https:// scheme')
    url1 = validate_https_url(args.urls[0], 'Only https:// URLs are supported')
    url2 = validate_https_url(args.urls[1], 'Only https:// URLs are supported')

    asyncio.run(run_two_requests(proxy, args.proxy_auth, url1, url2))


if __name__ == '__main__':
    main()
