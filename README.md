# HTTP3 CLI tool

This tool is primarily designed to work with HTTP/3 MASQUE proxies. It supports various HTTP methods, customizable headers, request payloads, and automatic redirect following.

## Installation

To use the H3 script, ensure that you have Python 3.x installed on your system.

``` sh
pip install git+https://github.com/luminati-io/h3-cli.git
```

## Examples

1. Basic GET request:

``` sh
h3 https://example.com
```

2. POST request with custom headers:

``` sh
h3 POST https://example.com -H "User-Agent: CustomAgent" -H "Authorization: Bearer <token>" -d "name=John&age=30"
```

3. GET request with proxy:

``` sh
h3 https://example.com --proxy brd.superproxy.io:10001 --proxy-auth brd-customer-hl_xxx-zone-yyy:password
```

4. Follow redirects (`-L`):

``` sh
h3 -L https://example.com/redirect-me
```

## Redirect following (`-L`)

By default, 3xx responses are returned as-is. Pass `-L` to follow redirects automatically (up to 10 hops):

- **301, 302, 303** — method is downgraded to GET and the request body is dropped.
- **307, 308** — method and body are preserved.

## Running the tests

``` sh
python3 tests/test_send_request.py
python3 tests/test_follow_redirects.py
```

# Both at once (if pytest is available)
python3 -m pytest tests/ -v
```

### Test coverage

| File | What it covers |
|---|---|
| `tests/test_send_request.py` | Basic GET/POST/HEAD, body output, `show_headers`, `ProxyBadStatus`, `Http3ClientError`, unexpected exception re-raise, `validate_https_url`, `validate_headers`, full `main()` arg-parsing flow |
| `tests/test_follow_redirects.py` | `-L` flag disabled by default, single 301/302/307 follow, relative/absolute-path/full-URL location resolution, POST→GET method downgrade on 301/302, POST preserved on 307, redirect loop guard (`MAX_REDIRECTS`) |

## License

ISC — see [LICENSE](LICENSE).
