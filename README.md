# HTTP3 CLI tool

This is a pip to a given URL. It supports various HTTP methods, customizable headers, request payloads. This tool is primarily designed to work with HTTP/3 MASQUE proxies

## Installation

To use the H3 script, ensure that you have Python 3.x installed on your system.

``` sh
pip install https://github.com/luminati-io/h3-cli.git
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
