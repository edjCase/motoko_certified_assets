# Certified Assets

A library designed to certify assets served via HTTP on the Internet Computer.
It implements the [Response Verification Standard](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification) and works by certifying data and their endpoints during update calls.
Once certified, the certificates are returned as headers in an HTTP response, ensuring the security and integrity of the data.

## Getting Started

### Installation

1. [Install mops](https://j4mwm-bqaaa-aaaam-qajbq-cai.ic0.app/#/docs/install)
2. Run the following command in your project directory:

```bash
mops install certified-assets
```

### Usage

To begin using Certified Assets, import the module into your project:

- class version

```motoko
import CertifiedAssets "mo:certified-assets";
```

- stable version

```motoko
import CertifiedAssets "mo:certified-assets/CertifiedAssets";
```

#### Create a new instance

- `Heap` - Creates a new instance that will be cleared during canister upgrades.

  ```motoko
      let certs = CertifiedAssets.CertifiedAssets(null);
  ```

- `Stable Heap` - For creating a persistent instance that remains stable through canister upgrades

  ```motoko
      stable let cert_store = CertifiedAssets.init_stable_store();
      let certs = CertifiedAssets.CertifiedAssets(?cert_store);
  ```

  > Note: For stable instances, it's recommended to `clear()` all certified endpoints and re-certify them if the data has changed during a canister upgrade.

#### Certify an Asset

Define an `Endpoint` with the URL where the asset will be hosted, the data for certification, and optionally, details about the HTTP request and response.

```motoko
    let endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!");
    certs.certify(endpoint);
```

The above method creates a new sha256 hash of the data, if you already have the hash, you can pass it in via the `hash()` method to avoid recomputing it.

```motoko
    let endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!")
        .hash(<sha256 hash of "Hello, World!">);
    certs.certify(endpoint);
```

[Certification V2](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification) allows for the inclusion of additional optional information in the future response's certificate.

These additional parameters include:

- **Flags**:
  - `no_certification()`: if called, none of the data will be certified
  - `no_request_certification()`: if called, only the response will be certified
- **Request methods**:
  - `method()`: the request method
  - `query_param()`: the query parameters
  - `request_headers()`: the request headers
- **Response methods**:
  - `status()`: the response status code
  - `response_headers()`: the response headers

When certifying assets, it's crucial to consider not just the content but also the context in which it's served, including HTTP headers, status code and query parameters.

```motoko

    let html_page = "<h2 style=\"color: red;\">Hello, World!</h2>";

    let endpoint = CertifiedAssets.Endpoint("/hello.html", html_page);
        .no_request_certification()
        .status(200)
        .response_header("Content-Type", "text/html");

    certs.certify(endpoint);

```

#### Update Certified Assets

A unique hash is generated for each endpoint, so any change to the data will require re-certification. To re-certify an asset, you need to `remove()` the existing one and `certify()` the new one.

```motoko
    let old_endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!");
    let new_endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World! Updated");

    certs.remove(endpoint);
    certs.certify(endpoint);
```

#### Serving A Certified Asset

To serve a certified asset, call the `get_certified_response()` function with the request and response, ensuring they match the defined endpoint. If they don't match, the function will return an error.

```motoko
    import Debug "mo:base/Debug";
    import Text "mo:base/Text";
    import HttpTypes "mo:http-types"; // -> https://mops.one/http-types

    public func http_request(req : HttpTypes.Request) : HttpTypes.Response {
        assert req.url == "/hello.html";

        let res : HttpTypes.Response = {
            status_code = 200;
            headers = [("Content-Type", "text/html")];
            body = Text.encodeUtf8(html_page);
            streaming_strategy = null;
            upgrade = null;
        };

        let result = certs.get_certified_response(req, res, null);

        let #ok(certified_response) = result else return Debug.trap(debug_show result);

        return certified_response;
    };
```

Once again, you can include the hash of the data when retrieving the certified response to avoid recomputing it.

```motoko
    let result = certs.get_certified_response(req, res, ?sha256_of_html_page);
```

### Credits & References

- [Response Verification Standard](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification)
- Libraries: [ic-certification](https://github.com/nomeata/ic-certification), [certified-http](https://github.com/infu/certified-http)
