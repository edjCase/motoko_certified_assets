# Certified Assets

A library designed to certify assets served via HTTP on the Internet Computer. This library only stores the certificates, not the assets themselves. It implements the [Response Verification Standard](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification) and works by certifying data and their endpoints during update calls. Once certified, the certificates are returned as headers in an HTTP response, ensuring the security and integrity of the data.

> Note that this library does not store the assets themselves, only the certificates. Either use the ic-assets library to store the assets or define your own storage mechanism.

## Motivation

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
import CertifiedAssets "mo:certified-assets/Stable";
```

#### Create a new instance

- Creates a persistent instance that remains stable through canister upgrades

```motoko
    stable let cert_store = CertifiedAssets.init_stable_store();
    let certs = CertifiedAssets.CertifiedAssets(?cert_store);
```

#### Certify an Asset

Define an `Endpoint` with the URL where the asset will be hosted, the data for certification, and optionally, details about the HTTP request and response.

> An Endpoint is a combination of the url path to the asset, and the http request and response details that are associated with the served asset.

```motoko
    let endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!");
    certs.certify(endpoint);
```

The above method creates a new sha256 hash of the data, if you already have the hash, you can pass it in via the `hash()` method to avoid recomputing it.

```motoko
    let endpoint = CertifiedAssets.Endpoint("/hello.txt", null)
        .hash(hello_world_sha256_hash);
    certs.certify(endpoint);
```

[Certification V2](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification) allows for the inclusion of additional optional information in the future response's certificate.

These additional parameters include:

- **Flags**:
  - `no_certification()`: if called, none of the data will be certified
  - `no_request_certification()`: if called, only the response will be certified. Set by default, as request certification is not supported
- **Request methods**:
  - `method()`: the request method, defaults to 'GET' if not set
  - `query_param()`: the query parameters
  - `request_headers()`: the request headers
- **Response methods**:
  - `status()`: the response status code, defaults to 200 if not set
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

A unique hash is generated for each endpoint, so any change to the data will require re-certification. To re-certify an asset, you need to `remove()` the old one and `certify()` the new one.

```motoko
    let old_endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!");
    let new_endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World! Updated");

    certs.remove(endpoint);
    certs.certify(endpoint);
```

#### Serving A Certified Asset

Serving a certified asset it is as easy as adding the two headers (`IC-Certificate` and `IC-CertificateExpression`) with the certificates in your HTTP response.
Using `get_certificate()` allows you to retrieve those two headers for the given endpoint.
While `get_certified_response()` returns an updated version of your response with the header certificates added to them.
These two functions will search the internal store for the certificates and return it if the search was successful. If not, the function will return an error. To prevent an error ensure that the Http Request and response match the details in the endpoint originally used to certify the asset.

```motoko
    import Debug "mo:base/Debug";
    import Text "mo:base/Text";
    import CertifiedAssets "mo:certified-assets";

    public func http_request(req : CertifiedAssets.HttpRequest) : CertifiedAssets.HttpResponse {
        assert req.url == "/hello.html";

        let res : CertifiedAssets.HttpResponse = {
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

### Fallback index.html files

<!-- A fallback is any prefix in the path of the requested file that can be used to serve a default index.html file. -->

Asset certification V2 allows you to fallback to a default index.html file if the requested file. Fallbacks only work if the index.html directory path is a prefix of the requested file path. For example, if the requested file is `/path/to/file.txt`, the fallback index.html file could be stored at either `/path/to/index.html`, `/path/index.html` or `/index.html`.

- Certify a fallback index.html file

```motoko
    let fallback = CertifiedAssets
        .Endpoint("/path/to/index.html", ?"Hello, World!")
        .status(200);

    certs.certify(endpoint);
```

- Request a missing file and fallback to the index.html file

```motoko

    public query func http_request(req: CertifiedAssets.HttpRequest) : CertifiedAssets.HttpResponse {
        // suppose this request was sent to your canister
        assert req == {
            method = "GET";
            url = "/path/to/unknown/file.txt";
            headers = [];
        };

        // search your file store for the requested file
        // if the file is not found, create a response with the index.html file

        let ?fallback_path = certs.get_fallback_path(req.url);

        let res : CertifiedAssets.HttpResponse = {
            status_code = 200;
            headers = [];
            body = Text.encodeUtf8("Hello, World!");
            streaming_strategy = null;
            upgrade = null;
        };

        // replace the url in the request with the index.html file's path
        let req_with_fallback_url = { req with url = "/path/to/index.html" };

        let result = certs.get_certified_response(req_with_fallback_url, res, null);

        let #ok(certified_response) = result else return Debug.trap(debug_show result);

        return certified_response;

    };

```

## Testing

### Unit tests

- Install [mops](https://docs.mops.one/quick-start)
- Run the following command in your project directory:

```bash
mops test
```

### Replica Tests

- Install zx with `npm install -g zx`
- Install dfinity's [`idl2json` package](https://github.com/dfinity/idl2json?tab=readme-ov-file#with-cargo-install)
- Run the following commands:

```bash
    dfx start --background
    zx -i ./z-scripts/canister-tests.mjs
```

## Limitations

- This implementation does not support request certification.

## Credits & References

- [Response Verification Standard](https://github.com/dfinity/interface-spec/blob/master/spec/http-gateway-protocol-spec.md#response-verification)
- Libraries: [ic-certification](https://github.com/nomeata/ic-certification), [certified-http](https://github.com/infu/certified-http)
