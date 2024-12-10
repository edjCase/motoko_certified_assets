import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat16 "mo:base/Nat16";
import Text "mo:base/Text";

import SHA256 "mo:sha2/Sha256";
import HttpParser "mo:http-parser";
import HttpTypes "mo:http-types";

module {

    /// An immutable record that contains all the information needed to certify a given endpoint.
    public type EndpointRecord = {
        url : Text;
        hash : Blob;
        method : Text;
        query_params : [(Text, Text)];
        request_headers : [HttpTypes.Header];
        status : Nat16;
        response_headers : [HttpTypes.Header];
        no_certification : Bool;
        no_request_certification : Bool;
        is_fallback_path : Bool;
    };

    /// An Endpoint is a combination of the url path to the asset, and the http request and response details that are associated with the served asset.
    /// It contains all the information needed to certify a given endpoint.
    ///
    /// > Note, that the first parameter only consumes the path to the asset and not the full URL.
    /// If you need to certify the URL's query parameters, use either the [`query_param()`](#query_param)
    /// function or the [`query_params()`](#query_params) function.

    public class Endpoint(url_text : Text, opt_body : ?Blob) = self {

        // flags
        var _no_certification = false;
        var _no_request_certification = false;

        // request
        var _method : Text = "GET";
        var _request_headers = Buffer.Buffer<HttpTypes.Header>(8);

        // response
        var _status : Nat16 = 200;
        var _response_headers = Buffer.Buffer<HttpTypes.Header>(8);

        var _hash : Blob = switch (opt_body) {
            case (?_body) SHA256.fromBlob(#sha256, _body);
            case (null) SHA256.fromBlob(#sha256, "");
        };

        var _is_fallback_path = false;

        let sha256 = SHA256.Digest(#sha256);
        let _url = HttpParser.URL(url_text, HttpParser.Headers([])); // clashing feature: removes ending slash if present
        let _queries = Buffer.Buffer<HttpTypes.Header>(8);

        /// Hashes the given blob and sets it as the hash for the endpoint.
        public func body(blob : Blob) : Endpoint {
            sha256.writeBlob(blob);
            _hash := sha256.sum();
            sha256.reset();
            return self;
        };

        /// Sets given value as the hash for the endpoint.
        public func hash(hash : Blob) : Endpoint {
            _hash := hash;
            return self;
        };

        /// Hashes the given blob chunks and sets it as the hash for the endpoint.
        public func chunks(chunks : [Blob]) : Endpoint {
            for (chunk in chunks.vals()) {
                sha256.writeBlob(chunk);
            };

            _hash := sha256.sum();
            sha256.reset();

            return self;
        };

        /// Sets the method for the endpoint.
        public func method(method : Text) : Endpoint {
            _method := method;
            return self;
        };

        /// Adds a request header to the endpoint.
        public func request_header(field : Text, value : Text) : Endpoint {
            _request_headers.add((field, value));
            return self;
        };

        /// Adds multiple request headers to the endpoint.
        public func request_headers(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _request_headers.add((field, value));
            };
            return self;
        };

        /// Adds a query parameter to the endpoint.
        public func query_param(field : Text, value : Text) : Endpoint {
            _queries.add((field, value));
            return self;
        };

        /// Adds multiple query parameters to the endpoint.
        public func query_params(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _queries.add((field, value));
            };
            return self;
        };

        /// Sets the status code for the endpoint.
        public func status(code : Nat16) : Endpoint {
            _status := code;
            return self;
        };

        /// Adds a response header to the endpoint.
        public func response_header(field : Text, value : Text) : Endpoint {
            _response_headers.add((field, value));
            return self;
        };

        /// Adds multiple response headers to the endpoint.
        public func response_headers(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _response_headers.add((field, value));
            };

            return self;
        };

        /// Sets the endpoint as a fallback path.
        public func is_fallback_path(val : Bool) : Endpoint {
            _is_fallback_path := val;
            return self;
        };

        /// Disables certification for the method, query parameters and request headers.
        public func no_request_certification() : Endpoint {
            _no_request_certification := true;
            return self;
        };

        /// Disables request certification and certification for the status and response headers.
        public func no_certification() : Endpoint {
            _no_certification := true;
            return self;
        };

        let url = HttpParser.URL(url_text, HttpParser.Headers([]));

        for (entry in url.queryObj.trieMap.entries()) {
            _queries.add(entry);
        };

        /// Constructs an `EndpointRecord` from the current state of the `Endpoint`.
        /// > The endpoint can still be modified after calling this function and used to create more records.
        public func build() : EndpointRecord {

            let record : EndpointRecord = {
                url = url.path.original;
                hash = _hash;
                method = _method;
                query_params = if (_no_request_certification)[] else Buffer.toArray(_queries);
                request_headers = if (_no_request_certification)[] else Buffer.toArray(_request_headers);
                status = _status;
                response_headers = if (_no_certification)[] else Buffer.toArray(_response_headers);
                no_certification = _no_certification;
                no_request_certification = _no_request_certification;
                is_fallback_path = _is_fallback_path;
            };
            record;
        };
    };
};
