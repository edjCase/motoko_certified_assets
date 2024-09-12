import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat16 "mo:base/Nat16";
import Text "mo:base/Text";

import SHA256 "mo:sha2/Sha256";
import HttpParser "mo:http-parser";
import HttpTypes "mo:http-types";

import Utils "Utils";

module {

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

    /// A class that contains all the information needed to certify a given endpoint.
    /// Recieves a URL endpoint and the data to be certified.
    /// Only the path of the URL is used for certification.
    /// If you need to certify the query parameters, use either the [`query_param()`](#query_param)
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

        public func body(blob : Blob) : Endpoint {
            sha256.writeBlob(blob);
            _hash := sha256.sum();
            sha256.reset();
            return self;
        };

        public func hash(hash : Blob) : Endpoint {
            _hash := hash;
            return self;
        };

        public func chunks(chunks : [Blob]) : Endpoint {
            for (chunk in chunks.vals()) {
                sha256.writeBlob(chunk);
            };

            _hash := sha256.sum();
            sha256.reset();

            return self;
        };

        public func method(method : Text) : Endpoint {
            _method := method;
            return self;
        };

        public func request_header(field : Text, value : Text) : Endpoint {
            _request_headers.add((field, value));
            return self;
        };

        public func request_headers(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _request_headers.add((field, value));
            };
            return self;
        };

        public func query_param(field : Text, value : Text) : Endpoint {
            _queries.add((field, value));
            return self;
        };

        public func query_params(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _queries.add((field, value));
            };
            return self;
        };

        public func status(code : Nat16) : Endpoint {
            _status := code;
            return self;
        };

        public func response_header(field : Text, value : Text) : Endpoint {
            _response_headers.add((field, value));
            return self;
        };

        public func response_headers(params : [(Text, Text)]) : Endpoint {
            for ((field, value) in params.vals()) {
                _response_headers.add((field, value));
            };

            return self;
        };

        public func is_fallback_path() : Endpoint {
            _is_fallback_path := true;
            return self;
        };

        public func no_request_certification() : Endpoint {
            _no_request_certification := true;
            return self;
        };

        public func no_certification() : Endpoint {
            _no_certification := true;
            return self;
        };

        let url = HttpParser.URL(url_text, HttpParser.Headers([]));

        for (entry in url.queryObj.trieMap.entries()) {
            _queries.add(entry);
        };

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
