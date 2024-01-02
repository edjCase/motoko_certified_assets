import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Error "mo:base/Error";
import Iter "mo:base/Iter";
import Nat16 "mo:base/Nat16";
import Result "mo:base/Result";
import Text "mo:base/Text";

import CertTree "mo:ic-certification/CertTree";
import CanisterSigs "mo:ic-certification/CanisterSigs";
import CertifiedData "mo:base/CertifiedData";
import SHA256 "mo:sha2/Sha256";
import HttpParser "mo:http-parser";
import HttpTypes "mo:http-types";
import { CBOR } "mo:serde";
import Map "mo:map/Map";
import RepIndyHash "mo:rep-indy-hash";
import Vector "mo:vector";

import Base64 "mo:encoding/Base64";

import Utils "Utils";

module CertifiedAssets {

    type Buffer<A> = Buffer.Buffer<A>;
    type Iter<A> = Iter.Iter<A>;
    type Map<K, V> = Map.Map<K, V>;
    type Result<T, E> = Result.Result<T, E>;
    type Vector<A> = Vector.Vector<A>;

    let { thash; bhash } = Map;

    type Metadata = {
        query_params : [(Text, Text)];
        request_headers : [HttpTypes.Header];
        response_headers : [HttpTypes.Header];
        encoded_expr_path : Blob;
        full_expr_path : [Blob];
        ic_certificate_expression : Text;
    };

    public type MetadataMap = Map<Text, Map<Blob, Vector<Metadata>>>;

    public type StableStore = {
        ct_store : CertTree.Store;
        metadata_map : MetadataMap;
    };

    public func endpoint(url : Text, data : Blob) : Endpoint {
        Endpoint(url, data);
    };

    /// Create a new stable CertifiedAssets instance on the heap.
    /// This instance is stable and will not be cleared on canister upgrade.
    ///
    /// ```motoko
    /// let stable_certs = CertifiedAssets.init_stable_store();
    /// let certs = CertifiedAssets.CertifiedAssets(stable_certs);
    /// ```

    public func init_stable_store() : StableStore {
        {
            ct_store = CertTree.newStore();
            metadata_map = Map.new();
        };
    };

    /// The implementation of the IC's Response Verification version 2.
    ///
    /// The module provides a way to store the certified data on the heap or in stable persistent memory.
    /// - heap - creates a new instance of the class that will be cleared on canister upgrade.
    /// ```motoko
    /// let certs = CertifiedAssets.CertifiedAssets(null);
    /// ```
    ///
    /// - stable heap - creates a new stable instance of the class that will persist on canister upgrade.
    /// ```motoko
    /// let stable_certs = CertifiedAssets.init_stable_store();
    /// let certs = CertifiedAssets.CertifiedAssets(?stable_certs);
    /// ```
    ///
    /// If your instance is stable, it is advised to `clear()` all the certified endpoints and
    /// re-certify them on canister upgrade if the data has changed.
    ///
    public class CertifiedAssets(internal : ?StableStore) = self {
        let metadata_map : MetadataMap = switch (internal) {
            case (?(internal)) internal.metadata_map;
            case (null) Map.new();
        };

        let ct_store = switch (internal) {
            case (?(internal)) internal.ct_store;
            case (null) CertTree.newStore();
        };

        let ct = CertTree.Ops(ct_store);

        let IC_CERTIFICATE_EXPRESSION = "ic-certificateexpression";

        public func certify(endpoint : Endpoint) : Result<(), Text> {
            let endpoint_record = endpoint.build();

            let url = HttpParser.URL(endpoint_record.url, HttpParser.Headers([]));
            let url_path = url.path.original;
            let body = endpoint_record.body;

            let hashed_body = SHA256.fromBlob(#sha256, body);
            ct.put(["http_assets", Text.encodeUtf8(url_path)], hashed_body);

            let text_expr_path = Array.tabulate(
                url.path.array.size() + 2,
                func(i : Nat) : Text {
                    if (i == 0) return "http_expr";
                    if (i < url.path.array.size() + 1) return url.path.array[i - 1];

                    // Expects the url to be an exact match. 
                    // This implementation does not support wildcards (partial matches)
                    return "<$>";
                },
            );

            // Debug.print("expr_path: " # debug_show text_expr_path);

            // encode the segments to cbor for the expr_path field for the certificate
            let candid_expr_path = to_candid (text_expr_path);
            let cbor_res = CBOR.encode(candid_expr_path, [], null);
            let #ok(encoded_expr_path) = cbor_res else return Utils.send_error(cbor_res);
            let expr_path = Array.map(text_expr_path, Text.encodeUtf8);

            let extract_field = func((field, _) : (Text, Text)) : Text = field;
            let certified_query_params = endpoint_record.queries;
            let certified_request_headers = endpoint_record.request_headers;
            let certified_response_headers = endpoint_record.response_headers;
            let no_certification = endpoint_record.no_certification;
            let no_request_certification = endpoint_record.no_request_certification;

            let query_params_fields = Array.map(endpoint_record.queries, extract_field);
            let request_headers_fields = Array.map(endpoint_record.request_headers, extract_field);
            let response_headers_fields = Array.map(endpoint_record.response_headers, extract_field);

            let fields = Buffer.Buffer<Text>(8);

            var ic_certificate_expression = switch (no_certification, no_request_certification) {
                case (true, _) {
                    "
                        default_certification (
                            ValidationArgs {
                                no_certification: Empty { }
                            }
                        )
                    ";
                };
                case (false, true) {
                    "
                        default_certification (
                            ValidationArgs {
                                certification: Certification {
                                    no_request_certification: Empty { },
                                    response_certification: ResponseCertification {
                                        certified_response_headers: ResponseHeaderList {
                                            headers: " # debug_show response_headers_fields # "
                                        }
                                    }
                                }
                            }
                        )
                    ";
                };
                case (false, false) {
                    "
                        default_certification (
                            ValidationArgs {
                                certification: Certification {
                                    request_certification: RequestCertification {
                                        certified_request_headers: " # debug_show request_headers_fields # ",
                                        certified_query_parameters: " # debug_show query_params_fields # "
                                    },
                                    response_certification: ResponseCertification {
                                        certified_response_headers: ResponseHeaderList {
                                            headers: " # debug_show response_headers_fields # "
                                        }
                                    }
                                }
                            }
                        )
                    ";
                };
            };

            ic_certificate_expression := Text.join(" ", Text.tokens(ic_certificate_expression, #predicate(func(c : Char) : Bool = c == ' ' or c == '\n')));

            let expr_hash = SHA256.fromBlob(#sha256, Text.encodeUtf8(ic_certificate_expression));

            var request_hash : Blob = "";

            if (not no_request_certification and not no_certification) {

                let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

                for ((name, body) in certified_request_headers.vals()) {
                    if (body.size() != 0) {
                        buffer.add((Text.toLowercase(name), #Text(body)));
                    };
                };

                let method = endpoint_record.method;
                buffer.add((":ic-cert-method", #Text(method)));

                let queries = Array.tabulate(
                    certified_query_params.size(),
                    func(i : Nat) : Text {
                        let (name, body) = certified_query_params[i];
                        (name # body);
                    },
                );

                let concatenated_queries = Text.join("&", queries.vals());
                // Debug.print("concatenated_queries: " # debug_show concatenated_queries);
                let hashed_queries = SHA256.fromBlob(#sha256, Text.encodeUtf8(concatenated_queries));
                buffer.add((":ic-cert-query", #Blob(hashed_queries)));

                let rep_val = #Map(Buffer.toArray(buffer));
                let request_header_hash = Blob.fromArray(RepIndyHash.hash_val(rep_val));

                let request_body_hash : Blob = ""; // the body is empty because these are expected to be GET, HEAD or OPTIONS requests

                request_hash := SHA256.fromArray(#sha256, Array.append(Blob.toArray(request_header_hash), Blob.toArray(request_body_hash)));
            };

            var response_hash : Blob = "";

            if (not no_certification) {

                let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

                for ((name, body) in certified_response_headers.vals()) {
                    if (body.size() != 0 and Text.toLowercase(name) != "ic-certificate") {
                        buffer.add((Text.toLowercase(name), #Text(body)));
                    };
                };

                buffer.add(IC_CERTIFICATE_EXPRESSION, #Text(ic_certificate_expression));

                let status = endpoint_record.status;
                buffer.add((":ic-cert-status", #Nat(Nat16.toNat(status))));

                let rep_val = #Map(Buffer.toArray(buffer));
                let response_headers_hash = Blob.fromArray(RepIndyHash.hash_val(rep_val));

                let headers_and_body_hash = Blob.fromArray(
                    Array.append(
                        Blob.toArray(response_headers_hash),
                        Blob.toArray(hashed_body),
                    )
                );

                response_hash := SHA256.fromBlob(#sha256, headers_and_body_hash);
            };

            // Debug.print(debug_show request_hash);
            // Debug.print(debug_show response_hash);

            assert (not no_certification) or (no_certification and ((request_hash == "") and (response_hash == "")));

            let full_expr_path = Array.append(expr_path, [expr_hash, request_hash, response_hash]);

            ct.put(full_expr_path, "");

            ct.setCertifiedData();

            let metadata : Metadata = {
                method = endpoint_record.method;
                query_params = endpoint_record.queries;
                request_headers = endpoint_record.request_headers;
                status = endpoint_record.status;
                response_headers = endpoint_record.response_headers;
                encoded_expr_path;
                full_expr_path;
                ic_certificate_expression;
            };

            let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(3);
            if (not no_certification) {
                buffer.add((":ic-cert-status", #Nat(Nat16.toNat(endpoint_record.status))));
            };

            if (not no_request_certification and not no_certification) {
                buffer.add((":ic-cert-method", #Text(endpoint_record.method)));
            };

            // this is not an official field, but it is used internally to uniquely identify the http request
            buffer.add((":ic-cert-body", #Blob(hashed_body)));

            // Debug.print("buffer for unique_http_hash: " # debug_show Buffer.toArray(buffer));
            let unique_http_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

            let opt_nested_map = Map.get(metadata_map, thash, url_path);

            let (nested_map, opt_vector) = switch (opt_nested_map) {
                case (?nested_map) {
                    (nested_map, Map.get(nested_map, bhash, unique_http_hash));
                };
                case (null) {
                    let nested_map = Map.new<Blob, Vector<Metadata>>();
                    ignore Map.put(metadata_map, thash, url_path, nested_map);
                    (nested_map, null);
                };
            };

            switch (opt_vector) {
                case (null) {
                    let vector = Vector.new<Metadata>();
                    Vector.add(vector, metadata);
                    ignore Map.put(nested_map, bhash, unique_http_hash, vector);
                };
                case (?(vector)) {
                    Vector.add(vector, metadata);
                };
            };

            #ok();
        };

        /// Remove a certified endpoint.
        public func remove(endpoint : Endpoint) {
            let endpoint_record = endpoint.build();
            let url = HttpParser.URL(endpoint_record.url, HttpParser.Headers([]));
            ct.delete(["http_assets", Text.encodeUtf8(url.path.original)]);

            let ?metadata = get_metadata_from_endpoint(endpoint_record) else return;
            ct.delete(metadata.full_expr_path);

            ct.setCertifiedData();
        };

        /// Removes all the certified endpoints that match the given URL.
        public func removeAll(url : Text) {
            let _url = HttpParser.URL(url, HttpParser.Headers([]));
            ct.delete(["http_assets", Text.encodeUtf8(_url.path.original)]);

            let ?nested_map = Map.remove(metadata_map, thash, _url.path.original) else return;

            for ((_, vector) in Map.entries(nested_map)) {
                for (metadata in Vector.vals(vector)) {
                    ct.delete(metadata.full_expr_path);
                };
            };

            ct.setCertifiedData();
        };

        /// Clear all certified endpoints.
        public func clear() {
            ct.delete(["http_assets"]);
            ct.delete(["http_expr"]);

            Map.clear(metadata_map);
            ct.setCertifiedData();
        };

        /// Modifies a given response by adding the certificate headers.
        /// This only works if the endpoint has already been certified.
        public func get_certified_response(req : HttpTypes.Request, res : HttpTypes.Response) : Result<HttpTypes.Response, Text> {
            let headers_res = get_certificate_headers(req, res);
            let #ok(headers) = headers_res else return Utils.send_error(headers_res);

            #ok({ res with headers = Array.append(res.headers, headers) });
        };

        /// Get the certificate headers for a given request.
        ///
        /// This function returns the certificate headers for a predefined response.
        /// This only works if the endpoint has already been certified.
        ///
        /// ```motoko
        /// public func http_request(req : HttpTypes.Request) : HttpTypes.Response {
        ///     let res : HttpTypes.Response = {
        ///         status_code = 200;
        ///         headers = cert.get_certificate_headers(req);
        ///         body = "Hello, World!";
        ///         ...
        ///     };
        /// };
        public func get_certificate_headers(req : HttpTypes.Request, res : HttpTypes.Response) : Result<[HttpTypes.Header], Text> {
            if (req.certificate_version == ?2) v2(req, res) else v1(req);
        };

        func v1(req : HttpTypes.Request) : Result<[HttpTypes.Header], Text> {
            let url = HttpParser.URL(req.url, HttpParser.Headers([]));
            let url_path = url.path.original;

            let witness = ct.reveal(["http_assets", Text.encodeUtf8(url_path)]);
            let encoded = ct.encodeWitness(witness);
            let ?certificate = CertifiedData.getCertificate() else {
                return #err("getCertificate failed. Call this as a query call!");
            };

            return #ok([(
                "ic-certificate",
                "certificate=:" # base64(certificate) # ":, " # "tree=:" # base64(encoded) # ":",
            )]);
        };

        func v2(req : HttpTypes.Request, res : HttpTypes.Response) : Result<[HttpTypes.Header], Text> {
            let url = HttpParser.URL(req.url, HttpParser.Headers([]));
            let url_path = url.path.original;

            let ?metadata = get_metadata(req, res) else return #err("no metadata found for this url");

            let witness = ct.reveal(metadata.full_expr_path);
            let encoded_witness = ct.encodeWitness(witness);

            let ?certificate = CertifiedData.getCertificate() else {
                return #err("getCertificate failed. Call this as a query call!");
            };

            Debug.print(debug_show metadata);
            let ic_certificate_fields = [
                "certificate=:" # base64(certificate) # ":",
                "tree=:" # base64(encoded_witness) # ":",
                "version=2",
                "expr_path=:" # base64(metadata.encoded_expr_path) # ":",
            ];

            return #ok([
                ("ic-certificate", Text.join(", ", ic_certificate_fields.vals())),
                (IC_CERTIFICATE_EXPRESSION, metadata.ic_certificate_expression),
            ]);
        };

        func get_metadata(req : HttpTypes.Request, res : HttpTypes.Response) : ?Metadata {
            let url = HttpParser.URL(req.url, HttpParser.Headers([]));
            let url_path = url.path.original;

            let endpoint_record = {
                url = req.url;
                body = res.body;
                method = req.method;
                queries = Iter.toArray(url.queryObj.trieMap.entries());
                request_headers = req.headers;
                status = res.status_code;
                response_headers = res.headers;
                no_certification = false;
                no_request_certification = false;
            };

            get_metadata_from_endpoint(endpoint_record);
        };

        func get_metadata_from_endpoint(endpoint_record : EndpointRecord) : ?Metadata {
            let url = HttpParser.URL(endpoint_record.url, HttpParser.Headers([]));
            let url_path = url.path.original;

            let nested_map = switch (Map.get(metadata_map, thash, url_path)) {
                case (?nested_map) nested_map;
                case (null) return null;
            };

            let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(3);
            buffer.add((":ic-cert-body", #Blob(SHA256.fromBlob(#sha256, endpoint_record.body))));

            let no_certification_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

            var metadata_array : [Metadata] = switch (Map.get(nested_map, bhash, no_certification_hash)) {
                case (?vec) Vector.toArray(vec);
                case (null)[];
            };

            if (metadata_array.size() == 0) {
                buffer.add((":ic-cert-status", #Nat(Nat16.toNat(endpoint_record.status))));
                let no_request_certification_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

                switch (Map.get(nested_map, bhash, no_request_certification_hash)) {
                    case (?vec) {
                        metadata_array := Array.append(Vector.toArray(vec), metadata_array);
                    };
                    case (null) {};
                };
            };

            if (metadata_array.size() == 0) {
                buffer.add((":ic-cert-method", #Text(endpoint_record.method)));
                let unique_http_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

                switch (Map.get(nested_map, bhash, unique_http_hash)) {
                    case (?vec) {
                        metadata_array := Array.append(Vector.toArray(vec), metadata_array);
                    };
                    case (null) return null;
                };
            };

            // Debug.print("metadata_array: " # debug_show metadata_array);

            func array_contains_all<A>(haystack : [A], needles : [A], eq : (A, A) -> Bool) : Bool {
                var contains_all = true;

                label loop1 for (x in needles.vals()) {
                    var found_match = false;

                    label loop2 for (y in haystack.vals()) {
                        if (eq(x, y)) {
                            found_match := true;
                            break loop2;
                        };
                    };

                    contains_all := contains_all and found_match;

                    if (not contains_all) return false;
                };

                contains_all;
            };

            for (metadata in metadata_array.vals()) {
                var check = true;

                func equal_tuples(a : (Text, Text), b : (Text, Text)) : Bool {
                    a.0 == b.0 and a.1 == b.1
                };

                check := check and array_contains_all(endpoint_record.request_headers, metadata.request_headers, equal_tuples);
                check := check and array_contains_all(endpoint_record.response_headers, metadata.response_headers, equal_tuples);
                check := check and array_contains_all(endpoint_record.queries, metadata.query_params, equal_tuples);

                // Debug.print("metadata: " # debug_show metadata);
                // Debug.print("check: " # debug_show check);

                if (check) return ?metadata;
            };

            return null;
        };

        func base64(data : Blob) : Text {
            let res = Base64.StdEncoding.encode(Blob.toArray(data));
            let ?utf8 = Text.decodeUtf8(Blob.fromArray(res)) else Debug.trap("base64 encoding failed");
            utf8;
        };

    };

    type EndpointRecord = {
        url : Text;
        body : Blob;
        method : Text;
        queries : [(Text, Text)];
        request_headers : [HttpTypes.Header];
        status : Nat16;
        response_headers : [HttpTypes.Header];
        no_certification : Bool;
        no_request_certification : Bool;
    };

    /// A class that contains all the information needed to certify a given endpoint.
    /// Recieves a URL endpoint and the data to be certified.
    /// Only the path of the URL is used for certification.
    /// If you need to certify the query parameters, use either the [`query_param()`](#query_param)
    /// function or the [`queries()`](#queries) function.
    public class Endpoint(url : Text, body : Blob) = self {

        // flags
        var _no_certification = false;
        var _no_request_certification = false;

        // request
        var _method : Text = "GET";
        var _queries = Buffer.Buffer<(Text, Text)>(8);
        var _request_headers = Buffer.Buffer<HttpTypes.Header>(8);

        // response
        var _status : Nat16 = 200;
        var _response_headers = Buffer.Buffer<HttpTypes.Header>(8);

        public func method(method : Text) : Endpoint {
            _method := method;
            return self;
        };

        public func request_header(name : Text, body : Text) : Endpoint {
            _request_headers.add((name, body));
            return self;
        };

        public func request_headers(params : [(Text, Text)]) : Endpoint {
            for ((name, body) in params.vals()) {
                _request_headers.add((name, body));
            };
            return self;
        };

        public func query_param(name : Text, body : Text) : Endpoint {
            _queries.add((name, body));
            return self;
        };

        public func queries(params : [(Text, Text)]) : Endpoint {
            for ((name, body) in params.vals()) {
                _queries.add((name, body));
            };
            return self;
        };

        public func status(code : Nat16) : Endpoint {
            _status := code;
            return self;
        };

        public func response_header(name : Text, body : Text) : Endpoint {
            _response_headers.add((name, body));
            return self;
        };

        public func response_headers(params : [(Text, Text)]) : Endpoint {
            for ((name, body) in params.vals()) {
                _response_headers.add((name, body));
            };

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

        public func build() : EndpointRecord {
            let record : EndpointRecord = {
                url;
                body;
                method = _method;
                queries = Buffer.toArray(_queries);
                request_headers = Buffer.toArray(_request_headers);
                status = _status;
                response_headers = Buffer.toArray(_response_headers);
                no_certification = _no_certification;
                no_request_certification = _no_request_certification;
            };
        };
    };

};
