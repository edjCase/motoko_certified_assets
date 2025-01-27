import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Iter "mo:base/Iter";
import Nat16 "mo:base/Nat16";
import Result "mo:base/Result";
import Text "mo:base/Text";

import MerkleTree "mo:ic-certification/MerkleTree";
import CertifiedData "mo:base/CertifiedData";
import SHA256 "mo:sha2/Sha256";
import HttpParser "mo:http-parser";
import HttpTypes "mo:http-types";
import Serde "mo:serde";
import Map "mo:map/Map";
import RepIndyHash "mo:rep-indy-hash";
import Vector "mo:vector";
import Itertools "mo:itertools/Iter";
import RevIter "mo:itertools/RevIter";

import Base64 "mo:encoding/Base64";

import Utils "Utils";
import EndpointModule "Endpoint";

module Module {

    type Buffer<A> = Buffer.Buffer<A>;
    type Iter<A> = Iter.Iter<A>;
    type Map<K, V> = Map.Map<K, V>;
    type Result<T, E> = Result.Result<T, E>;
    type Vector<A> = Vector.Vector<A>;

    let { thash; bhash } = Map;
    let { CBOR } = Serde;

    type Metadata = {
        endpoint : EndpointRecord;
        encoded_expr_path : Blob;
        full_expr_path : [Blob];
        ic_certificate_expression : Text;
    };

    public type EndpointsMap = Map<Blob, Vector<Metadata>>;

    public type SplitMetadataEndpoints = {
        fallback_endpoints : EndpointsMap;
        endpoints : EndpointsMap;
    };

    public type MetadataMap = Map<Text, SplitMetadataEndpoints>;

    public type StableStore = {
        var tree : MerkleTree.Tree;
        metadata_map : MetadataMap;
    };

    public let Endpoint = EndpointModule.Endpoint;
    public type Endpoint = EndpointModule.Endpoint;
    public type EndpointRecord = EndpointModule.EndpointRecord;

    public type HttpRequest = HttpTypes.Request;
    public type HttpResponse = HttpTypes.Response;
    public type Header = HttpTypes.Header;

    public type CertifiedTree = {
        certificate : Blob;
        tree : Blob;
    };

    public let IC_CERTIFICATE_EXPRESSION = "ic-certificateexpression";
    public let IC_CERT_BODY = ":ic-cert-body";
    public let IC_CERT_METHOD = ":ic-cert-method";
    public let IC_CERT_QUERY = ":ic-cert-query";
    public let IC_CERT_STATUS = ":ic-cert-status";
    public let IC_IS_FALLBACK = ":ic-is-fallback";

    public type CertifiedAssetErrors = {
        #GetCertifiedDataFailed : Text;
        #NoMatchingEndpointFound : Text;
    };

    public func init_stable_store() : StableStore {
        {
            var tree = MerkleTree.empty();
            metadata_map = Map.new();
        };
    };

    public func certify(ct : StableStore, endpoint : Endpoint) {
        let endpoint_record = endpoint.build();
        certify_record(ct, endpoint_record);
    };

    public func encode_text_expr_path(text_expr_path : [Text]) : Blob {
        let candid_record_expr_path = #Array(
            Array.map(text_expr_path, func(t : Text) : Serde.Candid = #Text(t))
        );

        let cbor_res = CBOR.fromCandid(candid_record_expr_path, Serde.defaultOptions);
        switch (cbor_res) {
            case (#ok(encoded_expr_path)) encoded_expr_path;
            case (#err(errMsg)) Debug.trap("Internal Error: Report bug in NatLabs/certified-assets repo.\n\t" # errMsg);
        };
    };

    public func get_text_expr_path(url : Text, is_fallback : Bool) : [Text] {

        let paths = if (url == "") {
            [];
        } else if (url == "/") {
            [""];
        } else {
            let paths_iter = Text.split(url, #text("/"));
            ignore paths_iter.next(); // skip the first element which is always empty
            Iter.toArray(paths_iter);
        };

        let text_expr_path = Array.tabulate(
            paths.size() + 2,
            func(i : Nat) : Text {
                if (i == 0) return "http_expr";
                if (i < paths.size() + 1) return paths[i - 1];

                if (is_fallback) {
                    "<*>";
                } else {
                    "<$>";
                };
            },
        );

        text_expr_path;

    };

    public func url_to_encoded_expr_path(url : Text, is_fallback : Bool) : ([Blob], Blob) {

        let text_expr_path = get_text_expr_path(url, is_fallback);

        let expr_path = Array.map(text_expr_path, Text.encodeUtf8);
        let encoded_expr_path = encode_text_expr_path(text_expr_path);

        (expr_path, encoded_expr_path);

    };

    public func get_ic_certificate_expression(
        no_certification : Bool,
        no_request_certification : Bool,
        query_params : [(Text, Text)],
        request_headers : [HttpTypes.Header],
        response_headers : [HttpTypes.Header],
    ) : Text {
        let extract_field = func((field, _) : (Text, Text)) : Text = field;

        let query_params_fields = Array.map(query_params, extract_field);
        let request_headers_fields = Array.map(request_headers, extract_field);
        let response_headers_fields = Array.map(response_headers, extract_field);

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

        Text.join(" ", Text.tokens(ic_certificate_expression, #predicate(func(c : Char) : Bool = c == ' ' or c == '\n')));

    };

    public func get_request_hash(
        no_certification : Bool,
        no_request_certification : Bool,
        method : Text,
        query_params : [(Text, Text)],
        request_headers : [HttpTypes.Header],
    ) : Blob {

        var request_hash : Blob = "";

        if (not no_request_certification and not no_certification) {

            let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

            for ((name, value) in request_headers.vals()) {
                if (value.size() != 0) {
                    buffer.add((Text.toLowercase(name), #Text(value)));
                };
            };

            buffer.add((IC_CERT_METHOD, #Text(method)));

            let query_params_key_value_pair = Iter.map<(Text, Text), Text>(
                query_params.vals(),
                func(name : Text, value : Text) : Text { (name # "=" # value) },
            );

            let concatenated_query_params = Text.join("&", query_params_key_value_pair);
            let hashed_query_params = SHA256.fromBlob(#sha256, Text.encodeUtf8(concatenated_query_params));
            buffer.add((IC_CERT_QUERY, #Blob(hashed_query_params)));

            let rep_val = #Map(Buffer.toArray(buffer));
            let request_header_hash = RepIndyHash.hash_val(rep_val);

            let request_body_hash : Blob = SHA256.fromBlob(#sha256, ""); // the body is empty because this is expected to be either a GET, HEAD or OPTIONS requests
            request_hash := SHA256.fromArray(#sha256, Array.append(request_header_hash, Blob.toArray(request_body_hash)));
        };

        request_hash

    };

    public func get_response_hash(
        no_certification : Bool,
        status : Nat16,
        body_hash : Blob,
        response_headers : [HttpTypes.Header],
        ic_certificate_expression : Text,
    ) : Blob {

        var response_hash : Blob = "";

        if (not no_certification) {

            let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

            for ((name, value) in response_headers.vals()) {
                if (value.size() != 0 and Text.toLowercase(name) != "ic-certificate") {
                    buffer.add((Text.toLowercase(name), #Text(value)));
                };
            };

            buffer.add(IC_CERTIFICATE_EXPRESSION, #Text(ic_certificate_expression));

            buffer.add((IC_CERT_STATUS, #Nat(Nat16.toNat(status))));

            let rep_val = #Map(Buffer.toArray(buffer));
            let response_headers_hash = RepIndyHash.hash_val(rep_val);

            let headers_and_body_hash = Array.append(
                response_headers_hash,
                Blob.toArray(body_hash),
            );

            response_hash := SHA256.fromArray(#sha256, headers_and_body_hash);
        };

        response_hash;

    };

    public func certify_record(ct : StableStore, endpoint_record : EndpointRecord) {
        // v1 certification
        MerkleTreeOps.put(ct, ["http_assets", Text.encodeUtf8(endpoint_record.url)], endpoint_record.hash);

        // start v2 certification
        let (expr_path, encoded_expr_path) = url_to_encoded_expr_path(endpoint_record.url, endpoint_record.is_fallback_path);

        let no_certification = endpoint_record.no_certification;
        let no_request_certification = endpoint_record.no_request_certification;

        let ic_certificate_expression = get_ic_certificate_expression(
            no_certification,
            no_request_certification,
            endpoint_record.query_params,
            endpoint_record.request_headers,
            endpoint_record.response_headers,
        );

        let ic_certificate_expression_hash = SHA256.fromBlob(#sha256, Text.encodeUtf8(ic_certificate_expression));

        let request_hash : Blob = get_request_hash(
            no_certification,
            no_request_certification,
            endpoint_record.method,
            endpoint_record.query_params,
            endpoint_record.request_headers,
        );

        let response_hash : Blob = get_response_hash(
            no_certification,
            endpoint_record.status,
            endpoint_record.hash,
            endpoint_record.response_headers,
            ic_certificate_expression,
        );

        assert (not no_certification) or (no_certification and ((request_hash == "") and (response_hash == "")));

        let full_expr_path = Array.append(expr_path, [ic_certificate_expression_hash, request_hash, response_hash]);

        // v2 certification
        MerkleTreeOps.put(ct, full_expr_path, "");
        MerkleTreeOps.setCertifiedData(ct);

        let metadata : Metadata = {
            endpoint = endpoint_record;
            encoded_expr_path;
            full_expr_path;
            ic_certificate_expression;
        };

        let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(3);

        // this is not an official field, but it is used internally to uniquely identify the http request
        buffer.add((IC_CERT_BODY, #Blob(endpoint_record.hash)));

        if (not no_certification) {
            buffer.add((IC_CERT_STATUS, #Nat(Nat16.toNat(endpoint_record.status))));
        };

        if (not no_request_certification and not no_certification) {
            buffer.add((IC_CERT_METHOD, #Text(endpoint_record.method)));
        };

        let unique_http_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

        let split_endpoints = Map.get(ct.metadata_map, thash, endpoint_record.url);

        let (nested_map, opt_vector) = switch (split_endpoints) {
            case (?split_map) {
                let nested_map = if (endpoint_record.is_fallback_path) {
                    split_map.fallback_endpoints;
                } else {
                    split_map.endpoints;
                };

                (nested_map, Map.get<Blob, Vector<Metadata>>(nested_map, bhash, unique_http_hash));
            };
            case (null) {
                let split_map = {
                    fallback_endpoints = Map.new<Blob, Vector<Metadata>>();
                    endpoints = Map.new<Blob, Vector<Metadata>>();
                };

                ignore Map.put(ct.metadata_map, thash, endpoint_record.url, split_map);

                if (endpoint_record.is_fallback_path) {
                    (split_map.fallback_endpoints, null);
                } else {
                    (split_map.endpoints, null);
                };
            };
        };

        switch (opt_vector) {
            case (null) {
                let vector = Vector.new<Metadata>();
                Vector.add(vector, metadata);
                ignore Map.put(nested_map, bhash, unique_http_hash, vector);
            };
            case (?(vector)) switch (get_metadata_index_from_vector(endpoint_record, vector)) {
                case (?(_, index)) { Vector.put(vector, index, metadata) };
                case (null) { Vector.add(vector, metadata) };
            };
        };
    };

    func vector_remove<A>(vec : Vector<A>, index : Nat) : ?A {

        let size = Vector.size(vec);

        if (size == 0) return null;

        let last_index = size - 1 : Nat;

        if (last_index == index) return Vector.removeLast(vec);

        let tmp = Vector.get(vec, last_index);
        Vector.put(vec, index, tmp);
        Vector.removeLast(vec);
    };

    /// Remove a certified EndpointModule.
    public func remove(ct : StableStore, endpoint : Endpoint) {
        let endpoint_record = endpoint.build();
        remove_record(ct, endpoint_record);
    };

    public func remove_record(ct : StableStore, endpoint_record : EndpointRecord) {
        let ?({
            endpoints_map;
            endpoint_unique_key;
            endpoint_variants;
            index;
        }) = get_metadata_index_from_endpoint(ct, endpoint_record) else return;

        let ?metadata = vector_remove(endpoint_variants, index) else return;
        if (Vector.size(endpoint_variants) == 0) {
            ignore Map.remove(endpoints_map, bhash, endpoint_unique_key);
        };
        MerkleTreeOps.delete(ct, metadata.full_expr_path);
        MerkleTreeOps.delete(ct, ["http_assets", Text.encodeUtf8(endpoint_record.url)]);

        MerkleTreeOps.setCertifiedData(ct);

    };

    /// Removes all the certified endpoints that match the given URL.
    public func remove_all(ct : StableStore, url : Text) {
        let endpoint = Endpoint(url, null).build();
        MerkleTreeOps.delete(ct, ["http_assets", Text.encodeUtf8(endpoint.url)]);

        let ?{ fallback_endpoints; endpoints } = Map.remove(ct.metadata_map, thash, endpoint.url) else return;

        for ((_, vector) in Itertools.chain(Map.entries(fallback_endpoints), Map.entries(endpoints))) {
            for (metadata in Vector.vals(vector)) {
                MerkleTreeOps.delete(ct, metadata.full_expr_path);
            };
        };

        MerkleTreeOps.setCertifiedData(ct);
    };

    func extract_endpoints_from_endpoints_map(endpoints_map : EndpointsMap) : Iter<EndpointRecord> {
        Itertools.flatten(
            Iter.map(
                Map.vals(endpoints_map),
                func(vector : Vector<Metadata>) : Iter<EndpointRecord> {
                    Iter.map(
                        Vector.vals(vector),
                        func(metadata : Metadata) : EndpointRecord {
                            metadata.endpoint;
                        },
                    );
                },
            )
        );
    };

    func extract_endpoints_from_split_endpoints_map(split_endpoints : SplitMetadataEndpoints) : Iter<EndpointRecord> {
        Itertools.chain(
            extract_endpoints_from_endpoints_map(split_endpoints.fallback_endpoints),
            extract_endpoints_from_endpoints_map(split_endpoints.endpoints),
        );
    };

    public func endpoints(ct : StableStore) : Iter<EndpointRecord> {
        Itertools.flatten(
            Iter.map(
                Map.vals(ct.metadata_map),
                extract_endpoints_from_split_endpoints_map,
            )
        );
    };

    public func endpoints_by_url(ct : StableStore, url : Text) : Iter<EndpointRecord> {
        let ?split_endpoints = Map.get(ct.metadata_map, thash, url) else return [].vals();
        extract_endpoints_from_split_endpoints_map(split_endpoints);
    };

    /// Clear all certified endpoints.
    public func clear(ct : StableStore) {
        MerkleTreeOps.delete(ct, ["http_assets"]);
        MerkleTreeOps.delete(ct, ["http_expr"]);

        Map.clear(ct.metadata_map);
        MerkleTreeOps.setCertifiedData(ct);
    };

    /// Modifies a given response by adding the certificate headers.
    public func get_certified_response(ct : StableStore, req : HttpTypes.Request, res : HttpTypes.Response, opt_response_hash : ?Blob) : Result<HttpTypes.Response, Text> {
        let headers_res = get_certificate(ct, req, res, opt_response_hash);
        let #ok(headers) = headers_res else return Utils.send_error(headers_res);

        #ok({ res with headers = Array.append(res.headers, headers) });
    };

    /// Get the certificate headers for a given request.
    public func get_certificate(ct : StableStore, req : HttpTypes.Request, res : HttpTypes.Response, opt_response_hash : ?Blob) : Result<[HttpTypes.Header], Text> {
        if (req.certificate_version == ?2) v2(ct, req, res, opt_response_hash, []) else v1(ct, req);
    };

    /// Gets the closest fallback path for the given path that has a certificate associated with it.
    public func get_fallback_path(ct : StableStore, path : Text) : ?Text {

        let paths = Iter.toArray(Text.split(path, #text("/")));

        for (i in RevIter.range(0, paths.size()).rev()) {
            let slice = Itertools.fromArraySlice(paths, 0, i);
            let possible_fallback = Text.join(("/"), slice);
            let possible_fallback_with_trailing_slash = possible_fallback # "/";

            switch (Map.get(ct.metadata_map, thash, possible_fallback_with_trailing_slash)) {
                case (?{ fallback_endpoints; endpoints }) {
                    if (Map.size(fallback_endpoints) > 0) return ?possible_fallback_with_trailing_slash;
                };
                case (_) {};
            };

            switch (Map.get(ct.metadata_map, thash, possible_fallback)) {
                case (?{ fallback_endpoints; endpoints }) {
                    if (Map.size(fallback_endpoints) > 0) return ?possible_fallback;
                };
                case (_) {};
            };
        };

        null;

    };

    public func get_all_fallback_paths_between_urls(init_start_path : Text, init_end_path : Text) : [Text] {
        let (start_path, end_path) = if (init_start_path.size() < init_end_path.size()) {
            (init_start_path, init_end_path);
        } else {
            (init_end_path, init_start_path);
        };

        let ?difference = Text.stripStart(end_path, #text(start_path)) else return [];
        let differing_paths = Iter.toArray(Text.tokens(difference, #text("/")));

        var curr = start_path;
        var i = 0;
        var j = 0;

        let all_paths_between = Buffer.Buffer<Text>(8);

        label building_paths while (Text.startsWith(end_path, #text(curr))) {
            if (i == 0 and Text.endsWith(curr, #text("/"))) {
                i += 1;
                continue building_paths;
            };

            if (i % 2 == 0) {
                curr #= "/";
            } else {
                curr #= differing_paths[j];
                j += 1;
            };

            if (curr == end_path) break building_paths;

            all_paths_between.add(curr);

            i += 1;
        };

        Buffer.toArray(all_paths_between);
    };

    public func get_fallback_certificate(ct : StableStore, req : HttpTypes.Request, fallback_path : Text, res : HttpTypes.Response, opt_response_hash : ?Blob) : Result<[HttpTypes.Header], Text> {

        let fallback_req = { req with url = fallback_path };

        // need to proove that the fallbacks in between are not certified
        let possible_fallback_paths = Array.map<Text, (Text, Bool)>(
            get_all_fallback_paths_between_urls(req.url, fallback_path),
            func(url : Text) : (Text, Bool) = (url, true),
        );

        let url_to_include_in_witness = Array.append([(req.url, false)], possible_fallback_paths);

        if (fallback_req.certificate_version == ?2) v2(ct, fallback_req, res, opt_response_hash, url_to_include_in_witness) else v1(ct, fallback_req);
    };

    /// Retrieves the certificate tree based on the given keys.
    /// If keys are set to `null`, the entire tree is returned.
    public func get_certified_tree(ct : StableStore, keys : ?[Text]) : Result<CertifiedTree, Text> {
        let ?certificate = CertifiedData.getCertificate() else {
            return #err("CertifiedData.getCertificate() failed: no data certificate available. \nTry calling this as a query call, if you are calling it as an update call.");
        };

        let vec = Vector.new<[Blob]>();

        let keys_iter : Iter<Text> = switch (keys) {
            case (?keys) keys.vals();
            case (null) Map.keys(ct.metadata_map);
        };

        label for_loop for (key in keys_iter) {
            // v1 certification
            Vector.add(vec, ["http_assets", Text.encodeUtf8(key)] : [Blob]);

            let split_endpoints = switch (Map.get(ct.metadata_map, thash, key)) {
                case (?nested_map) nested_map;
                case (null) continue for_loop;
            };

            for (vector in Itertools.chain(Map.vals(split_endpoints.fallback_endpoints), Map.vals(split_endpoints.endpoints))) {
                for (metadata in Vector.vals(vector)) {
                    // v2 certification
                    Vector.add(vec, metadata.full_expr_path);
                };
            };
        };

        let witness = MerkleTreeOps.reveals(ct, Vector.vals(vec));
        let tree = MerkleTreeOps.encodeWitness(witness);

        #ok({ certificate; tree });
    };

    func v1(ct : StableStore, req : HttpTypes.Request) : Result<[HttpTypes.Header], Text> {
        let url = HttpParser.URL(req.url, HttpParser.Headers([]));
        let url_path = url.path.original;

        let result = get_certified_tree(ct, ?[url_path]);
        let #ok({ certificate; tree }) = result else return Utils.send_error(result);

        return #ok([(
            "ic-certificate",
            "certificate=:" # base64(certificate) # ":, " # "tree=:" # base64(tree) # ":",
        )]);
    };

    func v2(ct : StableStore, req : HttpTypes.Request, res : HttpTypes.Response, opt_response_hash : ?Blob, paths_to_include_in_witness : [(Text, Bool)]) : Result<[HttpTypes.Header], Text> {

        let endpoint = http_req_res_to_endpoint(req, res, opt_response_hash);

        let metadata = switch (get_metadata_from_endpoint(ct, endpoint.build())) {
            case (?metadata) metadata;
            case (null) {
                ignore endpoint.is_fallback_path(true);
                switch (get_metadata_from_endpoint(ct, endpoint.build())) {
                    case (?metadata) metadata;
                    case (null) return #err("no metadata found for this url");
                };
            };
        };

        let witness = MerkleTreeOps.reveals(
            ct,
            Array.append<[Blob]>(
                [metadata.full_expr_path],
                Array.map<(Text, is_fallback : Bool), [Blob]>(
                    paths_to_include_in_witness,
                    func(path : Text, is_fallback : Bool) : [Blob] {
                        let text_expr_path = get_text_expr_path(path, is_fallback);
                        Array.map(text_expr_path, Text.encodeUtf8);
                    },
                ),
            ).vals(),
        );

        let encoded_witness = MerkleTreeOps.encodeWitness(witness);

        let ?certificate = CertifiedData.getCertificate() else {
            return #err("CertifiedData.getCertificate failed. Call this as a query call!");
        };

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

    public func http_req_res_to_endpoint(req : HttpTypes.Request, res : HttpTypes.Response, opt_response_hash : ?Blob) : Endpoint {
        let endpoint = Endpoint(req.url, null).method(req.method).request_headers(req.headers).response_headers(res.headers).status(res.status_code);

        switch (opt_response_hash) {
            case (?response_hash) {
                ignore endpoint.hash(response_hash);
            };
            case (null) {
                ignore endpoint.body(res.body);
            };
        };

        endpoint;

    };

    public func get_metadata(ct : StableStore, req : HttpTypes.Request, res : HttpTypes.Response, opt_response_hash : ?Blob) : ?Metadata {

        let endpoint = Endpoint(req.url, null).method(req.method).request_headers(req.headers).response_headers(res.headers).status(res.status_code);

        get_metadata_from_endpoint(ct, endpoint.build());
    };

    public func get_metadata_from_endpoint(ct : StableStore, endpoint_record : EndpointRecord) : ?Metadata {

        let opt_index = get_metadata_index_from_endpoint(ct, endpoint_record);

        switch (opt_index) {
            case (?({ endpoint_variants; index })) ?Vector.get(endpoint_variants, index);
            case (null) null;
        };

    };

    public type GetMetadataResponse = {
        endpoints_map : EndpointsMap;
        endpoint_unique_key : Blob;
        endpoint_variants : Vector<Metadata>;
        index : Nat;
    };

    public func get_metadata_index_from_endpoint(ct : StableStore, endpoint_record : EndpointRecord) : ?GetMetadataResponse {

        let endpoints_map = switch (Map.get(ct.metadata_map, thash, endpoint_record.url)) {
            case (?split_endpoints) if (endpoint_record.is_fallback_path) {
                split_endpoints.fallback_endpoints;
            } else {
                split_endpoints.endpoints;
            };
            case (null) return null;
        };

        let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(3);
        // first check for no certification hash (occurs when only the body is certified)
        buffer.add((IC_CERT_BODY, #Blob(endpoint_record.hash)));

        let no_certification_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

        switch (Map.get(endpoints_map, bhash, no_certification_hash)) {
            case (?vec) {
                let opt_index = get_metadata_index_from_vector(endpoint_record, vec);
                switch (opt_index) {
                    case (?(vec, index)) return ?({
                        endpoints_map;
                        endpoint_unique_key = no_certification_hash;
                        endpoint_variants = vec;
                        index;
                    });
                    case (null) {};
                };
            };
            case (null) {};
        };

        // if empty, check for only response certification

        buffer.add((IC_CERT_STATUS, #Nat(Nat16.toNat(endpoint_record.status))));
        let no_request_certification_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

        switch (Map.get(endpoints_map, bhash, no_request_certification_hash)) {
            case (?vec) {
                let opt_index = get_metadata_index_from_vector(endpoint_record, vec);
                switch (opt_index) {
                    case (?(vec, index)) return ?({
                        endpoints_map;
                        endpoint_unique_key = no_request_certification_hash;
                        endpoint_variants = vec;
                        index;
                    });
                    case (null) {};
                };
            };
            case (null) {};
        };

        // if empty, check for full certification

        buffer.add((IC_CERT_METHOD, #Text(endpoint_record.method)));
        let unique_http_hash = Blob.fromArray(RepIndyHash.hash_val(#Map(Buffer.toArray(buffer))));

        switch (Map.get(endpoints_map, bhash, unique_http_hash)) {
            case (?vec) {
                let opt_index = get_metadata_index_from_vector(endpoint_record, vec);
                switch (opt_index) {
                    case (?(vec, index)) return ?({
                        endpoints_map;
                        endpoint_unique_key = unique_http_hash;
                        endpoint_variants = vec;
                        index;
                    });
                    case (null) {};
                };
            };
            case (null) {};
        };

        return null;

    };

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

    public func get_metadata_index_from_vector(endpoint_record : EndpointRecord, metadata_array : Vector<Metadata>) : ?(Vector<Metadata>, Nat) {
        var i = 0;
        for (metadata in Vector.vals(metadata_array)) {
            var check = true;

            func equal_tuples(a : (Text, Text), b : (Text, Text)) : Bool {
                a.0 == b.0 and a.1 == b.1
            };

            check := check and array_contains_all(endpoint_record.request_headers, metadata.endpoint.request_headers, equal_tuples);
            check := check and array_contains_all(endpoint_record.response_headers, metadata.endpoint.response_headers, equal_tuples);
            check := check and array_contains_all(endpoint_record.query_params, metadata.endpoint.query_params, equal_tuples);

            if (check) return ?(metadata_array, i);

            i += 1;
        };

        return null;
    };

    func base64(data : Blob) : Text {
        let res = Base64.StdEncoding.encode(Blob.toArray(data));
        let ?utf8 = Text.decodeUtf8(Blob.fromArray(res)) else Debug.trap("base64 encoding failed");
        utf8;
    };

    public module MerkleTreeOps {
        type Path = MerkleTree.Path;
        type Value = MerkleTree.Value;
        type Key = MerkleTree.Key;
        type Hash = MerkleTree.Hash;
        type Witness = MerkleTree.Witness;

        public func put(ct : StableStore, ks : Path, v : Value) {
            ct.tree := MerkleTree.put(ct.tree, ks, v);
        };

        public func delete(ct : StableStore, ks : Path) {
            ct.tree := MerkleTree.delete(ct.tree, ks);
        };

        public func lookup(ct : StableStore, ks : Path) : ?Value {
            MerkleTree.lookup(ct.tree, ks);
        };

        public func labelsAt(ct : StableStore, ks : Path) : Iter.Iter<Key> {
            MerkleTree.labelsAt(ct.tree, ks);
        };

        public func treeHash(ct : StableStore) : Hash {
            MerkleTree.treeHash(ct.tree);
        };

        public func setCertifiedData(ct : StableStore) {
            CertifiedData.set(MerkleTreeOps.treeHash(ct));
        };

        public func reveal(ct : StableStore, path : Path) : Witness {
            MerkleTree.reveal(ct.tree, path);
        };

        public func reveals(ct : StableStore, paths : Iter.Iter<Path>) : Witness {
            MerkleTree.reveals(ct.tree, paths);
        };

        public func encodeWitness(w : Witness) : Blob {
            MerkleTree.encodeWitness(w);
        };
    };

};
