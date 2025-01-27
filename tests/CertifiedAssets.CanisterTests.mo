// @testmode wasi
import Array "mo:base/Array";
import Debug "mo:base/Debug";
import Option "mo:base/Option";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import CertifiedData "mo:base/CertifiedData";
import Blob "mo:base/Blob";
import Nat16 "mo:base/Nat16";

import SHA256 "mo:sha2/Sha256";
import Itertools "mo:itertools/Iter";
import Serde "mo:serde";
import Base64 "mo:encoding/Base64";
import RepIndyHash "mo:rep-indy-hash";

import CertifiedAssets "../src";
import {
    MerkleTreeOps;
    IC_CERT_METHOD;
    IC_CERT_QUERY;
    IC_CERTIFICATE_EXPRESSION;
    IC_CERT_STATUS;
} "../src/Stable";
import CanisterTests "CanisterTests";

actor {

    let suite = CanisterTests.Suite();

    // for running tests
    public query func run_query_test(test_name : Text) : async CanisterTests.TestResult {
        suite.run_query(test_name).0;
    };

    public func run_test(test_name : Text) : async CanisterTests.TestResult {
        (await suite.run(test_name)).0;
    };

    public func get_test_details() : async [CanisterTests.TestDetails] {
        suite.get_test_details().0;
    };

    public func get_test_result(test_name : Text) : async CanisterTests.TestResult {
        suite.get_test_result(test_name).0;
    };

    public func get_finished_test_results() : async [CanisterTests.TestResult] {
        suite.get_finished_test_results().0;
    };

    type Result<T, E> = Result.Result<T, E>;

    stable let sstore = CertifiedAssets.init_stable_store();
    let certs = CertifiedAssets.CertifiedAssets(sstore);

    func strip_start(t : Text, prefix : Text) : Text = Option.get(
        Text.stripStart(t, #text(prefix)),
        t,
    );

    type CertificateDetails = {
        certificate : Text;
        tree : Text;
        version : Text;
        expr_path : Text;
    };

    func split_certificate(ic_certificate : Text) : CertificateDetails {
        let split_certificate = Iter.toArray(Text.split(ic_certificate, #text(", ")));

        let certificate = strip_start(split_certificate[0], ("certificate="));
        let tree = strip_start(split_certificate[1], ("tree="));
        let version = strip_start(split_certificate[2], ("version="));
        let expr_path = strip_start(split_certificate[3], ("expr_path="));

        return {
            certificate = certificate;
            tree = tree;
            version = version;
            expr_path = expr_path;
        };
    };

    func to_cbor(paths : [Text]) : Blob {

        let candid_record_expr_path = #Array(
            Array.map(paths, func(t : Text) : Serde.Candid = #Text(t))
        );

        let cbor_res = Serde.CBOR.fromCandid(candid_record_expr_path, Serde.defaultOptions);
        let encoded_expr_path = switch (cbor_res) {
            case (#ok(encoded_expr_path)) encoded_expr_path;
            case (#err(errMsg)) Debug.trap("Internal Error: Report bug in NatLabs/certified-assets repo.\n\t" # errMsg);
        };

        encoded_expr_path;

    };

    func to_base64(blob : Blob) : Text {
        let res = Base64.StdEncoding.encode(Blob.toArray(blob));
        let ?utf8 = Text.decodeUtf8(Blob.fromArray(res)) else Debug.trap("base64 encoding failed");
        utf8;
    };

    func encode_expr_path(paths : [Text]) : Text {
        let cbor = to_cbor(paths);
        let base64 = to_base64(cbor);
        ":" # base64 # ":";
    };

    func get_witness(full_expr_path : [Blob]) : Text {
        let witness = MerkleTreeOps.reveal(sstore, full_expr_path);
        let encoded_witness = MerkleTreeOps.encodeWitness(witness);

        ":" # to_base64(encoded_witness) # ":";
    };

    func get_request_hash(method : Text, certified_request_headers : [(Text, Text)], certified_query_params : [(Text, Text)]) : Blob {
        let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

        for ((name, value) in certified_request_headers.vals()) {
            if (value.size() != 0) {
                buffer.add((Text.toLowercase(name), #Text(value)));
            };
        };

        buffer.add((IC_CERT_METHOD, #Text(method)));

        let query_params = Array.tabulate(
            certified_query_params.size(),
            func(i : Nat) : Text {
                let (name, value) = certified_query_params[i];
                (name # "=" # value);
            },
        );

        let concatenated_query_params = Text.join("&", query_params.vals());
        // Debug.print("concatenated_query_params: " # debug_show concatenated_query_params);
        let hashed_query_params = SHA256.fromBlob(#sha256, Text.encodeUtf8(concatenated_query_params));
        buffer.add((IC_CERT_QUERY, #Blob(hashed_query_params)));

        let rep_val = #Map(Buffer.toArray(buffer));
        let request_header_hash = RepIndyHash.hash_val(rep_val);

        let request_body_hash : Blob = SHA256.fromBlob(#sha256, ""); // the body is empty because this is expected to be either a GET, HEAD or OPTIONS requests
        // Debug.print("request rep val: " # debug_show rep_val);
        SHA256.fromArray(#sha256, Array.append(request_header_hash, Blob.toArray(request_body_hash)));
    };

    func get_respoonse_hash(status : Nat16, certified_response_headers : [(Text, Text)], body_hash : Blob, ic_certificate_expression : Text) : Blob {
        let buffer = Buffer.Buffer<(Text, RepIndyHash.Value)>(8);

        for ((name, value) in certified_response_headers.vals()) {
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

        SHA256.fromArray(#sha256, headers_and_body_hash);
    };

    suite.add(
        "verify certificate headers - upload hello file",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {

            let hello_endpoint = CertifiedAssets.Endpoint(
                "/hello",
                ?Text.encodeUtf8("👋 Hello, World!"),
            ).status(
                200
            ).response_header(
                "Content-Type",
                "text/plain",
            ).no_request_certification();

            certs.certify(hello_endpoint);

        },
    );

    suite.add_query(
        "verify certificate headers - headers should match expected values",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : () {

            let req : CertifiedAssets.HttpRequest = {
                method = "GET";
                url = "/hello";
                headers = [];
                body = "";
                certificate_version = ?2;
            };

            let res : CertifiedAssets.HttpResponse = {
                status_code = 200;
                headers = [("content-type", "text/plain")];
                body = "👋 Hello, World!";
                streaming_strategy = null;
                upgrade = null;
            };

            let #ok(certificate_headers) = certs.get_certificate(req, res, null) else return assert false;

            let (ic_certificate, ic_certificate_expression) = if (certificate_headers[0].0 == "ic-certificate") {
                (certificate_headers[0].1, certificate_headers[1].1);
            } else { (certificate_headers[1].1, certificate_headers[0].1) };

            let { certificate; tree; version; expr_path } = split_certificate(ic_certificate);

            ts_assert_or_print(
                certificate == ":" # to_base64(Option.get(CertifiedData.getCertificate(), "" : Blob)) # ":",
                "certificate does not match expected value",
            );

            ts_assert_or_print(
                version == "2",
                "version does not match expected value",
            );

            ts_assert_or_print(
                expr_path == encode_expr_path(["http_expr", "hello", "<$>"]),
                "expr_path does not match expected value",
            );

            ts_assert_or_print(
                ic_certificate_expression == "default_certification ( ValidationArgs { certification: Certification { no_request_certification: Empty { }, response_certification: ResponseCertification { certified_response_headers: ResponseHeaderList { headers: [\"content-type\"] } } } } )",
                "ic_certificate_expression does not match expected value",
            );

            let no_certification = false;
            let no_request_certification = true;

            let ic_certificate_expression_hash = SHA256.fromBlob(#sha256, Text.encodeUtf8(ic_certificate_expression));
            let request_hash : Blob = ""; // no_request_certification
            let response_hash = CertifiedAssets.get_response_hash(
                no_certification,
                200,
                SHA256.fromBlob(#sha256, "👋 Hello, World!"),
                [("content-type", "text/plain")],
                ic_certificate_expression,
            );

            let blob_http_expr_path = Array.map(["http_expr", "hello", "<$>"], Text.encodeUtf8);
            let full_expr_path = Array.append(blob_http_expr_path, [ic_certificate_expression_hash, request_hash, response_hash]);
            let tree_witness = get_witness(full_expr_path);

            ts_assert_or_print(
                tree == tree_witness,
                "tree does not match expected value ",
            );

        },
    );

    suite.add(
        "Certify '/hello_world.txt' asset",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {
            let endpoint = CertifiedAssets.Endpoint(
                "/hello_world.txt",
                ?Text.encodeUtf8("Hello, World!"),
            ).status(
                200
            ).response_header(
                "Content-Type",
                "text/plain",
            ).no_request_certification();

            certs.certify(endpoint);

            ts_assert(
                Itertools.any(
                    certs.endpoints(),
                    func(endpoint_record : CertifiedAssets.EndpointRecord) : Bool {
                        endpoint_record.url == "/hello_world.txt" and endpoint_record.status == 200 and endpoint_record.response_headers == [("content-type", "text/plain")] and endpoint_record.hash == SHA256.fromBlob(#sha256, "Hello, World!") and endpoint_record.no_request_certification
                    },
                )
            );
        },
    );

    suite.add_query(
        "Retrieve '/hello_world.txt' asset",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) {
            let req : CertifiedAssets.HttpRequest = {
                method = "GET";
                url = "/hello_world.txt";
                headers = [];
                body = "";
                certificate_version = ?2;
            };

            let res : CertifiedAssets.HttpResponse = {
                status_code = 200;
                headers = [("content-type", "text/plain")];
                body = "Hello, World!";
                streaming_strategy = null;
                upgrade = null;
            };

            let response_with_additional_headers = {
                res with headers = [("content-type", "text/plain"), ("x-test", "Test")];
            };

            let should_succeed = [
                res,
                response_with_additional_headers,
            ];

            for (res in should_succeed.vals()) switch (certs.get_certificate(req, res, null)) {
                case (#ok(_)) {};
                case (#err(_)) ts_assert(false);
            };

            let response_with_no_header = {
                res with headers = [];
            };

            let response_with_incorrect_status_code = {
                res with status_code : Nat16 = 404;
            };

            let response_with_incorrect_body = {
                res with body : Blob = "Goodbye, World!";
            };

            let response_with_incorrect_content_type = {
                res with headers = [("content-type", "text/html")];
            };

            let should_fail = [
                response_with_no_header,
                response_with_incorrect_status_code,
                response_with_incorrect_body,
                response_with_incorrect_content_type,
            ];

            for (res in should_fail.vals()) switch (certs.get_certificate(req, res, null)) {
                case (#ok(_)) ts_assert(false);
                case (#err(_)) {};
            };
        },
    );

    suite.add(
        "Certify '/hello_world.txt' asset with different headers and status code",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {

            certs.certify(
                CertifiedAssets.Endpoint(
                    "/hello_world.txt",
                    ?Text.encodeUtf8("Hello, World!"),
                ).status(
                    200
                ).response_header(
                    "Content-Type",
                    "gzip",
                ).response_header(
                    "x-test",
                    "Test",
                ).no_request_certification()
            );

            ts_assert(
                Itertools.any(
                    certs.endpoints(),
                    func(endpoint_record : CertifiedAssets.EndpointRecord) : Bool {
                        endpoint_record.url == "/hello_world.txt" and endpoint_record.status == 200 and endpoint_record.response_headers == [("content-type", "gzip"), ("x-test", "Test")] and endpoint_record.hash == SHA256.fromBlob(#sha256, "Hello, World!") and endpoint_record.no_request_certification
                    },
                )
            );

            certs.certify(
                CertifiedAssets.Endpoint(
                    "/hello_world.txt",
                    ?Text.encodeUtf8("Hello, World!"),
                ).status(
                    304
                ).response_header(
                    "Content-Type",
                    "text/plain",
                ).response_header(
                    "x-test",
                    "Test",
                ).no_request_certification()
            );

            ts_assert(
                Itertools.any(
                    certs.endpoints(),
                    func(endpoint_record : CertifiedAssets.EndpointRecord) : Bool {
                        endpoint_record.url == "/hello_world.txt" and endpoint_record.status == 304 and endpoint_record.response_headers == [("content-type", "text/plain"), ("x-test", "Test")] and endpoint_record.hash == SHA256.fromBlob(#sha256, "Hello, World!") and endpoint_record.no_request_certification
                    },
                )
            );

        },
    );

    suite.add_query(
        "Retrieve 'hello_world.txt' asset with different headers and status code",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) {
            let req : CertifiedAssets.HttpRequest = {
                method = "GET";
                url = "/hello_world.txt";
                headers = [];
                body = "";
                certificate_version = ?2;
            };

            let res_200 : CertifiedAssets.HttpResponse = {
                status_code = 200;
                headers = [("content-type", "gzip"), ("x-test", "Test")];
                body = "Hello, World!";
                streaming_strategy = null;
                upgrade = null;
            };

            let res_304 : CertifiedAssets.HttpResponse = {
                status_code = 304;
                headers = [("content-type", "text/plain"), ("x-test", "Test")];
                body = "Hello, World!";
                streaming_strategy = null;
                upgrade = null;
            };

            let should_succeed = [
                res_200,
                res_304,
            ];

            for (res in should_succeed.vals()) switch (certs.get_certificate(req, res, null)) {
                case (#ok(_)) {};
                case (#err(_)) ts_assert(false);
            };

            let should_fail = [
                {
                    res_200 with status_code : Nat16 = 404;
                },
                {
                    res_200 with body : Blob = "Goodbye, World!";
                },
                {
                    res_200 with headers = [("content-type", "text/html")];
                },
                {
                    res_304 with status_code : Nat16 = 404;
                },
                {
                    res_304 with body : Blob = "Goodbye, World!";
                },
                {
                    res_304 with headers = [("content-type", "text/html")];
                },
            ];

            for (res in should_fail.vals()) switch (certs.get_certificate(req, res, null)) {
                case (#ok(_)) ts_assert(false);
                case (#err(_)) {};
            };
        },
    );

    suite.add(
        "Certify '/assets/delete-me.txt'",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {
            certs.certify(
                CertifiedAssets.Endpoint(
                    "/assets/delete-me.txt",
                    ?Text.encodeUtf8("Delete me!"),
                ).status(
                    200
                ).response_header(
                    "Content-Type",
                    "text/plain",
                ).no_request_certification()
            );

            ts_assert(
                Itertools.any(
                    certs.endpoints(),
                    func(endpoint_record : CertifiedAssets.EndpointRecord) : Bool {
                        endpoint_record.url == "/assets/delete-me.txt" and endpoint_record.status == 200 and endpoint_record.response_headers == [("content-type", "text/plain")] and endpoint_record.hash == SHA256.fromBlob(#sha256, "Delete me!") and endpoint_record.no_request_certification
                    },
                )
            );
        },
    );

    suite.add(
        "delete certified endpoint",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {
            certs.remove(
                CertifiedAssets.Endpoint(
                    "/assets/delete-me.txt",
                    ?Text.encodeUtf8("Delete me!"),
                ).status(
                    200
                ).response_header(
                    "Content-Type",
                    "text/plain",
                ).no_request_certification()
            );

            ts_assert(
                not Itertools.all(
                    certs.endpoints(),
                    func(endpoint_record : CertifiedAssets.EndpointRecord) : Bool {
                        endpoint_record.url == "/assets/delete-me.txt" and endpoint_record.status == 200 and endpoint_record.response_headers == [("content-type", "text/plain")] and endpoint_record.hash == SHA256.fromBlob(#sha256, "Delete me!") and endpoint_record.no_request_certification
                    },
                )
            );
        },
    );

    suite.add(
        "certify fallback path",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : async () {
            certs.certify(
                CertifiedAssets.Endpoint(
                    "/fallback/",
                    ?Text.encodeUtf8("Fallback!"),
                ).status(
                    200
                ).response_header(
                    "Content-Type",
                    "text/plain",
                ).no_request_certification().is_fallback_path(true)
            );
        },
    );

    suite.add_query(
        "get fallback",
        func({ ts_assert; ts_print; ts_assert_or_print } : CanisterTests.TestTools) : () {
            let req : CertifiedAssets.HttpRequest = {
                method = "GET";
                url = "/fallback/missing_file.txt";
                headers = [];
                body = "";
                certificate_version = ?2;
            };

            let fallback_res : CertifiedAssets.HttpResponse = {
                status_code = 200;
                headers = [("content-type", "text/plain")];
                body = "Fallback!";
                streaming_strategy = null;
                upgrade = null;
            };

            let certificates = switch (certs.get_fallback_certificate(req, "/fallback/", fallback_res, null)) {
                case (#ok(certificates)) certificates;
                case (#err(msg)) return ts_assert_or_print(false, "Failed to retrieve fallback certificate: " # msg);
            };

            let (ic_certificate, ic_certificate_expression) = if (certificates[0].0 == "ic-certificate") {
                (certificates[0].1, certificates[1].1);
            } else { (certificates[1].1, certificates[0].1) };

            let { certificate; tree; version; expr_path } = split_certificate(ic_certificate);

            ts_assert_or_print(
                certificate == ":" # to_base64(Option.get(CertifiedData.getCertificate(), "" : Blob)) # ":",
                "certificate does not match expected value",
            );

            ts_assert_or_print(
                version == "2",
                "version does not match expected value",
            );

            ts_assert_or_print(
                expr_path == encode_expr_path(["http_expr", "fallback", "", "<*>"]),
                "expr_path does not match expected value ",
            );

            ts_assert_or_print(
                ic_certificate_expression == "default_certification ( ValidationArgs { certification: Certification { no_request_certification: Empty { }, response_certification: ResponseCertification { certified_response_headers: ResponseHeaderList { headers: [\"content-type\"] } } } } )",
                "ic_certificate_expression does not match expected value",
            );

            let ic_certificate_expression_hash = SHA256.fromBlob(#sha256, Text.encodeUtf8(ic_certificate_expression));
            let request_hash : Blob = ""; // no_request_certification
            let response_hash = get_respoonse_hash(200, [("content-type", "text/plain")], SHA256.fromBlob(#sha256, "Fallback!"), ic_certificate_expression);
            let blob_http_expr_path = Array.map(["http_expr", "fallback", "", "<*>"], func(t : Text) : Blob { Text.encodeUtf8(t) });
            let full_expr_path = Array.append(blob_http_expr_path, [ic_certificate_expression_hash, request_hash, response_hash]);
            let tree_witness = get_witness(full_expr_path);

            ts_assert_or_print(
                tree == tree_witness,
                "tree does not match expected value ",
            );
        },
    );

};
