import Text "mo:base/Text";
import Iter "mo:base/Iter";
import Debug "mo:base/Debug";
import Prelude "mo:base/Prelude";
import Nat16 "mo:base/Nat16";
import Buffer "mo:base/Buffer";

import Bench "mo:bench";
import Fuzz "mo:fuzz";

import CertifiedAssets "../src";
import HttpTypes "mo:http-types";

module {

    func random_endpoint(fuzz : Fuzz.Fuzzer) : (CertifiedAssets.EndpointRecord, Blob) {

        let status_codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 306, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511];

        let headers = [
            (
                "Content-Type",
                ["text/plain", "text/html", "application/json", "application/xml", "application/pdf", "image/png"],
            ),
            (
                "Cache-Control",
                ["no-cache", "no-store", "must-revalidate", "proxy-revalidate", "max-age=604800"],
            ),
            (
                "Content-Encoding",
                ["gzip", "deflate", "br", "compress", "identity"],
            ),
        ];

        let queries = [
            ("field1", "value1"),
            ("field2", "value2"),
            ("field3", "value3"),
            ("field4", "value4"),
            ("field5", "value5"),
        ];

        let hello_world_blob : Blob = "Hello, World!";
        let blob = fuzz.blob.randomBlob(13);

        let path : Text = Text.join(
            "/",
            Iter.map(
                Iter.range(0, 4),
                func(i : Nat) : Text = fuzz.text.randomAlphanumeric(3),
            ),
        );

        let include_status = fuzz.nat.randomRange(0, 10) > 3;
        let include_queries = fuzz.nat.randomRange(0, 10) > 3;
        let include_response_headers = fuzz.nat.randomRange(0, 10) > 3;
        let include_random_blob = fuzz.nat.randomRange(0, 10) > 5;
        let include_request_certification = fuzz.nat.randomRange(0, 10) > 10;

        let endpoint = CertifiedAssets.Endpoint(path, null);

        let body = if (include_random_blob) { blob } else { hello_world_blob };

        ignore endpoint.body(body);

        if (include_status) {
            let status = fuzz.array.randomValue(status_codes) |> Nat16.fromNat(_);
            ignore endpoint.status(status);
        };

        if (not include_request_certification) {
            ignore endpoint.no_request_certification();
        };

        if (include_response_headers) {
            let header_num = fuzz.nat.randomRange(1, 3);

            for (_ in Iter.range(0, header_num)) {
                let header = fuzz.array.randomValue(headers);
                let header_value = fuzz.array.randomValue(header.1);
                ignore endpoint.response_header(header.0, header_value);
            };
        };

        if (include_queries) {
            let query_num = fuzz.nat.randomRange(1, 3);

            for (_ in Iter.range(0, query_num)) {
                let (field, value) = fuzz.array.randomValue(queries);
                ignore endpoint.query_param((field, value));
            };
        };

        (endpoint.build(), body);

    };

    public func init() : Bench.Bench {
        let bench = Bench.Bench();

        bench.name("Benchmarking the CertifiedAssets");
        bench.description("Benchmarking the performance with 1k calls");

        bench.rows(["CertifiedAssets"]);
        bench.cols([
            "certify()",
            // "get_certificate()" // - disabled because the current bench library doesn't support query calls
            "remove()",
        ]);

        let fuzz = Fuzz.Fuzz();
        let limit = 1000;
        let cert_store = CertifiedAssets.init_stable_store();
        let certs = CertifiedAssets.CertifiedAssets(?cert_store);
        let endpoint_records = Buffer.Buffer<(CertifiedAssets.EndpointRecord)>(limit);
        let endpoint_bodies = Buffer.Buffer<(Blob)>(limit);

        for (_ in Iter.range(0, limit)) {
            let (endpoint_record, blob) = random_endpoint(fuzz);
            endpoint_records.add(endpoint_record);
            endpoint_bodies.add(blob);
        };

        bench.runner(
            func(row, col) = switch (row, col) {

                case ("CertifiedAssets", "certify()") {

                    for (endpoint_record in endpoint_records.vals()) {
                        certs.certify_record(endpoint_record);
                    };
                };

                case ("CertifiedAssets", "re-certify()") {

                    for (endpoint_record in endpoint_records.vals()) {
                        let new_endpoint = {
                            endpoint_record with body = "Re-certified!"
                        };

                        certs.remove_record(endpoint_record);
                        certs.certify_record(new_endpoint);
                    };
                };

                case ("CertifiedAssets", "get_certificate()") {

                    for (i in Iter.range(0, limit - 1)) {
                        let endpoint_record = endpoint_records.get(i);
                        let body = endpoint_bodies.get(i);

                        let http_request : HttpTypes.Request = {
                            method = "GET";
                            url = endpoint_record.url;
                            headers = endpoint_record.request_headers;
                            body = body;
                            streaming_strategy = null;
                            certificate_version = ?2;
                        };

                        let http_response : HttpTypes.Response = {
                            headers = endpoint_record.response_headers;
                            status_code = endpoint_record.status;
                            streaming_strategy = null;
                            upgrade = null;
                            body;
                        };

                        let certificate_res = certs.get_certificate(http_request, http_response, null);

                        let #ok(certificate_headers) = certificate_res else {
                            let #err(err) = certificate_res;
                            Debug.trap("Error: " # debug_show err);
                        };
                    };

                };

                case ("CertifiedAssets", "remove()") {

                    for (endpoint_record in endpoint_records.vals()) {
                        certs.remove_record(endpoint_record);
                    };
                };

                case (_) {
                    Debug.trap("Should be unreachable:\n row = \"" # debug_show row # "\" and col = \"" # debug_show col # "\"");
                };
            }
        );

        bench;
    };
};
