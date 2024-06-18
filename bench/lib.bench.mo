import Iter "mo:base/Iter";
import Debug "mo:base/Debug";
import Prelude "mo:base/Prelude";

import Bench "mo:bench";
import Fuzz "mo:fuzz";

import CertifiedAssets "../src";
import HttpTypes "mo:http-types";

module {
    public func init() : Bench.Bench {
        let bench = Bench.Bench();

        bench.name("Benchmarking the CertifiedAssets");
        bench.description("Benchmarking the performance with 10k calls");

        bench.rows(["CertifiedAssets"]);
        bench.cols([
            "certify()", 
            // "get_certificate()" // - disabled because the current bench implementation doesn't support query calls
        ]);

        let fuzz = Fuzz.Fuzz();
        let cert_store = CertifiedAssets.init_stable_store();
        let certs = CertifiedAssets.CertifiedAssets(?cert_store);

        bench.runner(
            func(row, col) = switch (row, col) {

                case ("CertifiedAssets", "certify()") {
                    let endpoint = CertifiedAssets.Endpoint("/hello.txt", ?"Hello, World!").no_request_certification().response_headers([("Content-Type", "text/plain")]).status(200);
                    certs.certify(endpoint);
                };

                case ("CertifiedAssets", "get_certificate()") {

                    let http_request : HttpTypes.Request = {
                        method = "GET";
                        url = "http://localhost:8080/hello.txt";
                        headers = [];
                        body = "";
                        streaming_strategy = null;
                        certificate_version = null;
                    };

                    let http_response : HttpTypes.Response = {
                        status_code = 200;
                        headers = [("Content-Type", "text/plain")];
                        body = "Hello, World!";
                        streaming_strategy = null;
                        upgrade = null;
                    };

                    let certificate_res = certs.get_certificate(http_request, http_response, null);
                    let #ok(certificate_headers) = certificate_res else {
                        let #err(err) = certificate_res;
                        Debug.trap("Error: " # debug_show err);
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
