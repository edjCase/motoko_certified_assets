import Debug "mo:base/Debug";
import Iter "mo:base/Iter";

import { suite; test } "mo:test";
import CertifiedAssets "../src/Stable";
import Fuzz "mo:fuzz";

actor {
    let fuzz = Fuzz.Fuzz();

    func get_endpoint(url : Text, is_fallback : Bool) : CertifiedAssets.Endpoint {
        let content : Blob = "Hello, World!";

        // default to status == 200 and method == "GET"
        return CertifiedAssets.Endpoint(url, ?content).response_header("Content-Type", "text/html").no_request_certification().is_fallback_path(is_fallback);
    };

    func certify(ct : CertifiedAssets.StableStore, (url, is_fallback) : (Text, Bool)) {
        let endpoint = get_endpoint(url, is_fallback);

        CertifiedAssets.certify(ct, endpoint);

    };

    func verify_expr_path(ct : CertifiedAssets.StableStore, (url, is_fallback) : (Text, Bool), expr_path : [Text]) : Bool {

        let endpoint = get_endpoint(url, is_fallback);

        let ?metadata = CertifiedAssets.get_metadata_from_endpoint(ct, endpoint.build()) else return false;

        return metadata.encoded_expr_path == CertifiedAssets.encode_text_expr_path(expr_path);

    };

    public func runTests() {

        let certs = CertifiedAssets.init_stable_store();

        suite(
            "CertifiedAssets Tests",
            func() {
                test(
                    "Certify endpoints, get metadata and verify encoded expression path",
                    func() {

                        certify(certs, ("/index.html", false));
                        certify(certs, ("/", false));
                        certify(certs, ("", false));

                        assert verify_expr_path(certs, ("/index.html", false), ["http_expr", "index.html", "<$>"]);
                        assert verify_expr_path(certs, ("/", false), ["http_expr", "", "<$>"]);
                        assert verify_expr_path(certs, ("", false), ["http_expr", "<$>"]);

                        certify(certs, ("/index.html", true));
                        certify(certs, ("/", true));
                        certify(certs, ("", true));

                        assert verify_expr_path(certs, ("/index.html", true), ["http_expr", "index.html", "<*>"]);
                        assert verify_expr_path(certs, ("/", true), ["http_expr", "", "<*>"]);
                        assert verify_expr_path(certs, ("", true), ["http_expr", "<*>"]);

                        // previous endpoint should not be overwritten
                        assert verify_expr_path(certs, ("/index.html", false), ["http_expr", "index.html", "<$>"]);
                        assert verify_expr_path(certs, ("/", false), ["http_expr", "", "<$>"]);
                        assert verify_expr_path(certs, ("", false), ["http_expr", "<$>"]);

                        certify(certs, ("/example/async/index.html", false));
                        certify(certs, ("/example/async/index", false));
                        certify(certs, ("/example/async/", false));
                        certify(certs, ("/example/async", false));
                        certify(certs, ("/example/", false));
                        certify(certs, ("/example", false));

                        assert verify_expr_path(certs, ("/example/async/index.html", false), ["http_expr", "example", "async", "index.html", "<$>"]);
                        assert verify_expr_path(certs, ("/example/async/index", false), ["http_expr", "example", "async", "index", "<$>"]);
                        assert verify_expr_path(certs, ("/example/async/", false), ["http_expr", "example", "async", "", "<$>"]);
                        assert verify_expr_path(certs, ("/example/async", false), ["http_expr", "example", "async", "<$>"]);
                        assert verify_expr_path(certs, ("/example/", false), ["http_expr", "example", "", "<$>"]);
                        assert verify_expr_path(certs, ("/example", false), ["http_expr", "example", "<$>"]);

                        certify(certs, ("/example/async/", true));

                        assert verify_expr_path(certs, ("/example/async/", true), ["http_expr", "example", "async", "", "<*>"]);

                    },
                );

                test(
                    "Get the fallback path with the highest priority",
                    func() {
                        let fallback_path = CertifiedAssets.get_fallback_path(certs, "/example/async/index.html");
                        assert fallback_path == ?"/example/async/";

                        let fallback_endpoint = get_endpoint("/example/async/", true);
                        CertifiedAssets.remove(certs, fallback_endpoint);
                        assert null == CertifiedAssets.get_metadata_from_endpoint(certs, fallback_endpoint.build());

                        let fallback_path2 = CertifiedAssets.get_fallback_path(certs, "/example/async/index.html");
                        assert fallback_path2 == ?"/";

                    },
                );

            },
        );

    }

};
