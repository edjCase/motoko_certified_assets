// @testmode wasi
import Debug "mo:base/Debug";

import CertifiedAssets "../src";

actor {
    stable let sstore = CertifiedAssets.init_stable_store();
    let certs = CertifiedAssets.CertifiedAssets(?sstore);

    public func test_certify() : async () {
        await test_cerify_path("/symbols/ç˙∆å¨∆´ˆ˚ß¨çß.pdf");
    };

    public query func test_exists() : async () {
        test_get_certificate_path("/symbols/ç˙∆å¨∆´ˆ˚ß¨çß.pdf");
    };

    public func test_cerify_path(path : Text) : async () {
        let endpoint = CertifiedAssets.Endpoint(
            path,
            ?"Hello, World!",
        ).status(
            200
        ).no_request_certification();
        Debug.print("about to certify");

        certs.certify(endpoint);
        Debug.print("endpoint certified");

    };

    func test_get_certificate_path(path : Text) : () {
        let req : CertifiedAssets.HttpRequest = {
            method = "GET";
            url = path;
            headers = [];
            body = "";
            certificate_version = ?2;
        };

        let res : CertifiedAssets.HttpResponse = {
            status_code = 200;
            headers = [];
            body = "Hello, World!";
            streaming_strategy = null;
            upgrade = null;
        };

        switch (certs.get_certificate(req, res, null)) {
            case (#ok(certificate_headers)) Debug.print("certificate headers: " # debug_show certificate_headers);
            case (#err(error)) Debug.trap("error: " # error);
        };

    };

    func test_delete_path(path : Text) : async () {
        certs.remove_all(path);
    };

};
