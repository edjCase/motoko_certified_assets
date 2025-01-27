import Debug "mo:base/Debug";
import Iter "mo:base/Iter";

import { suite; test } "mo:test";
import CertifiedAssets "../src/Stable";
import Fuzz "mo:fuzz";

suite(
    "CertifiedAssets Tests",
    func() {
        test(
            "Get all fallback paths between two urls",
            func() {

                assert CertifiedAssets.get_all_fallback_paths_between_urls("/", "/example/async/index.html") == [
                    "/example",
                    "/example/",
                    "/example/async",
                    "/example/async/",
                ];

                assert CertifiedAssets.get_all_fallback_paths_between_urls("/example/async/index.html", "/") == [
                    "/example",
                    "/example/",
                    "/example/async",
                    "/example/async/",
                ];

                assert CertifiedAssets.get_all_fallback_paths_between_urls("", "/example/async/") == [
                    "/",
                    "/example",
                    "/example/",
                    "/example/async",
                ];

            },
        );

        test(
            "get_text_expr_path()",
            func() {

                assert CertifiedAssets.get_text_expr_path("", false) == ["http_expr", "<$>"];
                assert CertifiedAssets.get_text_expr_path("", true) == ["http_expr", "<*>"];

                assert CertifiedAssets.get_text_expr_path("/", false) == ["http_expr", "", "<$>"];
                assert CertifiedAssets.get_text_expr_path("/", true) == ["http_expr", "", "<*>"];

                assert CertifiedAssets.get_text_expr_path("/index.html", false) == ["http_expr", "index.html", "<$>"];
                assert CertifiedAssets.get_text_expr_path("/example/async/index.html", false) == ["http_expr", "example", "async", "index.html", "<$>"];

            },
        );

    },
);
