import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import Prelude "mo:base/Prelude";

import Vector "mo:vector";
import Map "mo:map/Map";
import HttpTypes "mo:http-types";
import { JSON } "mo:serde";
import HttpParser "mo:http-parser";
import Itertools "mo:itertools/Iter";

import CertifiedAssets "../src";

actor {
    type Vector<A> = Vector.Vector<A>;

    stable let st_certs = CertifiedAssets.init_stable_store();
    let certs = CertifiedAssets.CertifiedAssets(?st_certs);

    let { thash } = Map;

    stable let users = Map.new<Text, Text>();
    stable let teams = Map.new<Text, Vector<Text>>();

    system func preupgrade() {
        certs.clear();
    };

    system func postupgrade() {
        certify_homepage();
    };

    func homepage() : Text {

        let user_list = Text.join(
            "\n",
            Iter.map<(Text, Text), Text>(
                Map.entries(users),
                func((k, v) : (Text, Text)) : Text {
                    return "<li>" # k # ": " # v # "</li>";
                },
            ),
        );

        let team_list = Text.join(
            "\n",
            Iter.map<(Text, Vector<Text>), Text>(
                Map.entries(teams),
                func((k, v) : (Text, Vector<Text>)) : Text {
                    return "<li>" # k # " team with " # debug_show (Vector.size(v)) # " members </li>";
                },
            ),
        );

        return "
        <html>
            <head>
                <title>Home</title>
            </head>
            <body>
                <h1>Home Page</h1>
                <h2>Users</h2>
                <ul> " # user_list # " </ul>

                <h2>Teams</h2>
                <ul> " # team_list # " </ul>
            </body>
        </html>
        ";
    };

    type Size = {
        #small;
        #medium;
        #large;
    };

    func teams_json(pagination : ?Size) : Text {
        let teams_as_text = Text.join(
            ", ",
            Itertools.take(
                Iter.map<(Text, Vector<Text>), Text>(
                    Map.entries(teams),
                    func((name, members) : (Text, Vector<Text>)) : Text {
                        return "\"" # name # "\": " # debug_show (Vector.toArray(members));
                    },
                ),
                switch (pagination) {
                    case (? #small) 3;
                    case (? #medium) 5;
                    case (? #large) 10;
                    case (_) Map.size(teams);
                },
            ),
        );

        "{ \"teams\": { " # teams_as_text # "} }";
    };

    func single_team_json(team : Text) : Text {
        let team_members = switch (Map.get(teams, thash, team)) {
            case (?v) Vector.toArray(v);
            case (_)[];
        };

        "{ \"members\": " # debug_show team_members # " }";
    };

    func certify_homepage() {
        let _homepage = homepage();
        let homepage_endpoint = CertifiedAssets.Endpoint("/home", Text.encodeUtf8(_homepage))
            .no_certification()
            .response_header("Content-Type", "text/html")
            .status(200);
        ignore certs.certify(homepage_endpoint);

        let teams_endpoint = CertifiedAssets.Endpoint("/v1/teams", Text.encodeUtf8(teams_json(null)))
            .no_request_certification()
            .response_header("Content-Type", "application/json")
            .status(200);
        ignore certs.certify(teams_endpoint);

        let small_teams_endpoint = CertifiedAssets.Endpoint("/v1/teams", Text.encodeUtf8(teams_json(? #small)))
            .query_param("size", "small")
            .response_header("Content-Type", "application/json")
            .status(200);
        ignore certs.certify(small_teams_endpoint);

        let medium_teams_endpoint = CertifiedAssets.Endpoint("/v1/teams", Text.encodeUtf8(teams_json(? #medium)))
            .query_param("size", "medium")
            .response_header("Content-Type", "application/json")
            .status(200);
        ignore certs.certify(medium_teams_endpoint);

        for ((team, _) in Map.entries(teams)) {
            let team_endpoint = CertifiedAssets.Endpoint("/v1/teams/" # team, Text.encodeUtf8(single_team_json(team)))
                .response_header("Content-Type", "application/json")
                .status(200);
            ignore certs.certify(team_endpoint);
        };

    };

    public func create_user(username : Text, team : Text) {
        ignore Map.put(users, thash, username, team);

        let team_vec = switch (Map.get(teams, thash, team)) {
            case (?v) v;
            case (_) {
                let v = Vector.new<Text>();
                ignore Map.put(teams, thash, team, v);
                v;
            };
        };

        Vector.add(team_vec, username);

        certify_homepage();

    };

    public func create_team(team : Text) {
        switch (Map.get(teams, thash, team)) {
            case (?v) {};
            case (_) {
                let v = Vector.new<Text>();
                ignore Map.put(teams, thash, team, v);
            };
        };

        certify_homepage();
    };

    public query func http_request(req : HttpTypes.Request) : async HttpTypes.Response {
        let url = HttpParser.URL(req.url, HttpParser.Headers([]));
        assert req.body == "";
        Debug.print("req: " # debug_show req);
        let response : HttpTypes.Response = switch (url.path.original, url.queryObj.get("size")) {
            case ("/home", _) {
                {
                    status_code = 200;
                    body = Text.encodeUtf8(homepage());
                    headers = [("Content-Type", "text/html")];
                    streaming_strategy = null;
                    upgrade = null;
                };
            };

            case (("/v1/teams" or "/v1/teams/"), ?text_size) {

                let size : Size = switch (text_size) {
                    case ("small") #small;
                    case ("medium") #medium;
                    case ("large") #large;
                    case (_) #small;
                };

                Debug.print("size: " # debug_show size);

                {
                    status_code = 200;
                    body = Text.encodeUtf8(teams_json(?size));
                    headers = [("Content-Type", "application/json")];
                    streaming_strategy = null;
                    upgrade = null;
                };
            };
            case (("/v1/teams" or "/v1/teams/"), _) {
                {
                    status_code = 200;
                    body = Text.encodeUtf8(teams_json(null));
                    headers = [("Content-Type", "application/json")];
                    streaming_strategy = null;
                    upgrade = null;
                };
            };
            case (_) {
                // path -> '/v1/teams/:team'
                if (Text.startsWith(url.path.original, #text "/v1/teams/")) {
                    let team = url.path.array[2];
                    if (Map.has(teams, thash, team)) {
                        return {
                            status_code = 200;
                            body = Text.encodeUtf8(single_team_json(team));
                            headers = [("Content-Type", "application/json")];
                            streaming_strategy = null;
                            upgrade = null;
                        };
                    };
                };
                return {
                    status_code = 404;
                    body = Text.encodeUtf8("Not Found");
                    headers = [];
                    streaming_strategy = null;
                    upgrade = null;
                };
            };
        };

        let result = certs.get_certified_response(req, response);

        let #ok(certified_response) = result else {

            let #err(errorMsg) = result else Prelude.unreachable();
            Debug.print("prev response: " # debug_show { response with streaming_strategy = null });
            return {
                status_code = 404;
                body = Text.encodeUtf8("Certified Assets Error: " # errorMsg);
                headers = [];
                streaming_strategy = null;
                upgrade = null;
            };

        };

        Debug.print("certified_response: " # debug_show { certified_response with streaming_strategy = null });
        certified_response;
        // response
    };
};
