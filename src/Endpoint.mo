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
import MerkleTree "mo:ic-certification/MerkleTree";
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

module {

    public type EndpointRecord = {
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
