import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Text "mo:base/Text";

import HttpParser "mo:http-parser";
import HttpTypes "mo:http-types";
import { CBOR } "mo:serde";
import Map "mo:map/Map";
import RepIndyHash "mo:rep-indy-hash";
import Vector "mo:vector";

import Utils "Utils";
import EndpointModule "Endpoint";
import Stable "Stable";

module {
    type Buffer<A> = Buffer.Buffer<A>;
    type Iter<A> = Iter.Iter<A>;
    type Map<K, V> = Map.Map<K, V>;
    type Result<T, E> = Result.Result<T, E>;
    type Vector<A> = Vector.Vector<A>;

    public type HttpRequest = HttpTypes.Request;
    public type HttpResponse = HttpTypes.Response;

    public type StableStore = Stable.StableStore;

    let { thash; bhash } = Map;

    public type MetadataMap = Stable.MetadataMap;

    public let Endpoint = EndpointModule.Endpoint;
    public type Endpoint = EndpointModule.Endpoint;
    public type EndpointRecord = EndpointModule.EndpointRecord;

    public type CertifiedTree = Stable.CertifiedTree;

    /// Create a new stable CertifiedAssets instance on the heap.
    /// This instance is stable and will not be cleared on canister upgrade.
    ///
    /// ```motoko
    /// let cert_store = CertifiedAssets.init_stable_store();
    /// let certs = CertifiedAssets.CertifiedAssets(?cert_store);
    /// ```

    public func init_stable_store() : StableStore = Stable.init_stable_store();

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
    /// let cert_store = CertifiedAssets.init_stable_store();
    /// let certs = CertifiedAssets.CertifiedAssets(?cert_store);
    /// ```
    ///
    /// If your instance is stable, it is advised to `clear()` all the certified endpoints and
    /// re-certify them on canister upgrade if the data has changed.
    ///
    public class CertifiedAssets(stable_store : ?StableStore) = self {

        let internal : StableStore = switch (stable_store) {
            case (?(stable_store)) stable_store;
            case (null) Stable.init_stable_store();
        };

        public func certify(endpoint : Endpoint) = Stable.certify(internal, endpoint);

        public func certify_record(endpoint_record : EndpointRecord) = Stable.certify_record(internal, endpoint_record);

        /// Remove a certified EndpointModule.
        public func remove(endpoint : Endpoint) = Stable.remove(internal, endpoint);

        public func remove_record(endpoint_record : EndpointRecord) = Stable.remove_record(internal, endpoint_record);

        /// Removes all the certified endpoints that match the given URL.
        public func remove_all(url : Text) = Stable.remove_all(internal, url);

        /// Get all certified endpoints.
        public func endpoints() : Iter<EndpointRecord> = Stable.endpoints(internal);

        /// Clear all certified endpoints.
        public func clear() = Stable.clear(internal);

        /// Modifies a given response by adding the certificate headers.
        /// This only works if the endpoint has already been certified.
        public func get_certified_response(req : HttpTypes.Request, res : HttpTypes.Response, response_hash : ?Blob) : Result<HttpTypes.Response, Text> {
            Stable.get_certified_response(internal, req, res, response_hash);
        };

        /// Get the certificate for a given request.
        ///
        /// This function returns the certificate headers for a predefined response.
        /// This only works if the endpoint has already been certified.
        ///
        /// ```motoko
        /// public func http_request(req : HttpTypes.Request) : HttpTypes.Response {
        ///     let res : HttpTypes.Response = {
        ///         status_code = 200;
        ///         headers = [("Content-Type", "text/plain")];
        ///         body = "Hello, World!";
        ///         ...
        ///     };
        ///
        ///     let #ok(certificate_headers) = cert.get_certificate(req, res, null);
        ///     return { res with headers = Array.append(res.headers, certificate_headers};
        /// };
        /// ```
        public func get_certificate(req : HttpTypes.Request, res : HttpTypes.Response, response_hash : ?Blob) : Result<[HttpTypes.Header], Text> {
            Stable.get_certificate(internal, req, res, response_hash);
        };

        /// Retrieves the encoded certificate and tree based on the given keys.
        /// If keys are set to `null`, the entire tree is returned.
        public func get_certified_tree(keys : ?[Text]) : Result<CertifiedTree, Text> {
            Stable.get_certified_tree(internal, keys);
        };
    };
};
