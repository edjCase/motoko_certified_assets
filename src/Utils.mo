import Result "mo:base/Result";
import Prelude "mo:base/Prelude";

module {
    type Result<T, E> = Result.Result<T, E>;

    public func send_error<OldOk, NewOk, Error>(res: Result<OldOk, Error>): Result<NewOk, Error>{
        switch (res) {
            case (#ok(_)) Prelude.unreachable();
            case (#err(errorMsg)) #err(errorMsg);
        };
    };

};