import Result "mo:base/Result";
import Prelude "mo:base/Prelude";
import Char "mo:base/Char";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Option "mo:base/Option";
import Hex "mo:encoding/Hex";
module {
    type Result<T, E> = Result.Result<T, E>;

    public func send_error<OldOk, NewOk, Error>(res: Result<OldOk, Error>): Result<NewOk, Error>{
        switch (res) {
            case (#ok(_)) Prelude.unreachable();
            case (#err(errorMsg)) #err(errorMsg);
        };
    };

    public func subText(value : Text, indexStart : Nat, indexEnd : Nat) : Text {
        if (indexStart == 0 and indexEnd >= value.size()) {
            return value;
        };
        if (indexStart >= value.size()) {
            return "";
        };

        var result : Text = "";
        var i : Nat = 0;
        label l for (c in value.chars()) {
            if (i >= indexStart and i < indexEnd) {
                result := result # Char.toText(c);
            };
            if (i == indexEnd) {
                break l;
            };
            i += 1;
        };

        result;
    };

    public func nat8ToChar(n8 : Nat8) : Char {
        let n = Nat8.toNat(n8);
        let n32 = Nat32.fromNat(n);
        Char.fromNat32(n32);
    };

    public func charToNat8(char : Char) : Nat8 {
        let n32 = Char.toNat32(char);
        let n = Nat32.toNat(n32);
        let n8 = Nat8.fromNat(n);
    };

    public func percent_decoding(t : Text) : Text {
        let iter = Text.split(t, #char '%');
        var decodedURI = Option.get(iter.next(), "");

        for (sp in iter) {
            let hex = subText(sp, 0, 2);

            switch (Hex.decode(hex)) {
                case (#ok(symbols)) {
                    let char = (nat8ToChar(symbols[0]));
                    decodedURI := decodedURI # Char.toText(char) #
                    Text.trimStart(sp, #text hex);
                };
                case (_) {
                    return Debug.trap("Improper url percent encoding");
                };
            };

        };

        decodedURI;
    };

    // A predicate for matching any char in the given text
    func matchAny(text : Text) : Text.Pattern {
        func pattern(c : Char) : Bool {
            Text.contains(text, #char c);
        };

        return #predicate pattern;
    };

    public func percent_encoding(t : Text) : Text {
        var encoded = "";

        for (c in t.chars()) {
            let cAsText = Char.toText(c);
            if (Text.contains(cAsText, matchAny("'()*-._~")) or Char.isAlphabetic(c) or Char.isDigit(c)) {
                encoded := encoded # Char.toText(c);
            } else {
                let hex = Hex.encodeByte(charToNat8(c));
                encoded := encoded # "%" # hex;
            };
        };
        encoded;
    };
};