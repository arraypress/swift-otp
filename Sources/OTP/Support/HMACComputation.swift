//
//  HMACComputation.swift
//  OTP
//
//  CryptoKit does the hashing; this picks the hash.
//

import CryptoKit
import Foundation

/// The MAC for each algorithm, and its constant-time check.
enum HMACComputation {

    /// The raw authentication code.
    static func mac(_ message: Data, key: Data, algorithm: HashAlgorithm) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha1:
            return Data(CryptoKit.HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey))
        case .sha256:
            return Data(CryptoKit.HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
        case .sha384:
            return Data(CryptoKit.HMAC<SHA384>.authenticationCode(for: message, using: symmetricKey))
        case .sha512:
            return Data(CryptoKit.HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey))
        }
    }

    /// CryptoKit's `isValidAuthenticationCode`, which compares in constant
    /// time. A code of the wrong length is simply invalid.
    static func isValid(_ code: Data, message: Data, key: Data, algorithm: HashAlgorithm) -> Bool {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha1:
            return CryptoKit.HMAC<Insecure.SHA1>.isValidAuthenticationCode(code, authenticating: message, using: symmetricKey)
        case .sha256:
            return CryptoKit.HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: message, using: symmetricKey)
        case .sha384:
            return CryptoKit.HMAC<SHA384>.isValidAuthenticationCode(code, authenticating: message, using: symmetricKey)
        case .sha512:
            return CryptoKit.HMAC<SHA512>.isValidAuthenticationCode(code, authenticating: message, using: symmetricKey)
        }
    }
}
