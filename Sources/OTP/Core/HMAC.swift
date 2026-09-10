//
//  HMAC.swift
//  OTP
//
//  Keyed hashes, RFC 2104 — signing a request, verifying a webhook.
//

import Foundation

/// Hash-based message authentication: a signature from a message and a key,
/// and the constant-time check of one that arrived.
///
/// This is what every signed API and webhook uses — Stripe, GitHub and
/// Shopify sign their payloads with a shared secret; Binance and Kraken want
/// requests signed the same way. The verify side matters as much as the sign
/// side: comparing signatures with `==` lets an attacker time how many
/// leading bytes matched, so ``HMAC/verify(_:message:key:)`` never does.
///
/// Named `HMAC` because that is what it is; if a file also imports
/// CryptoKit, write `OTP.HMAC`.
public enum HMAC {

    /// Signs a message with a key.
    ///
    /// - Throws: ``OTPError/emptySecret`` for an empty key.
    public static func sign(_ message: Data, key: Data, algorithm: HashAlgorithm = .sha256) throws -> Signature {
        try Validation.check(secret: key)
        return Signature(data: HMACComputation.mac(message, key: key, algorithm: algorithm), algorithm: algorithm)
    }

    /// Signs text with a text key, both as UTF-8 — the shape webhooks take.
    ///
    /// - Throws: ``OTPError/emptySecret`` for an empty key.
    public static func sign(_ text: String, key: String, algorithm: HashAlgorithm = .sha256) throws -> Signature {
        try sign(Data(text.utf8), key: Data(key.utf8), algorithm: algorithm)
    }

    /// Whether `signature` is the signature of `message` under `key`, in
    /// constant time.
    ///
    /// CryptoKit's own `isValidAuthenticationCode` does the comparison, so the
    /// time taken does not depend on where the first wrong byte is.
    ///
    /// - Throws: ``OTPError/emptySecret`` for an empty key.
    public static func verify(_ signature: Signature, message: Data, key: Data) throws -> Bool {
        try Validation.check(secret: key)
        return HMACComputation.isValid(signature.data, message: message, key: key, algorithm: signature.algorithm)
    }

    /// Whether raw signature bytes match, in constant time.
    ///
    /// - Throws: ``OTPError/emptySecret`` for an empty key.
    public static func verify(_ signature: Data, message: Data, key: Data, algorithm: HashAlgorithm) throws -> Bool {
        try verify(Signature(data: signature, algorithm: algorithm), message: message, key: key)
    }

    /// Whether a hex signature — the form GitHub and Stripe send — matches.
    ///
    /// - Throws: ``OTPError/badHex(_:)`` or ``OTPError/emptySecret``.
    public static func verify(hex: String, message: Data, key: Data, algorithm: HashAlgorithm = .sha256) throws -> Bool {
        try verify(Signature(hex: hex, algorithm: algorithm), message: message, key: key)
    }

    /// Whether a Base64 signature — the form Shopify sends — matches.
    ///
    /// - Throws: ``OTPError/badBase64(_:)`` or ``OTPError/emptySecret``.
    public static func verify(base64: String, message: Data, key: Data, algorithm: HashAlgorithm = .sha256) throws -> Bool {
        try verify(Signature(base64: base64, algorithm: algorithm), message: message, key: key)
    }
}
