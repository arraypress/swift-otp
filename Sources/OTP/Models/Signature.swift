//
//  Signature.swift
//  OTP
//

import Foundation

/// The bytes an HMAC produced, and the hash that produced them.
///
/// Carried together because a signature means nothing without its
/// algorithm: the same key and message give a different result under
/// SHA-1 and SHA-256, and a webhook header says which it used. Rendered
/// as hex or Base64 through ``Signature/hex`` and ``Signature/base64``,
/// which is how the wire carries it — GitHub and Stripe send hex, Shopify
/// sends Base64.
public struct Signature: Sendable, Hashable, Codable {

    /// The raw authentication code.
    public let data: Data

    /// The hash the code was made with.
    public let algorithm: HashAlgorithm

    /// A signature from raw bytes; see ``Signature/init(hex:algorithm:)`` and
    /// ``Signature/init(base64:algorithm:)`` for the forms headers carry.
    public init(data: Data, algorithm: HashAlgorithm) {
        self.data = data
        self.algorithm = algorithm
    }
}
