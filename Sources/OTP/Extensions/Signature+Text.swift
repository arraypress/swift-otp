//
//  Signature+Text.swift
//  OTP
//

import Foundation

extension Signature {

    /// Lowercase hexadecimal, two characters a byte: the form in
    /// `X-Hub-Signature-256: sha256=…` and Stripe's `v1=…`.
    public var hex: String { Rendering.hex(data) }

    /// Standard Base64 with padding: the form in `X-Shopify-Hmac-Sha256`.
    public var base64: String { data.base64EncodedString() }

    /// A signature from its hex form.
    ///
    /// - Throws: ``OTPError/badHex(_:)`` for odd length or non-hex characters.
    public init(hex: String, algorithm: HashAlgorithm) throws {
        self.init(data: try Rendering.data(fromHex: hex), algorithm: algorithm)
    }

    /// A signature from its Base64 form.
    ///
    /// - Throws: ``OTPError/badBase64(_:)``.
    public init(base64: String, algorithm: HashAlgorithm) throws {
        guard let data = Data(base64Encoded: base64) else { throw OTPError.badBase64(base64) }
        self.init(data: data, algorithm: algorithm)
    }
}
