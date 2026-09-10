//
//  Base32.swift
//  OTP
//
//  RFC 4648 Base32 — the encoding every authenticator secret arrives in.
//

import Foundation

/// Base32 as RFC 4648 defines it, and as authenticator apps read it.
///
/// The secret behind a QR code is Base32 because it fits on a screen and
/// survives being read aloud: A–Z and 2–7, no 0/O or 1/l to confuse. Apps
/// forgive what people do to it — lowercase, spaces every four characters,
/// dashes, missing `=` padding — and so does ``Base32/decode(_:)``. Encoding
/// pads by default, because that is what the RFC's own examples show.
public enum Base32 {

    /// Encodes bytes to the RFC 4648 alphabet, padded to a multiple of eight
    /// characters unless asked not to.
    public static func encode(_ data: Data, padding: Bool = true) -> String {
        Base32Coding.encode(Array(data), padding: padding)
    }

    /// Decodes text in the RFC 4648 alphabet, forgiving case, spaces, dashes
    /// and absent padding.
    ///
    /// - Throws: ``OTPError/badBase32(_:)`` naming the first character that is
    ///   not in the alphabet.
    public static func decode(_ text: String) throws -> Data {
        Data(try Base32Coding.decode(text))
    }
}
