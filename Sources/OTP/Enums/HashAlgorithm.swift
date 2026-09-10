//
//  HashAlgorithm.swift
//  OTP
//

import Foundation

/// The hash under an HMAC, an HOTP or a TOTP, spelled the way `otpauth://` spells it.
///
/// SHA-1 is the default everywhere in one-time codes — RFC 4226 has no other,
/// and most authenticator apps silently ignore anything else — so it is here,
/// weak as it is for anything but this. For signing a request, use SHA-256.
public enum HashAlgorithm: String, CaseIterable, Sendable, Codable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha384 = "SHA384"
    case sha512 = "SHA512"

    /// The length of the hash in bytes: 20, 32, 48 or 64.
    public var digestLength: Int { HashSupport.digestLength(of: self) }

    /// The algorithm an `otpauth://` URI names, case-insensitively, with or
    /// without the dash: `sha1`, `SHA-256`, `Sha512`.
    public init?(uriName: String) {
        guard let match = HashSupport.algorithm(named: uriName) else { return nil }
        self = match
    }
}
