//
//  HOTP.swift
//  OTP
//
//  Counter-based one-time codes, RFC 4226.
//

import Foundation

/// HMAC-based one-time passwords: a code from a secret and a counter.
///
/// The code is an HMAC of the counter, cut down by "dynamic truncation" —
/// the last nibble of the MAC picks four bytes out of it, and those bytes
/// modulo 10^digits are the number. TOTP is exactly this with the counter
/// replaced by a time step, which is why it lives one file over.
public enum HOTP {

    /// The code for a secret at a counter.
    ///
    /// - Parameters:
    ///   - secret: The shared secret's raw bytes (decode Base32 first).
    ///   - counter: The moving factor; the first code is counter 0.
    ///   - digits: 6, 7 or 8. Six is what nearly everything uses.
    ///   - algorithm: SHA-1 unless the service says otherwise.
    /// - Throws: ``OTPError/emptySecret`` or ``OTPError/badDigits(_:)``.
    public static func code(
        secret: Data, counter: UInt64, digits: Int = 6, algorithm: HashAlgorithm = .sha1
    ) throws -> String {
        try Validation.check(secret: secret)
        try Validation.check(digits: digits)
        let mac = HMACComputation.mac(HOTPComputation.counterBytes(counter), key: secret, algorithm: algorithm)
        return HOTPComputation.format(HOTPComputation.truncate(mac, digits: digits), digits: digits)
    }
}
