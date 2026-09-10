//
//  Validation.swift
//  OTP
//

import Foundation

/// The checks on the way in.
enum Validation {

    /// A secret or key has at least one byte.
    static func check(secret: Data) throws {
        guard !secret.isEmpty else { throw OTPError.emptySecret }
    }

    /// Codes are 6, 7 or 8 digits — RFC 4226 asks for at least six, and 10^9
    /// exceeds the 31-bit number the truncation yields, so nine would repeat
    /// leading zeros that carry nothing.
    static func check(digits: Int) throws {
        guard (6...8).contains(digits) else { throw OTPError.badDigits(digits) }
    }

    /// A period is a positive, finite number of seconds.
    static func check(period: TimeInterval) throws {
        guard period > 0, period.isFinite else { throw OTPError.badPeriod(period) }
    }
}
