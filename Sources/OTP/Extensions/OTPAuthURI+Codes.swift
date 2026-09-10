//
//  OTPAuthURI+Codes.swift
//  OTP
//

import Foundation

extension OTPAuthURI {

    /// The code this URI produces: at `date` for TOTP, at its counter for HOTP.
    ///
    /// - Throws: ``OTPError/dateBeforeEpoch(_:)`` for a TOTP date before 1970.
    public func code(at date: Date = Date()) throws -> String {
        switch type {
        case .totp:
            return try TOTP.code(secret: secret, at: date, period: period, digits: digits, algorithm: algorithm)
        case .hotp:
            return try HOTP.code(secret: secret, counter: counter ?? 0, digits: digits, algorithm: algorithm)
        }
    }

    /// For HOTP, the same URI with the counter advanced by one — the state to
    /// keep after a code has been used. A TOTP URI comes back unchanged.
    public func advanced() -> OTPAuthURI {
        guard type == .hotp, let counter else { return self }
        return (try? OTPAuthURI(
            type: .hotp, issuer: issuer, account: account, secret: secret,
            digits: digits, period: period, algorithm: algorithm, counter: counter &+ 1
        )) ?? self
    }
}
