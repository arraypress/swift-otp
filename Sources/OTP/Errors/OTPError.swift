//
//  OTPError.swift
//  OTP
//

import Foundation

/// What was refused, in words a caller can print unchanged.
public enum OTPError: Error, LocalizedError, Equatable, Sendable {

    /// A secret or key with no bytes in it.
    case emptySecret

    /// A digit count outside 6–8, the range the RFC and every authenticator use.
    case badDigits(Int)

    /// A period that is not a positive number of seconds.
    case badPeriod(TimeInterval)

    /// A date before 1970, which has no time step.
    case dateBeforeEpoch(Date)

    /// Text that is not Base32: the character named is not in the alphabet.
    case badBase32(String)

    /// Text that is not hexadecimal.
    case badHex(String)

    /// Text that is not Base64.
    case badBase64(String)

    /// A URI that is not `otpauth://totp/…` or `otpauth://hotp/…`.
    case badURI(String)

    /// An `otpauth://` URI with no `secret` parameter.
    case missingSecret

    /// An `otpauth://hotp/…` URI with no `counter` parameter.
    case missingCounter

    /// A parameter whose value cannot be read: `digits=six`.
    case badParameter(name: String, value: String)

    public var errorDescription: String? {
        switch self {
        case .emptySecret:
            return "the secret is empty\na one-time code or a signature needs at least one byte of key"
        case .badDigits(let digits):
            return "not a digit count: \(digits)\ncodes are 6, 7 or 8 digits long"
        case .badPeriod(let period):
            return "not a period: \(period) seconds\nuse a positive number; authenticator apps use 30"
        case .dateBeforeEpoch(let date):
            return "no time step before 1970: \(date)"
        case .badBase32(let what):
            return "not Base32: \(what)\nthe alphabet is A–Z and 2–7; spaces, dashes and = padding are ignored"
        case .badHex(let what):
            return "not hexadecimal: \(what)"
        case .badBase64(let what):
            return "not Base64: \(what)"
        case .badURI(let what):
            return "not an otpauth URI: \(what)\nexpected otpauth://totp/Issuer:account?secret=… or otpauth://hotp/…?secret=…&counter=…"
        case .missingSecret:
            return "the otpauth URI has no secret parameter"
        case .missingCounter:
            return "an otpauth://hotp URI needs a counter parameter"
        case .badParameter(let name, let value):
            return "not a value for \(name): \(value)"
        }
    }
}
