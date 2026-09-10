//
//  OTPType.swift
//  OTP
//

import Foundation

/// The two kinds of one-time code an `otpauth://` URI can carry.
public enum OTPType: String, CaseIterable, Sendable, Codable {

    /// Time-based (RFC 6238): the code changes every `period` seconds.
    case totp

    /// Counter-based (RFC 4226): the code changes each time it is used.
    case hotp
}
