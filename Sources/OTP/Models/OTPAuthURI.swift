//
//  OTPAuthURI.swift
//  OTP
//

import Foundation

/// Everything an `otpauth://` URI carries — what an authenticator app reads
/// off a QR code.
///
/// The format is Google Authenticator's key URI: a type, a label of the form
/// `Issuer:account`, and the secret with its parameters. Held as typed
/// values, with the secret already decoded from Base32, so the code is one
/// call away (``OTPAuthURI/code(at:)``).
public struct OTPAuthURI: Sendable, Hashable, Codable {

    /// Time-based or counter-based.
    public let type: OTPType

    /// Who issued it, e.g. `GitHub`. Empty when the URI gave none.
    public let issuer: String

    /// The account it is for, e.g. `alice@example.com`.
    public let account: String

    /// The shared secret, decoded.
    public let secret: Data

    /// How many digits the code has: 6, 7 or 8.
    public let digits: Int

    /// Seconds each code lives, for ``OTPType/totp``. 30 unless the URI says otherwise.
    public let period: TimeInterval

    /// The hash to use. SHA-1 unless the URI says otherwise.
    public let algorithm: HashAlgorithm

    /// The next counter to use, for ``OTPType/hotp``; nil for TOTP.
    public let counter: UInt64?

    /// A URI from its parts, checked.
    ///
    /// - Throws: ``OTPError/emptySecret``, ``OTPError/badDigits(_:)``,
    ///   ``OTPError/badPeriod(_:)`` or ``OTPError/missingCounter`` (an HOTP
    ///   URI without a counter cannot produce a code).
    public init(
        type: OTPType, issuer: String = "", account: String, secret: Data,
        digits: Int = 6, period: TimeInterval = 30, algorithm: HashAlgorithm = .sha1, counter: UInt64? = nil
    ) throws {
        try Validation.check(secret: secret)
        try Validation.check(digits: digits)
        try Validation.check(period: period)
        if type == .hotp, counter == nil { throw OTPError.missingCounter }
        self.type = type
        self.issuer = issuer
        self.account = account
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
        self.counter = type == .hotp ? counter : nil
    }
}
