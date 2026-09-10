//
//  TOTP.swift
//  OTP
//
//  Time-based one-time codes, RFC 6238 — the six digits an authenticator shows.
//

import Foundation

/// Time-based one-time passwords: the code an authenticator app shows.
///
/// ``HOTP`` with the counter set to the number of whole periods since 1970.
/// Every authenticator and every service computing this must agree on the
/// clock to the second, which is why the usual check accepts the step either
/// side (``TOTP/validate(_:secret:at:window:period:digits:algorithm:)``).
public enum TOTP {

    /// The code in force at `date`.
    ///
    /// - Throws: ``OTPError/emptySecret``, ``OTPError/badDigits(_:)``,
    ///   ``OTPError/badPeriod(_:)`` or ``OTPError/dateBeforeEpoch(_:)``.
    public static func code(
        secret: Data, at date: Date = Date(), period: TimeInterval = 30,
        digits: Int = 6, algorithm: HashAlgorithm = .sha1
    ) throws -> String {
        try Validation.check(period: period)
        let step = try TimeSteps.step(at: date, period: period)
        return try HOTP.code(secret: secret, counter: step, digits: digits, algorithm: algorithm)
    }

    /// Whole seconds until the code in force at `date` changes: `period` on
    /// the boundary itself, 1 just before the next one.
    ///
    /// - Throws: ``OTPError/badPeriod(_:)`` or ``OTPError/dateBeforeEpoch(_:)``.
    public static func remainingSeconds(at date: Date = Date(), period: TimeInterval = 30) throws -> Int {
        try Validation.check(period: period)
        return try TimeSteps.remainingSeconds(at: date, period: period)
    }

    /// Whether a code typed by a person is right, allowing `window` steps of
    /// clock drift either side.
    ///
    /// A window of one — the usual — accepts the code from the previous
    /// period and the next as well as the current, because the phone's clock
    /// and the server's are never exactly aligned and a code typed at the
    /// last second would otherwise fail. Comparison is constant-time so the
    /// check cannot leak which digits matched. Spaces in the typed code are
    /// ignored, since apps display `123 456`.
    ///
    /// - Throws: ``OTPError/emptySecret``, ``OTPError/badDigits(_:)``,
    ///   ``OTPError/badPeriod(_:)`` or ``OTPError/dateBeforeEpoch(_:)``.
    public static func validate(
        _ code: String, secret: Data, at date: Date = Date(), window: Int = 1,
        period: TimeInterval = 30, digits: Int = 6, algorithm: HashAlgorithm = .sha1
    ) throws -> Bool {
        try Validation.check(period: period)
        let typed = code.replacingOccurrences(of: " ", with: "")
        let step = try TimeSteps.step(at: date, period: period)
        var matched = false
        for candidate in TimeSteps.candidates(around: step, window: max(0, window)) {
            let expected = try HOTP.code(secret: secret, counter: candidate, digits: digits, algorithm: algorithm)
            // Every candidate is checked even after a match, so the time taken
            // does not say which step matched.
            if ConstantTime.equal(typed, expected) { matched = true }
        }
        return matched
    }
}
