//
//  OTPAuthURI+Text.swift
//  OTP
//
//  The URI as text, both ways.
//

import Foundation

extension OTPAuthURI {

    /// Reads an `otpauth://` URI — the text inside an authenticator QR code.
    ///
    /// The label may be `Issuer:account`, `Issuer%3Aaccount` or just the
    /// account; an `issuer` parameter wins over a prefix in the label, which
    /// is the rule Google's key-URI format states and what apps do when the
    /// two disagree. `digits`, `period` and `algorithm` fall back to 6, 30 and
    /// SHA-1 when absent.
    ///
    /// - Throws: ``OTPError/badURI(_:)``, ``OTPError/missingSecret``,
    ///   ``OTPError/missingCounter``, ``OTPError/badBase32(_:)``,
    ///   ``OTPError/badParameter(name:value:)``, ``OTPError/badDigits(_:)``,
    ///   ``OTPError/badPeriod(_:)``.
    public init(parsing text: String) throws {
        self = try URIParsing.parse(text)
    }

    /// The URI as text, ready for a QR code.
    ///
    /// The label is `Issuer:account` when there is an issuer, the `issuer`
    /// parameter is repeated (apps read either), and every parameter is
    /// written out even at its default so a reader never has to know the
    /// defaults.
    public var uri: String { URIBuilding.build(self) }
}
