//
//  URIParsing.swift
//  OTP
//
//  Google Authenticator's key URI format, read.
//

import Foundation

/// `otpauth://TYPE/LABEL?PARAMETERS` into an ``OTPAuthURI``.
enum URIParsing {

    static func parse(_ text: String) throws -> OTPAuthURI {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "otpauth",
              let host = components.host, let type = OTPType(rawValue: host.lowercased())
        else { throw OTPError.badURI(text) }

        // The label is the path minus its leading slash, percent-decoded by
        // URLComponents already. Some encoders write the colon as %3A; that
        // decodes to a colon and splits the same way.
        let label = components.path.hasPrefix("/") ? String(components.path.dropFirst()) : components.path
        let (labelIssuer, account) = split(label: label)

        var parameters: [String: String] = [:]
        for item in components.queryItems ?? [] {
            parameters[item.name.lowercased()] = item.value ?? ""
        }

        guard let secretText = parameters["secret"], !secretText.isEmpty else { throw OTPError.missingSecret }
        let secret = try Base32Coding.decode(secretText)

        // The parameter wins over the label prefix when both are present.
        let issuer = parameters["issuer"].flatMap { $0.isEmpty ? nil : $0 } ?? labelIssuer

        var digits = 6
        if let text = parameters["digits"] {
            guard let value = Int(text) else { throw OTPError.badParameter(name: "digits", value: text) }
            digits = value
        }
        var period: TimeInterval = 30
        if let text = parameters["period"] {
            guard let value = TimeInterval(text) else { throw OTPError.badParameter(name: "period", value: text) }
            period = value
        }
        var algorithm = HashAlgorithm.sha1
        if let text = parameters["algorithm"] {
            guard let value = HashSupport.algorithm(named: text) else { throw OTPError.badParameter(name: "algorithm", value: text) }
            algorithm = value
        }
        var counter: UInt64?
        if let text = parameters["counter"] {
            guard let value = UInt64(text) else { throw OTPError.badParameter(name: "counter", value: text) }
            counter = value
        }
        if type == .hotp, counter == nil { throw OTPError.missingCounter }

        return try OTPAuthURI(
            type: type, issuer: issuer, account: account, secret: Data(secret),
            digits: digits, period: period, algorithm: algorithm, counter: counter
        )
    }

    /// `Issuer:account` → both; `account` → no issuer. Only the first colon
    /// splits, because an account can be `user:name@host`.
    static func split(label: String) -> (issuer: String, account: String) {
        guard let colon = label.firstIndex(of: ":") else {
            return ("", label.trimmingCharacters(in: .whitespaces))
        }
        return (
            String(label[..<colon]).trimmingCharacters(in: .whitespaces),
            String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        )
    }
}
