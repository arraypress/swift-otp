//
//  URIBuilding.swift
//  OTP
//
//  Google Authenticator's key URI format, written.
//

import Foundation

/// An ``OTPAuthURI`` back into text.
enum URIBuilding {

    /// Everything the reader might want is written, defaults included.
    static func build(_ uri: OTPAuthURI) -> String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = uri.type.rawValue
        let label = uri.issuer.isEmpty ? uri.account : "\(uri.issuer):\(uri.account)"
        components.path = "/" + label

        var items = [URLQueryItem(name: "secret", value: Base32Coding.encode(Array(uri.secret), padding: false))]
        if !uri.issuer.isEmpty { items.append(URLQueryItem(name: "issuer", value: uri.issuer)) }
        items.append(URLQueryItem(name: "algorithm", value: uri.algorithm.rawValue))
        items.append(URLQueryItem(name: "digits", value: String(uri.digits)))
        switch uri.type {
        case .totp:
            items.append(URLQueryItem(name: "period", value: formatted(uri.period)))
        case .hotp:
            items.append(URLQueryItem(name: "counter", value: String(uri.counter ?? 0)))
        }
        components.queryItems = items
        // URLComponents leaves ':' and '@' in a path alone, which is what the
        // format expects; everything else it percent-encodes.
        return components.string ?? "otpauth://\(uri.type.rawValue)/"
    }

    /// `30`, not `30.0`.
    static func formatted(_ period: TimeInterval) -> String {
        period.rounded() == period ? String(Int(period)) : String(period)
    }
}
