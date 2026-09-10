//
//  HashSupport.swift
//  OTP
//

import Foundation

/// The facts about each hash, and the names a URI may use for it.
enum HashSupport {

    static func digestLength(of algorithm: HashAlgorithm) -> Int {
        switch algorithm {
        case .sha1: 20
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    /// `sha1`, `SHA-256`, `Sha512` — case and dash both forgiven.
    static func algorithm(named name: String) -> HashAlgorithm? {
        let normalised = name.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
        return HashAlgorithm(rawValue: normalised)
    }
}
