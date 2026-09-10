//
//  Fixtures.swift
//  OTP
//
//  The RFC secrets, as the RFCs state them. The SHA-256 and SHA-512 TOTP
//  secrets are NOT the SHA-1 secret hashed or padded: RFC 6238 Appendix B
//  uses "12345678901234567890" repeated to 32 and 64 bytes, and getting that
//  wrong is the classic reason a fresh implementation fails every vector.
//

import Foundation

enum Fixtures {
    static let sha1Secret = Data("12345678901234567890".utf8)
    static let sha256Secret = Data("12345678901234567890123456789012".utf8)
    static let sha512Secret = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    static func bytes(_ value: UInt8, count: Int) -> Data { Data(repeating: value, count: count) }

    static func hex(_ text: String) -> Data {
        var data = Data(); var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            data.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return data
    }
}
