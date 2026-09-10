//
//  Rendering.swift
//  OTP
//

import Foundation

/// Bytes as hex, and hex as bytes.
enum Rendering {

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Two hex characters a byte, either case, an optional `0x` prefix.
    static func data(fromHex text: String) throws -> Data {
        var body = Substring(text.trimmingCharacters(in: .whitespaces))
        if body.lowercased().hasPrefix("0x") { body = body.dropFirst(2) }
        guard body.count % 2 == 0, !body.isEmpty else { throw OTPError.badHex(text) }
        var bytes: [UInt8] = []
        var index = body.startIndex
        while index < body.endIndex {
            let next = body.index(index, offsetBy: 2)
            guard let byte = UInt8(body[index..<next], radix: 16) else { throw OTPError.badHex(text) }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}
