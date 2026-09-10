//
//  Base32Coding.swift
//  OTP
//

import Foundation

/// The RFC 4648 Base32 arithmetic on plain bytes.
enum Base32Coding {

    static let alphabet: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// Value of each alphabet character, keyed by its uppercase form.
    static let values: [Character: UInt8] = {
        var table: [Character: UInt8] = [:]
        for (index, character) in alphabet.enumerated() { table[character] = UInt8(index) }
        return table
    }()

    /// Five bits at a time out of the bytes, `=` to a multiple of eight characters.
    static func encode(_ bytes: [UInt8], padding: Bool) -> String {
        var output = ""
        var buffer: UInt64 = 0
        var bits = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt64(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[Int((buffer >> UInt64(bits)) & 0x1f)])
            }
        }
        if bits > 0 {
            output.append(alphabet[Int((buffer << UInt64(5 - bits)) & 0x1f)])
        }
        if padding {
            while output.count % 8 != 0 { output.append("=") }
        }
        return output
    }

    /// Five bits at a time back into bytes, tolerant of the ways people mangle
    /// a secret: case, spaces, dashes, dropped padding. Trailing bits that do
    /// not fill a byte are the encoder's zero padding and are discarded.
    static func decode(_ text: String) throws -> [UInt8] {
        var output: [UInt8] = []
        var buffer: UInt64 = 0
        var bits = 0
        for character in text {
            if character == " " || character == "-" { continue }
            // Padding ends a group: whatever bits are waiting were the
            // encoder's zero fill, and the next character starts fresh.
            if character == "=" { buffer = 0; bits = 0; continue }
            guard let value = values[Character(character.uppercased())] else {
                throw OTPError.badBase32(String(character))
            }
            buffer = (buffer << 5) | UInt64(value)
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> UInt64(bits)) & 0xff))
            }
        }
        return output
    }
}
